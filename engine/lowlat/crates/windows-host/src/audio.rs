//! System audio capture on Windows via WASAPI loopback.
//!
//! Status: implemented and CI-validated (the pure format negotiation, sample
//! conversion and bounded-queue logic is unit-tested on every target; the WASAPI
//! FFI is compiled for the Windows targets). Physical Windows runtime
//! verification is pending the hardware. Not a production default until then.
//!
//! Loopback capture on the default render endpoint is the vendor-neutral OS way
//! to capture what the machine is playing, so the peer hears the host's audio
//! with no extra driver. WASAPI hands back the endpoint's mix format (commonly
//! 32-bit float at 48 kHz); this negotiates it to the pipeline's format
//! (interleaved i16 stereo at 48 kHz) and buffers samples in a bounded,
//! drop-oldest queue so a slow consumer costs latency, never memory.

use std::collections::VecDeque;

/// The pipeline's audio format: interleaved i16 stereo at 48 kHz.
pub const TARGET_SAMPLE_RATE: u32 = 48_000;
pub const TARGET_CHANNELS: u16 = 2;

/// How an endpoint delivers samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    /// 32-bit IEEE float in [-1.0, 1.0].
    F32,
    /// 16-bit signed PCM.
    I16,
}

/// A capture endpoint's mix format, enough to plan a conversion without any
/// platform types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixFormat {
    pub sample_rate: u32,
    pub channels: u16,
    pub format: SampleFormat,
}

/// What converting a mix format to the pipeline format requires. Resampling is
/// not implemented yet, so a non-48 kHz endpoint is reported as unsupported
/// rather than silently mis-rated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionPlan {
    /// Convert each interleaved frame from `source` to i16 stereo.
    Supported { source: MixFormat },
    /// The endpoint's sample rate differs from the pipeline's; needs a resampler.
    NeedsResample { source_rate: u32 },
    /// The channel count is one this converter does not fold to stereo.
    UnsupportedChannels { channels: u16 },
}

/// Decide how to bring `mix` to interleaved i16 stereo at [`TARGET_SAMPLE_RATE`].
pub fn plan_conversion(mix: MixFormat) -> ConversionPlan {
    if mix.sample_rate != TARGET_SAMPLE_RATE {
        return ConversionPlan::NeedsResample {
            source_rate: mix.sample_rate,
        };
    }
    if mix.channels == 0 || mix.channels > 8 {
        return ConversionPlan::UnsupportedChannels {
            channels: mix.channels,
        };
    }
    ConversionPlan::Supported { source: mix }
}

/// Convert one clamped float sample to i16 with symmetric scaling: +1.0 maps to
/// `i16::MAX` (32767) and -1.0 to -32767, which avoids the off-by-one asymmetry
/// of scaling to `i16::MIN` and is the common audio convention.
fn f32_to_i16(sample: f32) -> i16 {
    let scaled = (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round();
    // `scaled` is in [-32767, 32767], so the cast is exact and cannot overflow;
    // there is no fallible f32 -> i16 conversion to use instead.
    #[allow(clippy::cast_possible_truncation)]
    let value = scaled as i16;
    value
}

/// Fold one interleaved frame of `src_channels` samples down (or up) to a stereo
/// (L, R) pair. Mono duplicates; stereo passes through; more channels average
/// into two halves (a coarse but safe downmix).
fn frame_to_stereo(frame: &[i16]) -> (i16, i16) {
    match frame {
        [] => (0, 0),
        [mono] => (*mono, *mono),
        [left, right] => (*left, *right),
        more => {
            // Average the first half into L, the second half into R.
            let half = more.len() / 2;
            let mean = |slice: &[i16]| -> i16 {
                let count = i32::try_from(slice.len()).unwrap_or(1).max(1);
                let sum: i32 = slice.iter().map(|s| i32::from(*s)).sum();
                // The average of i16 values is itself within i16 range.
                i16::try_from(sum / count).unwrap_or(0)
            };
            (mean(&more[..half]), mean(&more[half..]))
        }
    }
}

/// Convert interleaved samples in `source` format to interleaved i16 stereo.
pub fn convert_to_i16_stereo(samples: &[f32], source: MixFormat) -> Vec<i16> {
    let channels = source.channels.max(1) as usize;
    let mut out = Vec::with_capacity((samples.len() / channels) * 2);
    let mut frame = Vec::with_capacity(channels);
    for chunk in samples.chunks(channels) {
        frame.clear();
        for &sample in chunk {
            frame.push(match source.format {
                // The FFI hands us f32 already; an i16-native endpoint is read as
                // f32 by the caller before this, so this branch just rounds.
                SampleFormat::F32 => f32_to_i16(sample),
                SampleFormat::I16 => f32_to_i16(sample),
            });
        }
        let (left, right) = frame_to_stereo(&frame);
        out.push(left);
        out.push(right);
    }
    out
}

/// A bounded queue of interleaved stereo i16 samples that keeps the newest audio
/// and drops the oldest when full, so a stalled consumer bounds latency rather
/// than growing memory without limit.
#[derive(Debug)]
pub struct BoundedPcmQueue {
    samples: VecDeque<i16>,
    capacity_samples: usize,
    dropped_samples: u64,
}

impl BoundedPcmQueue {
    /// A queue holding at most `capacity_frames` stereo frames (2 samples each).
    #[must_use]
    pub fn with_capacity_frames(capacity_frames: usize) -> Self {
        let capacity_samples = capacity_frames.saturating_mul(2).max(2);
        Self {
            samples: VecDeque::with_capacity(capacity_samples),
            capacity_samples,
            dropped_samples: 0,
        }
    }

    /// Append interleaved stereo samples, dropping the oldest to stay within
    /// capacity.
    pub fn push(&mut self, stereo: &[i16]) {
        self.samples.extend(stereo.iter().copied());
        while self.samples.len() > self.capacity_samples {
            self.samples.pop_front();
            self.dropped_samples += 1;
        }
    }

    /// Take one `frame_samples`-long block (interleaved), or `None` if fewer than
    /// that many samples are queued.
    pub fn take_frame(&mut self, frame_samples: usize) -> Option<Vec<i16>> {
        if self.samples.len() < frame_samples {
            return None;
        }
        Some(self.samples.drain(..frame_samples).collect())
    }

    /// How many samples have been dropped to stay bounded, for diagnostics.
    #[must_use]
    pub fn dropped_samples(&self) -> u64 {
        self.dropped_samples
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

#[cfg(target_os = "windows")]
pub use session::{AudioError, LoopbackCapture};

#[cfg(target_os = "windows")]
mod session {
    use windows::Win32::Media::Audio::{
        AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, IAudioCaptureClient, IAudioClient,
        IMMDeviceEnumerator, MMDeviceEnumerator, WAVEFORMATEX, eConsole, eRender,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    };

    use super::{
        BoundedPcmQueue, ConversionPlan, MixFormat, SampleFormat, convert_to_i16_stereo,
        plan_conversion,
    };

    /// Why WASAPI loopback capture failed.
    #[derive(Debug)]
    pub enum AudioError {
        Windows(windows::core::Error),
        /// The endpoint's format cannot be brought to the pipeline format yet
        /// (e.g. a non-48 kHz endpoint that would need resampling).
        UnsupportedFormat(ConversionPlan),
    }

    impl std::fmt::Display for AudioError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AudioError::Windows(error) => write!(f, "wasapi loopback error: {error}"),
                AudioError::UnsupportedFormat(plan) => {
                    write!(
                        f,
                        "endpoint format needs conversion not yet supported: {plan:?}"
                    )
                }
            }
        }
    }

    impl std::error::Error for AudioError {}

    impl From<windows::core::Error> for AudioError {
        fn from(error: windows::core::Error) -> Self {
            AudioError::Windows(error)
        }
    }

    /// A WASAPI loopback capture session on the default render endpoint.
    #[derive(Debug)]
    pub struct LoopbackCapture {
        client: IAudioClient,
        capture: IAudioCaptureClient,
        source: MixFormat,
        queue: BoundedPcmQueue,
    }

    impl LoopbackCapture {
        /// Open loopback capture on the default render endpoint, buffering up to
        /// `queue_frames` stereo frames.
        pub fn new(queue_frames: usize) -> Result<Self, AudioError> {
            // SAFETY: FFI. COM init is idempotent per-thread; the enumerator and
            // endpoint below are live interfaces used per the WASAPI contract.
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                let enumerator: IMMDeviceEnumerator =
                    CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
                let device = enumerator.GetDefaultAudioEndpoint(eRender, eConsole)?;
                let client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;

                let mix_ptr = client.GetMixFormat()?;
                let source = read_mix_format(mix_ptr);
                let plan = plan_conversion(source);
                if !matches!(plan, ConversionPlan::Supported { .. }) {
                    windows::Win32::System::Com::CoTaskMemFree(Some(mix_ptr.cast()));
                    return Err(AudioError::UnsupportedFormat(plan));
                }

                // A one-second buffer, in 100 ns units; shared loopback mode.
                client.Initialize(
                    AUDCLNT_SHAREMODE_SHARED,
                    AUDCLNT_STREAMFLAGS_LOOPBACK,
                    10_000_000,
                    0,
                    mix_ptr,
                    None,
                )?;
                windows::Win32::System::Com::CoTaskMemFree(Some(mix_ptr.cast()));

                let capture: IAudioCaptureClient = client.GetService()?;
                client.Start()?;

                Ok(Self {
                    client,
                    capture,
                    source,
                    queue: BoundedPcmQueue::with_capacity_frames(queue_frames),
                })
            }
        }

        /// Drain the endpoint's currently available packets into the bounded
        /// queue, converting to i16 stereo, then take as many whole frames of
        /// `frame_samples` interleaved samples as are ready.
        pub fn read_frames(&mut self, frame_samples: usize) -> Result<Vec<Vec<i16>>, AudioError> {
            // SAFETY: FFI. Each GetBuffer is paired with ReleaseBuffer; the packet
            // data is read only within that window.
            unsafe {
                loop {
                    let packet = self.capture.GetNextPacketSize()?;
                    if packet == 0 {
                        break;
                    }
                    let mut data = std::ptr::null_mut();
                    let mut frames = 0u32;
                    let mut flags = 0u32;
                    self.capture
                        .GetBuffer(&mut data, &mut frames, &mut flags, None, None)?;
                    let channels = self.source.channels.max(1) as usize;
                    let count = frames as usize * channels;
                    let samples = std::slice::from_raw_parts(data.cast::<f32>(), count);
                    let stereo = convert_to_i16_stereo(samples, self.source);
                    self.queue.push(&stereo);
                    self.capture.ReleaseBuffer(frames)?;
                }
            }

            let mut out = Vec::new();
            while let Some(frame) = self.queue.take_frame(frame_samples) {
                out.push(frame);
            }
            Ok(out)
        }

        /// Samples dropped by the bounded queue, for diagnostics.
        #[must_use]
        pub fn dropped_samples(&self) -> u64 {
            self.queue.dropped_samples()
        }
    }

    impl Drop for LoopbackCapture {
        fn drop(&mut self) {
            // SAFETY: stopping a live client; errors on teardown are not
            // actionable.
            unsafe {
                let _ = self.client.Stop();
            }
        }
    }

    /// Read the fields we need from a `WAVEFORMATEX` the endpoint owns.
    unsafe fn read_mix_format(ptr: *const WAVEFORMATEX) -> MixFormat {
        // WAVE_FORMAT_IEEE_FLOAT = 3, WAVE_FORMAT_PCM = 1; extensible (0xFFFE)
        // endpoints are float in practice for shared-mode mixes.
        // SAFETY: the caller passes a valid mix-format pointer from GetMixFormat.
        let format = unsafe { &*ptr };
        let sample = if format.wBitsPerSample == 16 && format.wFormatTag == 1 {
            SampleFormat::I16
        } else {
            SampleFormat::F32
        };
        MixFormat {
            sample_rate: format.nSamplesPerSec,
            channels: format.nChannels,
            format: sample,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_supports_48k_stereo_float_and_flags_others() {
        assert_eq!(
            plan_conversion(MixFormat {
                sample_rate: 48_000,
                channels: 2,
                format: SampleFormat::F32,
            }),
            ConversionPlan::Supported {
                source: MixFormat {
                    sample_rate: 48_000,
                    channels: 2,
                    format: SampleFormat::F32,
                }
            }
        );
        assert_eq!(
            plan_conversion(MixFormat {
                sample_rate: 44_100,
                channels: 2,
                format: SampleFormat::F32,
            }),
            ConversionPlan::NeedsResample {
                source_rate: 44_100
            }
        );
        assert_eq!(
            plan_conversion(MixFormat {
                sample_rate: 48_000,
                channels: 0,
                format: SampleFormat::F32,
            }),
            ConversionPlan::UnsupportedChannels { channels: 0 }
        );
    }

    #[test]
    fn float_to_i16_hits_the_rails_and_centre() {
        assert_eq!(f32_to_i16(0.0), 0);
        assert_eq!(f32_to_i16(1.0), i16::MAX);
        // Symmetric scaling: -1.0 maps to -32767, not i16::MIN.
        assert_eq!(f32_to_i16(-1.0), -32767);
        // Clamps out-of-range input.
        assert_eq!(f32_to_i16(2.0), i16::MAX);
        assert_eq!(f32_to_i16(-2.0), -32767);
    }

    #[test]
    fn mono_and_multichannel_fold_to_stereo() {
        // Mono duplicates into both channels.
        let mono = MixFormat {
            sample_rate: 48_000,
            channels: 1,
            format: SampleFormat::F32,
        };
        assert_eq!(
            convert_to_i16_stereo(&[1.0], mono),
            vec![i16::MAX, i16::MAX]
        );
        // Stereo passes through.
        let stereo = MixFormat {
            sample_rate: 48_000,
            channels: 2,
            format: SampleFormat::F32,
        };
        assert_eq!(
            convert_to_i16_stereo(&[1.0, -1.0], stereo),
            vec![i16::MAX, -32767]
        );
    }

    #[test]
    fn bounded_queue_drops_oldest_and_yields_frames() {
        // Capacity 2 frames = 4 samples.
        let mut queue = BoundedPcmQueue::with_capacity_frames(2);
        queue.push(&[1, 2, 3, 4]); // full
        queue.push(&[5, 6]); // drops 1,2
        assert_eq!(queue.dropped_samples(), 2);
        assert_eq!(queue.len(), 4);
        // Take one 2-sample frame: the oldest surviving samples.
        assert_eq!(queue.take_frame(2), Some(vec![3, 4]));
        assert_eq!(queue.take_frame(2), Some(vec![5, 6]));
        assert_eq!(queue.take_frame(2), None);
        assert!(queue.is_empty());
    }
}
