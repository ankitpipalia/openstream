//! Minimal native bridge for Android/iOS client front ends.
//!
//! The bridge owns signaling, authenticated UDP, bounded video reassembly,
//! and reliable input transport on a Rust worker thread. The platform UI owns the
//! video decoder and presentation surface: Android should feed the H.264
//! access units to MediaCodec and iOS to VideoToolbox. The bridge emits
//! decoded stereo PCM for the native audio sink. No host capture or input
//! injection API is exported here, so mobile builds remain client-only.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::net::SocketAddr;
use std::slice;
use std::thread::{self, JoinHandle};

use openstream_client_core::{Pairing, PeerSession, ReliableControl, Role, VideoCodec};
use openstream_media::input::RumbleEvent;
use openstream_media::{
    Assembler, AudioEvent, AudioFrame, Fragment, FrameAck, JitterBuffer, KEYFRAME_REQUEST,
};
use openstream_protocol::{Kind, MAX_PLAINTEXT};
use tokio::sync::{mpsc, watch};

mod policy;

pub use policy::{Foreground, ThermalLevel};

/// Foreign callers pass lengths explicitly, but a bad length must not turn
/// `from_raw_parts` into an arbitrarily large allocation or read. Pairing JSON
/// and ICE configuration are small control-plane values, so a quarter MiB is
/// deliberately generous while remaining a hard ABI boundary.
const MAX_FFI_STRING_BYTES: usize = 256 * 1024;

/// Callback table owned by the platform application.
///
/// The pointers passed to callbacks are valid only for the duration of the
/// callback. A platform must copy an access unit before returning.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenStreamCallbacks {
    pub context: *mut c_void,
    pub on_ready: Option<extern "C" fn(*mut c_void, u16, u16, u16)>,
    pub on_video: Option<extern "C" fn(*mut c_void, *const u8, usize, bool, u64)>,
    pub on_audio: Option<extern "C" fn(*mut c_void, *const i16, usize, u64)>,
    pub on_rumble: Option<extern "C" fn(*mut c_void, u32, u8, u8)>,
    /// Encoded, validated `MD` topology bytes. The pointer is valid only for
    /// the callback; a platform must copy them before returning.
    pub on_displays: Option<extern "C" fn(*mut c_void, *const u8, usize)>,
    pub on_error: Option<extern "C" fn(*mut c_void, i32)>,
}

// The callback table is copied into a worker and the caller guarantees that
// its context remains alive until `openstream_client_stop` returns. Raw
// pointers intentionally represent an opaque foreign-owned context here.
unsafe impl Send for OpenStreamCallbacks {}
unsafe impl Sync for OpenStreamCallbacks {}

/// Opaque client handle returned to Kotlin/Swift/C callers.
#[derive(Debug)]
pub struct OpenStreamClient {
    input_tx: mpsc::Sender<Vec<u8>>,
    stop_tx: watch::Sender<bool>,
    pause_tx: watch::Sender<bool>,
    thermal_tx: watch::Sender<u8>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct IceConfiguration {
    urls: String,
    turn_username: Option<String>,
    turn_password: Option<String>,
}

/// The worker's channel bundle, kept as one argument so the client entry
/// point stays readable as lifecycle handling grows.
#[derive(Debug)]
struct ClientChannels {
    input_rx: mpsc::Receiver<Vec<u8>>,
    stop_rx: watch::Receiver<bool>,
    pause_rx: watch::Receiver<bool>,
    thermal_rx: watch::Receiver<u8>,
}

/// Start one client worker.
///
/// Returns null when either UTF-8 input is invalid or the pairing JSON cannot
/// be decoded. The asynchronous connection error is delivered through
/// `on_error` with a negative code; no credential material is sent to logs or
/// callback strings.
#[unsafe(no_mangle)]
pub extern "C" fn openstream_client_start(
    origin: *const u8,
    origin_len: usize,
    pairing_json: *const u8,
    pairing_len: usize,
    callbacks: OpenStreamCallbacks,
) -> *mut OpenStreamClient {
    let Some(origin) = copy_utf8(origin, origin_len) else {
        return std::ptr::null_mut();
    };
    let Some(pairing_json) = copy_utf8(pairing_json, pairing_len) else {
        return std::ptr::null_mut();
    };
    let Ok(pairing) = serde_json::from_str::<Pairing>(&pairing_json) else {
        return std::ptr::null_mut();
    };
    start_worker(origin, pairing, callbacks, None)
}

/// Start a client worker with application-supplied ICE/TURN configuration.
///
/// `ice_urls` is a comma-separated list of RFC 7064/7065 URLs, for example
/// `stun:stun.example:3478,turn:turn.example:3478?transport=udp`.
/// Username and password are separate nullable byte strings so a mobile app
/// can load them from secure storage without putting them into pairing JSON,
/// URL strings, or logs. Supplying this configuration always selects the full
/// ICE path; the environment variables used by desktop tools are not needed.
#[unsafe(no_mangle)]
pub extern "C" fn openstream_client_start_with_ice(
    origin: *const u8,
    origin_len: usize,
    pairing_json: *const u8,
    pairing_len: usize,
    ice_urls: *const u8,
    ice_urls_len: usize,
    turn_username: *const u8,
    turn_username_len: usize,
    turn_password: *const u8,
    turn_password_len: usize,
    callbacks: OpenStreamCallbacks,
) -> *mut OpenStreamClient {
    let Some(origin) = copy_utf8(origin, origin_len) else {
        return std::ptr::null_mut();
    };
    let Some(pairing_json) = copy_utf8(pairing_json, pairing_len) else {
        return std::ptr::null_mut();
    };
    let Some(ice_urls) = copy_utf8(ice_urls, ice_urls_len) else {
        return std::ptr::null_mut();
    };
    let Some(turn_username) = copy_optional_utf8(turn_username, turn_username_len) else {
        return std::ptr::null_mut();
    };
    let Some(turn_password) = copy_optional_utf8(turn_password, turn_password_len) else {
        return std::ptr::null_mut();
    };
    let Ok(pairing) = serde_json::from_str::<Pairing>(&pairing_json) else {
        return std::ptr::null_mut();
    };
    start_worker(
        origin,
        pairing,
        callbacks,
        Some(IceConfiguration {
            urls: ice_urls,
            turn_username,
            turn_password,
        }),
    )
}

fn start_worker(
    origin: String,
    pairing: Pairing,
    callbacks: OpenStreamCallbacks,
    ice_configuration: Option<IceConfiguration>,
) -> *mut OpenStreamClient {
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(32);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (pause_tx, pause_rx) = watch::channel(false);
    let (thermal_tx, thermal_rx) = watch::channel(0_u8);
    let pause_handle = pause_tx.clone();
    let thermal_handle = thermal_tx.clone();
    let worker = match thread::Builder::new()
        .name("openstream-client".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    report_error(callbacks, -1);
                    return;
                }
            };
            let result = runtime.block_on(run_client(
                origin,
                pairing,
                callbacks,
                ClientChannels {
                    input_rx,
                    stop_rx,
                    pause_rx,
                    thermal_rx,
                },
                ice_configuration,
            ));
            if result.is_err() {
                report_error(callbacks, -2);
            }
        }) {
        Ok(worker) => worker,
        // A native thread may fail to start under process pressure. Return a
        // null handle instead of allowing a Rust panic to unwind through the
        // C/Swift/Kotlin ABI.
        Err(_) => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(OpenStreamClient {
        input_tx,
        stop_tx,
        pause_tx: pause_handle,
        thermal_tx: thermal_handle,
        worker: Some(worker),
    }))
}

/// Queue one already-encoded OpenStream input message.
///
/// The host must still opt into input and validate the message according to
/// its platform policy. This API only enforces the encrypted datagram size
/// bound and never interprets keyboard/gamepad bytes on mobile.
///
/// # Safety
///
/// `client` must be a live handle returned by `openstream_client_start`, and
/// `payload` must point to `payload_len` readable bytes for the duration of
/// this call. The handle must not be stopped concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openstream_client_send_input(
    client: *mut OpenStreamClient,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    if client.is_null() || payload_len > MAX_PLAINTEXT || (payload.is_null() && payload_len != 0) {
        return -1;
    }
    let client = unsafe { &*client };
    let bytes = if payload_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(payload, payload_len) }.to_vec()
    };
    match client.input_tx.try_send(bytes) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Request one display from the host's validated `MD` topology.
///
/// The request is sent through the same bounded ordered control channel as
/// input and lifecycle messages. The host still validates that the id is
/// currently advertised; this call does not grant access to arbitrary host
/// outputs.
///
/// # Safety
///
/// `client` must be a live handle returned by `openstream_client_start`, and
/// it must not be stopped concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openstream_client_select_display(
    client: *mut OpenStreamClient,
    display_id: u32,
) -> i32 {
    if client.is_null() {
        return -1;
    }
    let client = unsafe { &*client };
    let payload = openstream_media::displays::encode_select(display_id).to_vec();
    client.input_tx.try_send(payload).map_or(-2, |_| 0)
}

/// Suspend or resume media callbacks without tearing down the session.
///
/// While suspended the worker keeps assembly ACKs and keyframe requests
/// flowing so the host preserves the session, but drops decoded video/audio
/// callbacks and incoming input. Call with `paused != 0` from the platform
/// background hook and with `0` on foreground return. Returns `0` on
/// success, `-1` for a null handle.
///
/// # Safety
///
/// `client` must be a live handle returned by `openstream_client_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openstream_client_set_paused(
    client: *mut OpenStreamClient,
    paused: u8,
) -> i32 {
    if client.is_null() {
        return -1;
    }
    let client = unsafe { &*client };
    let _ = client.pause_tx.send(paused != 0);
    0
}

/// Report OS thermal pressure so the worker sheds decode load.
///
/// `level` follows the normalized 0-3 scale (`policy::ThermalLevel`) and is
/// clamped; anything above 3 behaves as critical. Returns `0` on success,
/// `-1` for a null handle.
///
/// # Safety
///
/// `client` must be a live handle returned by `openstream_client_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openstream_client_set_thermal(
    client: *mut OpenStreamClient,
    level: u8,
) -> i32 {
    if client.is_null() {
        return -1;
    }
    let client = unsafe { &*client };
    let _ = client.thermal_tx.send(level.min(3));
    0
}

/// Stop the worker and release its opaque handle.
///
/// # Safety
///
/// `client` must be null or a live handle returned by
/// `openstream_client_start`, and it must not be used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openstream_client_stop(client: *mut OpenStreamClient) {
    if client.is_null() {
        return;
    }
    let mut client = unsafe { Box::from_raw(client) };
    let _ = client.stop_tx.send(true);
    if let Some(worker) = client.worker.take() {
        if worker.thread().id() == thread::current().id() {
            // A platform callback is allowed to request stop. Joining the
            // current worker would panic, and freeing the handle is safe here:
            // the worker owns only channel endpoints and a copied callback
            // table, never a pointer to this Box. Dropping JoinHandle detaches
            // it; the stop watch wakes its select loop immediately after the
            // callback returns.
            return;
        }
        let _ = worker.join();
    }
}

fn copy_utf8(pointer: *const u8, length: usize) -> Option<String> {
    if pointer.is_null() || length > MAX_FFI_STRING_BYTES {
        return None;
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, length) };
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

fn copy_optional_utf8(pointer: *const u8, length: usize) -> Option<Option<String>> {
    if pointer.is_null() {
        return (length == 0).then_some(None);
    }
    copy_utf8(pointer, length).map(Some)
}

async fn run_client(
    origin: String,
    pairing: Pairing,
    callbacks: OpenStreamCallbacks,
    channels: ClientChannels,
    ice_configuration: Option<IceConfiguration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ClientChannels {
        mut input_rx,
        mut stop_rx,
        mut pause_rx,
        mut thermal_rx,
    } = channels;
    let mut session = if let Some(configuration) = ice_configuration {
        PeerSession::establish_with_ice_spec(
            &origin,
            &pairing,
            Role::Client,
            "0.0.0.0:0".parse::<SocketAddr>()?,
            &configuration.urls,
            configuration.turn_username.as_deref(),
            configuration.turn_password.as_deref(),
        )
        .await?
    } else {
        PeerSession::establish_configured(
            &origin,
            &pairing,
            Role::Client,
            "0.0.0.0:0".parse::<SocketAddr>()?,
            &[],
        )
        .await?
    };
    // Android MediaCodec and iOS VideoToolbox are currently wired for the
    // H.264 Annex-B access-unit callback. Advertising H.265 here would let a
    // host legally select HEVC and deliver bytes the mobile bridge cannot
    // decode, so mobile advertises only the codec it actually consumes.
    let mut client_capabilities = openstream_client_core::Capabilities::client_default();
    client_capabilities.video_codecs = vec![VideoCodec::H264];
    client_capabilities.multi_monitor = true;
    let negotiated = session
        .negotiate_client_with_capabilities(client_capabilities)
        .await?;
    if let Some(on_ready) = callbacks.on_ready {
        on_ready(
            callbacks.context,
            negotiated.width,
            negotiated.height,
            negotiated.fps,
        );
    }
    if *stop_rx.borrow() {
        return Ok(());
    }

    let mut assembler = Assembler::default();
    let mut reliable_control = ReliableControl::new(openstream_client_core::MAX_CONTROL_PENDING);
    let mut waiting_for_keyframe = false;
    let mut paused = *pause_rx.borrow();
    let mut thermal = ThermalLevel::clamp(*thermal_rx.borrow());
    let mut predicted_since_keyframe = 0_u64;
    let mut audio_decoder = opus_rs::OpusDecoder::new(48_000, lowlat_audio::CHANNELS)
        .map_err(|error| format!("could not create Opus decoder: {error}"))?;
    let mut audio_jitter = JitterBuffer::new(3);
    let mut audio_pcm = vec![0_f32; lowlat_audio::FRAME * lowlat_audio::CHANNELS];
    let mut last_audio_toc = None;
    let mut control_tick = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        // `openstream_client_stop` may be called from a foreign callback. A
        // watch notification is observable immediately on this worker, so
        // check it before another packet can produce a callback. This closes
        // the self-stop window for the C/Swift ABI, whose caller cannot join
        // the worker from inside its own callback.
        if *stop_rx.borrow() {
            return Ok(());
        }
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return Ok(());
                }
            }
            _ = pause_rx.changed() => {
                paused = *pause_rx.borrow();
            }
            _ = thermal_rx.changed() => {
                thermal = ThermalLevel::clamp(*thermal_rx.borrow());
            }
            Some(input) = input_rx.recv() => {
                if paused {
                    // Drop input queued while backgrounded instead of
                    // replaying a stale burst on foreground return.
                    continue;
                }
                // Input state is ordered and must not disappear during a
                // short Wi-Fi loss. The bounded helper still lets the UI
                // apply backpressure instead of growing a hidden queue.
                reliable_control.send(&mut session, &input).await?;
            }
            _ = control_tick.tick() => {
                reliable_control.retry(&mut session).await?;
                session.maintain_liveness().await?;
            }
            packet = session.recv() => {
                let packet = packet?;
                if packet.kind == Kind::Control {
                    if let Some(deliveries) = reliable_control.receive(&mut session, &packet).await? {
                        for payload in deliveries {
                            if *stop_rx.borrow() {
                                return Ok(());
                            }
                            if payload == b"openstream/end" {
                                return Ok(());
                            }
                            if report_display_topology(callbacks, &payload) {
                                continue;
                            }
                            if let Ok(rumble) = RumbleEvent::decode(&payload)
                                && let Some(on_rumble) = callbacks.on_rumble
                            {
                                on_rumble(
                                    callbacks.context,
                                    rumble.device_id,
                                    rumble.strong,
                                    rumble.weak,
                                );
                            }
                        }
                        continue;
                    }
                    if packet.payload == b"openstream/end" {
                        return Ok(());
                    }
                    if report_display_topology(callbacks, &packet.payload) {
                        continue;
                    }
                    if let Ok(rumble) = RumbleEvent::decode(&packet.payload)
                        && let Some(on_rumble) = callbacks.on_rumble
                    {
                        on_rumble(
                            callbacks.context,
                            rumble.device_id,
                            rumble.strong,
                            rumble.weak,
                        );
                    }
                }
                if packet.kind == Kind::Audio {
                    let Ok(audio) = AudioFrame::decode(&packet.payload) else {
                        // A malformed authenticated packet is a media loss,
                        // not a reason to tear down the native session.
                        continue;
                    };
                    audio_jitter.push(audio);
                    while let Some(event) = audio_jitter.poll() {
                        let (payload, timestamp) = match event {
                            AudioEvent::Frame(frame) => {
                                (frame.payload, frame.presentation_time_us)
                            }
                            AudioEvent::Missing(_sequence) => {
                                let Some(toc) = last_audio_toc else {
                                    continue;
                                };
                                (vec![toc], 0)
                            }
                        };
                        let samples = match audio_decoder
                            .decode(&payload, lowlat_audio::FRAME, &mut audio_pcm)
                        {
                            Ok(samples) => samples,
                            Err(_) => continue,
                        };
                        if let Some(toc) = payload.first().copied() {
                            last_audio_toc = Some(toc);
                        }
                        if !paused && thermal.present_audio() && let Some(on_audio) = callbacks.on_audio {
                            let mut pcm16 = Vec::with_capacity(
                                samples * lowlat_audio::CHANNELS,
                            );
                            for sample in audio_pcm
                                .iter()
                                .take(samples * lowlat_audio::CHANNELS)
                            {
                                #[allow(clippy::cast_possible_truncation)]
                                let sample = (sample.clamp(-1.0, 1.0) * 32767.0) as i16;
                                pcm16.push(sample);
                            }
                            on_audio(
                                callbacks.context,
                                pcm16.as_ptr(),
                                pcm16.len(),
                                timestamp,
                            );
                        }
                        if *stop_rx.borrow() {
                            return Ok(());
                        }
                    }
                    continue;
                }
                if packet.kind != Kind::Video {
                    continue;
                }
                let Ok(fragment) = Fragment::decode(&packet.payload) else {
                    continue;
                };
                let mut ready_frames = Vec::new();
                match assembler.push(fragment) {
                    Ok(Some(frame)) => ready_frames.push(frame),
                    Ok(None) => {}
                    Err(_) => continue,
                }
                while let Some(frame) = assembler.pop_ready() {
                    ready_frames.push(frame);
                }
                if assembler.take_keyframe_request() {
                    waiting_for_keyframe = true;
                    reliable_control
                        .send(&mut session, KEYFRAME_REQUEST)
                        .await?;
                }
                for frame in ready_frames {
                    if *stop_rx.borrow() {
                        return Ok(());
                    }
                    if frame.keyframe {
                        waiting_for_keyframe = false;
                        predicted_since_keyframe = 0;
                    } else {
                        predicted_since_keyframe = predicted_since_keyframe.wrapping_add(1);
                    }
                    if waiting_for_keyframe {
                        continue;
                    }
                    if !paused
                        && thermal.present_video(frame.keyframe, predicted_since_keyframe)
                        && let Some(on_video) = callbacks.on_video
                    {
                        on_video(
                            callbacks.context,
                            frame.payload.as_ptr(),
                            frame.payload.len(),
                            frame.keyframe,
                            frame.presentation_time_us,
                        );
                    }
                    let ack = FrameAck {
                        frame_id: frame.frame_id,
                        lost_frames: assembler.take_frame_gap(),
                    }
                    .encode();
                    let _ = reliable_control
                        .send_if_available(&mut session, &ack)
                        .await?;
                }
            }
        }
    }
}

/// Validate and forward an `MD` topology without making foreign code parse an
/// untrusted byte slice. A malformed topology is consumed and ignored; it is
/// a peer media/control error, not a reason to invoke a platform callback with
/// data it cannot trust.
fn report_display_topology(callbacks: OpenStreamCallbacks, payload: &[u8]) -> bool {
    if !payload.starts_with(b"MD") {
        return false;
    }
    if openstream_media::displays::decode_list(payload).is_err() {
        return true;
    }
    if let Some(on_displays) = callbacks.on_displays {
        on_displays(callbacks.context, payload.as_ptr(), payload.len());
    }
    true
}

fn report_error(callbacks: OpenStreamCallbacks, code: i32) {
    if let Some(on_error) = callbacks.on_error {
        on_error(callbacks.context, code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn count_display_callbacks(context: *mut c_void, bytes: *const u8, length: usize) {
        if context.is_null() || (bytes.is_null() && length != 0) {
            return;
        }
        // The production callback contract requires the foreign side to copy
        // only during the call. This test records that a validated payload
        // crossed the boundary without retaining the borrowed pointer.
        unsafe {
            *context.cast::<usize>() += 1;
        }
    }

    #[test]
    fn lifecycle_and_thermal_setters_reject_null_handles() {
        assert_eq!(
            unsafe { openstream_client_set_paused(std::ptr::null_mut(), 1) },
            -1
        );
        assert_eq!(
            unsafe { openstream_client_set_thermal(std::ptr::null_mut(), 3) },
            -1
        );
        assert_eq!(
            unsafe { openstream_client_send_input(std::ptr::null_mut(), std::ptr::null(), 0) },
            -1
        );
        assert_eq!(
            unsafe { openstream_client_select_display(std::ptr::null_mut(), 1) },
            -1
        );
        // Stopping a null handle is a no-op, never a crash.
        unsafe { openstream_client_stop(std::ptr::null_mut()) };
    }

    #[test]
    fn display_topology_is_validated_before_the_foreign_callback() {
        let mut callbacks_seen = 0_usize;
        let callbacks = OpenStreamCallbacks {
            context: (&mut callbacks_seen as *mut usize).cast(),
            on_displays: Some(count_display_callbacks),
            ..OpenStreamCallbacks::default()
        };
        let topology =
            openstream_media::displays::encode_list(&[openstream_media::displays::Display {
                id: 7,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                flags: openstream_media::displays::PRIMARY_FLAG,
            }])
            .expect("topology");
        assert!(report_display_topology(callbacks, &topology));
        assert_eq!(callbacks_seen, 1);
        assert!(report_display_topology(callbacks, b"MD\x01"));
        assert_eq!(callbacks_seen, 1, "malformed topology reached the callback");
        assert!(!report_display_topology(callbacks, b"other"));
    }
}
