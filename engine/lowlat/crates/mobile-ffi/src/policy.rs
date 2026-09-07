//! Mobile lifecycle and thermal policy for the client bridge.
//!
//! Backgrounding a phone must not kill the session (the user returns to a
//! live stream), but it must stop decoder/audio work and stale input.
//! Thermal pressure must shed decode load before the OS kills the app.
//! Both are pure policy so host-side unit tests pin the behavior without a
//! device; the FFI layer only carries the resulting levels.

/// Thermal pressure reported by the OS (Android `PowerManager`, iOS
/// `ProcessInfo.thermalState`), normalized to four levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThermalLevel {
    /// Nominal: present every decodable frame.
    #[default]
    Nominal = 0,
    /// Fair: present every decodable frame, input unchanged.
    Fair = 1,
    /// Serious: present keyframes plus every other predicted frame.
    Serious = 2,
    /// Critical: present keyframes only, mute PCM callbacks.
    Critical = 3,
}

impl ThermalLevel {
    /// Clamp a raw OS level into the supported range.
    pub fn clamp(level: u8) -> Self {
        match level {
            0 => Self::Nominal,
            1 => Self::Fair,
            2 => Self::Serious,
            _ => Self::Critical,
        }
    }

    /// Whether a decoded video frame should reach the platform decoder.
    ///
    /// `predicted_seen` counts predicted frames since the last keyframe and
    /// lets Serious shed half the decode load deterministically.
    pub fn present_video(self, keyframe: bool, predicted_seen: u64) -> bool {
        match self {
            Self::Nominal | Self::Fair => true,
            Self::Serious => keyframe || predicted_seen % 2 == 0,
            Self::Critical => keyframe,
        }
    }

    /// Whether decoded PCM should reach the platform audio sink.
    pub fn present_audio(self) -> bool {
        !matches!(self, Self::Critical)
    }
}

/// Session behavior while the app is backgrounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Foreground {
    /// Normal operation.
    #[default]
    Active,
    /// Backgrounded: keep ACKs/keyframe requests flowing so the host does
    /// not collapse the session, but drop media callbacks and input.
    Suspended,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_clamp_into_range() {
        assert_eq!(ThermalLevel::clamp(0), ThermalLevel::Nominal);
        assert_eq!(ThermalLevel::clamp(1), ThermalLevel::Fair);
        assert_eq!(ThermalLevel::clamp(2), ThermalLevel::Serious);
        assert_eq!(ThermalLevel::clamp(3), ThermalLevel::Critical);
        assert_eq!(ThermalLevel::clamp(255), ThermalLevel::Critical);
    }

    #[test]
    fn nominal_and_fair_present_everything() {
        for level in [ThermalLevel::Nominal, ThermalLevel::Fair] {
            assert!(level.present_video(false, 7));
            assert!(level.present_audio());
        }
    }

    #[test]
    fn serious_sheds_half_the_predicted_frames() {
        let level = ThermalLevel::Serious;
        assert!(level.present_video(true, 99));
        assert!(level.present_video(false, 0));
        assert!(!level.present_video(false, 1));
        assert!(level.present_video(false, 2));
        assert!(level.present_audio());
    }

    #[test]
    fn critical_keeps_keyframes_and_mutes_audio() {
        let level = ThermalLevel::Critical;
        assert!(level.present_video(true, 99));
        assert!(!level.present_video(false, 0));
        assert!(!level.present_audio());
    }
}
