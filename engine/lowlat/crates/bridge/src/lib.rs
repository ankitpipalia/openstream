//! Backend traits plus opt-in Sunshine/Moonlight subprocess bridges.
//!
//! The native OpenStream host/client and the Sunshine/Moonlight pair solve
//! the same problem with incompatible wires. These traits let one
//! application drive either without coupling them, and the bridges below
//! are **separate processes, never linked libraries**: Sunshine is GPL-3.0
//! and Moonlight clients carry their own licenses, so the MIT-licensed
//! OpenStream workspace must not combine with them into one binary.
//! Operators who distribute a combined setup publish complete
//! corresponding source per the GPL terms; see `THIRD_PARTY.md`.

use std::path::PathBuf;

/// Stream parameters shared by every backend profile.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamProfile {
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub bitrate_mbps: f64,
    pub codec_h265: bool,
}

impl StreamProfile {
    /// Validate operator-supplied parameters before any process starts.
    pub fn validated(
        width: u16,
        height: u16,
        fps: u16,
        bitrate_mbps: f64,
        codec_h265: bool,
    ) -> Result<Self, String> {
        if width == 0 || height == 0 || fps == 0 {
            return Err("stream dimensions and frame rate must be nonzero".into());
        }
        if width > 7680 || height > 4320 || fps > 240 {
            return Err("stream parameters exceed the supported ceiling".into());
        }
        if !bitrate_mbps.is_finite() || bitrate_mbps <= 0.0 || bitrate_mbps > 200.0 {
            return Err("stream bitrate must be within 0..200 Mbps".into());
        }
        Ok(Self {
            width,
            height,
            fps,
            bitrate_mbps,
            codec_h265,
        })
    }
}

/// A host backend: something that serves one desktop session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostBackendKind {
    /// The project-owned host adapters in this workspace.
    Native,
    /// An external Sunshine process driven through generated config.
    Sunshine,
}

/// A client backend: something that presents one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientBackendKind {
    /// The project-owned desktop/mobile clients in this workspace.
    Native,
    /// An external Moonlight process.
    Moonlight,
}

/// Kilobits for one validated profile. Validated profiles pin bitrate to
/// finite (0, 200] Mbps, so the rounded value always fits; the clamp states
/// the bound at the conversion site.
fn bitrate_kbps(profile: &StreamProfile) -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let kbps = (profile.bitrate_mbps * 1000.0)
        .round()
        .clamp(1.0, 200_000.0) as u64;
    kbps
}
/// Sunshine `sunshine.conf` key/value rendering for one profile.
///
/// Only the streaming-relevant keys are generated; credentials, certificates,
/// and pairing PINs stay with the operator's own Sunshine setup and are never
/// written here.
pub fn sunshine_conf(profile: &StreamProfile) -> String {
    let codec = if profile.codec_h265 { "hevc" } else { "h264" };
    // Bitrate in kbps, matching Sunshine's `channels`/`bitrate` units.
    let kbps = bitrate_kbps(profile);
    format!(
        "output_name = 0\n\
         resolutions = [{w}x{h}x{fps}]\n\
         fps = [{fps}]\n\
         bitrate = {kbps}\n\
         codec = {codec}\n",
        w = profile.width,
        h = profile.height,
        fps = profile.fps,
        kbps = kbps,
        codec = codec,
    )
}

/// Sunshine `apps.json` entry exposing one desktop session.
pub fn sunshine_apps_entry(name: &str, profile: &StreamProfile) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "output": "",
        "width": profile.width,
        "height": profile.height,
        "fps": profile.fps,
    })
}

/// Resolve the Sunshine executable without a shell (`OPENSTREAM_SUNSHINE`
/// overrides the `sunshine` PATH lookup).
pub fn sunshine_binary() -> PathBuf {
    std::env::var("OPENSTREAM_SUNSHINE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("sunshine"))
}

/// Moonlight CLI arguments for one stream (`moonlight stream <host> ...`).
/// No shell is involved; the caller spawns these argv elements directly.
pub fn moonlight_args(
    host: &str,
    app: &str,
    profile: &StreamProfile,
) -> Result<Vec<String>, String> {
    if host.trim().is_empty() || app.trim().is_empty() {
        return Err("moonlight host and app must be non-empty".into());
    }
    Ok(vec![
        "stream".into(),
        host.trim().to_string(),
        "--app".into(),
        app.trim().to_string(),
        "--width".into(),
        profile.width.to_string(),
        "--height".into(),
        profile.height.to_string(),
        "--fps".into(),
        profile.fps.to_string(),
        "--bitrate".into(),
        bitrate_kbps(profile).to_string(),
        "--codec".into(),
        (if profile.codec_h265 { "hevc" } else { "h264" }).into(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> StreamProfile {
        StreamProfile::validated(1920, 1080, 60, 10.0, false).expect("valid profile")
    }

    #[test]
    fn profiles_reject_nonsense_before_any_process_starts() {
        assert!(StreamProfile::validated(0, 1080, 60, 10.0, false).is_err());
        assert!(StreamProfile::validated(1920, 1080, 0, 10.0, false).is_err());
        assert!(StreamProfile::validated(1920, 1080, 60, f64::NAN, false).is_err());
        assert!(StreamProfile::validated(1920, 1080, 60, 500.0, false).is_err());
        assert!(StreamProfile::validated(9000, 1080, 60, 10.0, false).is_err());
    }

    #[test]
    fn sunshine_conf_pins_resolution_fps_bitrate_codec() {
        let conf = sunshine_conf(&profile());
        assert!(conf.contains("1920x1080x60"));
        assert!(conf.contains("bitrate = 10000"));
        assert!(conf.contains("codec = h264"));
        let hevc = sunshine_conf(
            &StreamProfile::validated(3840, 2160, 120, 40.0, true).expect("hevc profile"),
        );
        assert!(hevc.contains("codec = hevc"));
        assert!(hevc.contains("3840x2160x120"));
    }

    #[test]
    fn sunshine_apps_entry_carries_dimensions_without_secrets() {
        let entry = sunshine_apps_entry("Desktop", &profile());
        assert_eq!(entry["width"], 1920);
        assert_eq!(entry["height"], 1080);
        assert_eq!(entry["fps"], 60);
        assert!(!entry.to_string().contains("pin"));
    }

    #[test]
    fn moonlight_args_are_shell_free_and_validated() {
        let args = moonlight_args("192.0.2.10", "Desktop", &profile()).expect("moonlight args");
        assert_eq!(args[0], "stream");
        assert!(args.contains(&"--bitrate".to_string()));
        assert!(moonlight_args("", "Desktop", &profile()).is_err());
        assert!(moonlight_args("192.0.2.10", "", &profile()).is_err());
    }
}
