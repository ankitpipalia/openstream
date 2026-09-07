//! PipeWire screen-source discovery for Wayland sessions.
//!
//! The host never links PipeWire: it shells out to `pw-dump` with a fixed
//! argument vector (no interpolation, no shell) and parses the JSON node
//! list. FFmpeg's `pipewire` input then captures the selected node. When
//! `pw-dump` is absent the module reports `Unavailable` so the caller falls
//! back to X11 or the lowlat display pipeline.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

/// One PipeWire source node that can feed screen capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceNode {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) media_class: String,
    pub(crate) object_serial: Option<u32>,
}

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable(String),
    Spawn(std::io::Error),
    InvalidJson(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(f, "PipeWire discovery unavailable: {detail}"),
            Self::Spawn(error) => write!(f, "could not start pw-dump: {error}"),
            Self::InvalidJson(detail) => write!(f, "pw-dump output did not parse: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// List candidate screen-source nodes via `pw-dump`.
pub(crate) fn list_source_nodes() -> Result<Vec<SourceNode>, Error> {
    let output = run_pw_dump().map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => Error::Unavailable("pw-dump is not installed".into()),
        _ => Error::Spawn(error),
    })?;
    parse_nodes(&output)
}

/// Parse `pw-dump` JSON into source nodes. Pure and unit-tested.
pub(crate) fn parse_nodes(json: &str) -> Result<Vec<SourceNode>, Error> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| Error::InvalidJson(error.to_string()))?;
    let entries = value
        .as_array()
        .ok_or_else(|| Error::InvalidJson("top level is not an array".into()))?;
    let mut nodes = Vec::new();
    for entry in entries {
        if entry.get("type").and_then(|kind| kind.as_str()) != Some("PipeWire:Interface:Node") {
            continue;
        }
        let id = entry
            .get("id")
            .and_then(|id| id.as_u64())
            .and_then(|id| u32::try_from(id).ok())
            .unwrap_or(u32::MAX);
        let props = entry.get("info").and_then(|info| info.get("props"));
        let name = props
            .and_then(|props| props.get("node.name"))
            .and_then(|name| name.as_str())
            .unwrap_or_default();
        let media_class = props
            .and_then(|props| props.get("media.class"))
            .and_then(|class| class.as_str())
            .unwrap_or_default();
        // Keep video sources and monitors; audio sinks are handled by the
        // audio path, not screen capture.
        if !media_class.contains("Video")
            && !name.contains("screencast")
            && !name.contains("monitor")
        {
            continue;
        }
        let object_serial = props
            .and_then(|props| props.get("object.serial"))
            .and_then(|serial| serial.as_u64())
            .and_then(|serial| u32::try_from(serial).ok());
        nodes.push(SourceNode {
            id,
            name: name.to_string(),
            media_class: media_class.to_string(),
            object_serial,
        });
        if nodes.len() >= 64 {
            break;
        }
    }
    Ok(nodes)
}

fn run_pw_dump() -> std::io::Result<String> {
    const MAX_PW_DUMP_BYTES: usize = 8 * 1024 * 1024;
    let mut child = Command::new("pw-dump")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pw-dump stdout was not piped",
            ));
        }
    };
    // Drain stdout concurrently so a large local pw-dump response cannot
    // deadlock the child on a full pipe. Retain at most the configured bound;
    // once it is exceeded the parent kills the command and reports invalid
    // discovery data.
    let oversized = Arc::new(AtomicBool::new(false));
    let reader_oversized = Arc::clone(&oversized);
    let reader = thread::spawn(move || {
        let mut output = Vec::with_capacity(4096);
        let mut buffer = [0_u8; 8192];
        loop {
            let length = stdout.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            if output.len().saturating_add(length) > MAX_PW_DUMP_BYTES {
                reader_oversized.store(true, Ordering::Release);
                continue;
            }
            output.extend_from_slice(&buffer[..length]);
        }
        Ok::<Vec<u8>, std::io::Error>(output)
    });
    let start = std::time::Instant::now();
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(error);
            }
        };
        match status {
            Some(status) if status.success() => break,
            Some(_) => {
                let _ = reader.join();
                return Err(std::io::Error::other("pw-dump exited nonzero"));
            }
            None if start.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "pw-dump timed out",
                ));
            }
            None if oversized.load(Ordering::Acquire) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pw-dump output exceeded the bound",
                ));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let output = reader
        .join()
        .map_err(|_| std::io::Error::other("pw-dump reader thread panicked"))??;
    if oversized.load(Ordering::Acquire) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "pw-dump output exceeded the bound",
        ));
    }
    String::from_utf8(output)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {"id": 28, "type": "PipeWire:Interface:Node",
         "info": {"props": {"node.name": "screencast-output-0", "media.class": "Video/Source", "object.serial": 41}}},
        {"id": 31, "type": "PipeWire:Interface:Node",
         "info": {"props": {"node.name": "alsa_output.pci", "media.class": "Audio/Sink"}}},
        {"id": 44, "type": "PipeWire:Interface:Device", "info": {"props": {}}},
        {"id": 55, "type": "PipeWire:Interface:Node",
         "info": {"props": {"node.name": "v4l2-camera", "media.class": "Video/Source"}}}
    ]"#;

    #[test]
    fn keeps_video_sources_and_drops_audio_and_devices() {
        let nodes = parse_nodes(FIXTURE).expect("parse fixture");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, 28);
        assert_eq!(nodes[0].name, "screencast-output-0");
        assert_eq!(nodes[0].object_serial, Some(41));
        assert_eq!(nodes[1].id, 55);
    }

    #[test]
    fn rejects_non_json_and_non_array() {
        assert!(matches!(parse_nodes("nope"), Err(Error::InvalidJson(_))));
        assert!(matches!(parse_nodes("{}"), Err(Error::InvalidJson(_))));
    }
}
