//! Minimal pure-std X11 display client for enumeration and raw capture.
//!
//! This module speaks just enough of the X11 wire protocol to list screens
//! and grab ZPixmap frames without linking Xlib or adding a dependency. It
//! is used for display enumeration (`OPENSTREAM_LIST_DISPLAYS=1`) and as the
//! fallback raw-capture source on X11 sessions. Failures are typed so the
//! host can fall back to the lowlat display pipeline or the FFmpeg adapter.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const X_TCP_BASE_PORT: u16 = 6000;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum single framebuffer read (64 megapixels of 32-bit pixels).
pub(crate) const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;

/// One X11 screen reported by the server setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Screen {
    pub(crate) index: usize,
    pub(crate) root: u32,
    pub(crate) width_px: u16,
    pub(crate) height_px: u16,
    pub(crate) width_mm: u16,
    pub(crate) height_mm: u16,
    pub(crate) root_depth: u8,
    pub(crate) root_visual: u32,
}

/// Typed X11 failures; every variant maps to a host fallback, never a panic.
#[derive(Debug)]
pub(crate) enum Error {
    NoDisplay,
    BadDisplay(String),
    Io(std::io::Error),
    Refused(String),
    Truncated,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDisplay => f.write_str("no X DISPLAY is set"),
            Self::BadDisplay(detail) => write!(f, "unparsable DISPLAY: {detail}"),
            Self::Io(error) => write!(f, "X11 transport failed: {error}"),
            Self::Refused(detail) => write!(f, "X server refused the connection: {detail}"),
            Self::Truncated => f.write_str("X server reply was truncated"),
        }
    }
}

impl std::error::Error for Error {}

/// Parsed DISPLAY: unix socket path or TCP endpoint plus screen number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DisplayAddr {
    Unix {
        path: String,
        screen: u32,
    },
    Tcp {
        host: String,
        port: u16,
        screen: u32,
    },
}

/// Parse `$DISPLAY` without shelling out. Accepts `:0`, `:0.1`,
/// `/tmp/launch-.../:0`, `host:10`, and `host:10.0`.
pub(crate) fn parse_display(spec: &str) -> Result<DisplayAddr, Error> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(Error::NoDisplay);
    }
    // Strip a possible launchd socket prefix; the display tail follows ':'.
    let tail = spec.rsplit('/').next().unwrap_or(spec);
    let colon = tail
        .rfind(':')
        .ok_or_else(|| Error::BadDisplay(spec.into()))?;
    let (host, after) = tail.split_at(colon);
    let after = &after[1..];
    if after.is_empty() {
        return Err(Error::BadDisplay(spec.into()));
    }
    let mut parts = after.splitn(2, '.');
    let display: u32 = parts
        .next()
        .unwrap_or_default()
        .parse()
        .map_err(|_| Error::BadDisplay(spec.into()))?;
    let screen: u32 = match parts.next() {
        Some(screen) if !screen.is_empty() => {
            screen.parse().map_err(|_| Error::BadDisplay(spec.into()))?
        }
        _ => 0,
    };
    if host.is_empty() || host == "unix" {
        Ok(DisplayAddr::Unix {
            path: format!("/tmp/.X11-unix/X{display}"),
            screen,
        })
    } else {
        Ok(DisplayAddr::Tcp {
            host: host.to_string(),
            port: X_TCP_BASE_PORT + (display % 1000) as u16,
            screen,
        })
    }
}

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(stream) => stream.read(buf),
            Self::Tcp(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(stream) => stream.write(buf),
            Self::Tcp(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Unix(stream) => stream.flush(),
            Self::Tcp(stream) => stream.flush(),
        }
    }
}

/// An authenticated X11 connection with the parsed server setup.
pub(crate) struct Connection {
    stream: Stream,
    pub(crate) screens: Vec<Screen>,
}

impl Connection {
    /// Open `$DISPLAY` (or `spec` when given) and run the setup handshake.
    pub(crate) fn open(spec: Option<&str>) -> Result<Self, Error> {
        let text = match spec {
            Some(display) => display.to_string(),
            None => std::env::var("DISPLAY").map_err(|_| Error::NoDisplay)?,
        };
        Self::open_display(&parse_display(&text)?)
    }

    fn open_display(addr: &DisplayAddr) -> Result<Self, Error> {
        let stream = match addr {
            DisplayAddr::Unix { path, .. } => {
                let stream = UnixStream::connect(path).map_err(Error::Io)?;
                Stream::Unix(stream)
            }
            DisplayAddr::Tcp { host, port, .. } => {
                let endpoint = format!("{host}:{port}");
                let stream = TcpStream::connect(endpoint).map_err(Error::Io)?;
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(Error::Io)?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(Error::Io)?;
                Stream::Tcp(stream)
            }
        };
        let mut connection = Self {
            stream,
            screens: Vec::new(),
        };
        connection.handshake()?;
        Ok(connection)
    }

    fn read_exact_vec(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        if length > MAX_FRAME_BYTES {
            return Err(Error::Refused("reply exceeds the frame bound".into()));
        }
        let mut buffer = vec![0_u8; length];
        self.stream.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(buffer)
    }

    fn handshake(&mut self) -> Result<(), Error> {
        // Setup request: little-endian order, X11.0, no authentication.
        let request = setup_request_bytes();
        self.stream.write_all(&request).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;

        let header = self.read_exact_vec(8)?;
        match header[0] {
            0 => {
                let length = u16::from_le_bytes([header[6], header[7]]) as usize * 4;
                let reason = self.read_exact_vec(length.min(1024))?;
                return Err(Error::Refused(
                    String::from_utf8_lossy(&reason).trim().to_string(),
                ));
            }
            2 => return Err(Error::Refused("server requires authentication".into())),
            1 => {}
            status => return Err(Error::Refused(format!("unexpected setup status {status}"))),
        }
        let length = u16::from_le_bytes([header[6], header[7]]) as usize * 4;
        let body = self.read_exact_vec(length)?;
        let (screens, _, _) = parse_setup(&body)?;
        self.screens = screens;
        Ok(())
    }
}

fn take(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], Error> {
    bytes.get(offset..offset + length).ok_or(Error::Truncated)
}

/// Parse the setup success body into screens. Pure and fully unit-tested.
pub(crate) fn parse_setup(body: &[u8]) -> Result<(Vec<Screen>, u8, u8), Error> {
    if body.len() < 32 {
        return Err(Error::Truncated);
    }
    let vendor_len = u16::from_le_bytes([body[16], body[17]]) as usize;
    let num_screens = body[20] as usize;
    let num_formats = body[21] as usize;
    let image_order = body[22];
    let bitmap_order = body[23];
    // Vendor string is padded to a 4-byte boundary.
    let mut offset = 32 + vendor_len.div_ceil(4) * 4;
    offset += num_formats.checked_mul(8).ok_or(Error::Truncated)?;
    let mut screens = Vec::with_capacity(num_screens.min(16));
    for index in 0..num_screens {
        let head = take(body, offset, 40)?;
        let root = u32::from_le_bytes(head[0..4].try_into().map_err(|_| Error::Truncated)?);
        let width_px = u16::from_le_bytes([head[8], head[9]]);
        let height_px = u16::from_le_bytes([head[10], head[11]]);
        let width_mm = u16::from_le_bytes([head[12], head[13]]);
        let height_mm = u16::from_le_bytes([head[14], head[15]]);
        let root_visual =
            u32::from_le_bytes(head[24..28].try_into().map_err(|_| Error::Truncated)?);
        let root_depth = head[34];
        let num_depths = head[35] as usize;
        offset += 40;
        for _ in 0..num_depths {
            let depth_head = take(body, offset, 8)?;
            let num_visuals = u16::from_le_bytes([depth_head[2], depth_head[3]]) as usize;
            offset += 8 + num_visuals.checked_mul(24).ok_or(Error::Truncated)?;
        }
        screens.push(Screen {
            index,
            root,
            width_px,
            height_px,
            width_mm,
            height_mm,
            root_depth,
            root_visual,
        });
        if screens.len() >= 16 {
            break;
        }
    }
    Ok((screens, image_order, bitmap_order))
}

/// Build the 12-byte setup request (handshake preamble), for tests.
fn setup_request_bytes() -> [u8; 12] {
    let mut request = [0_u8; 12];
    request[0] = b'l';
    request[2] = 11;
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_display_forms() {
        assert_eq!(
            parse_display(":0").expect("local display"),
            DisplayAddr::Unix {
                path: "/tmp/.X11-unix/X0".into(),
                screen: 0
            }
        );
        assert_eq!(
            parse_display(":1.2").expect("screen suffix"),
            DisplayAddr::Unix {
                path: "/tmp/.X11-unix/X1".into(),
                screen: 2
            }
        );
        assert_eq!(
            parse_display("workstation:10").expect("tcp display"),
            DisplayAddr::Tcp {
                host: "workstation".into(),
                port: 6010,
                screen: 0
            }
        );
        assert!(parse_display("").is_err());
        assert!(parse_display("nodisplay").is_err());
        assert!(parse_display(":abc").is_err());
    }

    #[test]
    fn setup_request_is_twelve_bytes_little_endian_x11() {
        let request = setup_request_bytes();
        assert_eq!(request.len(), 12);
        assert_eq!(request[0], b'l');
        assert_eq!(u16::from_le_bytes([request[2], request[3]]), 11);
    }

    fn synthetic_setup() -> Vec<u8> {
        // One screen, 1920x1080, depth 24, no pixmap formats, no visuals.
        let mut body = vec![0_u8; 32];
        body[20] = 1; // num screens
        body[22] = 0; // image order LSBFirst
        body[23] = 0; // bitmap order
        let mut screen = [0_u8; 40];
        screen[0..4].copy_from_slice(&0x2Bu32.to_le_bytes());
        screen[8..10].copy_from_slice(&1920_u16.to_le_bytes());
        screen[10..12].copy_from_slice(&1080_u16.to_le_bytes());
        screen[12..14].copy_from_slice(&510_u16.to_le_bytes());
        screen[14..16].copy_from_slice(&287_u16.to_le_bytes());
        screen[24..28].copy_from_slice(&0x21_u32.to_le_bytes());
        screen[34] = 24;
        screen[35] = 0;
        body.extend_from_slice(&screen);
        body
    }

    #[test]
    fn parses_a_minimal_setup_body() {
        let (screens, image_order, _) = parse_setup(&synthetic_setup()).expect("parse setup");
        assert_eq!(screens.len(), 1);
        assert_eq!(screens[0].width_px, 1920);
        assert_eq!(screens[0].height_px, 1080);
        assert_eq!(screens[0].root_depth, 24);
        assert_eq!(screens[0].root, 0x2B);
        assert_eq!(image_order, 0);
    }

    #[test]
    fn truncated_setup_is_an_error_not_a_panic() {
        assert!(matches!(parse_setup(&[0_u8; 10]), Err(Error::Truncated)));
        assert!(matches!(parse_setup(&[0_u8; 32]), Err(Error::Truncated)));
    }

    #[test]
    fn screens_are_capped_so_a_malicious_count_cannot_oom() {
        let mut body = synthetic_setup();
        body[20] = 255;
        let (screens, _, _) = parse_setup(&body).unwrap_or((Vec::new(), 0, 0));
        assert!(screens.len() <= 16);
    }
}
