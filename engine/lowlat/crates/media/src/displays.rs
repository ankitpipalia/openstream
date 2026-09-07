//! Bounded multi-monitor enumeration and selection.
//!
//! Display topology rides the reliable control channel as small framed
//! messages. The host enumerates its outputs (X11 RandR on Linux, one
//! synthetic display elsewhere until native enumeration lands per OS) and
//! the client selects which display to stream with an authenticated `MS`
//! message. `OPENSTREAM_DISPLAY` is a host-side startup index; clients do not
//! guess host monitor numbering. All parsing is total: malformed topology
//! never panics, it is rejected.

/// Maximum displays carried in one topology message.
pub const MAX_DISPLAYS: usize = 16;
const MAGIC: [u8; 2] = *b"MD";
const VERSION: u8 = 1;
const SELECT_MAGIC: [u8; 2] = *b"MS";
/// Bit in [`Display::flags`] marking the primary desktop output.
pub const PRIMARY_FLAG: u16 = 1 << 0;
/// Bit in [`Display::flags`] marking the output currently being captured.
pub const SELECTED_FLAG: u16 = 1 << 1;
const KNOWN_FLAGS: u16 = PRIMARY_FLAG | SELECTED_FLAG;
/// Fixed bytes per display record: id + x + y + w + h + flags.
pub const DISPLAY_RECORD_LEN: usize = 22;

/// One enumerated display output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Display {
    pub id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u16,
    pub height: u16,
    /// Bit 0 set marks the primary output.
    pub flags: u16,
}

impl Display {
    /// Whether this output is the primary display.
    pub fn primary(self) -> bool {
        self.flags & PRIMARY_FLAG != 0
    }

    /// Whether this output is the one the host is currently capturing.
    pub fn selected(self) -> bool {
        self.flags & SELECTED_FLAG != 0
    }
}

/// Topology framing failures; all map to dropping the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadLength,
    BadMagic,
    UnsupportedVersion(u8),
    TooMany,
    ReservedBits,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => f.write_str("display message length is invalid"),
            Self::BadMagic => f.write_str("display message magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported display version {version}")
            }
            Self::TooMany => f.write_str("display count exceeds the bound"),
            Self::ReservedBits => f.write_str("display reserved bits are not zero"),
        }
    }
}

impl std::error::Error for Error {}

/// Encode up to [`MAX_DISPLAYS`] displays into one control payload.
pub fn encode_list(displays: &[Display]) -> Result<Vec<u8>, Error> {
    if displays.len() > MAX_DISPLAYS {
        return Err(Error::TooMany);
    }
    let mut out = Vec::with_capacity(4 + displays.len() * DISPLAY_RECORD_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(u8::try_from(displays.len()).map_err(|_| Error::TooMany)?);
    for display in displays {
        if display.flags & !KNOWN_FLAGS != 0 {
            return Err(Error::ReservedBits);
        }
        out.extend_from_slice(&display.id.to_be_bytes());
        out.extend_from_slice(&display.x.to_be_bytes());
        out.extend_from_slice(&display.y.to_be_bytes());
        out.extend_from_slice(&display.width.to_be_bytes());
        out.extend_from_slice(&display.height.to_be_bytes());
        out.extend_from_slice(&display.flags.to_be_bytes());
        // Reserved layout-generation bytes, always zero on the wire.
        out.extend_from_slice(&[0_u8; 4]);
    }
    Ok(out)
}

/// Decode one topology message after outer transport authentication.
pub fn decode_list(bytes: &[u8]) -> Result<Vec<Display>, Error> {
    if bytes.len() < 4 || (bytes.len() - 4) % DISPLAY_RECORD_LEN != 0 {
        return Err(Error::BadLength);
    }
    if bytes[0..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[2] != VERSION {
        return Err(Error::UnsupportedVersion(bytes[2]));
    }
    let count = bytes[3] as usize;
    if count > MAX_DISPLAYS || 4 + count * DISPLAY_RECORD_LEN != bytes.len() {
        return Err(Error::BadLength);
    }
    let mut displays = Vec::with_capacity(count);
    for chunk in bytes[4..].chunks_exact(DISPLAY_RECORD_LEN) {
        displays.push(Display {
            id: u32::from_be_bytes(chunk[0..4].try_into().expect("record checked")),
            x: i32::from_be_bytes(chunk[4..8].try_into().expect("record checked")),
            y: i32::from_be_bytes(chunk[8..12].try_into().expect("record checked")),
            width: u16::from_be_bytes(chunk[12..14].try_into().expect("record checked")),
            height: u16::from_be_bytes(chunk[14..16].try_into().expect("record checked")),
            flags: u16::from_be_bytes(chunk[16..18].try_into().expect("record checked")),
        });
        if displays
            .last()
            .is_some_and(|display| display.flags & !KNOWN_FLAGS != 0)
        {
            return Err(Error::ReservedBits);
        }
        // Last 4 bytes of each record are reserved for layout generation.
        if chunk[18..22] != [0, 0, 0, 0] {
            return Err(Error::ReservedBits);
        }
    }
    Ok(displays)
}

/// Encode a client display selection (one display id).
pub fn encode_select(display_id: u32) -> [u8; 8] {
    let mut out = [0_u8; 8];
    out[0..2].copy_from_slice(&SELECT_MAGIC);
    out[2] = VERSION;
    out[4..8].copy_from_slice(&display_id.to_be_bytes());
    out
}

/// Decode a client display selection.
pub fn decode_select(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() != 8 {
        return Err(Error::BadLength);
    }
    if bytes[0..2] != SELECT_MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[2] != VERSION {
        return Err(Error::UnsupportedVersion(bytes[2]));
    }
    if bytes[3] != 0 {
        return Err(Error::ReservedBits);
    }
    Ok(u32::from_be_bytes(
        bytes[4..8].try_into().expect("selection checked"),
    ))
}

/// Parse `xrandr --listmonitors` output into displays. Pure and tested.
///
/// Expected shape:
/// ```text
/// Monitors: 2
///  0: +*DP-1 1920/510x1080/287+0+0  DP-1
///  1: +HDMI-1 1280/340x1024/270+1920+0  HDMI-1
/// ```
/// The leading `*` marks primary; geometry is `WxH+X+Y` (mm sizes ignored).
pub fn parse_xrandr_listmonitors(text: &str) -> Vec<Display> {
    let mut displays = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 || displays.len() >= MAX_DISPLAYS {
            continue;
        }
        let line = line.trim();
        let geometry = line.split_whitespace().nth(2).unwrap_or_default();
        let Some((size, offsets)) = split_geometry_offsets(geometry) else {
            continue;
        };
        // Size interleaves mm dimensions: `1920/510x1080/287` means
        // 1920x1080 px. Take the pixel part before each `/`.
        let px = size
            .split('x')
            .map(|part| part.split('/').next().unwrap_or_default())
            .collect::<Vec<_>>();
        let (width, height) = match px.as_slice() {
            [width, height] => (width.parse().unwrap_or(0), height.parse().unwrap_or(0)),
            _ => continue,
        };
        let Some((x, y)) = parse_signed_offsets(offsets) else {
            continue;
        };
        if width == 0 || height == 0 {
            continue;
        }
        let primary = line
            .split_whitespace()
            .nth(1)
            .is_some_and(|flags| flags.contains('*'));
        displays.push(Display {
            id: u32::try_from(displays.len()).unwrap_or(u32::MAX),
            x,
            y,
            width,
            height,
            flags: u16::from(primary),
        });
    }
    displays
}

fn split_geometry_offsets(geometry: &str) -> Option<(&str, &str)> {
    let x = geometry.find('x')?;
    let offset_start = geometry[x + 1..]
        .char_indices()
        .find(|(_, character)| *character == '+' || *character == '-')
        .map(|(index, _)| x + 1 + index)?;
    Some((&geometry[..offset_start], &geometry[offset_start..]))
}

fn parse_signed_offsets(offsets: &str) -> Option<(i32, i32)> {
    let bytes = offsets.as_bytes();
    if bytes
        .first()
        .is_none_or(|byte| *byte != b'+' && *byte != b'-')
    {
        return None;
    }
    let second = bytes[1..]
        .iter()
        .position(|byte| *byte == b'+' || *byte == b'-')
        .map(|index| index + 1)?;
    let x = offsets[..second].parse::<i32>().ok()?;
    let y = offsets[second..].parse::<i32>().ok()?;
    Some((x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_round_trips_with_primary_flag() {
        let displays = vec![
            Display {
                id: 0,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                flags: PRIMARY_FLAG | SELECTED_FLAG,
            },
            Display {
                id: 1,
                x: 1920,
                y: 0,
                width: 1280,
                height: 1024,
                flags: 0,
            },
        ];
        let encoded = encode_list(&displays).expect("encode topology");
        let decoded = decode_list(&encoded).expect("decode topology");
        assert_eq!(decoded, displays);
        assert!(decoded[0].primary());
        assert!(decoded[0].selected());
        assert!(!decoded[1].primary());
        assert!(!decoded[1].selected());
    }

    #[test]
    fn oversized_and_malformed_topology_is_rejected() {
        let too_many = vec![
            Display {
                id: 0,
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                flags: 0,
            };
            MAX_DISPLAYS + 1
        ];
        assert_eq!(encode_list(&too_many), Err(Error::TooMany));
        assert_eq!(decode_list(&[0, 1]), Err(Error::BadLength));
        let mut bad = encode_list(&too_many[..1]).expect("one display");
        bad[0] = b'X';
        assert_eq!(decode_list(&bad), Err(Error::BadMagic));
        bad = encode_list(&too_many[..1]).expect("one display");
        bad[22] = 1;
        assert_eq!(decode_list(&bad), Err(Error::ReservedBits));
        bad = encode_list(&too_many[..1]).expect("one display");
        bad[20] = 0x80;
        assert_eq!(decode_list(&bad), Err(Error::ReservedBits));
    }

    #[test]
    fn selection_round_trips_as_eight_bytes() {
        let encoded = encode_select(7);
        assert_eq!(encoded.len(), 8);
        assert_eq!(decode_select(&encoded), Ok(7));
        assert_eq!(decode_select(&encoded[..7]), Err(Error::BadLength));
    }

    #[test]
    fn xrandr_fixture_parses_two_monitors() {
        let text = "Monitors: 2\n 0: +*DP-1 1920/510x1080/287+0+0  DP-1\n 1: +HDMI-1 1280/340x1024/270+1920+0  HDMI-1\n";
        let displays = parse_xrandr_listmonitors(text);
        assert_eq!(displays.len(), 2);
        assert_eq!((displays[0].width, displays[0].height), (1920, 1080));
        assert!((displays[0].x, displays[0].y) == (0, 0) && displays[0].primary());
        assert_eq!((displays[1].x, displays[1].width), (1920, 1280));
        assert!(!displays[1].primary());
    }

    #[test]
    fn xrandr_garbage_yields_no_displays_never_a_panic() {
        assert!(parse_xrandr_listmonitors("").is_empty());
        assert!(parse_xrandr_listmonitors("Monitors: 0\n").is_empty());
        assert!(parse_xrandr_listmonitors("garbage\n 0: +X bogus\n").is_empty());
    }

    #[test]
    fn xrandr_parser_accepts_negative_monitor_offsets() {
        let displays = parse_xrandr_listmonitors(
            "Monitors: 2\n  0: +*DP-1 1920/510x1080/287-1920+0  DP-1\n  1: +HDMI-1 1280/340x1024/270+0-1080  HDMI-1\n",
        );
        assert_eq!(displays.len(), 2);
        assert_eq!((displays[0].x, displays[0].y), (-1920, 0));
        assert_eq!((displays[1].x, displays[1].y), (0, -1080));
    }
}
