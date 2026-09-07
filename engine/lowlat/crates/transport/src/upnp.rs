//! Small, opt-in UPnP Internet Gateway Device (IGD) mapper.
//!
//! This module deliberately implements only the part needed by an
//! OpenStream UDP session: SSDP discovery, WANIPConnection/WANPPPConnection
//! control-URL discovery, external-address lookup, and one UDP mapping. It
//! uses bounded HTTP/XML parsing and never executes router-provided data.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use url::Url;

const SSDP_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
const SSDP_WAIT: Duration = Duration::from_secs(2);
const HTTP_WAIT: Duration = Duration::from_secs(3);
const MAX_HTTP_BYTES: usize = 128 * 1024;
const WAN_IP_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const WAN_PPP_SERVICE: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Timeout,
    NoGateway,
    InvalidLocation(String),
    Http(String),
    Xml(String),
    Address(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "UPnP I/O failed: {error}"),
            Self::Timeout => f.write_str("UPnP discovery or SOAP request timed out"),
            Self::NoGateway => f.write_str("no UPnP Internet Gateway Device was discovered"),
            Self::InvalidLocation(location) => {
                write!(f, "UPnP device location is invalid: {location}")
            }
            Self::Http(reason) => write!(f, "UPnP HTTP request failed: {reason}"),
            Self::Xml(reason) => write!(f, "UPnP device description is invalid: {reason}"),
            Self::Address(reason) => write!(f, "UPnP address is invalid: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A successful UDP port mapping that can be explicitly removed.
#[derive(Debug)]
pub struct Mapping {
    control_url: Url,
    service_type: &'static str,
    external_addr: SocketAddr,
    internal_ip: IpAddr,
    internal_port: u16,
}

impl Mapping {
    pub fn external_addr(&self) -> SocketAddr {
        self.external_addr
    }

    /// Delete this mapping. Routers commonly delete short leases themselves;
    /// callers should still invoke this during an orderly session shutdown.
    pub async fn release(&self) -> Result<(), Error> {
        let arguments = [
            ("NewRemoteHost", ""),
            ("NewExternalPort", &self.external_addr.port().to_string()),
            ("NewProtocol", "UDP"),
            ("NewInternalPort", &self.internal_port.to_string()),
            ("NewInternalClient", &self.internal_ip.to_string()),
        ];
        soap_request(
            &self.control_url,
            self.service_type,
            "DeletePortMapping",
            &arguments,
        )
        .await
        .map(|_| ())
    }
}

/// Discover an IGD and map the UDP port of `socket`.
pub(crate) async fn map_udp_port(socket: &UdpSocket, lease: Duration) -> Result<Mapping, Error> {
    let local = socket.local_addr()?;
    let local_port = local.port();
    if local_port == 0 {
        return Err(Error::Address(
            "the UDP socket has no assigned port".to_string(),
        ));
    }
    let location = discover_location().await?;
    let description = http_get(&location).await?;
    let (control_url, service_type) = find_control_url(&location, &description)?;
    let gateway = location
        .host_str()
        .ok_or_else(|| Error::InvalidLocation(location.to_string()))?
        .parse::<Ipv4Addr>()
        .map_err(|_| Error::Address("the IGD location is not an IPv4 address".to_string()))?;
    let internal_ip = match local.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => address,
        _ => local_ipv4_for_gateway(gateway).await?,
    };
    let external_ip = get_external_address(&control_url, service_type).await?;
    let lease_seconds = u32::try_from(lease.as_secs()).unwrap_or(u32::MAX).max(60);
    let external_port = local_port;
    let internal_port = local_port;
    let arguments = [
        ("NewRemoteHost", ""),
        ("NewExternalPort", &external_port.to_string()),
        ("NewProtocol", "UDP"),
        ("NewInternalPort", &internal_port.to_string()),
        ("NewInternalClient", &internal_ip.to_string()),
        ("NewEnabled", "1"),
        ("NewPortMappingDescription", "OpenStream"),
        ("NewLeaseDuration", &lease_seconds.to_string()),
    ];
    soap_request(&control_url, service_type, "AddPortMapping", &arguments).await?;
    Ok(Mapping {
        control_url,
        service_type,
        external_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
        internal_ip: IpAddr::V4(internal_ip),
        internal_port,
    })
}

async fn discover_location() -> Result<Url, Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let request = ssdp_request(WAN_IP_SERVICE);
    socket.send_to(request.as_bytes(), SSDP_ADDR).await?;
    socket
        .send_to(ssdp_request(WAN_PPP_SERVICE).as_bytes(), SSDP_ADDR)
        .await?;
    let deadline = Instant::now() + SSDP_WAIT;
    let mut buffer = [0_u8; 8192];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let received = match timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => break,
        };
        let Some(location) = header_value(&buffer[..received.0], "location") else {
            continue;
        };
        if let Ok(url) = Url::parse(location.trim())
            && valid_device_location(&url)
        {
            return Ok(url);
        }
    }
    Err(Error::NoGateway)
}

fn ssdp_request(service: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {service}\r\n\r\n"
    )
}

async fn local_ipv4_for_gateway(gateway: Ipv4Addr) -> Result<Ipv4Addr, Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket
        .connect(SocketAddr::new(IpAddr::V4(gateway), 1900))
        .await?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => Ok(address),
        _ => Err(Error::Address(
            "could not determine the local IPv4 address".to_string(),
        )),
    }
}

async fn get_external_address(
    control_url: &Url,
    service_type: &'static str,
) -> Result<Ipv4Addr, Error> {
    let body = soap_request(control_url, service_type, "GetExternalIPAddress", &[]).await?;
    let xml = std::str::from_utf8(&body)
        .map_err(|_| Error::Xml("GetExternalIPAddress response is not UTF-8".to_string()))?;
    let address = tag_text(xml, "NewExternalIPAddress")
        .ok_or_else(|| Error::Xml("GetExternalIPAddress returned no address".to_string()))?;
    address
        .parse()
        .map_err(|_| Error::Address("router returned a non-IPv4 external address".to_string()))
}

fn find_control_url(location: &Url, description: &[u8]) -> Result<(Url, &'static str), Error> {
    let xml = std::str::from_utf8(description)
        .map_err(|_| Error::Xml("device description is not UTF-8".to_string()))?;
    for (service, service_type) in [
        (WAN_IP_SERVICE, WAN_IP_SERVICE),
        (WAN_PPP_SERVICE, WAN_PPP_SERVICE),
    ] {
        let mut search_from = 0;
        while let Some(relative_start) = xml[search_from..].find("<service>") {
            let start = search_from + relative_start;
            let Some(relative_end) = xml[start..].find("</service>") else {
                break;
            };
            let end = start + relative_end + "</service>".len();
            let block = &xml[start..end];
            if tag_text(block, "serviceType").as_deref() == Some(service) {
                let control = tag_text(block, "controlURL")
                    .ok_or_else(|| Error::Xml("WAN service has no controlURL".to_string()))?;
                let url = location
                    .join(&control)
                    .map_err(|error| Error::InvalidLocation(error.to_string()))?;
                if !same_safe_host(location, &url) {
                    return Err(Error::InvalidLocation(
                        "device control URL escapes the discovered gateway".to_string(),
                    ));
                }
                return Ok((
                    url,
                    if service_type == WAN_IP_SERVICE {
                        WAN_IP_SERVICE
                    } else {
                        WAN_PPP_SERVICE
                    },
                ));
            }
            search_from = end;
        }
    }
    Err(Error::Xml(
        "no WANIPConnection or WANPPPConnection service".to_string(),
    ))
}

async fn soap_request(
    url: &Url,
    service_type: &str,
    action: &str,
    arguments: &[(&str, &str)],
) -> Result<Vec<u8>, Error> {
    let mut inner = String::new();
    for &(name, value) in arguments {
        inner.push('<');
        inner.push_str(name);
        inner.push('>');
        inner.push_str(&escape_xml(value));
        inner.push_str("</");
        inner.push_str(name);
        inner.push('>');
    }
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service_type}\">{inner}</u:{action}></s:Body></s:Envelope>"
    );
    http_post(url, service_type, action, body.as_bytes()).await
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

async fn http_get(url: &Url) -> Result<Vec<u8>, Error> {
    http_request(url, "GET", None, None).await
}

async fn http_post(
    url: &Url,
    service_type: &str,
    action: &str,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    http_request(url, "POST", Some((service_type, action)), Some(body)).await
}

async fn http_request(
    url: &Url,
    method: &str,
    soap: Option<(&str, &str)>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::InvalidLocation(url.to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::InvalidLocation(url.to_string()))?;
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let address = format!("{host}:{port}");
    let mut stream = timeout(HTTP_WAIT, TcpStream::connect(address))
        .await
        .map_err(|_| Error::Timeout)??;
    let body = body.unwrap_or_default();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some((service_type, action)) = soap {
        request.push_str(&format!("SOAPAction: \"{service_type}#{action}\"\r\n"));
        request.push_str("Content-Type: text/xml; charset=\"utf-8\"\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    timeout(HTTP_WAIT, async {
        stream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| Error::Timeout)??;
    let response = timeout(HTTP_WAIT, read_bounded(&mut stream))
        .await
        .map_err(|_| Error::Timeout)??;
    parse_http_response(&response)
}

async fn read_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            break;
        }
        if response.len().saturating_add(length) > MAX_HTTP_BYTES {
            return Err(Error::Http(
                "response exceeded the bounded size".to_string(),
            ));
        }
        response.extend_from_slice(&chunk[..length]);
    }
    Ok(response)
}

fn valid_device_location(url: &Url) -> bool {
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some_and(|host| {
            host.parse::<Ipv4Addr>()
                .map(|address| address.is_private() || address.is_link_local())
                .unwrap_or(false)
        })
}

fn same_safe_host(base: &Url, candidate: &Url) -> bool {
    candidate.scheme() == base.scheme()
        && candidate.host_str() == base.host_str()
        && candidate.port_or_known_default() == base.port_or_known_default()
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, Error> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::Http("response has no header terminator".to_string()))?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|_| Error::Http("response headers are not UTF-8".to_string()))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::Http("response status is invalid".to_string()))?;
    if !(200..300).contains(&status) {
        return Err(Error::Http(format!("router returned HTTP status {status}")));
    }
    Ok(response[separator + 4..].to_vec())
}

fn header_value<'a>(response: &'a [u8], name: &str) -> Option<&'a str> {
    let headers = std::str::from_utf8(response).ok()?;
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(unescape_xml(xml[start..end].trim()))
}

fn unescape_xml(value: &str) -> String {
    value
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_request_is_bounded_and_targets_the_wan_service() {
        let request = ssdp_request(WAN_IP_SERVICE);
        assert!(request.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(request.contains("ST: urn:schemas-upnp-org:service:WANIPConnection:1"));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn device_description_resolves_relative_control_url() {
        let location = Url::parse("http://192.168.1.1:1900/root.xml").unwrap();
        let xml = br#"<root><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/WANIPConn</controlURL></service></serviceList></root>"#;
        let (url, service) = find_control_url(&location, xml).unwrap();
        assert_eq!(url.as_str(), "http://192.168.1.1:1900/ctl/WANIPConn");
        assert_eq!(service, WAN_IP_SERVICE);
    }

    #[test]
    fn soap_values_are_xml_escaped() {
        let escaped = escape_xml("a&<b>\"'");
        assert_eq!(escaped, "a&amp;&lt;b&gt;&quot;&apos;");
    }

    #[test]
    fn non_success_http_status_is_rejected() {
        let response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";
        assert!(matches!(
            parse_http_response(response),
            Err(Error::Http(reason)) if reason.contains("500")
        ));
    }

    #[test]
    fn device_locations_are_restricted_to_local_gateway_addresses() {
        assert!(valid_device_location(
            &Url::parse("http://192.168.1.1:1900/root.xml").unwrap()
        ));
        assert!(!valid_device_location(
            &Url::parse("http://example.com/root.xml").unwrap()
        ));
        assert!(!valid_device_location(
            &Url::parse("http://127.0.0.1:1900/root.xml").unwrap()
        ));
    }

    #[test]
    fn control_url_cannot_escape_the_discovered_gateway() {
        let base = Url::parse("http://192.168.1.1:1900/root.xml").unwrap();
        let same = Url::parse("http://192.168.1.1:1900/ctl").unwrap();
        let other = Url::parse("http://192.168.1.2:1900/ctl").unwrap();
        assert!(same_safe_host(&base, &same));
        assert!(!same_safe_host(&base, &other));
    }
}
