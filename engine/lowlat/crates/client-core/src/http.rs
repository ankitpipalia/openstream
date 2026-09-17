//! A small HTTPS client for the control-plane calls the engine has to make.
//!
//! The engine workspace had no HTTP client at all: `reqwest` is a desktop-only
//! dependency, and `client-core` carried only `tokio-tungstenite`. That is why
//! the machine service could never enrol itself -- the code to ask the control
//! plane for anything did not exist below the desktop app.
//!
//! **Why not `reqwest`.** The calls needed here are a handful of JSON `POST`s
//! and `GET`s against one origin. `reqwest` brings `hyper`, `h2`, `tower` and
//! their dependencies into a workspace that ships a privileged broker; this is
//! a few hundred lines over the `rustls` and `tokio` that `client-core` already
//! depends on, and adds no package to the tree that `tokio-tungstenite` did not
//! already pull in. For this shape of use that is the better trade.
//!
//! **What it deliberately does not do.** No connection pooling, no HTTP/2, no
//! redirects, no cookies, no compression, no proxies. A redirect is returned to
//! the caller as the status it is, because silently following one on a request
//! carrying a bearer token is how tokens end up at hosts nobody chose.
//! Everything here is HTTP/1.1 with a known `Content-Length`.
//!
//! **Bounds.** Every response is read under a size cap and every request under
//! a deadline, so a hostile or wedged server cannot exhaust memory or hang a
//! service thread indefinitely.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest response body accepted. Control-plane replies are small; this exists
/// so a wrong or hostile origin cannot make the service allocate without limit.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// How long a whole request may take, connection included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a request did not produce a response.
#[derive(Debug)]
pub enum HttpError {
    /// The origin could not be parsed, or names a scheme this does not speak.
    Origin(String),
    /// DNS, TCP, TLS, or a read or write failed.
    Transport(io::Error),
    /// The server's reply was not something this could parse.
    Malformed(&'static str),
    /// The reply exceeded [`MAX_RESPONSE_BYTES`].
    TooLarge,
    /// The request did not finish within [`REQUEST_TIMEOUT`].
    TimedOut,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin(detail) => write!(formatter, "bad origin: {detail}"),
            Self::Transport(error) => write!(formatter, "transport: {error}"),
            Self::Malformed(detail) => write!(formatter, "malformed response: {detail}"),
            Self::TooLarge => write!(
                formatter,
                "the response exceeded {MAX_RESPONSE_BYTES} bytes"
            ),
            Self::TimedOut => write!(formatter, "the request timed out"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<io::Error> for HttpError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error)
    }
}

/// A response: the status line's code and the body.
///
/// Headers are dropped. Nothing the control plane returns is carried in one,
/// and keeping them would invite callers to depend on something this client
/// does not promise to parse correctly.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as UTF-8, or empty if it is not.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// An origin split into the parts a request needs.
struct Target {
    tls: bool,
    host: String,
    port: u16,
}

/// Parse `http://host[:port]` or `https://host[:port]`.
///
/// Plain HTTP is accepted because the machine service's default origin is
/// `http://127.0.0.1:8080` for local development. It is the caller's job not to
/// send a bearer token to a plaintext origin that is not loopback.
fn parse_origin(origin: &str) -> Result<Target, HttpError> {
    let origin = origin.trim().trim_end_matches('/');
    let (tls, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(HttpError::Origin(
            "expected an http:// or https:// origin".into(),
        ));
    };
    if rest.is_empty() {
        return Err(HttpError::Origin("no host".into()));
    }
    // A path in the origin would silently disappear, so refuse it rather than
    // send requests somewhere the caller did not name.
    if rest.contains('/') {
        return Err(HttpError::Origin(
            "the origin must be scheme and host only, with no path".into(),
        ));
    }
    let (host, port) = match rest.rsplit_once(':') {
        // An IPv6 literal contains colons of its own; the port is only the part
        // after the last one when that part is entirely digits.
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => {
            let port = tail
                .parse::<u16>()
                .map_err(|_| HttpError::Origin("the port is not a number".into()))?;
            (head.to_string(), port)
        }
        _ => (rest.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(HttpError::Origin("no host".into()));
    }
    Ok(Target { tls, host, port })
}

/// Build the request bytes.
///
/// `Connection: close` because there is no pooling here: letting the server
/// close the connection is also what marks the end of a body that arrives
/// without a `Content-Length`.
fn request_bytes(
    method: &str,
    target: &Target,
    path: &str,
    bearer: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let host_header = if (target.tls && target.port == 443) || (!target.tls && target.port == 80) {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: openstream\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n"
    );
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Read an entire response under the size cap.
async fn read_all<S>(stream: &mut S) -> Result<Vec<u8>, HttpError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if raw.len() + read > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    Ok(raw)
}

/// Split a raw HTTP/1.1 response into its status and body.
///
/// Handles `Transfer-Encoding: chunked`, which a server may use even for a
/// small JSON reply -- decoding it is not optional, and a client that ignored
/// it would hand callers a body with hex length prefixes embedded in it.
fn parse_response(raw: &[u8]) -> Result<Response, HttpError> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(HttpError::Malformed("no header terminator"))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| HttpError::Malformed("the headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::Malformed("no status line"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(HttpError::Malformed("no status code"))?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });

    let body = &raw[split + 4..];
    if !chunked {
        return Ok(Response {
            status,
            body: body.to_vec(),
        });
    }
    Ok(Response {
        status,
        body: decode_chunked(body)?,
    })
}

/// Decode a chunked body.
fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(HttpError::Malformed("a chunk size line is unterminated"))?;
        let size_line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| HttpError::Malformed("a chunk size is not UTF-8"))?;
        // A chunk size line may carry extensions after a semicolon.
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpError::Malformed("a chunk size is not hex"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if size > body.len() {
            return Err(HttpError::Malformed("a chunk is shorter than it claims"));
        }
        if decoded.len() + size > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        decoded.extend_from_slice(&body[..size]);
        // Each chunk is followed by its own CRLF.
        body = body
            .get(size + 2..)
            .ok_or(HttpError::Malformed("a chunk is not terminated"))?;
    }
}

/// The TLS configuration, built once.
///
/// Roots come from `webpki-roots` rather than the platform store, which is what
/// `tokio-tungstenite` is already configured with here -- a service that trusts
/// one set of roots for its websocket and another for its HTTP calls would be
/// answering two different questions about the same origin.
fn tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Perform one request.
///
/// `path` must start with `/`. `bearer`, when given, is sent as an
/// `Authorization: Bearer` header.
pub async fn request(
    method: &str,
    origin: &str,
    path: &str,
    bearer: Option<&str>,
    body: &[u8],
) -> Result<Response, HttpError> {
    if !path.starts_with('/') {
        return Err(HttpError::Origin("the path must start with /".into()));
    }
    let target = parse_origin(origin)?;
    let bytes = request_bytes(method, &target, path, bearer, body);

    let work = async {
        let stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
        // Small JSON requests: waiting to coalesce them only adds latency.
        stream.set_nodelay(true)?;
        let raw = if target.tls {
            let name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| HttpError::Origin("the host is not a valid TLS server name".into()))?;
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            let mut stream = connector.connect(name, stream).await?;
            stream.write_all(&bytes).await?;
            stream.flush().await?;
            read_all(&mut stream).await?
        } else {
            let mut stream = stream;
            stream.write_all(&bytes).await?;
            stream.flush().await?;
            read_all(&mut stream).await?
        };
        parse_response(&raw)
    };

    match tokio::time::timeout(REQUEST_TIMEOUT, work).await {
        Ok(result) => result,
        Err(_) => Err(HttpError::TimedOut),
    }
}

/// `POST` a JSON body.
pub async fn post_json(
    origin: &str,
    path: &str,
    bearer: Option<&str>,
    body: &[u8],
) -> Result<Response, HttpError> {
    request("POST", origin, path, bearer, body).await
}

/// `GET` a path.
pub async fn get(origin: &str, path: &str, bearer: Option<&str>) -> Result<Response, HttpError> {
    request("GET", origin, path, bearer, &[]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_without_a_port_uses_the_scheme_default() {
        let target = parse_origin("https://signal.example.com").expect("parse");
        assert!(target.tls);
        assert_eq!(target.host, "signal.example.com");
        assert_eq!(target.port, 443);

        let target = parse_origin("http://127.0.0.1").expect("parse");
        assert!(!target.tls);
        assert_eq!(target.port, 80);
    }

    #[test]
    fn an_explicit_port_is_used() {
        let target = parse_origin("http://127.0.0.1:8080").expect("parse");
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn a_trailing_slash_is_not_a_path() {
        let target = parse_origin("https://signal.example.com/").expect("parse");
        assert_eq!(target.host, "signal.example.com");
    }

    #[test]
    fn an_origin_with_a_path_is_refused_rather_than_silently_dropped() {
        // Accepting it would send every request to the root of the host while
        // the caller believed it was prefixed, which is the kind of mistake
        // that only shows up as a 404 from an endpoint that exists.
        assert!(parse_origin("https://example.com/api").is_err());
    }

    #[test]
    fn a_scheme_this_does_not_speak_is_refused() {
        for bad in ["ws://example.com", "example.com", "ftp://example.com", ""] {
            assert!(parse_origin(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_ipv6_literal_keeps_its_colons() {
        let target = parse_origin("http://[::1]:8080").expect("parse");
        assert_eq!(target.host, "[::1]");
        assert_eq!(target.port, 8080);

        let target = parse_origin("http://[::1]").expect("parse");
        assert_eq!(
            target.host, "[::1]",
            "the address is not mistaken for a port"
        );
        assert_eq!(target.port, 80);
    }

    #[test]
    fn the_host_header_omits_a_default_port_and_keeps_a_custom_one() {
        let target = parse_origin("https://example.com").expect("parse");
        let bytes = request_bytes("GET", &target, "/v1/x", None, b"");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("Host: example.com\r\n"), "{text}");

        let target = parse_origin("http://example.com:8080").expect("parse");
        let bytes = request_bytes("GET", &target, "/v1/x", None, b"");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("Host: example.com:8080\r\n"), "{text}");
    }

    #[test]
    fn a_bearer_token_is_sent_only_when_given() {
        let target = parse_origin("https://example.com").expect("parse");
        let without = String::from_utf8(request_bytes("GET", &target, "/x", None, b"")).unwrap();
        assert!(!without.contains("Authorization"));

        let with =
            String::from_utf8(request_bytes("GET", &target, "/x", Some("tok"), b"")).unwrap();
        assert!(with.contains("Authorization: Bearer tok\r\n"), "{with}");
    }

    #[test]
    fn a_body_carries_its_length_and_content_type() {
        let target = parse_origin("https://example.com").expect("parse");
        let bytes = request_bytes("POST", &target, "/x", None, b"{\"a\":1}");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("Content-Length: 7\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: application/json\r\n"),
            "{text}"
        );
        assert!(text.ends_with("{\"a\":1}"), "{text}");
    }

    #[test]
    fn an_empty_body_still_declares_a_length() {
        // A POST with no Content-Length invites the server to wait for a body
        // that is never coming.
        let target = parse_origin("https://example.com").expect("parse");
        let text = String::from_utf8(request_bytes("POST", &target, "/x", None, b"")).unwrap();
        assert!(text.contains("Content-Length: 0\r\n"), "{text}");
    }

    #[test]
    fn a_plain_response_is_split_into_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"a\":1}");
        assert!(response.is_success());
    }

    #[test]
    fn a_chunked_response_is_decoded_rather_than_handed_over_raw() {
        // A server may chunk even a small JSON reply. Without this the caller
        // gets hex length prefixes embedded in the body and a JSON parse error
        // that points nowhere useful.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body, b"{\"a\":1}",
            "the chunk framing must not survive into the body"
        );
    }

    #[test]
    fn chunk_extensions_do_not_break_the_size() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3;name=value\r\nabc\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).expect("parse").body, b"abc");
    }

    #[test]
    fn a_header_name_is_matched_case_insensitively() {
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).expect("parse").body, b"abc");
    }

    #[test]
    fn an_error_status_is_reported_rather_than_turned_into_an_error() {
        // The control plane says a great deal through status codes -- 409 for
        // an enrolment that already happened, 403 for a token that is not
        // allowed. Collapsing them into one transport error would throw that
        // away.
        let raw = b"HTTP/1.1 409 Conflict\r\nContent-Length: 2\r\n\r\n{}";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.status, 409);
        assert!(!response.is_success());
    }

    #[test]
    fn a_truncated_response_is_an_error_not_a_guess() {
        assert!(parse_response(b"HTTP/1.1 200 OK").is_err());
        assert!(parse_response(b"nonsense\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 OK\r\n\r\n").is_err());
    }

    #[test]
    fn a_chunk_shorter_than_it_claims_is_refused() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nabc\r\n";
        assert!(
            parse_response(raw).is_err(),
            "a body cut short must not be returned as if it were whole"
        );
    }

    #[test]
    fn a_path_must_be_absolute() {
        let error = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(request("GET", "https://example.com", "v1/x", None, b""));
        assert!(error.is_err(), "a relative path must not be sent");
    }
}
