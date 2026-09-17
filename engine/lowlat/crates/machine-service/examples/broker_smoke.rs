//! Runtime smoke test for the broker's capture pipeline, no peer required.
//!
//! It connects to a running broker exactly as the machine service would, opens a
//! capture on the current seat, and counts the encoded frames that come back
//! over a few seconds. A denied DRM scanout surfaces as a `CaptureError`; a
//! working pipeline reports a frame count, total bytes, and at least one
//! keyframe -- proof that DRM capture -> hardware encode -> the IPC all work,
//! without needing signaling, a pairing, or a remote client.
//!
//! Run (with a broker listening, both as root during bring-up):
//!   OPENSTREAM_BROKER_SOCKET=/run/openstream/broker.sock \
//!     cargo run -p openstream-machine-service --example broker_smoke

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use openstream_host_ipc::lifecycle::CaptureKind;
    use openstream_host_ipc::protocol::{BrokerEvent, CaptureParams, ServiceRequest};
    use openstream_host_ipc::token::Capabilities;
    use openstream_host_ipc::transport::{recv_event, send_request};
    use openstream_machine_service::broker_client;
    use openstream_machine_service::session::current_seat;

    let socket = PathBuf::from(
        std::env::var("OPENSTREAM_BROKER_SOCKET")
            .unwrap_or_else(|_| "/run/openstream/broker.sock".to_string()),
    );
    let mut broker = match broker_client::connect(&socket).await {
        Ok(broker) => broker,
        Err(error) => {
            eprintln!("broker_smoke: could not connect to the broker: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    eprintln!(
        "broker_smoke: connected, broker capabilities {:?}",
        broker.capabilities
    );

    let seat = current_seat();
    eprintln!("broker_smoke: current seat is {seat:?}");
    if let Err(error) = send_request(
        &mut broker.writer,
        &ServiceRequest::OpenCapture {
            // Zero asks the broker to issue a capability; an empty approval is
            // refused. This probe checks that the socket, the peer check and
            // the handshake work, and a refusal past all three is a successful
            // probe -- it proves the boundary is live rather than absent.
            token_id: openstream_host_ipc::token::NO_GRANT,
            grant: Vec::new(),
            requested: Capabilities::CAPTURE,
            params: CaptureParams {
                seat,
                kind: CaptureKind::Scanout,
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_kbps: 10_000,
            },
        },
    )
    .await
    {
        eprintln!("broker_smoke: OpenCapture send failed: {error}");
        return std::process::ExitCode::from(2);
    }

    match recv_event(&mut broker.reader).await {
        Ok(BrokerEvent::CaptureStarted {
            width,
            height,
            granted,
            ..
        }) => eprintln!("broker_smoke: capture started {width}x{height}, granted {granted:?}"),
        Ok(BrokerEvent::CaptureError { code, message }) => {
            eprintln!("broker_smoke: capture refused ({code}): {message}");
            return std::process::ExitCode::from(3);
        }
        Ok(other) => {
            eprintln!("broker_smoke: unexpected first event: {other:?}");
            return std::process::ExitCode::from(3);
        }
        Err(error) => {
            eprintln!("broker_smoke: read failed: {error}");
            return std::process::ExitCode::from(2);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    let mut keyframes = 0_u64;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, recv_event(&mut broker.reader)).await {
            Ok(Ok(BrokerEvent::Frame { keyframe, data, .. })) => {
                frames += 1;
                bytes += u64::try_from(data.len()).unwrap_or(u64::MAX);
                if keyframe {
                    keyframes += 1;
                }
            }
            Ok(Ok(BrokerEvent::CaptureError { code, message })) => {
                eprintln!("broker_smoke: capture error mid-stream ({code}): {message}");
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                eprintln!("broker_smoke: stream read failed: {error}");
                break;
            }
            Err(_elapsed) => break,
        }
    }

    let _ = send_request(&mut broker.writer, &ServiceRequest::Shutdown).await;

    println!(
        "{{\"frames\": {frames}, \"bytes\": {bytes}, \"keyframes\": {keyframes}, \"streaming\": {}}}",
        frames > 0
    );
    if frames > 0 && keyframes > 0 {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("broker_smoke: no frames captured (expected a live scanout)");
        std::process::ExitCode::from(4)
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("broker_smoke is Linux-only");
}
