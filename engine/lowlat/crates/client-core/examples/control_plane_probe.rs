//! Prove the engine's HTTP client works against a real control plane.
//!
//! Unit tests cover the parsing; they say nothing about whether TLS negotiates,
//! whether the roots are right, or whether a real server's framing is what this
//! expects. This makes the calls.
//!
//! Run: `cargo run --release -p openstream-client-core --example
//! control_plane_probe -- https://signal.example.com`

#[tokio::main]
async fn main() -> std::process::ExitCode {
    use openstream_client_core::http;

    let origin = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://signal.ankitpipalia.site".to_string());
    let mut failures = 0;
    for path in ["/healthz", "/version"] {
        match http::get(&origin, path, None).await {
            Ok(response) => {
                let body = response.text();
                let shown = body.chars().take(200).collect::<String>();
                println!("{path} -> {} {shown}", response.status);
            }
            Err(error) => {
                eprintln!("{path} -> FAILED: {error}");
                failures += 1;
            }
        }
    }
    if failures > 0 {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}
