//! Host-agent process and protected local IPC server.

#[cfg(unix)]
mod unix_main {
    use openstream_host_agent::{
        AgentError, AgentIpcCommand, AgentIpcRequest, AgentIpcResponse,
        HOST_AGENT_PROTOCOL_VERSION, HostAgent, HostAgentConfig, HostBackend, HostErrorCode,
        run_preflight,
    };
    use openstream_local_ipc::{Endpoint, IpcError, read_frame, write_frame};
    use openstream_settings::{apply_environment_overrides, default_config};
    use std::env;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::{Mutex, watch};
    use tokio::task::JoinSet;

    const IPC_READ_TIMEOUT: Duration = Duration::from_secs(30);
    const TICK_INTERVAL: Duration = Duration::from_millis(100);
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

    pub(crate) async fn run() -> Result<(), String> {
        let (config, report) = build_config()?;
        eprintln!(
            "OpenStream host agent: selected backend={}",
            report.selected.label()
        );
        if let Some(reason) = report.reason {
            return Err(format!("host preflight failed: {reason:?}"));
        }

        let socket = socket_path()?;
        let endpoint = Endpoint::new(socket).map_err(|error| error.to_string())?;
        let listener = bind_endpoint(&endpoint).await?;
        let agent = HostAgent::new(config).map_err(|error| error.to_string())?;
        let agent = Arc::new(Mutex::new(agent));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut connections = JoinSet::new();
        let mut ticker = tokio::time::interval(TICK_INTERVAL);
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|error| format!("could not install SIGTERM handler: {error}"))?;

        {
            let mut guard = agent.lock().await;
            let events = guard
                .start(Instant::now())
                .map_err(|error| error.to_string())?;
            log_events(&events);
        }

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _address)) => {
                            let child_agent = Arc::clone(&agent);
                            let child_shutdown = shutdown_tx.clone();
                            connections.spawn(async move {
                                if let Err(error) = serve_connection(stream, child_agent, child_shutdown).await {
                                    eprintln!("OpenStream host agent IPC closed: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("OpenStream host agent IPC accept failed: {}", error.kind());
                        }
                    }
                }
                _ = ticker.tick() => {
                    let mut guard = agent.lock().await;
                    match guard.tick(Instant::now()) {
                        Ok(events) => log_events(&events),
                        Err(error) => eprintln!("OpenStream host agent tick failed: {error}"),
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                result = &mut ctrl_c => {
                    if let Err(error) = result {
                        eprintln!("OpenStream host agent signal handler failed: {error}");
                    }
                    break;
                }
                _ = sigterm.recv() => {
                    break;
                }
            }
        }

        {
            let mut guard = agent.lock().await;
            if let Err(error) = guard.stop(Instant::now()) {
                eprintln!("OpenStream host agent shutdown failed: {error}");
            }
        }
        let shutdown_deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            let stopped = {
                let mut guard = agent.lock().await;
                match guard.tick(Instant::now()) {
                    Ok(events) => log_events(&events),
                    Err(error) => eprintln!("OpenStream host agent shutdown tick failed: {error}"),
                }
                guard.state() == openstream_host_agent::ChildState::Stopped
            };
            if stopped {
                break;
            }
            if Instant::now() >= shutdown_deadline {
                eprintln!("OpenStream host agent shutdown failed: child reap deadline exceeded");
                break;
            }
            tokio::time::sleep(TICK_INTERVAL).await;
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        endpoint.cleanup().map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn serve_connection(
        mut stream: UnixStream,
        agent: Arc<Mutex<HostAgent>>,
        shutdown: watch::Sender<bool>,
    ) -> Result<(), IpcError> {
        loop {
            let request = tokio::time::timeout(
                IPC_READ_TIMEOUT,
                read_frame::<_, AgentIpcRequest>(&mut stream),
            )
            .await
            .map_err(|_| IpcError::Io(std::io::ErrorKind::TimedOut))??;
            let Some(request) = request else {
                return Ok(());
            };
            let is_shutdown = request.command == AgentIpcCommand::Shutdown;
            let response = handle_request(request, &agent).await;
            write_frame(&mut stream, &response).await?;
            if is_shutdown {
                let _ = shutdown.send(true);
                return Ok(());
            }
        }
    }

    async fn bind_endpoint(endpoint: &Endpoint) -> Result<UnixListener, String> {
        match endpoint.bind().await {
            Ok(listener) => Ok(listener),
            Err(IpcError::SocketInUse) => {
                let probe =
                    tokio::time::timeout(Duration::from_millis(250), endpoint.connect()).await;
                match probe {
                    Ok(Ok(_stream)) => Err("host-agent IPC endpoint is already active".to_string()),
                    Ok(Err(IpcError::Io(std::io::ErrorKind::ConnectionRefused)))
                    | Ok(Err(IpcError::Io(std::io::ErrorKind::NotFound))) => {
                        endpoint.cleanup().map_err(|error| error.to_string())?;
                        endpoint.bind().await.map_err(|error| error.to_string())
                    }
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("host-agent IPC endpoint probe timed out".to_string()),
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn handle_request(
        request: AgentIpcRequest,
        agent: &Arc<Mutex<HostAgent>>,
    ) -> AgentIpcResponse {
        let request_id = request.request_id.clone();
        if request.version != HOST_AGENT_PROTOCOL_VERSION {
            return AgentIpcResponse::Error {
                version: HOST_AGENT_PROTOCOL_VERSION,
                request_id,
                code: HostErrorCode::InvalidConfig,
                retryable: false,
            };
        }

        if request.command == AgentIpcCommand::Health {
            let guard = agent.lock().await;
            return AgentIpcResponse::Health {
                version: HOST_AGENT_PROTOCOL_VERSION,
                request_id,
                health: guard.health(Instant::now()),
            };
        }

        let mut guard = agent.lock().await;
        let command = match request.command {
            AgentIpcCommand::Start => openstream_host_agent::HostAgentCommand::Start,
            AgentIpcCommand::Stop => openstream_host_agent::HostAgentCommand::Stop,
            AgentIpcCommand::Tick => openstream_host_agent::HostAgentCommand::Tick,
            AgentIpcCommand::Health | AgentIpcCommand::Shutdown => {
                openstream_host_agent::HostAgentCommand::Shutdown
            }
        };
        match guard.dispatch(command, Instant::now()) {
            Ok(events) => {
                log_events(&events);
                AgentIpcResponse::Accepted {
                    version: HOST_AGENT_PROTOCOL_VERSION,
                    request_id,
                    events,
                }
            }
            Err(error) => {
                let code = error_code(guard.health(Instant::now()).last_error, error);
                AgentIpcResponse::Error {
                    version: HOST_AGENT_PROTOCOL_VERSION,
                    request_id,
                    code,
                    retryable: code.retryable(),
                }
            }
        }
    }

    fn error_code(_last_error: Option<HostErrorCode>, error: AgentError) -> HostErrorCode {
        match error {
            AgentError::InvalidConfig => HostErrorCode::InvalidConfig,
            AgentError::SpawnFailed => HostErrorCode::SpawnFailed,
            AgentError::ChildIo(_) => HostErrorCode::ChildFailed,
            AgentError::StopFailed => HostErrorCode::StopFailed,
            AgentError::UnsupportedPlatform => HostErrorCode::InvalidConfig,
        }
    }

    fn log_events(events: &[openstream_host_agent::HostAgentEvent]) {
        for event in events {
            eprintln!("OpenStream host agent event: {event:?}");
        }
    }

    fn build_config() -> Result<(HostAgentConfig, openstream_host_agent::PreflightReport), String> {
        let mut settings = default_config();
        apply_environment_overrides(&mut settings).map_err(|error| error.to_string())?;
        let explicit_child = env::var_os("OPENSTREAM_HOST_CHILD");
        let executable = explicit_child
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("openstream-ffmpeg-host"));
        let ffmpeg = env::var_os("OPENSTREAM_FFMPEG");
        let report = run_preflight(
            &settings.host.capture,
            native_drm_reachable(),
            env::var_os("DISPLAY").is_some(),
            env::var_os("PIPEWIRE_REMOTE").is_some() || env::var_os("WAYLAND_DISPLAY").is_some(),
            executable_available(ffmpeg.as_ref()),
        );
        if report.selected == HostBackend::NativeDrm && explicit_child.is_none() {
            return Err(
                "native DRM preflight is positive but the persistent agent has no native child configured"
                    .to_string(),
            );
        }
        let mut config = HostAgentConfig::from_settings(&settings, executable)
            .map_err(|error| error.to_string())?
            .with_backend(report.selected.label())
            .map_err(|error| error.to_string())?;
        let selected_capture = match report.selected {
            HostBackend::FfmpegX11 => Some("x11grab"),
            HostBackend::FfmpegPipewire => Some("pipewire"),
            HostBackend::FfmpegFallback | HostBackend::NativeDrm | HostBackend::Unavailable => None,
        };
        if let Some(capture) = selected_capture {
            config = config
                .with_runtime_env("OPENSTREAM_CAPTURE_BACKEND", capture)
                .map_err(|error| error.to_string())?;
        }
        if let Some(value) = ffmpeg {
            config = config
                .with_runtime_env("OPENSTREAM_FFMPEG", value.to_string_lossy())
                .map_err(|error| error.to_string())?;
        }
        if let Ok(value) = env::var("OPENSTREAM_PAIRING_JSON") {
            config = config
                .with_runtime_env("OPENSTREAM_PAIRING_JSON", value)
                .map_err(|error| error.to_string())?;
        }
        Ok((config, report))
    }

    fn native_drm_reachable() -> bool {
        native_drm_reachable_with(
            cfg!(target_os = "linux"),
            native_drm_probe_ready(),
            |name| env::var(name).ok(),
        )
    }

    fn native_drm_reachable_with(
        platform_supported: bool,
        probe_ready: bool,
        environment: impl Fn(&str) -> Option<String>,
    ) -> bool {
        if !platform_supported {
            return false;
        }
        if probe_ready {
            return true;
        }
        let developer_override =
            environment("OPENSTREAM_DEVELOPER_OVERRIDE").as_deref() == Some("1");
        let assume_native_drm =
            environment("OPENSTREAM_DEVELOPER_ASSUME_NATIVE_DRM").as_deref() == Some("1");
        if developer_override && assume_native_drm {
            // Unsafe by design: this developer-only escape hatch asserts that
            // native DRM works even though the real probe could not prove it.
            eprintln!(
                "OpenStream host agent warning: unsafe developer assumption is bypassing the native DRM readiness probe"
            );
            return true;
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn native_drm_probe_ready() -> bool {
        lowlat::display::native_drm_probe().is_ready()
    }

    #[cfg(not(target_os = "linux"))]
    const fn native_drm_probe_ready() -> bool {
        false
    }

    fn executable_available(program: Option<&OsString>) -> bool {
        let program = program.map_or_else(|| OsString::from("ffmpeg"), OsString::clone);
        std::process::Command::new(program)
            .arg("-version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    fn socket_path() -> Result<PathBuf, String> {
        if let Some(path) = env::var_os("OPENSTREAM_HOST_AGENT_SOCKET") {
            return Ok(PathBuf::from(path));
        }
        let base = env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| {
                env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").into_os_string())
            })
            .unwrap_or_else(|| OsString::from("/tmp"));
        let base = PathBuf::from(base);
        Ok(base.join("openstream").join("host-agent.sock"))
    }

    #[cfg(test)]
    mod tests {
        use super::{error_code, native_drm_reachable_with};
        use openstream_host_agent::{AgentError, HostBackend, HostErrorCode, run_preflight};
        use openstream_settings::default_config;

        #[test]
        fn current_typed_error_wins_over_stale_health_error() {
            assert_eq!(
                error_code(
                    Some(HostErrorCode::LifetimeExceeded),
                    AgentError::StopFailed,
                ),
                HostErrorCode::StopFailed
            );
        }

        #[test]
        fn legacy_native_drm_flag_cannot_override_an_unreachable_probe() {
            let environment =
                |name: &str| (name == "OPENSTREAM_NATIVE_DRM_READY").then_some("1".to_string());
            let native_drm_reachable = native_drm_reachable_with(true, false, environment);
            let settings = default_config();
            let report = run_preflight(
                &settings.host.capture,
                native_drm_reachable,
                true,
                false,
                true,
            );

            assert!(!native_drm_reachable);
            assert_eq!(report.selected, HostBackend::FfmpegX11);
        }

        #[test]
        fn native_drm_probe_can_select_native_backend() {
            let settings = default_config();
            let report = run_preflight(&settings.host.capture, true, true, false, true);

            assert_eq!(report.selected, HostBackend::NativeDrm);
        }

        #[test]
        fn developer_native_drm_assumption_requires_override_mode() {
            let assumption_only = |name: &str| {
                (name == "OPENSTREAM_DEVELOPER_ASSUME_NATIVE_DRM").then_some("1".to_string())
            };
            assert!(!native_drm_reachable_with(true, false, assumption_only));

            let explicit_override = |name: &str| match name {
                "OPENSTREAM_DEVELOPER_OVERRIDE" | "OPENSTREAM_DEVELOPER_ASSUME_NATIVE_DRM" => {
                    Some("1".to_string())
                }
                _ => None,
            };
            assert!(native_drm_reachable_with(true, false, explicit_override));
        }

        #[test]
        fn unsupported_platform_rejects_developer_native_drm_assumption() {
            let explicit_override = |name: &str| match name {
                "OPENSTREAM_DEVELOPER_OVERRIDE" | "OPENSTREAM_DEVELOPER_ASSUME_NATIVE_DRM" => {
                    Some("1".to_string())
                }
                _ => None,
            };

            assert!(!native_drm_reachable_with(false, false, explicit_override));
        }
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(error) = unix_main::run().await {
        eprintln!("OpenStream host agent failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("OpenStream host agent requires a Unix local IPC platform");
    std::process::exit(2);
}
