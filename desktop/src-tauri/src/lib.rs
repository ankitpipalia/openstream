use std::sync::{Arc, Mutex};
use std::time::Duration;

use host_agent::{HostAgentBridgeError, HostAgentClient};
use openstream_host_agent::HostHealth;
use openstream_settings::AppConfig;
use runtime::{RuntimeCommand, RuntimeDispatchResult, RuntimeError, RuntimeSnapshot, RuntimeState};
use tauri::Manager;

pub mod host_agent;
pub mod runtime;

/// How often the background reconciler asks the host agent what it is
/// actually doing. The agent supervises its child on its own clock -- it
/// restarts a crashed child, backs off, and eventually gives up, none of
/// which is a reply to anything the shell asked for -- so without a poll
/// the shell's `HostStatus` only ever changes when the operator happens to
/// press a button.
const HOST_HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Serialises every operation that may start or stop the host agent.
///
/// Enable and disable are each individually idempotent at the agent, which
/// is not the same as being safe to interleave. Two overlapping Tauri
/// invocations used to apply their intents under the state mutex, drop it
/// for their respective `.await`s, and then apply their outcomes in
/// whatever order the replies happened to arrive -- so a disable that won
/// the race to `AppModel` could be followed by a start that won the race to
/// the agent, leaving a running host behind a shell that said `Disabled`.
/// Holding this across the whole intent-to-outcome transaction makes the
/// order the agent sees the order the model recorded.
#[derive(Debug, Default)]
pub struct HostLifecycleLock(tokio::sync::Mutex<()>);

/// Runtime state shared between the Tauri commands and the background
/// host-health reconciler.
type SharedRuntime = Arc<Mutex<RuntimeState>>;

/// The lifecycle lock, shared the same way.
type SharedHostLock = Arc<HostLifecycleLock>;

#[tauri::command]
fn runtime_snapshot(
    state: tauri::State<'_, SharedRuntime>,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.snapshot())
}

#[tauri::command]
fn runtime_settings(state: tauri::State<'_, SharedRuntime>) -> Result<AppConfig, RuntimeError> {
    let runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    Ok(runtime.settings().clone())
}

#[tauri::command]
fn runtime_update_settings(
    state: tauri::State<'_, SharedRuntime>,
    settings: AppConfig,
) -> Result<RuntimeSnapshot, RuntimeError> {
    let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
    runtime.update_settings(settings)?;
    Ok(runtime.snapshot())
}

/// The single entry point for every user-intent command, hosting included.
/// `EnableHosting`/`DisableHosting` are not a thin pass-through to
/// `RuntimeState::dispatch`: they must also drive the real host agent, so
/// this command is `async` and delegates to `dispatch_command`, which never
/// holds the state mutex across an `.await`.
#[tauri::command]
async fn runtime_dispatch(
    state: tauri::State<'_, SharedRuntime>,
    host_lock: tauri::State<'_, SharedHostLock>,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    dispatch_command(state.inner(), host_lock.inner(), command).await
}

/// Tauri-independent core of `runtime_dispatch`, so it can be exercised
/// directly in tests without a running Tauri application.
async fn dispatch_command(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    command: RuntimeCommand,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    match command {
        RuntimeCommand::EnableHosting => dispatch_host_lifecycle(state, host_lock, true).await,
        RuntimeCommand::DisableHosting => dispatch_host_lifecycle(state, host_lock, false).await,
        other => {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            runtime.dispatch(other)
        }
    }
}

/// Enable or disable hosting through the one path that may start or stop
/// the real host agent process. Production always targets the process
/// default socket via `HostAgentClient::new`.
async fn dispatch_host_lifecycle(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    enable: bool,
) -> Result<RuntimeDispatchResult, RuntimeError> {
    dispatch_host_lifecycle_with(state, host_lock, enable, HostAgentClient::new).await
}

/// Apply the intent, drop the mutex guard, await the host-agent call built
/// by `client_factory`, then re-lock and apply its real outcome. Each
/// `{ ... }` block below ends -- and its guard drops -- before the
/// `.await` that follows it, so the state mutex is never held across one.
///
/// The whole transaction runs under `host_lock`, so a second enable or
/// disable arriving while this one is in flight waits rather than
/// interleaving its own intent, IPC call, and outcome with this one's.
/// That lock is an async mutex precisely because it *is* held across
/// `.await`; the state mutex is the synchronous one and still is not.
///
/// `client_factory` is `HostAgentClient::new` in production; tests
/// substitute a factory that targets a private, unreachable endpoint
/// instead of the process-default socket, without adding any Tauri command
/// parameter that would let the web UI choose one.
async fn dispatch_host_lifecycle_with<F>(
    state: &Mutex<RuntimeState>,
    host_lock: &HostLifecycleLock,
    enable: bool,
    client_factory: F,
) -> Result<RuntimeDispatchResult, RuntimeError>
where
    F: FnOnce() -> Result<HostAgentClient, HostAgentBridgeError>,
{
    let _serialised = host_lock.0.lock().await;
    let intent = if enable {
        RuntimeCommand::EnableHosting
    } else {
        RuntimeCommand::DisableHosting
    };
    let mut events = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        runtime.dispatch(intent)?.events
    };

    let client = client_factory();
    let outcome = match &client {
        Ok(client) => {
            if enable {
                client.start().await
            } else {
                client.stop().await
            }
        }
        Err(error) => Err(*error),
    };

    let result = {
        let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
        if enable {
            runtime.apply_host_start_outcome(outcome)?
        } else {
            runtime.apply_host_stop_outcome(outcome)?
        }
    };
    events.extend(result.events);

    // An accepted `Start` only means the agent took the request; the child
    // may still be in its startup grace period, or already gone. Ask the
    // agent what actually happened before answering the caller, so the
    // snapshot the shell renders is the agent's state and not an optimistic
    // guess. A health call that fails changes nothing: the model keeps the
    // state the outcome above gave it, and the background reconciler tries
    // again on its own schedule.
    let mut snapshot = result.snapshot;
    if let Ok(client) = &client {
        if let Ok(health) = client.health().await {
            let mut runtime = state.lock().map_err(|_| RuntimeError::StateUnavailable)?;
            if let Ok(reconciled) = runtime.reconcile_host_health(&health) {
                events.extend(reconciled.events);
                snapshot = reconciled.snapshot;
            }
        }
    }

    Ok(RuntimeDispatchResult { snapshot, events })
}

/// Poll the host agent forever, adopting its state into `AppModel`.
///
/// This is the only thing that notices a host that died, restarted, or
/// exhausted its restart budget without anyone pressing a button, and the
/// only thing that tells a freshly opened shell that an agent which was
/// already running is hosting. Every failure here is non-fatal by design:
/// an agent that is not installed, not running, or not reachable simply
/// leaves the model as it is, and the next tick tries again.
///
/// It takes the same lifecycle lock the enable/disable path takes. An
/// operation in flight is a transaction whose intent has been applied and
/// whose result has not; polling in the middle of one would read the agent's
/// pre-request state and helpfully "correct" the model back, so a tick that
/// landed between the intent and the IPC call would flip a just-requested
/// enable to disabled and back again.
async fn reconcile_host_health_forever(state: SharedRuntime, host_lock: SharedHostLock) {
    let mut ticker = tokio::time::interval(HOST_HEALTH_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let _serialised = host_lock.0.lock().await;
        let Ok(client) = HostAgentClient::new() else {
            continue;
        };
        let Ok(health) = client.health().await else {
            continue;
        };
        let Ok(mut runtime) = state.lock() else {
            continue;
        };
        let _ = runtime.reconcile_host_health(&health);
    }
}

// `host_agent_health` takes no frontend-supplied endpoint: the client
// always derives the process-default socket, so the web UI has no way to
// redirect it elsewhere. `host_agent_start`/`host_agent_stop` are
// deliberately not exposed as Tauri commands: `runtime_dispatch`'s
// `EnableHosting`/`DisableHosting`, via `dispatch_host_lifecycle`, is the
// only path from *this shell* that may start or stop the host agent.
//
// That is not the same as the two never disagreeing, and this used to claim
// it was. The agent restarts, backs off, and gives up on its own schedule,
// another shell or an operator with the socket can drive it, and a shell
// that has just opened knows nothing about an agent that was already
// running. `reconcile_host_health_forever` is what keeps them in agreement;
// the agent is authoritative whenever they differ.
#[tauri::command]
async fn host_agent_health() -> Result<HostHealth, HostAgentBridgeError> {
    HostAgentClient::new()?.health().await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .map_err(|_| RuntimeError::SettingsUnavailable)?
                .join("settings.json");
            let runtime: SharedRuntime = Arc::new(Mutex::new(RuntimeState::from_settings_path(
                Some(settings_path),
            )?));
            let host_lock: SharedHostLock = Arc::new(HostLifecycleLock::default());
            app.manage(Arc::clone(&runtime));
            app.manage(Arc::clone(&host_lock));
            // Adopt whatever the agent is already doing, then keep adopting
            // it. A shell that has just opened over a running agent would
            // otherwise report hosting as disabled until someone pressed a
            // button, and a child that crashed after being reported ready
            // would never be reported as anything else.
            tauri::async_runtime::spawn(reconcile_host_health_forever(runtime, host_lock));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            runtime_snapshot,
            runtime_settings,
            runtime_update_settings,
            runtime_dispatch,
            host_agent_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenStream desktop shell");
}

#[cfg(test)]
mod tests {
    use super::{
        dispatch_host_lifecycle_with, HostAgentClient, HostLifecycleLock, RuntimeError,
        RuntimeState,
    };
    use openstream_app_core::HostStatus;
    use openstream_host_agent::{
        AgentIpcCommand, AgentIpcRequest, AgentIpcResponse, ChildState, HostAgentEvent, HostHealth,
        HOST_AGENT_PROTOCOL_VERSION,
    };
    use openstream_local_ipc::{read_frame, write_frame, Endpoint};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::task::JoinHandle;

    /// A socket path nothing is listening on, private to this call.
    fn unreachable_endpoint() -> Endpoint {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf =
            std::env::temp_dir().join(format!("openstream-lib-test-{nanos:x}-{sequence:x}.sock"));
        Endpoint::new(path).expect("valid test endpoint path")
    }

    /// A short, private socket path. Kept well under the AF_UNIX length
    /// limit, which a long default temporary directory can otherwise blow.
    fn short_socket_path() -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("oslb-{nanos:x}-{sequence:x}"))
            .join("s.sock")
    }

    /// A host-agent double that serves many requests, records the order it
    /// saw lifecycle commands in, and reports a programmable child state.
    ///
    /// The recorded order is the point: it is the agent's own view of what
    /// happened, and it is what the shell's `AppModel` has to agree with.
    struct RecordingAgent {
        endpoint: Endpoint,
        seen: Arc<Mutex<Vec<AgentIpcCommand>>>,
        task: JoinHandle<()>,
    }

    impl RecordingAgent {
        /// `state_after` decides the `ChildState` reported to a `Health`
        /// call, given the lifecycle commands seen so far. `start_delay`
        /// is applied while serving a `Start`, which is what lets a test
        /// detect an unserialised `Stop` overtaking it.
        async fn spawn(
            state_after: fn(&[AgentIpcCommand]) -> ChildState,
            start_delay: Duration,
        ) -> Self {
            let endpoint = Endpoint::new(short_socket_path()).expect("valid test endpoint path");
            let listener = endpoint.bind().await.expect("bind test endpoint");
            let seen: Arc<Mutex<Vec<AgentIpcCommand>>> = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&seen);
            // Each connection is served on its own task. A server that
            // handled them one at a time would serialise the client's
            // requests for it, which is exactly the property under test.
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _address)) = listener.accept().await {
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        let request: Option<AgentIpcRequest> =
                            read_frame(&mut stream).await.unwrap_or(None);
                        let Some(request) = request else { return };
                        let response = match request.command {
                            AgentIpcCommand::Health => {
                                let history = recorded.lock().expect("test lock").clone();
                                AgentIpcResponse::Health {
                                    version: HOST_AGENT_PROTOCOL_VERSION,
                                    request_id: request.request_id,
                                    health: HostHealth {
                                        state: state_after(&history),
                                        backend: "test".into(),
                                        pid: None,
                                        restart_count: 0,
                                        next_restart_in_ms: None,
                                        last_exit: None,
                                        last_error: None,
                                    },
                                }
                            }
                            command => {
                                // The delay lands before the command is
                                // recorded, so a `Stop` issued concurrently
                                // with a stalled `Start` overtakes it.
                                if command == AgentIpcCommand::Start && !start_delay.is_zero() {
                                    tokio::time::sleep(start_delay).await;
                                }
                                recorded.lock().expect("test lock").push(command);
                                AgentIpcResponse::Accepted {
                                    version: HOST_AGENT_PROTOCOL_VERSION,
                                    request_id: request.request_id,
                                    events: Vec::new(),
                                }
                            }
                        };
                        let _ = write_frame(&mut stream, &response).await;
                    });
                }
            });
            Self {
                endpoint,
                seen,
                task,
            }
        }

        fn client(&self) -> HostAgentClient {
            HostAgentClient::with_endpoint(self.endpoint.clone())
        }

        fn lifecycle_commands(&self) -> Vec<AgentIpcCommand> {
            self.seen.lock().expect("test lock").clone()
        }
    }

    impl Drop for RecordingAgent {
        fn drop(&mut self) {
            self.task.abort();
            let _ = self.endpoint.cleanup();
        }
    }

    fn shared_state() -> Arc<Mutex<RuntimeState>> {
        Arc::new(Mutex::new(RuntimeState::for_test()))
    }

    /// `EnableHosting` must actually call the real host agent, and a call
    /// that cannot even connect must leave `AppModel` in a typed failed
    /// state -- never the optimistic `Ready` a frontend-driven `HostReady`
    /// command used to be able to fabricate.
    #[tokio::test]
    async fn enable_hosting_reports_a_typed_failure_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();
        let endpoint = unreachable_endpoint();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect("the intent still applies even though the agent call fails");

        assert!(matches!(
            result.snapshot.app.host_status,
            HostStatus::Failed { .. }
        ));
    }

    /// The same path for `DisableHosting` -- a stop call that cannot even
    /// connect is a typed error, not one silently accepted as success.
    #[tokio::test]
    async fn disable_hosting_reports_a_typed_error_when_the_host_agent_is_unreachable() {
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();
        let endpoint = unreachable_endpoint();

        let error = dispatch_host_lifecycle_with(&state, &lock, false, move || {
            Ok(HostAgentClient::with_endpoint(endpoint))
        })
        .await
        .expect_err("a stop call that cannot connect must not be silently accepted");

        assert!(matches!(error, RuntimeError::CommandRejected { .. }));
    }

    /// An accepted `Start` is not a running host.
    ///
    /// The agent accepts the request and reports no events -- exactly what
    /// it does for a child that has only just been spawned, or when it was
    /// already starting -- and its child is still in `Starting`. The shell
    /// used to call that `Ready`, and would then sit on `Ready` while the
    /// child crashed behind it.
    #[tokio::test]
    async fn an_accepted_start_does_not_report_a_host_as_ready() {
        let agent = RecordingAgent::spawn(|_| ChildState::Starting, Duration::ZERO).await;
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, || Ok(agent.client()))
            .await
            .expect("an accepted start is not an error");

        assert_eq!(
            result.snapshot.app.host_status,
            HostStatus::Starting,
            "a spawned-but-not-ready child must not be reported as ready"
        );
    }

    /// ...and once the agent's own child reaches `Ready`, the reconciler
    /// adopts that, so the shell does report a host that really is up.
    #[tokio::test]
    async fn a_host_becomes_ready_when_the_agent_says_its_child_is_ready() {
        let agent = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let state = Mutex::new(RuntimeState::for_test());
        let lock = HostLifecycleLock::default();

        let result = dispatch_host_lifecycle_with(&state, &lock, true, || Ok(agent.client()))
            .await
            .expect("an accepted start is not an error");

        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }

    /// The agent must see lifecycle commands in the order the model
    /// recorded the operator's intents.
    ///
    /// An enable and a disable are issued at once and the agent stalls the
    /// `Start`. Unserialised, each operation applies its intent, drops the
    /// state mutex for its own `.await`, and applies its outcome whenever
    /// its reply happens to arrive -- so the disable, which is not stalled,
    /// reaches the agent first and the model's "enable, then disable"
    /// becomes the agent's "stop, then start": a host left running behind a
    /// shell the operator just told to stop hosting.
    ///
    /// `join!` polls the enable first, so the enable's intent is the one
    /// the model records first, and the agent has to see `Start` first too.
    #[tokio::test]
    async fn concurrent_enable_and_disable_reach_the_agent_in_the_order_intended() {
        let agent = RecordingAgent::spawn(
            |history| match history.last() {
                Some(AgentIpcCommand::Start) => ChildState::Ready,
                _ => ChildState::Stopped,
            },
            Duration::from_millis(150),
        )
        .await;
        let state = shared_state();
        let lock = HostLifecycleLock::default();

        let enable =
            dispatch_host_lifecycle_with(state.as_ref(), &lock, true, || Ok(agent.client()));
        let disable =
            dispatch_host_lifecycle_with(state.as_ref(), &lock, false, || Ok(agent.client()));
        let (enable_result, disable_result) = tokio::join!(enable, disable);
        assert!(enable_result.is_ok(), "the enable transaction completed");
        assert!(disable_result.is_ok(), "the disable transaction completed");

        assert_eq!(
            agent.lifecycle_commands(),
            vec![AgentIpcCommand::Start, AgentIpcCommand::Stop],
            "the agent saw the operations in a different order than the model applied them"
        );

        // The operator's last word was "stop", and that is what stands.
        let status = state.lock().expect("test lock").snapshot().app.host_status;
        assert_eq!(status, HostStatus::Disabled);
    }

    /// A shell that opens over an agent which is already hosting must adopt
    /// that, rather than reporting hosting as disabled until someone
    /// happens to press a button.
    #[tokio::test]
    async fn an_already_hosting_agent_is_adopted_by_a_freshly_started_shell() {
        let agent = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        assert_eq!(state.snapshot().app.host_status, HostStatus::Disabled);

        let health = agent.client().health().await.expect("health call succeeds");
        let result = state
            .reconcile_host_health(&health)
            .expect("adopting a running agent is not an error");

        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }

    /// A child that crashes after being reported ready must stop being
    /// reported as ready. Nothing but the reconciler notices this: the
    /// agent restarts the child on its own, without a request from here.
    #[tokio::test]
    async fn a_child_that_crashes_after_ready_stops_being_reported_as_ready() {
        let ready = RecordingAgent::spawn(|_| ChildState::Ready, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        let health = ready.client().health().await.expect("health call succeeds");
        state.reconcile_host_health(&health).expect("adopt ready");
        assert_eq!(state.snapshot().app.host_status, HostStatus::Ready);

        let restarting = RecordingAgent::spawn(|_| ChildState::Backoff, Duration::ZERO).await;
        let health = restarting
            .client()
            .health()
            .await
            .expect("health call succeeds");
        state.reconcile_host_health(&health).expect("adopt backoff");

        assert_eq!(
            state.snapshot().app.host_status,
            HostStatus::Starting,
            "a child being restarted is not a ready host"
        );
    }

    /// The agent is authoritative about its child, but not about whether
    /// the operator wants to host at all. An agent reporting a terminal
    /// failure must not raise a failure the operator cannot act on when
    /// hosting is simply switched off.
    #[tokio::test]
    async fn an_agent_failure_does_not_disturb_deliberately_disabled_hosting() {
        let agent = RecordingAgent::spawn(|_| ChildState::Failed, Duration::ZERO).await;
        let mut state = RuntimeState::for_test();
        let health = agent.client().health().await.expect("health call succeeds");

        state.reconcile_host_health(&health).expect("reconcile");

        assert_eq!(state.snapshot().app.host_status, HostStatus::Disabled);
    }

    /// `HostAgentEvent::Ready` in the accepted response is itself proof of
    /// readiness and is honoured without waiting for a health poll.
    #[tokio::test]
    async fn an_agent_that_reports_ready_in_its_response_is_believed() {
        let events = vec![
            HostAgentEvent::Started { pid: Some(7) },
            HostAgentEvent::Ready,
        ];
        let mut state = RuntimeState::for_test();
        state
            .dispatch(super::RuntimeCommand::EnableHosting)
            .expect("enable intent applies");
        let result = state
            .apply_host_start_outcome(Ok(events))
            .expect("a ready event is not an error");
        assert_eq!(result.snapshot.app.host_status, HostStatus::Ready);
    }
}
