//! Native session-process ownership for the desktop product shell.
//!
//! The WebView is a control surface only. This module starts the existing
//! latency-sensitive session runner as a separate native process, passes it a
//! protected pairing-file path rather than bearer material, and observes a
//! small secret-free status file written by the runner. Video, audio and
//! input never cross Tauri IPC.

use openstream_client_core::{load_pairing_from_file, Pairing, Role, RoleCredential};
use openstream_platform::process_containment::{self, Containment};
use openstream_settings::AppConfig;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};

const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STATUS_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionProcessState {
    Idle,
    Starting,
    Running,
    Connected,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHealth {
    pub state: SessionProcessState,
    pub pid: Option<u32>,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub generation: Option<u64>,
    pub last_exit_code: Option<i32>,
    pub status_age_ms: Option<u64>,
    /// Whether something from the last session is still being cleaned up.
    ///
    /// Separate from `state` because `Failed` alone cannot distinguish "the
    /// runner exited badly" from "the runner is gone but its children are
    /// not". Only the second one means the next connect will fail.
    pub cleanup_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    PairingUnavailable,
    PairingInsecure,
    RunnerUnavailable,
    AlreadyActive,
    CleanupPending,
    SpawnFailed,
    StopFailed,
    StatusInvalid,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PairingUnavailable => "session pairing is unavailable",
            Self::PairingInsecure => "session pairing file is not private",
            Self::RunnerUnavailable => "session runner is unavailable",
            Self::AlreadyActive => "a session is already active",
            Self::CleanupPending => "the previous session has processes that are still running",
            Self::SpawnFailed => "session runner could not be started",
            Self::StopFailed => "session runner could not be stopped",
            Self::StatusInvalid => "session runner status is invalid",
        })
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug, Deserialize)]
struct RunnerStatus {
    state: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    generation: Option<u64>,
}

/// What has to be proven gone before a session is over.
///
/// Held separately from the [`Child`], because the two have different
/// lifetimes and conflating them is what lets an orphan survive a "stopped"
/// session. `wait` reaps the runner and the handle is then worthless, but the
/// runner is only the group leader -- the FFmpeg process it spawned is still
/// holding the pairing file and the UDP port. The cleanup target outlives the
/// handle and is cleared only once the group is observably empty.
///
/// Windows has no process groups. The equivalent container is a Job Object
/// with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, which terminates the whole
/// associated tree when the last handle closes; that belongs here as a
/// `Job(OwnedHandle)` variant when it is implemented. Until then
/// [`sweep_process_group`] is a documented no-op off Unix, so this type names
/// the seam rather than pretending the platform difference does not exist.
#[derive(Debug, Clone)]
enum CleanupTarget {
    /// Whatever this platform uses to hold a session's process tree: a
    /// process group on Unix, a job object on Windows.
    ///
    /// `Arc` because the supervisor clones the target to sweep it without
    /// holding a borrow across an await, and a Windows job is an owned handle
    /// that must not be duplicated -- closing one copy early would terminate
    /// the tree, since the job is created with `KILL_ON_JOB_CLOSE`.
    Contained(std::sync::Arc<Containment>),
    /// Test-only: a target whose drain outcome the test decides.
    ///
    /// The supervisor's retry contract cannot be tested deterministically
    /// against real processes. Provoking a failed drain means racing a
    /// `SIGKILL`: the test has to observe the group *before* the kernel
    /// reaps it, and whether it wins depends on scheduling. That is how the
    /// first version of these tests passed here and failed in CI.
    ///
    /// So the state machine is tested against a target that fails on demand,
    /// and the sweep itself is tested separately against real process groups
    /// where the assertions are about draining rather than about timing.
    #[cfg(test)]
    Controlled(std::sync::Arc<std::sync::atomic::AtomicBool>),
}

impl CleanupTarget {
    async fn sweep(&self, grace: Duration, drain: Duration) -> Result<(), SessionError> {
        match self {
            Self::Contained(containment) => sweep_containment(containment, grace, drain).await,
            #[cfg(test)]
            Self::Controlled(drains) => {
                if drains.load(std::sync::atomic::Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(SessionError::StopFailed)
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct SessionSupervisor {
    child: Option<Child>,
    /// Set at spawn, cleared only when the session's processes are proven
    /// gone. While this is `Some`, the supervisor is not idle whatever else
    /// it knows.
    cleanup: Option<CleanupTarget>,
    device_id: Option<String>,
    session_id: Option<String>,
    generation: Option<u64>,
    status_file: PathBuf,
    /// Where a broker credential is written for the runner to read.
    ///
    /// Inside the supervisor's private runtime directory, which is already
    /// 0700 and owner-checked, so the capability never sits anywhere another
    /// user could reach it.
    credential_file: PathBuf,
    /// Whether this supervisor wrote the pairing file it handed the runner,
    /// and must therefore remove it when the session ends.
    ///
    /// A developer pairing file belongs to whoever launched the shell and
    /// must survive; a broker credential is this supervisor's to clean up.
    owns_pairing_file: bool,
    state: SessionProcessState,
    /// What to settle to once cleanup completes, when the runner exited by
    /// itself rather than being asked to stop. Retained across retries so a
    /// later poll settles to the same verdict the exit deserved.
    exit_state: SessionProcessState,
    last_exit_code: Option<i32>,
    /// Escalation budgets, as fields so a test can force the drain to fail
    /// without needing a process that survives SIGKILL.
    sweep_grace: Duration,
    drain_timeout: Duration,
}

impl SessionSupervisor {
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Result<Self, SessionError> {
        let runtime_dir = runtime_dir.into();
        ensure_private_runtime_dir(&runtime_dir)?;
        Ok(Self {
            child: None,
            cleanup: None,
            device_id: None,
            session_id: None,
            generation: None,
            status_file: runtime_dir.join("session-status.json"),
            credential_file: runtime_dir.join("session-credential.json"),
            owns_pairing_file: false,
            state: SessionProcessState::Idle,
            exit_state: SessionProcessState::Idle,
            last_exit_code: None,
            sweep_grace: GROUP_SWEEP_GRACE,
            drain_timeout: GROUP_DRAIN_TIMEOUT,
        })
    }

    pub async fn connect(
        &mut self,
        settings: &AppConfig,
        device_id: impl Into<String>,
    ) -> Result<SessionHealth, SessionError> {
        self.poll().await?;
        if self.child.is_some() {
            return Err(SessionError::AlreadyActive);
        }
        // A previous session whose processes are still running owns the
        // pairing file and the UDP port. Starting a second runner on top of
        // it produces a failure that looks like anything but this, so it is
        // refused by name instead.
        if self.cleanup.is_some() {
            return Err(SessionError::CleanupPending);
        }
        let pairing_path = env::var_os("OPENSTREAM_PAIRING_FILE")
            .map(PathBuf::from)
            .ok_or(SessionError::PairingUnavailable)?;
        validate_pairing_path(&pairing_path)?;
        let pairing =
            load_pairing_from_file(&pairing_path).map_err(|_| SessionError::PairingInsecure)?;
        self.launch(
            settings,
            device_id,
            &pairing_path,
            pairing.session_id,
            false,
        )
        .await
    }

    /// Start a session from a capability the Connect broker granted.
    ///
    /// This is the product path. The credential names one role and carries
    /// one token, so the file written here cannot be used to act as the host
    /// of its own session -- which the environment pairing file, carrying
    /// both, always could.
    pub async fn connect_with_credential(
        &mut self,
        settings: &AppConfig,
        device_id: impl Into<String>,
        credential: RoleCredential,
    ) -> Result<SessionHealth, SessionError> {
        self.poll().await?;
        if self.child.is_some() {
            return Err(SessionError::AlreadyActive);
        }
        if self.cleanup.is_some() {
            return Err(SessionError::CleanupPending);
        }
        let pairing = Pairing::from_role_credential(credential);
        // This supervisor runs the client end. A host credential here would
        // be a routing mistake somewhere above, and starting the client
        // runner with it would fail later and less legibly.
        if !pairing.can_act_as(Role::Client) {
            return Err(SessionError::PairingInsecure);
        }
        let session_id = pairing.session_id.clone();
        let path = self.credential_file.clone();
        write_private_json(&path, &pairing)?;
        let started = self
            .launch(settings, device_id, &path, session_id, true)
            .await;
        if started.is_err() {
            // Nothing is going to read it now, and a capability left on disk
            // after a failed start is a capability nobody is watching.
            let _ = std::fs::remove_file(&path);
        }
        started
    }

    /// Spawn the runner against a pairing file that is already on disk.
    ///
    /// Shared by the developer path, which is handed a file by its launcher,
    /// and the product path, which writes one from a broker credential. The
    /// two differ only in who owns the file afterwards.
    async fn launch(
        &mut self,
        settings: &AppConfig,
        device_id: impl Into<String>,
        pairing_path: &Path,
        session_id: String,
        owns_pairing_file: bool,
    ) -> Result<SessionHealth, SessionError> {
        let runner = env::var_os("OPENSTREAM_SESSION_RUNNER")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("openstream-desktop-client"));
        if runner.as_os_str().is_empty() {
            return Err(SessionError::RunnerUnavailable);
        }
        let effective = settings.effective();
        let bind = effective
            .network
            .client_port
            .or(effective.network.udp_port)
            .map_or_else(|| "0.0.0.0:0".to_string(), |port| format!("0.0.0.0:{port}"));
        let mut command = Command::new(runner);
        command
            .env_remove("OPENSTREAM_PAIRING_JSON")
            .env_remove("OPENSTREAM_IDENTITY_KEY")
            .env("OPENSTREAM_PAIRING_FILE", pairing_path)
            .env("OPENSTREAM_SIGNAL_ORIGIN", &effective.client.signal_origin)
            .env("OPENSTREAM_UDP_BIND", bind)
            .env("OPENSTREAM_SESSION_STATUS_FILE", &self.status_file)
            .env("OPENSTREAM_RENDERER", mode_text(&effective.client.renderer))
            .env("OPENSTREAM_DECODER", mode_text(&effective.client.decoder))
            .env("OPENSTREAM_VIDEO_CODEC", mode_text(&effective.video.codec))
            .env(
                "OPENSTREAM_PIXEL_FORMAT",
                mode_text(&effective.video.pixel_format),
            )
            .env("OPENSTREAM_WIDTH", effective.video.width.to_string())
            .env("OPENSTREAM_HEIGHT", effective.video.height.to_string())
            .env("OPENSTREAM_FPS", effective.video.fps.to_string())
            .env(
                "OPENSTREAM_VIDEO_MBPS",
                format!("{:.6}", effective.video.bitrate_mbps),
            )
            .env(
                "OPENSTREAM_VIDEO_MIN_MBPS",
                format!("{:.6}", effective.video.min_bitrate_mbps),
            )
            .env(
                "OPENSTREAM_WINDOW_MODE",
                mode_text(&effective.client.window_mode),
            )
            .env("OPENSTREAM_VSYNC", mode_text(&effective.client.vsync))
            .env(
                "OPENSTREAM_IMMERSIVE",
                if effective.client.immersive { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_OVERLAY",
                if effective.client.overlay { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_AUDIO",
                if effective.audio.enabled { "1" } else { "0" },
            )
            .env("OPENSTREAM_AUDIO_CODEC", mode_text(&effective.audio.codec))
            .env(
                "OPENSTREAM_AUDIO_BITRATE_KBPS",
                effective.audio.bitrate_kbps.to_string(),
            )
            .env(
                "OPENSTREAM_AUDIO_LATENCY",
                mode_text(&effective.audio.latency_mode),
            )
            .env(
                "OPENSTREAM_ENABLE_INPUT",
                if effective.input.enabled { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_ENABLE_KEYBOARD",
                if effective.input.enabled && effective.input.keyboard {
                    "1"
                } else {
                    "0"
                },
            )
            .env(
                "OPENSTREAM_ENABLE_MOUSE",
                if effective.input.enabled && effective.input.mouse {
                    "1"
                } else {
                    "0"
                },
            )
            .env(
                "OPENSTREAM_ICE",
                if effective.network.ice { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_TURN",
                if effective.network.turn { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_FORCE_RELAY",
                if effective.network.force_relay {
                    "1"
                } else {
                    "0"
                },
            )
            .env(
                "OPENSTREAM_UPNP",
                if effective.network.upnp { "1" } else { "0" },
            )
            .env(
                "OPENSTREAM_CONGESTION",
                mode_text(&effective.network.congestion),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // Whatever this platform needs before the child exists: a new process
        // group on Unix, a suspended start on Windows so the runner cannot
        // spawn FFmpeg before it has been put in its job.
        //
        // No `cfg` here on purpose. This shell is built for Windows nowhere --
        // not on a developer machine, not in CI -- so a platform branch
        // written here would be verified by nothing. It lives in
        // `openstream-platform`, which the target matrix compiles for both
        // Windows targets.
        process_containment::prepare_command(command.as_std_mut());
        let prepared = Containment::prepare().map_err(|_| SessionError::SpawnFailed)?;
        // Remove a status left by a previous runner before spawning the new
        // one. Removing it after spawn creates a race in which a fast runner
        // writes `starting` and the supervisor immediately deletes the only
        // proof that it exists.
        let _ = std::fs::remove_file(&self.status_file);
        let child = command.spawn().map_err(|_| SessionError::SpawnFailed)?;
        // Bound now, while the pid is certainly live. Taking it later -- after
        // `wait` has reaped the leader -- is how the container gets lost
        // precisely in the case where it is still needed.
        //
        // No platform branch here on purpose: `prepare` returns the job that
        // Windows must create beforehand and nothing on Unix, and `bind` does
        // whichever of "assign into the job" or "name the group" applies.
        // Putting that difference in the caller is how one platform ends up
        // uncontained without anybody noticing.
        // Contain, then start. On Windows the child is suspended until this
        // succeeds, so it cannot spawn anything outside its job; on Unix it
        // is already in its own group and `resume` is a no-op.
        //
        // An uncontained session is the leak this exists to stop and would
        // only be discovered when the next connect failed, so a failure here
        // kills the child rather than running it loose. While it is still
        // suspended, killing the runner and killing the tree are the same
        // thing.
        let contained = child
            .id()
            .ok_or(SessionError::SpawnFailed)
            .and_then(|pid| Containment::bind(prepared, pid).map_err(|_| SessionError::SpawnFailed))
            .and_then(|containment| {
                containment
                    .resume()
                    .map(|()| containment)
                    .map_err(|_| SessionError::SpawnFailed)
            });
        let containment = match contained {
            Ok(containment) => containment,
            Err(error) => {
                let mut child = child;
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        self.cleanup = Some(CleanupTarget::Contained(std::sync::Arc::new(containment)));
        self.child = Some(child);
        self.owns_pairing_file = owns_pairing_file;
        self.device_id = Some(device_id.into());
        self.session_id = Some(session_id);
        self.generation = None;
        self.state = SessionProcessState::Starting;
        self.exit_state = SessionProcessState::Idle;
        self.last_exit_code = None;
        Ok(self.health())
    }

    pub async fn disconnect(&mut self) -> Result<SessionHealth, SessionError> {
        if self.child.is_none() {
            // No runner is not the same as nothing left to do. A previous
            // stop can have reaped the leader and then failed to drain its
            // group, and the whole point of keeping the cleanup target is
            // that this call retries it rather than declaring victory.
            self.state = SessionProcessState::Stopping;
            return self.settle(SessionProcessState::Idle).await;
        }
        self.state = SessionProcessState::Stopping;
        let mut child = self.child.take().ok_or(SessionError::StopFailed)?;
        // Ask first, and mean it. The runner's own shutdown path is what
        // sends `openstream/end` and releases every key and button it is
        // holding on the host; killing it outright leaves that state for the
        // host's watchdog to clean up, which is a visible stuck modifier on
        // the remote desktop in the meantime. So the graceful signal gets the
        // full `STOP_TIMEOUT` before anything escalates.
        //
        // On a platform with no graceful group signal -- Windows -- this is
        // refused and the wait below simply times out into the forced stop,
        // which is the only mechanism available there.
        if let Some(CleanupTarget::Contained(containment)) = self.cleanup.as_ref() {
            let _ = containment.terminate(false);
        }
        let status = match tokio::time::timeout(STOP_TIMEOUT, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => return Err(SessionError::StopFailed),
            Err(_) => {
                // It ignored the request or is wedged. Take the whole tree
                // with it: the runner owns an FFmpeg child of its own, and a
                // decoder left holding the pairing file and a UDP socket is
                // exactly what makes the next connect fail.
                if let Some(CleanupTarget::Contained(containment)) = self.cleanup.as_ref() {
                    let _ = containment.terminate(true);
                }
                let _ = child.kill().await;
                child.wait().await.map_err(|_| SessionError::StopFailed)?
            }
        };
        // The runner having exited is not the same as the session having
        // stopped. It spawns FFmpeg, and a descendant that ignores SIGTERM
        // outlives a parent that handled it -- so waiting on the parent alone
        // reports a clean shutdown while a decoder still holds the pairing
        // file and the UDP port, and the next connect fails for reasons that
        // look nothing like this one. Sweep the group before declaring the
        // session stopped.
        self.last_exit_code = status.code();
        self.settle(SessionProcessState::Idle).await
    }

    /// Prove the session's processes are gone, and only then report `Idle`.
    ///
    /// Every path that ends a session goes through here, so there is one
    /// answer to "is it actually over" rather than one per caller. On failure
    /// the cleanup target and the session's identity are both kept: the
    /// operator needs to see *which* session will not stop, and the next
    /// `poll` or `disconnect` needs something to retry with.
    ///
    /// `settled` is the state to adopt once the session really is over. An
    /// explicit stop settles to `Idle`; a runner that exited by itself
    /// settles to whatever its exit status deserves.
    async fn settle(
        &mut self,
        settled: SessionProcessState,
    ) -> Result<SessionHealth, SessionError> {
        if let Some(target) = self.cleanup.clone() {
            if let Err(error) = target.sweep(self.sweep_grace, self.drain_timeout).await {
                self.state = SessionProcessState::Failed;
                return Err(error);
            }
            self.cleanup = None;
        }
        self.device_id = None;
        self.session_id = None;
        self.generation = None;
        self.state = settled;
        let _ = std::fs::remove_file(&self.status_file);
        if self.owns_pairing_file {
            // The capability outlives its session by exactly as long as this
            // file does, so it goes when the session does.
            let _ = std::fs::remove_file(&self.credential_file);
            self.owns_pairing_file = false;
        }
        Ok(self.health())
    }

    pub async fn poll(&mut self) -> Result<SessionHealth, SessionError> {
        let mut just_exited = false;
        if let Some(child) = self.child.as_mut() {
            if let Some(status) = child.try_wait().map_err(|_| SessionError::StatusInvalid)? {
                self.last_exit_code = status.code();
                self.child = None;
                // The leader exiting on its own is the case most likely to
                // leave orphans, because nothing asked its children to stop
                // first.
                self.exit_state = if status.success() {
                    SessionProcessState::Idle
                } else {
                    SessionProcessState::Failed
                };
                just_exited = true;
            }
        }
        // The same settle path `disconnect` uses, and on every poll rather
        // than only the one where the runner exited. A sweep that failed
        // leaves the target in place precisely so it can be retried, and a
        // supervisor whose only retry is an explicit disconnect does not
        // retry at all in the case that matters -- a background poll loop
        // watching a session nobody is looking at.
        //
        // The cost is paid only while something is genuinely still running:
        // the sweep's first act is a signal-0 probe, and an empty group
        // returns immediately.
        if self.child.is_none() && (just_exited || self.cleanup.is_some()) {
            // The error is deliberately not raised. `poll` reports health,
            // and a failed sweep has already recorded itself as `Failed`
            // with the cleanup target kept for the next attempt.
            let _ = self.settle(self.exit_state).await;
        }
        if self.child.is_some() {
            if let Some(status) = self.read_status()? {
                if status.session_id.as_deref() == self.session_id.as_deref() {
                    self.generation = status.generation;
                    self.state = match status.state.as_str() {
                        "connected" => SessionProcessState::Connected,
                        "stopped" => SessionProcessState::Failed,
                        "negotiating" | "starting" => SessionProcessState::Running,
                        _ => return Err(SessionError::StatusInvalid),
                    };
                }
            }
        }
        Ok(self.health())
    }

    pub fn health(&self) -> SessionHealth {
        SessionHealth {
            state: self.state,
            pid: self.child.as_ref().and_then(|child| child.id()),
            device_id: self.device_id.clone(),
            session_id: self.session_id.clone(),
            generation: self.generation,
            last_exit_code: self.last_exit_code,
            status_age_ms: self.status_age_ms(),
            cleanup_pending: self.cleanup.is_some(),
        }
    }

    fn read_status(&self) -> Result<Option<RunnerStatus>, SessionError> {
        let link = match std::fs::symlink_metadata(&self.status_file) {
            Ok(link) => link,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SessionError::StatusInvalid),
        };
        if link.file_type().is_symlink() {
            return Err(SessionError::StatusInvalid);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if link.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(SessionError::StatusInvalid);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if link.uid() != unsafe { libc::geteuid() } || link.mode() & 0o077 != 0 {
                return Err(SessionError::StatusInvalid);
            }
        }
        let file = {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            options
                .open(&self.status_file)
                .map_err(|_| SessionError::StatusInvalid)?
        };
        let metadata = file.metadata().map_err(|_| SessionError::StatusInvalid)?;
        if !metadata.is_file() || metadata.len() > MAX_STATUS_BYTES {
            return Err(SessionError::StatusInvalid);
        }
        serde_json::from_reader(file)
            .map(Some)
            .map_err(|_| SessionError::StatusInvalid)
    }

    fn status_age_ms(&self) -> Option<u64> {
        let metadata = std::fs::symlink_metadata(&self.status_file).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return None;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return None;
            }
        }
        metadata
            .modified()
            .ok()?
            .elapsed()
            .ok()
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
    }
}

/// Write JSON to a private file, atomically, readable only by this user.
///
/// A capability on disk. The temporary file is created with 0600 *before*
/// anything is written to it and renamed into place, so the contents are
/// never visible under the final name at wider permissions, and a reader
/// never sees a half-written credential.
fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), SessionError> {
    let parent = path.parent().ok_or(SessionError::PairingInsecure)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(SessionError::PairingInsecure)?,
        std::process::id()
    ));
    let encoded = serde_json::to_vec(value).map_err(|_| SessionError::PairingInsecure)?;
    let write = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        use std::io::Write;
        file.write_all(&encoded)?;
        file.sync_all()
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(SessionError::PairingInsecure);
    }
    std::fs::rename(&temporary, path).map_err(|_| {
        let _ = std::fs::remove_file(&temporary);
        SessionError::PairingInsecure
    })
}

fn ensure_private_runtime_dir(path: &Path) -> Result<(), SessionError> {
    if path.exists() {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| SessionError::RunnerUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SessionError::RunnerUnavailable);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(SessionError::RunnerUnavailable);
            }
        }
    } else {
        std::fs::create_dir_all(path).map_err(|_| SessionError::RunnerUnavailable)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SessionError::RunnerUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SessionError::RunnerUnavailable);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SessionError::RunnerUnavailable);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(SessionError::RunnerUnavailable);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SessionError::RunnerUnavailable)?;
    }
    Ok(())
}

fn mode_text<T: Serialize>(mode: &T) -> String {
    serde_json::to_value(mode)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "auto".to_string())
}

fn validate_pairing_path(path: &Path) -> Result<(), SessionError> {
    if !path.is_absolute() {
        return Err(SessionError::PairingInsecure);
    }
    let link = std::fs::symlink_metadata(path).map_err(|_| SessionError::PairingUnavailable)?;
    if link.file_type().is_symlink() {
        return Err(SessionError::PairingInsecure);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if link.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SessionError::PairingInsecure);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if link.uid() != unsafe { libc::geteuid() } || link.mode() & 0o077 != 0 {
            return Err(SessionError::PairingInsecure);
        }
    }
    Ok(())
}

/// How long a descendant gets between the container's polite stop and its
/// forced one.
///
/// Short on purpose: the tree has already had the full [`STOP_TIMEOUT`] to
/// respond to the first request by the time this runs. This is the grace for
/// a process that only started shutting down when its parent went away.
const GROUP_SWEEP_GRACE: Duration = Duration::from_millis(500);

/// How long to wait for a terminated tree to actually disappear.
///
/// A forced termination is not catchable, so this is only scheduling and
/// reaping latency. It is bounded because "wait until it is gone" must not
/// become "wait forever" when something is unkillable -- a process stuck in
/// uninterruptible I/O, or one this user may signal but not reap.
const GROUP_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Make sure nothing is left running in the session's container.
///
/// Returns only once the container is observably empty. Returning after
/// merely *asking* would be reporting an intention rather than a result: the
/// caller marks the session idle and deletes its state on the strength of
/// this, so it has to be a fact by then.
///
/// `Err` means the tree could not be proven empty within
/// [`GROUP_DRAIN_TIMEOUT`]. The caller must not claim a clean shutdown in
/// that case -- something is still holding the pairing file and the UDP port,
/// and saying otherwise makes the next connect fail for reasons that look
/// nothing like this one.
///
/// There is a narrow pid-reuse hazard on Unix worth stating rather than
/// hiding: the group id is the exited runner's pid, so between its reaping
/// and the probe below the operating system could in principle recycle that
/// pid as a new group leader. The window is microseconds and requires the
/// recycled process to become a group leader; against that, skipping the
/// sweep leaves an orphaned decoder every time a descendant ignores a polite
/// stop, which is a certainty rather than a race. Windows job objects have no
/// equivalent hazard: the handle names the job directly.
async fn sweep_containment(
    containment: &Containment,
    grace: Duration,
    drain: Duration,
) -> Result<(), SessionError> {
    if containment.is_empty() {
        return Ok(());
    }
    // Something is still there. Ask it to leave, then insist.
    let _ = containment.terminate(false);
    if drain_containment(containment, grace).await {
        return Ok(());
    }
    let _ = containment.terminate(true);
    if drain_containment(containment, drain).await {
        return Ok(());
    }
    Err(SessionError::StopFailed)
}

/// Poll until the container is empty or `budget` elapses. Reports whether it
/// actually drained.
async fn drain_containment(containment: &Containment, budget: Duration) -> bool {
    const POLL: Duration = Duration::from_millis(20);
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if containment.is_empty() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        sweep_containment, write_private_json, CleanupTarget, Containment, Pairing, Role,
        RoleCredential, SessionError, SessionProcessState, SessionSupervisor, GROUP_DRAIN_TIMEOUT,
        GROUP_SWEEP_GRACE,
    };
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// A private runtime directory that removes itself.
    ///
    /// The suffix is a counter rather than a clock reading: these tests run
    /// concurrently and each one deletes its own directory, so two of them
    /// sharing a name means one removes the other's status file mid-run.
    struct RuntimeDir(std::path::PathBuf);

    impl Drop for RuntimeDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Whether anything is still running in `group`.
    ///
    /// The supervisor no longer owns this check -- it belongs to the shared
    /// containment primitive -- but the process tests still need it to assert
    /// that a sweep did something.
    fn group_has_members(group: i32) -> bool {
        u32::try_from(group)
            .ok()
            .and_then(|pid| Containment::adopt(pid).ok())
            .is_some_and(|containment| !containment.is_empty())
    }

    fn supervisor() -> (SessionSupervisor, RuntimeDir) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "openstream-session-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let supervisor = SessionSupervisor::new(&path).expect("supervisor");
        (supervisor, RuntimeDir(path))
    }

    /// A runner that exits immediately while leaving a descendant that
    /// ignores SIGTERM, all inside one process group.
    ///
    /// This is the shape that matters: waiting on the runner alone returns
    /// almost at once and reports a clean exit, while the descendant keeps
    /// the session's resources. `sh` is used rather than a fixture binary so
    /// the test needs nothing built.
    fn spawn_group_with_stubborn_descendant() -> (std::process::Child, i32) {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sh -c 'trap \"\" TERM; while :; do sleep 1; done' & exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(0);
        let child = command.spawn().expect("spawn session group");
        let group = i32::try_from(child.id()).expect("group id");
        (child, group)
    }

    #[tokio::test]
    async fn a_descendant_that_ignores_sigterm_does_not_outlive_the_session() {
        let (mut child, group) = spawn_group_with_stubborn_descendant();

        // The runner exits on its own, promptly. This is the observation that
        // used to be mistaken for the session having stopped.
        let status = child.wait().expect("runner exits");
        assert!(status.success(), "the runner exits cleanly by itself");

        // Wait for the descendant to be scheduled and install its trap.
        assert!(
            await_group_members(group).await,
            "the descendant should still be running; the test cannot prove \
             anything if the group is already empty"
        );

        sweep_containment(
            &Containment::adopt(u32::try_from(group).expect("group id")).expect("containment"),
            GROUP_SWEEP_GRACE,
            GROUP_DRAIN_TIMEOUT,
        )
        .await
        .expect("the sweep proves the group drained");

        // Asserted immediately, with no polling of its own. The sweep is what
        // the caller relies on before reporting a stopped session, so it has
        // to return a fact rather than an intention -- a test that waits after
        // the call would hide exactly that gap.
        assert!(
            !group_has_members(group),
            "the group must already be empty when the sweep returns"
        );
    }

    /// The two pid values `kill` reserves must never be treated as groups.
    ///
    /// `kill(-1, sig)` signals every process the caller may signal and
    /// `kill(0, sig)` signals the caller's own group, so negating a group id
    /// of 1 or 0 reaches the whole login session rather than one runner. This
    /// asserts the guard by inspection only -- deliberately never calling the
    /// sweep with those values, because a test that got it wrong would take
    /// the machine with it.
    #[test]
    fn wildcard_and_self_group_ids_are_never_signallable() {
        // The gate itself is asserted in `openstream_platform`, which owns
        // it. What matters here is that the supervisor cannot construct a
        // containment around one of those values at all.
        assert!(Containment::adopt(0).is_err());
        assert!(
            Containment::adopt(1).is_err(),
            "negating 1 is kill's every-process wildcard, not process group 1"
        );
        assert!(Containment::adopt(2).is_ok());
        assert!(!group_has_members(1));
    }

    /// A group that will not drain must never be reported as a finished
    /// session, and the second attempt must retry rather than forget.
    ///
    /// This is the reported bug in sequence. `disconnect` used to take the
    /// child, and on a failed sweep left nothing behind to retry with -- so
    /// the *next* call saw `child == None`, went straight to `Idle`, and the
    /// orphan kept the pairing file and the UDP port while the UI said the
    /// session had stopped.
    ///
    /// The drain budget is zeroed rather than using a process that survives
    /// SIGKILL, because no such process can be created on purpose. Zero
    /// budget means the sweep sends its signals and then refuses to claim an
    /// outcome it has not observed, which is the same failure the timeout
    /// produces.
    /// The same shape as [`spawn_group_with_stubborn_descendant`], but owned
    /// by Tokio so the supervisor can hold it as its own child.
    fn spawn_supervised_group_with_stubborn_descendant() -> (tokio::process::Child, i32) {
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sh -c 'trap \"\" TERM; while :; do sleep 1; done' & exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.as_std_mut().process_group(0);
        let child = command.spawn().expect("spawn session group");
        let group = i32::try_from(child.id().expect("live pid")).expect("group id");
        (child, group)
    }

    /// Wait until the group actually has members, or give up.
    ///
    /// A fixed sleep is a guess about how fast the machine is. These tests
    /// need the descendant to be running before they assert anything, and a
    /// loaded CI runner can take longer to get there than any constant a test
    /// author would pick -- while a fast one makes the wait pure delay.
    async fn await_group_members(group: i32) -> bool {
        for _ in 0..200 {
            if group_has_members(group) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// A cleanup target that will not drain, under the test's control.
    fn controlled() -> (CleanupTarget, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let drains = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            CleanupTarget::Controlled(std::sync::Arc::clone(&drains)),
            drains,
        )
    }

    fn set_drains(flag: &std::sync::atomic::AtomicBool, value: bool) {
        flag.store(value, std::sync::atomic::Ordering::SeqCst);
    }

    /// A group that will not drain is never reported as a finished session,
    /// and the next attempt retries rather than forgetting.
    ///
    /// This is the reported bug in sequence. `disconnect` used to take the
    /// child, and on a failed sweep left nothing behind to retry with -- so
    /// the *next* call saw `child == None`, went straight to `Idle`, and the
    /// orphan kept the pairing file and the UDP port while the UI said the
    /// session had stopped.
    #[tokio::test]
    async fn a_cleanup_that_will_not_drain_is_never_reported_idle() {
        let (mut supervisor, _directory) = supervisor();
        let (target, drains) = controlled();
        supervisor.cleanup = Some(target);
        supervisor.device_id = Some("rig".to_string());
        supervisor.session_id = Some("session-1".to_string());

        let error = supervisor
            .disconnect()
            .await
            .expect_err("a sweep that cannot prove the group is empty must fail");
        assert_eq!(error, SessionError::StopFailed);

        let health = supervisor.health();
        assert_eq!(
            health.state,
            SessionProcessState::Failed,
            "an unfinished cleanup is not an idle supervisor"
        );
        assert!(
            health.cleanup_pending,
            "the cleanup target must survive the failure so it can be retried"
        );
        assert_eq!(
            health.session_id.as_deref(),
            Some("session-1"),
            "the operator has to be able to see which session will not stop"
        );

        // A new session must not be started on top of the old one's
        // processes: they still hold the pairing file and the UDP port.
        let settings = openstream_settings::default_config();
        assert_eq!(
            supervisor.connect(&settings, "rig").await.unwrap_err(),
            SessionError::CleanupPending
        );

        // Still refused, and still retried, however many times it is asked.
        assert!(supervisor.disconnect().await.is_err());
        assert!(supervisor.health().cleanup_pending);

        set_drains(&drains, true);
        let health = supervisor
            .disconnect()
            .await
            .expect("the retry proves the group drained");
        assert_eq!(health.state, SessionProcessState::Idle);
        assert!(!health.cleanup_pending);
        assert_eq!(health.session_id, None);
    }

    /// A failed sweep must be retried by polling, not only by disconnect.
    ///
    /// The invariant held before this -- `Idle` was never reported and a new
    /// session was refused -- but the only thing that could actually retry
    /// was an explicit `disconnect`. A background poll loop watching a
    /// session nobody is looking at would never recover, which is the case
    /// where recovery matters most.
    #[tokio::test]
    async fn polling_retries_a_cleanup_that_failed() {
        let (mut supervisor, _directory) = supervisor();
        let (target, drains) = controlled();
        supervisor.cleanup = Some(target);
        supervisor.session_id = Some("session-3".to_string());
        supervisor.state = SessionProcessState::Running;

        let health = supervisor.poll().await.expect("poll reports health");
        assert_eq!(
            health.state,
            SessionProcessState::Failed,
            "an unfinished cleanup is not a finished session"
        );
        assert!(health.cleanup_pending);
        assert_eq!(health.session_id.as_deref(), Some("session-3"));

        // Polling again -- with no disconnect in between -- must retry.
        set_drains(&drains, true);
        let health = supervisor.poll().await.expect("poll retries the sweep");
        assert_eq!(health.state, SessionProcessState::Idle);
        assert!(!health.cleanup_pending);
        assert_eq!(health.session_id, None);
    }

    /// A runner that exits badly settles to `Failed`, and stays there across
    /// a retry rather than being upgraded to `Idle` by the retry itself.
    #[tokio::test]
    async fn an_unclean_exit_settles_to_failed_even_after_a_retry() {
        let (mut supervisor, _directory) = supervisor();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exit 3")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().expect("spawn runner");
        child.wait().await.expect("runner exits");

        let (target, drains) = controlled();
        supervisor.child = Some(child);
        supervisor.cleanup = Some(target);
        supervisor.state = SessionProcessState::Running;
        assert_eq!(
            supervisor.poll().await.expect("poll").state,
            SessionProcessState::Failed
        );
        assert!(supervisor.health().cleanup_pending);

        set_drains(&drains, true);
        let health = supervisor.poll().await.expect("poll retries");
        assert!(!health.cleanup_pending, "the group drained on the retry");
        assert_eq!(
            health.state,
            SessionProcessState::Failed,
            "the runner exited with status 3; cleaning up after it does not \
             make that a clean session"
        );
        assert_eq!(health.last_exit_code, Some(3));
    }

    fn client_credential(session: &str) -> RoleCredential {
        RoleCredential {
            session_id: session.to_string(),
            role: Role::Client,
            token: "CLIENT-CAPABILITY".to_string(),
            websocket_path: format!("/v1/signal/{session}/client"),
            expires_in_seconds: 60,
            relay_address: None,
            relay_ticket: Some("ticket".to_string()),
            turn: None,
        }
    }

    /// A broker credential is written where only this user can read it.
    ///
    /// It is a bearer capability sitting on a filesystem, so the permissions
    /// are the whole protection. 0600 inside a 0700 runtime directory.
    #[tokio::test]
    async fn a_broker_credential_is_written_privately_and_names_one_role() {
        let (supervisor, _directory) = supervisor();
        let path = supervisor.credential_file.clone();
        let pairing = Pairing::from_role_credential(client_credential("session-1"));
        write_private_json(&path, &pairing).expect("write credential");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "a capability must not be readable by anyone else"
            );
        }

        let loaded = openstream_client_core::load_pairing_from_file(&path)
            .expect("the runner can read it back");
        assert!(loaded.can_act_as(Role::Client));
        assert!(
            !loaded.can_act_as(Role::Host),
            "a client credential on disk must not be usable as the host"
        );
    }

    /// A host credential is refused: this supervisor runs the client end.
    #[tokio::test]
    async fn a_host_credential_is_refused_by_the_client_supervisor() {
        let (mut supervisor, _directory) = supervisor();
        let settings = openstream_settings::default_config();
        let mut credential = client_credential("session-1");
        credential.role = Role::Host;
        assert_eq!(
            supervisor
                .connect_with_credential(&settings, "rig", credential)
                .await
                .unwrap_err(),
            SessionError::PairingInsecure,
            "a host capability here is a routing mistake, not a session"
        );
        assert!(
            !supervisor.credential_file.exists(),
            "and nothing is left on disk"
        );
    }

    /// The credential does not outlive its session.
    #[tokio::test]
    async fn a_written_credential_is_removed_when_the_session_settles() {
        let (mut supervisor, _directory) = supervisor();
        let path = supervisor.credential_file.clone();
        let pairing = Pairing::from_role_credential(client_credential("session-1"));
        write_private_json(&path, &pairing).expect("write credential");
        supervisor.owns_pairing_file = true;
        supervisor.session_id = Some("session-1".to_string());
        assert!(path.exists());

        supervisor.disconnect().await.expect("settle");
        assert!(
            !path.exists(),
            "a capability nobody is watching must not survive its session"
        );
    }

    /// A pairing file the supervisor did not write is left alone.
    ///
    /// The developer flow is handed a file by whoever launched the shell, and
    /// deleting someone else's credential on disconnect would break the next
    /// launch for a reason that looks nothing like this one.
    #[tokio::test]
    async fn a_pairing_file_the_supervisor_does_not_own_survives() {
        let (mut supervisor, _directory) = supervisor();
        let path = supervisor.credential_file.clone();
        let pairing = Pairing::from_role_credential(client_credential("session-1"));
        write_private_json(&path, &pairing).expect("write credential");
        supervisor.owns_pairing_file = false;

        supervisor.disconnect().await.expect("settle");
        assert!(
            path.exists(),
            "someone else's pairing file is not ours to delete"
        );
    }

    /// An idle supervisor with nothing to clean up still reports idle.
    #[tokio::test]
    async fn disconnect_without_a_session_is_idle() {
        let (mut supervisor, _directory) = supervisor();
        let health = supervisor.disconnect().await.expect("nothing to stop");
        assert_eq!(health.state, SessionProcessState::Idle);
        assert!(!health.cleanup_pending);
    }

    /// The runner exiting by itself is the case most likely to leave orphans,
    /// because nothing asked its children to stop first.
    ///
    /// `poll` used to drop the child handle and go straight to a terminal
    /// state, which leaked an FFmpeg process on every runner crash and hid it
    /// behind an `Idle` supervisor.
    #[tokio::test]
    async fn an_unexpected_runner_exit_still_sweeps_its_descendants() {
        let (mut supervisor, _directory) = supervisor();
        let (mut child, group) = spawn_supervised_group_with_stubborn_descendant();
        // Two conditions, both required, and neither guaranteed by a sleep:
        // the runner must have exited by itself (that is the case under
        // test), and its descendant must still be running (or there is
        // nothing for the sweep to prove). `try_wait` remembers the status,
        // so the supervisor's own `poll` still observes the exit.
        let mut exited = false;
        for _ in 0..200 {
            exited = exited || child.try_wait().expect("try_wait").is_some();
            if exited && group_has_members(group) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(exited, "the runner should have exited on its own");
        assert!(
            group_has_members(group),
            "the descendant must be running or this test proves nothing"
        );

        supervisor.child = Some(child);
        supervisor.cleanup = Some(CleanupTarget::Contained(std::sync::Arc::new(
            Containment::adopt(u32::try_from(group).expect("group id")).expect("containment"),
        )));
        supervisor.session_id = Some("session-2".to_string());
        supervisor.state = SessionProcessState::Running;

        let health = supervisor.poll().await.expect("poll observes the exit");
        assert_eq!(
            health.state,
            SessionProcessState::Idle,
            "the runner exited cleanly and its group drained"
        );
        assert!(!health.cleanup_pending);
        assert!(
            !group_has_members(group),
            "poll must sweep the group, not merely forget the child"
        );
    }

    #[tokio::test]
    async fn sweeping_an_empty_group_is_a_no_op() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(0);
        let mut child = command.spawn().expect("spawn short-lived group");
        let group = i32::try_from(child.id()).expect("group id");
        child.wait().expect("child exits");

        // Nothing to signal, and nothing to wait for.
        let started = std::time::Instant::now();
        sweep_containment(
            &Containment::adopt(u32::try_from(group).expect("group id")).expect("containment"),
            GROUP_SWEEP_GRACE,
            GROUP_DRAIN_TIMEOUT,
        )
        .await
        .expect("an empty group sweeps cleanly");
        assert!(
            started.elapsed() < GROUP_SWEEP_GRACE,
            "an empty group must not cost the escalation grace period"
        );
    }
}
