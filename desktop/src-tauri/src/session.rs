//! Native session-process ownership for the desktop product shell.
//!
//! The WebView is a control surface only. This module starts the existing
//! latency-sensitive session runner as a separate native process, passes it a
//! protected pairing-file path rather than bearer material, and observes a
//! small secret-free status file written by the runner. Video, audio and
//! input never cross Tauri IPC.

use openstream_client_core::load_pairing_from_file;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    PairingUnavailable,
    PairingInsecure,
    RunnerUnavailable,
    AlreadyActive,
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

#[derive(Debug)]
pub struct SessionSupervisor {
    child: Option<Child>,
    device_id: Option<String>,
    session_id: Option<String>,
    generation: Option<u64>,
    status_file: PathBuf,
    state: SessionProcessState,
    last_exit_code: Option<i32>,
}

impl SessionSupervisor {
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Result<Self, SessionError> {
        let runtime_dir = runtime_dir.into();
        ensure_private_runtime_dir(&runtime_dir)?;
        Ok(Self {
            child: None,
            device_id: None,
            session_id: None,
            generation: None,
            status_file: runtime_dir.join("session-status.json"),
            state: SessionProcessState::Idle,
            last_exit_code: None,
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
        let pairing_path = env::var_os("OPENSTREAM_PAIRING_FILE")
            .map(PathBuf::from)
            .ok_or(SessionError::PairingUnavailable)?;
        validate_pairing_path(&pairing_path)?;
        let pairing =
            load_pairing_from_file(&pairing_path).map_err(|_| SessionError::PairingInsecure)?;
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
            .env("OPENSTREAM_PAIRING_FILE", &pairing_path)
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
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Keep FFmpeg and any helper it creates in a session-owned
            // process group. The supervisor can therefore release capture,
            // decoder and audio resources together on disconnect.
            command.as_std_mut().process_group(0);
        }
        // Remove a status left by a previous runner before spawning the new
        // one. Removing it after spawn creates a race in which a fast runner
        // writes `starting` and the supervisor immediately deletes the only
        // proof that it exists.
        let _ = std::fs::remove_file(&self.status_file);
        let child = command.spawn().map_err(|_| SessionError::SpawnFailed)?;
        self.child = Some(child);
        self.device_id = Some(device_id.into());
        self.session_id = Some(pairing.session_id);
        self.generation = None;
        self.state = SessionProcessState::Starting;
        self.last_exit_code = None;
        Ok(self.health())
    }

    pub async fn disconnect(&mut self) -> Result<SessionHealth, SessionError> {
        if self.child.is_none() {
            self.state = SessionProcessState::Idle;
            return Ok(self.health());
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
        // On a platform with no graceful process-group signal,
        // `signal_process_group` is a no-op and the wait below simply times
        // out into the kill, which is the only mechanism available there.
        // Remembered before waiting, because the runner is the group leader
        // and its pid is the group id -- and `wait` reaps it.
        let group = child.id().and_then(|pid| i32::try_from(pid).ok());
        signal_process_group(&child, false);
        let status = match tokio::time::timeout(STOP_TIMEOUT, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => return Err(SessionError::StopFailed),
            Err(_) => {
                // It ignored the request or is wedged. Take the group with
                // it: the runner owns an FFmpeg child of its own, and a
                // decoder left holding the pairing file and a UDP socket is
                // exactly what makes the next connect fail.
                signal_process_group(&child, true);
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
        if let Some(group) = group {
            // Something in the session's group outliving SIGKILL means the
            // session is not stopped and must not be reported as idle. The
            // supervisor keeps its identifying state: the operator needs to
            // see which session failed to stop, and a later `poll` or
            // `disconnect` can retry.
            if let Err(error) = sweep_process_group(group).await {
                self.state = SessionProcessState::Failed;
                return Err(error);
            }
        }
        self.device_id = None;
        self.session_id = None;
        self.generation = None;
        self.state = SessionProcessState::Idle;
        let _ = std::fs::remove_file(&self.status_file);
        Ok(self.health())
    }

    pub async fn poll(&mut self) -> Result<SessionHealth, SessionError> {
        if let Some(child) = self.child.as_mut() {
            if let Some(status) = child.try_wait().map_err(|_| SessionError::StatusInvalid)? {
                self.last_exit_code = status.code();
                self.child = None;
                self.state = if status.success() {
                    SessionProcessState::Idle
                } else {
                    SessionProcessState::Failed
                };
                self.device_id = None;
                self.session_id = None;
                self.generation = None;
                let _ = std::fs::remove_file(&self.status_file);
            }
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

/// Whether a group id may be signalled with a negated pid.
///
/// **This is a safety gate, not a validation nicety.** `kill` gives two pid
/// values a meaning that has nothing to do with the number itself:
///
/// ```text
/// kill(-1, sig)   every process the caller may signal
/// kill(0, sig)    the caller's own process group -- including the caller
/// ```
///
/// So negating a group id of 1 does not target "process group 1"; it targets
/// the entire session, the desktop shell, and everything else this user is
/// running. A group id of 0 would kill the supervisor itself. Neither can be
/// a real session runner's group, so both are refused here rather than
/// anywhere a caller might forget.
#[cfg(unix)]
const fn is_signallable_group(group: i32) -> bool {
    group > 1
}

#[cfg(unix)]
fn signal_process_group(child: &Child, force: bool) {
    let Some(pid) = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| is_signallable_group(*pid))
    else {
        return;
    };
    let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
    // SAFETY: `child.id()` is a live positive process id owned by this
    // supervisor, and negating it targets the process group created for the
    // session runner rather than an unrelated process.
    let result = unsafe { libc::kill(-pid, signal) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        // The direct child kill below remains the authoritative fallback. A
        // group that cannot be signalled must not make disconnect hang.
    }
}

#[cfg(not(unix))]
fn signal_process_group(_child: &Child, _force: bool) {}

/// How long a descendant gets between the group's SIGTERM and its SIGKILL.
///
/// Short on purpose: the group has already had the full [`STOP_TIMEOUT`] to
/// respond to the first SIGTERM by the time this runs. This is the grace for
/// a process that only started shutting down when its parent went away.
#[cfg(unix)]
const GROUP_SWEEP_GRACE: Duration = Duration::from_millis(500);

/// How long to wait for a SIGKILLed group to actually disappear.
///
/// SIGKILL is not catchable, so this is only scheduling and reaping latency.
/// It is bounded because "wait until it is gone" must not become "wait
/// forever" when something is unkillable -- a process stuck in uninterruptible
/// I/O, or one this user may signal but not reap.
#[cfg(unix)]
const GROUP_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Make sure nothing is left running in the session's process group.
///
/// Returns only once the group is observably empty. Returning after merely
/// *sending* SIGKILL would be reporting an intention rather than a result: the
/// caller marks the session idle and deletes its state on the strength of
/// this, so it has to be a fact by then.
///
/// `Err` means the group could not be proven empty within
/// [`GROUP_DRAIN_TIMEOUT`]. The caller must not claim a clean shutdown in that
/// case -- something is still holding the pairing file and the UDP port, and
/// saying otherwise makes the next connect fail for reasons that look nothing
/// like this one.
///
/// There is a narrow pid-reuse hazard worth stating rather than hiding: the
/// group id is the exited runner's pid, so between its reaping and the probe
/// below the operating system could in principle recycle that pid as a new
/// group leader. The window is microseconds and requires the recycled process
/// to become a group leader; against that, skipping the sweep leaves an
/// orphaned decoder every time a descendant ignores SIGTERM, which is a
/// certainty rather than a race.
#[cfg(unix)]
async fn sweep_process_group(group: i32) -> Result<(), SessionError> {
    if !is_signallable_group(group) {
        // Not a group this may sweep. See `is_signallable_group`: negating 1
        // or 0 would reach far beyond this session.
        return Ok(());
    }
    if !process_group_has_members(group) {
        return Ok(());
    }
    // Signal 0 above proved something is still there. Ask it to leave, then
    // insist.
    unsafe { libc::kill(-group, libc::SIGTERM) };
    if drain_process_group(group, GROUP_SWEEP_GRACE).await {
        return Ok(());
    }
    unsafe { libc::kill(-group, libc::SIGKILL) };
    if drain_process_group(group, GROUP_DRAIN_TIMEOUT).await {
        return Ok(());
    }
    Err(SessionError::StopFailed)
}

/// Poll until the group is empty or `budget` elapses. Reports whether it
/// actually drained.
#[cfg(unix)]
async fn drain_process_group(group: i32, budget: Duration) -> bool {
    const POLL: Duration = Duration::from_millis(20);
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if !process_group_has_members(group) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Whether any process remains in `group`.
///
/// Signal 0 performs the permission and existence checks without delivering
/// anything, which is exactly the probe wanted here.
#[cfg(unix)]
fn process_group_has_members(group: i32) -> bool {
    if !is_signallable_group(group) {
        return false;
    }
    // SAFETY: signal 0 delivers nothing; it only reports whether the target
    // group exists and is signallable by this process.
    let result = unsafe { libc::kill(-group, 0) };
    if result == 0 {
        return true;
    }
    // ESRCH means the group is empty, which is the outcome wanted. Anything
    // else (EPERM, say) means something is there that cannot be signalled,
    // and reporting it as empty would be the wrong answer.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(not(unix))]
async fn sweep_process_group(_group: i32) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        is_signallable_group, process_group_has_members, sweep_process_group, GROUP_SWEEP_GRACE,
    };
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

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

        // Give the descendant a moment to be scheduled and install its trap.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            process_group_has_members(group),
            "the descendant should still be running; the test cannot prove \
             anything if the group is already empty"
        );

        sweep_process_group(group)
            .await
            .expect("the sweep proves the group drained");

        // Asserted immediately, with no polling of its own. The sweep is what
        // the caller relies on before reporting a stopped session, so it has
        // to return a fact rather than an intention -- a test that waits after
        // the call would hide exactly that gap.
        assert!(
            !process_group_has_members(group),
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
        assert!(!is_signallable_group(-1));
        assert!(!is_signallable_group(0));
        assert!(
            !is_signallable_group(1),
            "negating 1 is kill's every-process wildcard, not process group 1"
        );
        assert!(is_signallable_group(2));
        assert!(!process_group_has_members(1));
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
        sweep_process_group(group)
            .await
            .expect("an empty group sweeps cleanly");
        assert!(
            started.elapsed() < GROUP_SWEEP_GRACE,
            "an empty group must not cost the escalation grace period"
        );
    }
}
