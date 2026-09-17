//! Service lifecycle, Job Object containment, and graceful shutdown.
//!
//! Status: implemented and CI-validated (the lifecycle state machine, service
//! state codes and shutdown coordinator are unit-tested on every target with
//! mocked commands; the Job Object FFI is compiled for the Windows targets).
//! Physical Windows runtime verification is pending the hardware.
//!
//! A remote-desktop host runs as a Windows service so it survives sign-out and
//! starts at boot. The [`Lifecycle`] state machine models the SCM's
//! start/stop/interrogate protocol without any OS call, so it is testable; the
//! Windows service dispatcher drives it. A [`ShutdownCoordinator`] fans a stop
//! request out to the capture/encode/audio loops for a clean drain. The
//! [`JobObject`] (Windows) ties any helper process the host spawns to the host's
//! own lifetime, so nothing is orphaned if the host dies.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The service's run state, mirroring the SCM's model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

impl ServiceState {
    /// The Windows `SERVICE_STATUS` current-state code for this state.
    #[must_use]
    pub fn win32_code(self) -> u32 {
        match self {
            ServiceState::Stopped => 1,  // SERVICE_STOPPED
            ServiceState::Starting => 2, // SERVICE_START_PENDING
            ServiceState::Stopping => 3, // SERVICE_STOP_PENDING
            ServiceState::Running => 4,  // SERVICE_RUNNING
        }
    }
}

/// A control the service control manager (or a test) delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCommand {
    /// Start the service (from stopped).
    Start,
    /// The worker finished coming up and is serving.
    WorkReady,
    /// Stop or shut down the service.
    Stop,
    /// The worker finished draining and has stopped.
    WorkStopped,
    /// Report the current state.
    Interrogate,
}

/// What the OS glue should do in response to a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAction {
    /// Report `state` to the SCM.
    Report(ServiceState),
    /// Start the host worker (capture/encode/serve).
    StartWorker,
    /// Signal the host worker to drain and stop.
    StopWorker,
}

/// The service lifecycle state machine. Pure: it takes commands and yields the
/// state changes and actions the OS glue performs, so the protocol is testable
/// without a service host.
#[derive(Debug)]
pub struct Lifecycle {
    state: ServiceState,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ServiceState::Stopped,
        }
    }

    #[must_use]
    pub fn state(&self) -> ServiceState {
        self.state
    }

    /// Apply a command, transitioning state and returning the actions to take.
    /// Invalid transitions (a stop while already stopped, work-ready while not
    /// starting) are no-ops, so a duplicated or out-of-order control from the SCM
    /// cannot wedge the machine.
    pub fn apply(&mut self, command: ServiceCommand) -> Vec<LifecycleAction> {
        use LifecycleAction as A;
        use ServiceState as S;
        match (self.state, command) {
            (S::Stopped, ServiceCommand::Start) => {
                self.state = S::Starting;
                vec![A::Report(S::Starting), A::StartWorker]
            }
            (S::Starting, ServiceCommand::WorkReady) => {
                self.state = S::Running;
                vec![A::Report(S::Running)]
            }
            (S::Starting | S::Running, ServiceCommand::Stop) => {
                self.state = S::Stopping;
                vec![A::Report(S::Stopping), A::StopWorker]
            }
            (S::Stopping, ServiceCommand::WorkStopped) => {
                self.state = S::Stopped;
                vec![A::Report(S::Stopped)]
            }
            (_, ServiceCommand::Interrogate) => vec![A::Report(self.state)],
            // Any other pairing is out of order; report the unchanged state so
            // the SCM stays informed but nothing transitions.
            _ => vec![A::Report(self.state)],
        }
    }
}

/// A cloneable stop signal shared by the host's loops. Requesting a stop is
/// one-way; every loop polls [`ShutdownCoordinator::is_stopping`] and drains.
#[derive(Debug, Clone, Default)]
pub struct ShutdownCoordinator {
    stopping: Arc<AtomicBool>,
}

impl ShutdownCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a stop. Idempotent; returns whether this call was the one that
    /// flipped it (so exactly one caller can run teardown).
    pub fn request_stop(&self) -> bool {
        !self.stopping.swap(true, Ordering::SeqCst)
    }

    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

#[cfg(target_os = "windows")]
pub use job::JobObject;

#[cfg(target_os = "windows")]
mod job {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    /// A Job Object that kills every assigned process when it is closed. The host
    /// assigns itself (and thereby its children) so that if the host dies, no
    /// helper process it spawned is left orphaned holding the desktop.
    #[derive(Debug)]
    pub struct JobObject {
        handle: HANDLE,
    }

    impl JobObject {
        /// Create a Job Object with kill-on-close set.
        pub fn new_kill_on_close() -> Result<Self, windows::core::Error> {
            // SAFETY: FFI. CreateJobObjectW yields an owned handle; the limit
            // struct is fully initialised and its size is passed exactly.
            unsafe {
                let handle = CreateJobObjectW(None, None)?;
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let size =
                    u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                        .unwrap_or(0);
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&info).cast(),
                    size,
                )?;
                Ok(Self { handle })
            }
        }

        /// Assign the current process to the job, so it and its children share
        /// the job's kill-on-close lifetime.
        pub fn assign_current_process(&self) -> Result<(), windows::core::Error> {
            // SAFETY: FFI on the owned job handle and the current-process pseudo
            // handle.
            unsafe { AssignProcessToJobObject(self.handle, GetCurrentProcess()) }
        }
    }

    impl Drop for JobObject {
        fn drop(&mut self) {
            // SAFETY: closing the owned job handle; with kill-on-close this also
            // terminates assigned processes.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_state_codes_match_win32() {
        assert_eq!(ServiceState::Stopped.win32_code(), 1);
        assert_eq!(ServiceState::Starting.win32_code(), 2);
        assert_eq!(ServiceState::Stopping.win32_code(), 3);
        assert_eq!(ServiceState::Running.win32_code(), 4);
    }

    #[test]
    fn a_clean_start_to_stop_cycle_drives_the_expected_actions() {
        let mut lifecycle = Lifecycle::new();
        assert_eq!(lifecycle.state(), ServiceState::Stopped);

        assert_eq!(
            lifecycle.apply(ServiceCommand::Start),
            vec![
                LifecycleAction::Report(ServiceState::Starting),
                LifecycleAction::StartWorker
            ]
        );
        assert_eq!(lifecycle.state(), ServiceState::Starting);

        assert_eq!(
            lifecycle.apply(ServiceCommand::WorkReady),
            vec![LifecycleAction::Report(ServiceState::Running)]
        );
        assert_eq!(lifecycle.state(), ServiceState::Running);

        assert_eq!(
            lifecycle.apply(ServiceCommand::Stop),
            vec![
                LifecycleAction::Report(ServiceState::Stopping),
                LifecycleAction::StopWorker
            ]
        );
        assert_eq!(
            lifecycle.apply(ServiceCommand::WorkStopped),
            vec![LifecycleAction::Report(ServiceState::Stopped)]
        );
        assert_eq!(lifecycle.state(), ServiceState::Stopped);
    }

    #[test]
    fn out_of_order_controls_do_not_wedge_the_machine() {
        let mut lifecycle = Lifecycle::new();
        // Stop while already stopped: no transition, just a state report.
        assert_eq!(
            lifecycle.apply(ServiceCommand::Stop),
            vec![LifecycleAction::Report(ServiceState::Stopped)]
        );
        assert_eq!(lifecycle.state(), ServiceState::Stopped);
        // WorkReady before Start: ignored.
        lifecycle.apply(ServiceCommand::WorkReady);
        assert_eq!(lifecycle.state(), ServiceState::Stopped);
        // Interrogate always reports the current state.
        assert_eq!(
            lifecycle.apply(ServiceCommand::Interrogate),
            vec![LifecycleAction::Report(ServiceState::Stopped)]
        );
    }

    #[test]
    fn a_stop_during_startup_is_honoured() {
        let mut lifecycle = Lifecycle::new();
        lifecycle.apply(ServiceCommand::Start);
        // Stop arrives before the worker finished coming up.
        assert_eq!(
            lifecycle.apply(ServiceCommand::Stop),
            vec![
                LifecycleAction::Report(ServiceState::Stopping),
                LifecycleAction::StopWorker
            ]
        );
        assert_eq!(lifecycle.state(), ServiceState::Stopping);
    }

    #[test]
    fn shutdown_coordinator_flips_once_and_fans_out() {
        let coordinator = ShutdownCoordinator::new();
        assert!(!coordinator.is_stopping());
        // A clone sees the same signal.
        let peer = coordinator.clone();
        assert!(coordinator.request_stop());
        assert!(coordinator.is_stopping());
        assert!(peer.is_stopping());
        // A second request is not the flipping one.
        assert!(!peer.request_stop());
    }
}
