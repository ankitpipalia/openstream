//! Holding a session's whole process tree, and proving it is gone.
//!
//! # The problem
//!
//! A session is not one process. The runner spawns FFmpeg, which may spawn
//! more, and stopping "the session" means stopping all of them. Waiting on the
//! runner alone reports a clean shutdown while a decoder still holds the
//! pairing file and the UDP port, so the next connect fails for reasons that
//! look nothing like the real one.
//!
//! The two platforms solve this with unrelated primitives, and the difference
//! is not cosmetic:
//!
//! ```text
//! Unix     process group   the child opts in at spawn (setpgid)
//!                          signalled as a unit with kill(-pgid)
//!                          membership probed with signal 0
//!
//! Windows  job object      the parent creates it first, then assigns
//!                          the child; KILL_ON_JOB_CLOSE means the tree
//!                          dies with the last handle, even if the
//!                          supervisor is killed
//! ```
//!
//! So the lifecycle differs: on Unix the container comes into existence
//! *with* the child, on Windows it must exist *before* it. This module keeps
//! that difference visible rather than hiding it behind one API that would be
//! a lie on one platform or the other.
//!
//! # The Windows ordering hazard
//!
//! On Windows the child is created first and assigned second, and between
//! those two steps it is running. A session runner that reaches its first
//! `CreateProcess` in that gap spawns FFmpeg *outside* the job, and that
//! descendant is then not covered by anything -- so the leak this type exists
//! to stop happens anyway, intermittently, under load.
//!
//! The child is therefore created suspended, assigned, and only then resumed.
//! It cannot run at all, let alone spawn anything, until it is contained. If
//! assignment fails the process is killed while still suspended, which is the
//! only point at which "kill the runner" and "kill the tree" are the same
//! thing.
//!
//! [`prepare_command`] applies whatever each platform needs to the
//! `Command` before it is spawned, so callers need no platform branch of
//! their own -- the Tauri shell that uses this cannot be compiled for Windows
//! on a developer machine or in CI, and a `cfg` there would be verified
//! nowhere.
//!
//! # What this does not do
//!
//! It does not decide policy: how long to wait, when to escalate, whether a
//! failure to drain is fatal. Those belong to the supervisor, which is the
//! only thing that knows what a session is worth. This reports facts.

/// Why a containment operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentError {
    /// The operating system refused the call.
    Os,
    /// The value given is not one this may act on. See
    /// [`is_signallable_group`].
    Unusable,
}

impl core::fmt::Display for ContainmentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Os => "the operating system refused a process-containment call",
            Self::Unusable => "the process-containment target is not one this may act on",
        })
    }
}

impl std::error::Error for ContainmentError {}

/// Whether a group id may be signalled with a negated pid.
///
/// **A safety gate, not a validation nicety.** `kill` gives two pid values a
/// meaning that has nothing to do with the number itself:
///
/// ```text
/// kill(-1, sig)   every process the caller may signal
/// kill(0, sig)    the caller's own process group -- including the caller
/// ```
///
/// So negating a group id of 1 does not target "process group 1"; it targets
/// every process the user is running. A group id of 0 would take out the
/// supervisor itself. Neither can be a real session's group.
#[must_use]
pub const fn is_signallable_group(group: i32) -> bool {
    group > 1
}

#[cfg(unix)]
mod platform {
    use super::{ContainmentError, is_signallable_group};

    /// A Unix process group.
    ///
    /// Created by the child itself at spawn (`setpgid(0, 0)`), so there is
    /// nothing to prepare beforehand and nothing to own afterwards: the group
    /// is named by a number and outlives any handle.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Containment {
        group: i32,
    }

    /// Put the child in its own process group at spawn.
    pub fn prepare_command(command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    impl Containment {
        /// Nothing to create before spawning on Unix.
        pub const fn prepare() -> Result<Option<Self>, ContainmentError> {
            Ok(None)
        }

        /// Nothing to resume: the child was never suspended.
        pub const fn resume(&self) -> Result<(), ContainmentError> {
            Ok(())
        }

        /// Name the group a spawned child leads.
        pub fn adopt(pid: u32) -> Result<Self, ContainmentError> {
            let group = i32::try_from(pid).map_err(|_| ContainmentError::Unusable)?;
            if !is_signallable_group(group) {
                return Err(ContainmentError::Unusable);
            }
            Ok(Self { group })
        }

        /// Ask the group to stop, or insist.
        pub fn terminate(&self, force: bool) -> Result<(), ContainmentError> {
            let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
            // SAFETY: `group` is a positive pid greater than 1, so negating
            // it names this session's process group and nothing else.
            let result = unsafe { libc::kill(-self.group, signal) };
            if result == 0 {
                return Ok(());
            }
            // Already gone is the outcome that was being asked for.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            Err(ContainmentError::Os)
        }

        /// Bind a freshly spawned child to its container.
        ///
        /// On Unix the child put itself in a new group at spawn, so
        /// `prepared` is always `None` and this only names the group.
        pub fn bind(prepared: Option<Self>, pid: u32) -> Result<Self, ContainmentError> {
            debug_assert!(prepared.is_none(), "Unix prepares nothing before spawn");
            let _ = prepared;
            Self::adopt(pid)
        }

        /// Whether every process in the group has exited.
        ///
        /// Signal 0 performs the existence and permission checks without
        /// delivering anything. Anything other than `ESRCH` means something
        /// is there that cannot be signalled, and reporting that as empty
        /// would be the wrong answer.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            // SAFETY: signal 0 delivers nothing.
            let result = unsafe { libc::kill(-self.group, 0) };
            if result == 0 {
                return false;
            }
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::ContainmentError;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, OpenProcess, OpenThread, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        ResumeThread, THREAD_SUSPEND_RESUME,
    };

    /// Create the child suspended, so it cannot spawn anything before it is
    /// contained.
    ///
    /// Without this there is a window between `CreateProcess` and
    /// `AssignProcessToJobObject` in which the runner is running: a
    /// descendant started in that window does not join the job, and the leak
    /// this module exists to stop happens anyway, intermittently.
    pub fn prepare_command(command: &mut std::process::Command) {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_SUSPENDED);
    }

    /// A Windows job object owning a session's process tree.
    ///
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is the point: when the last
    /// handle closes the whole tree is terminated, so a supervisor that is
    /// itself killed does not leak the session. A Unix process group has no
    /// equivalent guarantee -- orphans are reparented and survive -- which is
    /// why the two platforms cannot share one mental model.
    #[derive(Debug)]
    pub struct Containment {
        job: OwnedHandle,
        /// The process assigned into the job, recorded so [`Self::resume`]
        /// knows whose thread to start.
        contained_pid: Option<u32>,
    }

    impl Containment {
        /// Create the job before spawning, because a child cannot join one
        /// itself.
        pub fn prepare() -> Result<Option<Self>, ContainmentError> {
            // SAFETY: both arguments are null, which requests an unnamed job
            // with default security.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(ContainmentError::Os);
            }
            // SAFETY: `handle` is a valid kernel handle this call just
            // created and nothing else owns.
            let job = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };

            // SAFETY: an all-zero limit structure is the documented "no
            // limits" starting point; the flag below is the only one set.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| ContainmentError::Os)?;
            // SAFETY: the pointer and length describe `limits`, which lives
            // for the duration of the call.
            let set = unsafe {
                SetInformationJobObject(
                    job.as_raw_handle().cast(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    size,
                )
            };
            if set == 0 {
                return Err(ContainmentError::Os);
            }
            Ok(Some(Self {
                job,
                contained_pid: None,
            }))
        }

        /// Not how containment is obtained on Windows.
        ///
        /// A pid does not name a job, and a process cannot be placed in one
        /// after the fact by number alone. Present so the two platforms offer
        /// the same surface, and refusing rather than guessing.
        pub const fn adopt(_pid: u32) -> Result<Self, ContainmentError> {
            Err(ContainmentError::Unusable)
        }

        /// Put a spawned process into the job.
        ///
        /// Descendants it creates join automatically unless they explicitly
        /// break out, which is what makes this a tree rather than a list.
        pub fn adopt_process(&self, pid: u32) -> Result<(), ContainmentError> {
            // SAFETY: opening a handle to a pid this process just created.
            let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
            if process.is_null() {
                return Err(ContainmentError::Os);
            }
            // SAFETY: both handles are valid for the duration of the call.
            let assigned =
                unsafe { AssignProcessToJobObject(self.job.as_raw_handle().cast(), process) };
            // SAFETY: closing the handle opened immediately above.
            unsafe { CloseHandle(process) };
            if assigned == 0 {
                return Err(ContainmentError::Os);
            }
            Ok(())
        }

        /// Bind a freshly spawned child to its container.
        ///
        /// On Windows the job had to exist first, so `prepared` carries it
        /// and the child is assigned into it here. A missing job is refused
        /// rather than silently leaving the process uncontained: an
        /// uncontained session is exactly the leak this type exists to stop,
        /// and it would only be discovered when the next connect failed.
        pub fn bind(prepared: Option<Self>, pid: u32) -> Result<Self, ContainmentError> {
            let mut job = prepared.ok_or(ContainmentError::Unusable)?;
            job.adopt_process(pid)?;
            job.contained_pid = Some(pid);
            Ok(job)
        }

        /// Let the contained child start running.
        ///
        /// Called only after assignment has succeeded. A freshly created
        /// suspended process has exactly one thread, so this resumes the one
        /// thread belonging to the job's process. Rust's `Child` does not
        /// expose the initial thread handle, which is why the snapshot is
        /// necessary rather than merely convenient.
        pub fn resume(&self) -> Result<(), ContainmentError> {
            let pid = self.contained_pid.ok_or(ContainmentError::Unusable)?;
            // SAFETY: a thread snapshot over all processes; closed below.
            //
            // The sentinel here is INVALID_HANDLE_VALUE, not null --
            // `CreateToolhelp32Snapshot` is one of the Win32 calls that
            // returns the former. Checking for null instead would let a
            // failed snapshot through, and the walk below would then be
            // performed on an invalid handle: it still fails closed, but it
            // fails two calls later and reports the wrong cause.
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
                return Err(ContainmentError::Os);
            }
            // SAFETY: an all-zero entry is the documented starting state; the
            // size field below is what the API validates.
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            let Ok(size) = u32::try_from(std::mem::size_of::<THREADENTRY32>()) else {
                // SAFETY: closing the snapshot taken above.
                unsafe { CloseHandle(snapshot) };
                return Err(ContainmentError::Os);
            };
            entry.dwSize = size;
            let mut resumed = false;
            // SAFETY: `entry` is sized as the API requires and lives for the
            // whole walk.
            let mut more = unsafe { Thread32First(snapshot, &raw mut entry) };
            while more != 0 {
                if entry.th32OwnerProcessID == pid {
                    // SAFETY: opening a thread of the process just created.
                    let thread =
                        unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                    if !thread.is_null() {
                        // SAFETY: a valid handle with the right access,
                        // closed immediately after.
                        let previous = unsafe { ResumeThread(thread) };
                        // SAFETY: closing the handle opened just above.
                        unsafe { CloseHandle(thread) };
                        if previous != u32::MAX {
                            resumed = true;
                        }
                    }
                }
                // SAFETY: same invariants as `Thread32First`.
                more = unsafe { Thread32Next(snapshot, &raw mut entry) };
            }
            // SAFETY: closing the snapshot taken above.
            unsafe { CloseHandle(snapshot) };
            if resumed {
                Ok(())
            } else {
                // The child is still suspended and contained. The caller
                // kills it rather than leaving a process that will never run.
                Err(ContainmentError::Os)
            }
        }

        /// Terminate every process in the job.
        ///
        /// Windows has no graceful group signal, so `force` is accepted for a
        /// common surface and ignored. Saying so here rather than silently
        /// treating a polite request as a kill: a caller that believes it
        /// asked nicely will misread what happened to the session.
        pub fn terminate(&self, _force: bool) -> Result<(), ContainmentError> {
            // SAFETY: the job handle is valid for the life of `self`.
            let terminated = unsafe { TerminateJobObject(self.job.as_raw_handle().cast(), 1) };
            if terminated == 0 {
                return Err(ContainmentError::Os);
            }
            Ok(())
        }

        /// Whether the job has no live processes left.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            // SAFETY: an all-zero accounting structure is a valid output
            // buffer for the query below.
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            let Ok(size) =
                u32::try_from(std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
            else {
                return false;
            };
            // SAFETY: the pointer and length describe `accounting`.
            let queried = unsafe {
                QueryInformationJobObject(
                    self.job.as_raw_handle().cast(),
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut accounting).cast(),
                    size,
                    std::ptr::null_mut(),
                )
            };
            // A query that fails is not evidence of emptiness. Reporting
            // "empty" here would let the supervisor declare a session stopped
            // on the strength of a failed call.
            queried != 0 && accounting.ActiveProcesses == 0
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::ContainmentError;

    /// No containment primitive on this platform.
    ///
    /// Deliberately reports failure rather than success: a caller that
    /// believes a session is contained when it is not will report a clean
    /// shutdown over a leaked process tree.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Containment;

    /// Nothing this platform can do to a command before it is spawned.
    pub fn prepare_command(_command: &mut std::process::Command) {}

    impl Containment {
        pub const fn prepare() -> Result<Option<Self>, ContainmentError> {
            Ok(None)
        }
        pub const fn resume(&self) -> Result<(), ContainmentError> {
            Err(ContainmentError::Unusable)
        }
        pub const fn adopt(_pid: u32) -> Result<Self, ContainmentError> {
            Err(ContainmentError::Unusable)
        }
        pub fn bind(_prepared: Option<Self>, _pid: u32) -> Result<Self, ContainmentError> {
            Err(ContainmentError::Unusable)
        }
        pub const fn terminate(&self, _force: bool) -> Result<(), ContainmentError> {
            Err(ContainmentError::Unusable)
        }
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            false
        }
    }
}

pub use platform::{Containment, prepare_command};

#[cfg(test)]
mod tests {
    use super::is_signallable_group;

    /// The two pid values `kill` reserves must never be treated as a group.
    ///
    /// Asserted by inspection only. A test that actually signalled one of
    /// these would take the machine with it.
    #[test]
    fn wildcard_and_self_group_ids_are_never_signallable() {
        assert!(!is_signallable_group(-1));
        assert!(!is_signallable_group(0));
        assert!(
            !is_signallable_group(1),
            "negating 1 is kill's every-process wildcard, not process group 1"
        );
        assert!(is_signallable_group(2));
    }

    /// A pid too large for an `i32` is refused rather than truncated.
    ///
    /// An unchecked cast wraps to a negative value, and negating *that*
    /// produces a positive number naming some unrelated process: a truncation
    /// bug whose symptom is signalling a stranger.
    #[cfg(unix)]
    #[test]
    fn an_out_of_range_or_reserved_pid_is_refused() {
        use super::Containment;
        assert!(Containment::adopt(u32::MAX).is_err());
        assert!(Containment::adopt(1).is_err());
        assert!(Containment::adopt(0).is_err());
        assert!(Containment::adopt(2).is_ok());
    }

    /// `prepare` then `bind` is the shape a caller uses on every platform.
    #[cfg(unix)]
    #[test]
    fn prepare_then_bind_needs_no_platform_branch_in_the_caller() {
        use super::Containment;
        let prepared = Containment::prepare().expect("prepare");
        assert!(
            prepared.is_none(),
            "Unix creates the group at spawn, not before it"
        );
        assert!(Containment::bind(prepared, 2).is_ok());
    }

    /// A real group is reported as occupied while it runs and empty after.
    #[cfg(unix)]
    #[test]
    fn a_live_group_is_not_empty_and_a_reaped_one_is() {
        use super::Containment;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(0);
        let mut child = command.spawn().expect("spawn group");
        let containment = Containment::adopt(child.id()).expect("adopt the group");
        assert!(!containment.is_empty(), "the group is running");

        containment.terminate(true).expect("kill the group");
        child.wait().expect("reap the leader");
        for _ in 0..200 {
            if containment.is_empty() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("the group never drained");
    }
}
