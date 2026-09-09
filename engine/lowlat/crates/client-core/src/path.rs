use std::fmt;
use std::time::{Duration, Instant};

use openstream_protocol::path_control::{AbortReason, PATH_TOKEN_BYTES, PathControl, PathKind};

use openstream_transport::{
    FIRST_PATH_GENERATION, PathGeneration, PathMtuState, PathState, PeerTransportSnapshot,
    TransportPathKind, UdpTransport,
};

use crate::{CandidateKind, IcePath, Role};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTarget {
    DirectUdp,
    OpaqueRelay,
    Ice,
}

impl From<PathKind> for MigrationTarget {
    fn from(kind: PathKind) -> Self {
        match kind {
            PathKind::DirectUdp => Self::DirectUdp,
            PathKind::OpaqueRelay => Self::OpaqueRelay,
            PathKind::Ice => Self::Ice,
        }
    }
}

impl MigrationTarget {
    fn wire_kind(self) -> PathKind {
        match self {
            Self::DirectUdp => PathKind::DirectUdp,
            Self::OpaqueRelay => PathKind::OpaqueRelay,
            Self::Ice => PathKind::Ice,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    Idle,
    Preparing,
    Ready,
    CommitPending,
    Active,
    CommitUnconfirmed,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MigrationToken([u8; PATH_TOKEN_BYTES]);

impl MigrationToken {
    pub(crate) fn random() -> Result<Self, PathMigrationError> {
        let mut bytes = [0; PATH_TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| PathMigrationError::PathUnavailable)?;
        if bytes == [0; PATH_TOKEN_BYTES] {
            return Err(PathMigrationError::PathUnavailable);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(self) -> [u8; PATH_TOKEN_BYTES] {
        self.0
    }
}

impl fmt::Debug for MigrationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationToken([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub previous_generation: PathGeneration,
    pub active_generation: PathGeneration,
    pub previous_kind: TransportPathKind,
    pub active_kind: TransportPathKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMigrationError {
    CapabilityNotNegotiated,
    MigrationAlreadyPending,
    HostMigrationRequired,
    UnsupportedIceRestart,
    CommitUnconfirmed,
    PathUnavailable,
}

impl fmt::Display for PathMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CapabilityNotNegotiated => "path migration was not negotiated",
            Self::MigrationAlreadyPending => "a path migration is pending",
            Self::HostMigrationRequired => "only the host can initiate path migration",
            Self::UnsupportedIceRestart => "ICE restart is not supported",
            Self::CommitUnconfirmed => "path commit could not be confirmed",
            Self::PathUnavailable => "replacement path is unavailable",
        })
    }
}

impl std::error::Error for PathMigrationError {}

pub(crate) const MIN_DRAIN_GRACE: Duration = Duration::from_millis(250);
pub(crate) const MAX_DRAIN_GRACE: Duration = Duration::from_secs(2);
pub(crate) const COMMIT_RETRY: Duration = Duration::from_millis(250);
pub(crate) const MIGRATION_DEADLINE: Duration = Duration::from_secs(5);

fn safe_datagram_size() -> u16 {
    u16::try_from(openstream_protocol::MAX_DATAGRAM)
        .expect("MAX_DATAGRAM must fit in path-control datagram_size")
}

fn drain_grace(rtt: Option<Duration>) -> Duration {
    rtt.unwrap_or_default()
        .saturating_mul(3)
        .clamp(MIN_DRAIN_GRACE, MAX_DRAIN_GRACE)
}

/// A stable ingress identity: swapping active/prepared never renames a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathSlot(pub PathGeneration);

#[derive(Debug)]
pub(crate) enum MigrationAction {
    Send(PathSlot, PathControl),
    Open {
        generation: PathGeneration,
        target: MigrationTarget,
        token: MigrationToken,
    },
    Activate {
        generation: PathGeneration,
    },
    Retire,
    Discard,
}

pub(crate) struct PendingMigration {
    pub generation: PathGeneration,
    pub token: MigrationToken,
    pub target: MigrationTarget,
    pub deadline: Instant,
    opened: bool,
    proved: bool,
    peer_ready: bool,
    next_retry: Instant,
}

/// The same bounded, clock-driven controller is used by the socket driver
/// and deterministic tests. Actions preserve durable transition-before-I/O.
pub(crate) struct MigrationController {
    pub role: Role,
    pub state: MigrationState,
    pub active_generation: PathGeneration,
    pub pending: Option<PendingMigration>,
    committed: Option<(PathGeneration, MigrationToken)>,
    draining: Option<(PathSlot, Instant)>,
    old_failed: bool,
    last_request: Option<u32>,
    pub old_rtt: Option<Duration>,
}

impl MigrationController {
    pub(crate) fn drain_deadline(&self) -> Option<Instant> {
        self.draining.map(|(_, until)| until)
    }

    pub(crate) fn busy(&self) -> bool {
        self.pending.is_some()
            || self.draining.is_some()
            || self.state == MigrationState::CommitUnconfirmed
    }
    pub(crate) fn new(role: Role) -> Self {
        Self {
            role,
            state: MigrationState::Idle,
            active_generation: FIRST_PATH_GENERATION,
            pending: None,
            committed: None,
            draining: None,
            old_failed: false,
            last_request: None,
            old_rtt: None,
        }
    }

    pub(crate) fn start(
        &mut self,
        target: MigrationTarget,
        token: MigrationToken,
        now: Instant,
    ) -> Result<Vec<MigrationAction>, PathMigrationError> {
        if self.pending.is_some()
            || self.draining.is_some()
            || self.state == MigrationState::CommitUnconfirmed
        {
            return Err(PathMigrationError::MigrationAlreadyPending);
        }
        if self.role != Role::Host {
            return Err(PathMigrationError::HostMigrationRequired);
        }
        if target == MigrationTarget::Ice {
            return Err(PathMigrationError::UnsupportedIceRestart);
        }
        let generation = self
            .active_generation
            .checked_add(1)
            .ok_or(PathMigrationError::PathUnavailable)?;
        let mut actions = vec![MigrationAction::Send(
            PathSlot(self.active_generation),
            PathControl::Prepare {
                generation,
                kind: target.wire_kind(),
                token: token.0,
            },
        )];
        actions.extend(self.prepare(generation, target, token, now));
        Ok(actions)
    }

    fn prepare(
        &mut self,
        generation: PathGeneration,
        target: MigrationTarget,
        token: MigrationToken,
        now: Instant,
    ) -> Vec<MigrationAction> {
        self.pending = Some(PendingMigration {
            generation,
            token,
            target,
            deadline: now + MIGRATION_DEADLINE,
            opened: false,
            proved: false,
            peer_ready: false,
            next_retry: now + COMMIT_RETRY,
        });
        self.state = MigrationState::Preparing;
        self.old_failed = false;
        vec![MigrationAction::Open {
            generation,
            target,
            token,
        }]
    }

    pub(crate) fn application_slot(&self) -> Result<PathSlot, PathMigrationError> {
        match self.state {
            MigrationState::CommitPending => Err(PathMigrationError::MigrationAlreadyPending),
            MigrationState::CommitUnconfirmed => Err(PathMigrationError::CommitUnconfirmed),
            _ => Ok(PathSlot(self.active_generation)),
        }
    }

    pub(crate) fn accepts_application(&self, slot: PathSlot, now: Instant) -> bool {
        slot == PathSlot(self.active_generation)
            || self
                .draining
                .is_some_and(|(old, until)| slot == old && now < until)
    }

    pub(crate) fn opened(&mut self, now: Instant) -> Vec<MigrationAction> {
        let Some(p) = self.pending.as_mut() else {
            return vec![];
        };
        p.opened = true;
        p.next_retry = now + COMMIT_RETRY;
        vec![MigrationAction::Send(
            PathSlot(p.generation),
            PathControl::Probe {
                generation: p.generation,
                token: p.token.0,
            },
        )]
    }

    pub(crate) fn receive(
        &mut self,
        ingress: PathSlot,
        record: PathControl,
        now: Instant,
    ) -> Vec<MigrationAction> {
        if let PathControl::Request { request_id, kind } = record {
            if self.role != Role::Host
                || ingress != PathSlot(self.active_generation)
                || self.last_request == Some(request_id)
                || self.pending.is_some()
                || self.draining.is_some()
            {
                return vec![];
            }
            self.last_request = Some(request_id);
            return MigrationToken::random()
                .and_then(|token| self.start(kind.into(), token, now))
                .unwrap_or_default();
        }
        if let PathControl::Prepare {
            generation,
            kind,
            token,
        } = record
        {
            if self.role != Role::Client
                || ingress != PathSlot(self.active_generation)
                || self.active_generation.checked_add(1) != Some(generation)
                || token == [0; PATH_TOKEN_BYTES]
            {
                return vec![];
            }
            let target = kind.into();
            if let Some(p) = self.pending.as_ref() {
                if p.generation != generation || p.token.bytes() != token || p.target != target {
                    return vec![];
                }
                let new = PathSlot(generation);
                return if p.proved {
                    vec![MigrationAction::Send(
                        ingress,
                        PathControl::Ready {
                            generation,
                            token,
                            datagram_size: safe_datagram_size(),
                        },
                    )]
                } else if p.opened {
                    vec![MigrationAction::Send(
                        new,
                        PathControl::Probe { generation, token },
                    )]
                } else {
                    vec![]
                };
            }
            if self.draining.is_some() {
                return vec![];
            }
            if kind == PathKind::Ice {
                return vec![MigrationAction::Send(
                    ingress,
                    PathControl::Abort {
                        generation,
                        reason: AbortReason::Unsupported,
                    },
                )];
            }
            return self.prepare(generation, target, MigrationToken(token), now);
        }
        if let PathControl::Abort { generation, .. } = record {
            let aborts_current_attempt = self.pending.as_ref().is_some_and(|pending| {
                pending.generation == generation
                    && ingress == PathSlot(self.active_generation)
                    && matches!(
                        self.state,
                        MigrationState::Preparing | MigrationState::Ready
                    )
            });
            if aborts_current_attempt {
                self.pending = None;
                self.state = MigrationState::Failed;
                return vec![MigrationAction::Discard];
            }
            return vec![];
        }
        // A committed responder repeats the ACK even when the first send was
        // lost. Only the current socket or its bounded draining predecessor
        // may carry this duplicate.
        if let PathControl::Commit { generation, token } = &record {
            if self.role == Role::Client
                && self.committed == Some((*generation, MigrationToken(*token)))
                && self.accepts_application(ingress, now)
            {
                return vec![MigrationAction::Send(
                    PathSlot(*generation),
                    PathControl::CommitAck {
                        generation: *generation,
                        token: *token,
                    },
                )];
            }
        }
        let Some(p) = self.pending.as_mut() else {
            return vec![];
        };
        let (generation, token) = match &record {
            PathControl::Probe { generation, token }
            | PathControl::ProbeAck { generation, token }
            | PathControl::Ready {
                generation, token, ..
            }
            | PathControl::Commit { generation, token }
            | PathControl::CommitAck { generation, token } => (*generation, *token),
            // Abort has no token. It is handled above only for the current
            // pre-commit attempt; it cannot roll back a committed migration
            // or disambiguate a later attempt reusing N+1.
            _ => return vec![],
        };
        if generation != p.generation || token != p.token.0 || now >= p.deadline {
            return vec![];
        }
        let new = PathSlot(generation);
        let old = PathSlot(self.active_generation);
        let mut actions = vec![];
        match record {
            PathControl::Probe { .. } if p.opened && ingress == new => {
                actions.push(MigrationAction::Send(
                    new,
                    PathControl::ProbeAck { generation, token },
                ));
            }
            PathControl::ProbeAck { .. } if p.opened && ingress == new && !p.proved => {
                p.proved = true;
                self.state = MigrationState::Ready;
                actions.push(MigrationAction::Send(
                    old,
                    PathControl::Ready {
                        generation,
                        token,
                        datagram_size: safe_datagram_size(),
                    },
                ));
            }
            PathControl::Ready { datagram_size, .. }
                if ingress == old && datagram_size == safe_datagram_size() =>
            {
                p.peer_ready = true;
            }
            PathControl::Commit { .. }
                if self.role == Role::Client && p.proved && (ingress == old || ingress == new) =>
            {
                actions.extend(self.activate(now));
                actions.push(MigrationAction::Send(
                    new,
                    PathControl::CommitAck { generation, token },
                ));
                return actions;
            }
            PathControl::CommitAck { .. }
                if self.role == Role::Host
                    && self.state == MigrationState::CommitPending
                    && ingress == new =>
            {
                return self.activate(now);
            }
            _ => {}
        }
        if self.role == Role::Host
            && p.proved
            && p.peer_ready
            && self.state == MigrationState::Ready
        {
            self.state = MigrationState::CommitPending;
            p.next_retry = now + COMMIT_RETRY;
            actions.push(MigrationAction::Send(
                if self.old_failed { new } else { old },
                PathControl::Commit { generation, token },
            ));
        }
        actions
    }

    fn activate(&mut self, now: Instant) -> Vec<MigrationAction> {
        let p = self.pending.take().expect("validated pending migration");
        self.draining = Some((
            PathSlot(self.active_generation),
            now + drain_grace(self.old_rtt),
        ));
        self.active_generation = p.generation;
        self.committed = Some((p.generation, p.token));
        self.state = MigrationState::Active;
        vec![MigrationAction::Activate {
            generation: p.generation,
        }]
    }

    pub(crate) fn old_path_failed(&mut self) {
        self.old_failed = true;
    }

    pub(crate) fn fail_preparation(&mut self, reason: AbortReason) -> Vec<MigrationAction> {
        if self.state == MigrationState::CommitPending
            || self.state == MigrationState::CommitUnconfirmed
        {
            self.state = MigrationState::CommitUnconfirmed;
            return vec![];
        }
        let Some(pending) = self.pending.take() else {
            return vec![];
        };
        self.state = MigrationState::Failed;
        vec![
            MigrationAction::Send(
                PathSlot(self.active_generation),
                PathControl::Abort {
                    generation: pending.generation,
                    reason,
                },
            ),
            MigrationAction::Discard,
        ]
    }

    pub(crate) fn tick(&mut self, now: Instant) -> Vec<MigrationAction> {
        if self.draining.is_some_and(|(_, until)| now >= until) {
            self.draining = None;
            return vec![MigrationAction::Retire];
        }
        let Some(p) = self.pending.as_mut() else {
            return vec![];
        };
        if now >= p.deadline {
            return self.fail_preparation(AbortReason::Timeout);
        }
        if now < p.next_retry {
            return vec![];
        }
        p.next_retry = now + COMMIT_RETRY;
        let generation = p.generation;
        let token = p.token.0;
        let old = PathSlot(self.active_generation);
        let new = PathSlot(generation);
        if self.state == MigrationState::CommitPending {
            let commit = PathControl::Commit { generation, token };
            return if self.old_failed {
                vec![MigrationAction::Send(new, commit)]
            } else {
                vec![MigrationAction::Send(old, commit)]
            };
        }
        let mut actions = vec![];
        if self.role == Role::Host {
            actions.push(MigrationAction::Send(
                old,
                PathControl::Prepare {
                    generation,
                    kind: p.target.wire_kind(),
                    token,
                },
            ));
        }
        if p.opened && !p.proved {
            actions.push(MigrationAction::Send(
                new,
                PathControl::Probe { generation, token },
            ));
        }
        if p.proved {
            actions.push(MigrationAction::Send(
                old,
                PathControl::Ready {
                    generation,
                    token,
                    datagram_size: safe_datagram_size(),
                },
            ));
        }
        actions
    }
}

pub(crate) struct PeerPath {
    backend: PeerPathBackend,
    generation: PathGeneration,
    state: PathState,
    started_at: Instant,
    datagram_size: Option<usize>,
    path_mtu_state: PathMtuState,
}

impl PeerPath {
    pub(crate) fn replacement(
        backend: PeerPathBackend,
        generation: PathGeneration,
        now: Instant,
    ) -> Self {
        let mut path = Self::new(backend, generation, PathState::Preparing, now);
        path.datagram_size = Some(openstream_protocol::MAX_DATAGRAM);
        path
    }

    pub(crate) fn activate(&mut self, now: Instant) {
        self.state = PathState::Active;
        self.started_at = now;
        self.path_mtu_state = PathMtuState::Unavailable;
        if let PeerPathBackend::Direct { transport, .. } = &mut self.backend {
            transport.activate_generation(self.generation);
        }
    }
    fn new(
        backend: PeerPathBackend,
        generation: PathGeneration,
        state: PathState,
        started_at: Instant,
    ) -> Self {
        Self {
            backend,
            generation,
            state,
            started_at,
            datagram_size: None,
            path_mtu_state: PathMtuState::Unavailable,
        }
    }

    pub(crate) fn backend(&self) -> &PeerPathBackend {
        &self.backend
    }

    pub(crate) fn backend_mut(&mut self) -> &mut PeerPathBackend {
        &mut self.backend
    }

    pub(crate) fn generation(&self) -> PathGeneration {
        self.generation
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn state(&self) -> PathState {
        self.state
    }

    fn snapshot(&self, now: Instant) -> PeerTransportSnapshot {
        let path = match &self.backend {
            PeerPathBackend::Direct { candidate, .. } => match candidate {
                CandidateKind::Relay => TransportPathKind::OpaqueRelay,
                CandidateKind::Host | CandidateKind::Mapped | CandidateKind::ServerReflexive => {
                    TransportPathKind::DirectUdp
                }
            },
            PeerPathBackend::Ice(_) => TransportPathKind::Ice,
        };
        PeerTransportSnapshot {
            path,
            path_generation: self.generation,
            state: self.state,
            path_age_ms: u64::try_from(now.saturating_duration_since(self.started_at).as_millis())
                .unwrap_or(u64::MAX),
            datagram_size: self.datagram_size,
            path_mtu_state: self.path_mtu_state,
            sample: None,
        }
    }
}

impl fmt::Debug for PeerPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPath")
            .field("backend", &self.backend)
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("datagram_size", &self.datagram_size)
            .field("path_mtu_state", &self.path_mtu_state)
            .finish()
    }
}

pub(crate) enum PeerPathBackend {
    Direct {
        transport: Box<UdpTransport>,
        candidate: CandidateKind,
    },
    Ice(IcePath),
}

impl PeerPathBackend {
    pub(crate) async fn probe(&self, cipher: &mut crate::CipherSession) -> crate::ProbeResult {
        match self {
            Self::Direct { transport, .. } => crate::probe_path(transport, cipher).await,
            Self::Ice(_) => crate::ProbeResult::Failed,
        }
    }
}

impl fmt::Debug for PeerPathBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct { candidate, .. } => f
                .debug_struct("Direct")
                .field("candidate", candidate)
                .finish_non_exhaustive(),
            Self::Ice(_) => f.debug_tuple("Ice").finish(),
        }
    }
}

#[allow(dead_code)] // Allocation is reserved for the later host-controlled migration task.
#[derive(Debug)]
pub(crate) struct GenerationAllocator {
    next_generation: PathGeneration,
}

#[allow(dead_code)]
impl GenerationAllocator {
    pub(crate) const fn new(next_generation: PathGeneration) -> Self {
        Self { next_generation }
    }

    pub(crate) fn reserve(&mut self) -> Option<PathGeneration> {
        if self.next_generation < FIRST_PATH_GENERATION {
            return None;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.checked_add(1)?;
        Some(generation)
    }

    const fn next_generation(&self) -> PathGeneration {
        self.next_generation
    }
}

pub(crate) struct PathRuntime {
    pub active: PeerPath,
    pub prepared: Option<PeerPath>,
    pub next_generation: PathGeneration,
}

impl PathRuntime {
    pub(crate) fn at(&self, slot: PathSlot) -> Option<&PeerPath> {
        if self.active.generation == slot.0 {
            return Some(&self.active);
        }
        self.prepared
            .as_ref()
            .filter(|path| path.generation == slot.0)
    }

    pub(crate) fn install(&mut self, path: PeerPath) {
        self.next_generation = path.generation.saturating_add(1);
        self.prepared = Some(path);
    }
    pub(crate) fn initial_active(backend: PeerPathBackend, started_at: Instant) -> Self {
        Self {
            active: PeerPath::new(
                backend,
                FIRST_PATH_GENERATION,
                PathState::Active,
                started_at,
            ),
            prepared: None,
            next_generation: FIRST_PATH_GENERATION + 1,
        }
    }

    pub(crate) fn active(&self) -> &PeerPath {
        &self.active
    }

    pub(crate) fn active_mut(&mut self) -> &mut PeerPath {
        &mut self.active
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn reserve_generation(
        &mut self,
        backend: PeerPathBackend,
        started_at: Instant,
    ) -> Option<&mut PeerPath> {
        if self.prepared.is_some() {
            return None;
        }
        let mut allocator = GenerationAllocator::new(self.next_generation);
        let generation = allocator.reserve()?;
        self.next_generation = allocator.next_generation();
        self.prepared = Some(PeerPath::new(
            backend,
            generation,
            PathState::Preparing,
            started_at,
        ));
        self.prepared.as_mut()
    }

    pub(crate) fn snapshot(&self, now: Instant) -> PeerTransportSnapshot {
        self.active.snapshot(now)
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn mark_ready(&mut self) -> bool {
        let Some(prepared) = self.prepared.as_mut() else {
            return false;
        };
        if prepared.state != PathState::Preparing {
            return false;
        }
        prepared.state = PathState::Ready;
        true
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn mark_commit_pending(&mut self) -> bool {
        let Some(prepared) = self.prepared.as_mut() else {
            return false;
        };
        if prepared.state != PathState::Ready {
            return false;
        }
        prepared.state = PathState::CommitPending;
        true
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn activate_prepared(&mut self) -> bool {
        let Some(mut prepared) = self.prepared.take() else {
            return false;
        };
        if prepared.state != PathState::CommitPending {
            self.prepared = Some(prepared);
            return false;
        }
        prepared.state = PathState::Active;
        self.prepared = Some(std::mem::replace(&mut self.active, prepared));
        true
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn begin_drain(&mut self) -> bool {
        let Some(previous) = self.prepared.as_mut() else {
            return false;
        };
        if previous.state != PathState::Active {
            return false;
        }
        previous.state = PathState::Draining;
        true
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn retire_old(&mut self) -> bool {
        let Some(mut previous) = self.prepared.take() else {
            return false;
        };
        if previous.state != PathState::Draining {
            self.prepared = Some(previous);
            return false;
        }
        previous.state = PathState::Retired;
        true
    }

    #[allow(dead_code)] // Transition handling begins in the later migration task.
    pub(crate) fn close_all(&mut self) {
        self.active.state = PathState::Closed;
        if let Some(prepared) = self.prepared.as_mut() {
            prepared.state = PathState::Closed;
        }
    }
}

impl fmt::Debug for PathRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathRuntime")
            .field("active", &self.active)
            .field("prepared", &self.prepared)
            .field("next_generation", &self.next_generation)
            .finish()
    }
}

#[cfg(test)]
mod path_migration {
    use super::*;
    use crate::Role;
    use openstream_protocol::{
        Kind,
        path_control::{PATH_CONTROL_CHANNEL, PathControl, PathKind},
    };

    // Only socket I/O is replaced: every transition and encoded record comes
    // from the production controller. Records can be removed or delivered in
    // any order, modelling loss/reordering without wall-clock sleeps.
    #[derive(Default)]
    struct RecordingDriver {
        records: Vec<(PathSlot, Kind, u8, Vec<u8>)>,
        opens: usize,
    }

    impl RecordingDriver {
        fn apply(&mut self, actions: Vec<MigrationAction>) {
            for action in actions {
                match action {
                    MigrationAction::Send(slot, record) => self.records.push((
                        slot,
                        Kind::Control,
                        PATH_CONTROL_CHANNEL,
                        record.encode().unwrap(),
                    )),
                    MigrationAction::Open { .. } => self.opens += 1,
                    _ => {}
                }
            }
        }

        fn take(&mut self, index: usize) -> (PathSlot, PathControl) {
            let (slot, kind, channel, payload) = self.records.remove(index);
            assert_eq!(kind, Kind::Control);
            assert_eq!(channel, PATH_CONTROL_CHANNEL);
            (slot, PathControl::decode(&payload).unwrap())
        }
    }

    const TOKEN: [u8; 16] = [7; 16];

    fn prepared_pair(now: Instant) -> (MigrationController, MigrationController) {
        let mut host = MigrationController::new(Role::Host);
        let mut client = MigrationController::new(Role::Client);
        host.start(MigrationTarget::OpaqueRelay, MigrationToken(TOKEN), now)
            .unwrap();
        client.receive(
            PathSlot(1),
            PathControl::Prepare {
                generation: 2,
                token: TOKEN,
                kind: PathKind::OpaqueRelay,
            },
            now,
        );
        for controller in [&mut host, &mut client] {
            controller.opened(now);
            controller.receive(
                PathSlot(2),
                PathControl::ProbeAck {
                    generation: 2,
                    token: TOKEN,
                },
                now,
            );
        }
        (host, client)
    }

    fn ready() -> PathControl {
        PathControl::Ready {
            generation: 2,
            token: TOKEN,
            datagram_size: 1200,
        }
    }

    #[test]
    fn application_sends_are_blocked_while_commit_is_pending() {
        let now = Instant::now();
        let (mut host, _) = prepared_pair(now);
        assert_eq!(host.application_slot(), Ok(PathSlot(1)));
        host.receive(PathSlot(1), ready(), now);
        assert_eq!(host.state, MigrationState::CommitPending);
        assert_eq!(
            host.application_slot(),
            Err(PathMigrationError::MigrationAlreadyPending)
        );
        host.receive(
            PathSlot(2),
            PathControl::CommitAck {
                generation: 2,
                token: TOKEN,
            },
            now,
        );
        assert_eq!(host.application_slot(), Ok(PathSlot(2)));
    }

    #[test]
    fn host_commit_uses_old_path_and_client_ack_uses_new_path() {
        let now = Instant::now();
        let (mut host, mut client) = prepared_pair(now);
        let mut driver = RecordingDriver::default();
        driver.apply(host.receive(PathSlot(1), ready(), now));
        let (slot, commit) = driver.take(0);
        assert_eq!(slot, PathSlot(1));
        assert!(matches!(commit, PathControl::Commit { generation: 2, .. }));
        driver.apply(client.receive(slot, commit, now));
        let (slot, ack) = driver.take(0);
        assert_eq!(slot, PathSlot(2));
        host.receive(PathSlot(1), ack.clone(), now);
        assert_eq!(host.active_generation, 1, "ACK on old ingress is not proof");
        host.receive(slot, ack.clone(), now);
        host.receive(slot, ack, now);
        assert_eq!(host.active_generation, 2);
    }

    #[test]
    fn client_commit_is_durable_before_ack_and_duplicate_commit_repeats_ack() {
        let now = Instant::now();
        let (_, mut client) = prepared_pair(now);
        let commit = PathControl::Commit {
            generation: 2,
            token: TOKEN,
        };
        let actions = client.receive(PathSlot(1), commit.clone(), now);
        assert_eq!(
            client.active_generation, 2,
            "commit is durable even if ACK send is dropped"
        );
        assert!(matches!(
            actions.first(),
            Some(MigrationAction::Activate { .. })
        ));
        let mut driver = RecordingDriver::default();
        driver.apply(actions);
        let first = driver.take(0); // drop first ACK
        driver.apply(client.receive(PathSlot(2), commit, now));
        assert_eq!(driver.take(0), first);
        assert_eq!(client.application_slot(), Ok(PathSlot(2)));
    }

    #[test]
    fn wrong_generation_or_token_does_not_change_active_path() {
        let now = Instant::now();
        let (mut host, mut client) = prepared_pair(now);
        host.receive(PathSlot(1), ready(), now);
        for (generation, token) in [(1, TOKEN), (3, TOKEN), (2, [8; 16])] {
            assert!(
                client
                    .receive(PathSlot(1), PathControl::Commit { generation, token }, now)
                    .is_empty()
            );
            assert!(
                host.receive(
                    PathSlot(2),
                    PathControl::CommitAck { generation, token },
                    now
                )
                .is_empty()
            );
        }
        assert_eq!(host.active_generation, 1);
        assert_eq!(client.active_generation, 1);
    }

    #[test]
    fn client_request_does_not_allocate_a_generation() {
        let now = Instant::now();
        let mut client = MigrationController::new(Role::Client);
        assert_eq!(
            client
                .start(MigrationTarget::OpaqueRelay, MigrationToken(TOKEN), now)
                .unwrap_err(),
            PathMigrationError::HostMigrationRequired
        );
        assert!(
            client
                .receive(
                    PathSlot(1),
                    PathControl::Request {
                        request_id: 4,
                        kind: PathKind::OpaqueRelay
                    },
                    now
                )
                .is_empty()
        );
        assert_eq!(client.active_generation, 1);
        assert!(client.pending.is_none());
    }

    #[test]
    fn duplicate_requests_coalesce_to_one_preparation() {
        let now = Instant::now();
        let mut host = MigrationController::new(Role::Host);
        let mut driver = RecordingDriver::default();
        let request = PathControl::Request {
            request_id: 4,
            kind: PathKind::OpaqueRelay,
        };
        driver.apply(host.receive(PathSlot(1), request.clone(), now));
        driver.apply(host.receive(PathSlot(1), request, now));
        assert_eq!(driver.opens, 1);
        assert_eq!(host.pending.as_ref().unwrap().generation, 2);
        assert_eq!(host.active_generation, 1);
    }

    #[test]
    fn duplicate_prepare_repeats_ready_without_allocating_a_generation() {
        let now = Instant::now();
        let mut client = MigrationController::new(Role::Client);
        let prepare = PathControl::Prepare {
            generation: 2,
            token: TOKEN,
            kind: PathKind::OpaqueRelay,
        };
        let first = client.receive(PathSlot(1), prepare.clone(), now);
        assert!(matches!(first.as_slice(), [MigrationAction::Open { .. }]));
        client.opened(now);
        client.receive(
            PathSlot(2),
            PathControl::ProbeAck {
                generation: 2,
                token: TOKEN,
            },
            now,
        );

        let mut driver = RecordingDriver::default();
        driver.apply(client.receive(PathSlot(1), prepare, now));
        assert_eq!(client.active_generation, 1);
        assert_eq!(client.pending.as_ref().unwrap().generation, 2);
        let (slot, record) = driver.take(0);
        assert_eq!(slot, PathSlot(1));
        assert!(matches!(
            record,
            PathControl::Ready {
                generation: 2,
                token: TOKEN,
                datagram_size
            } if datagram_size == safe_datagram_size()
        ));
        assert_eq!(driver.opens, 0);
    }

    #[test]
    fn preparation_failure_notifies_peer_before_discard() {
        let now = Instant::now();
        let mut host = MigrationController::new(Role::Host);
        host.start(MigrationTarget::OpaqueRelay, MigrationToken(TOKEN), now)
            .unwrap();

        let mut driver = RecordingDriver::default();
        driver.apply(host.fail_preparation(AbortReason::ProbeFailed));
        let (slot, record) = driver.take(0);
        assert_eq!(slot, PathSlot(1));
        assert_eq!(
            record,
            PathControl::Abort {
                generation: 2,
                reason: AbortReason::ProbeFailed,
            }
        );
        assert_eq!(host.state, MigrationState::Failed);
        assert!(host.pending.is_none());
        assert!(driver.records.is_empty());
        assert!(host.fail_preparation(AbortReason::ProbeFailed).is_empty());
    }

    #[test]
    fn commit_retries_stay_on_old_path_until_old_path_fails() {
        let now = Instant::now();
        let (mut host, _) = prepared_pair(now);
        host.receive(PathSlot(1), ready(), now);

        let mut driver = RecordingDriver::default();
        driver.apply(host.tick(now + COMMIT_RETRY));
        assert_eq!(driver.records.len(), 1);
        let (slot, record) = driver.take(0);
        assert_eq!(slot, PathSlot(1));
        assert!(matches!(record, PathControl::Commit { .. }));

        host.old_path_failed();
        driver.apply(host.tick(now + COMMIT_RETRY * 2));
        assert_eq!(driver.records.len(), 1);
        let (slot, record) = driver.take(0);
        assert_eq!(slot, PathSlot(2));
        assert!(matches!(record, PathControl::Commit { .. }));
    }

    #[test]
    fn deadline_after_lost_ack_fails_closed_and_retries_on_replacement() {
        let now = Instant::now();
        let (mut host, mut client) = prepared_pair(now);
        host.receive(PathSlot(1), ready(), now);
        client.receive(
            PathSlot(1),
            PathControl::Commit {
                generation: 2,
                token: TOKEN,
            },
            now,
        );
        host.old_path_failed();
        let mut driver = RecordingDriver::default();
        driver.apply(host.tick(now + Duration::from_millis(250)));
        assert_eq!(
            driver.take(0),
            (
                PathSlot(2),
                PathControl::Commit {
                    generation: 2,
                    token: TOKEN
                }
            )
        );
        host.tick(now + Duration::from_secs(5));
        assert_eq!(host.state, MigrationState::CommitUnconfirmed);
        assert_eq!(
            host.application_slot(),
            Err(PathMigrationError::CommitUnconfirmed)
        );
        assert_eq!(
            host.active_generation, 1,
            "unconfirmed is never reported active"
        );
        assert_eq!(client.active_generation, 2, "responder does not roll back");
    }

    #[test]
    fn ingress_is_bounded_and_drain_expires_exactly_once() {
        let now = Instant::now();
        let (mut host, _) = prepared_pair(now);
        assert!(host.accepts_application(PathSlot(1), now));
        assert!(!host.accepts_application(PathSlot(2), now));
        assert!(!host.accepts_application(PathSlot(99), now));
        host.receive(PathSlot(1), ready(), now);
        host.receive(
            PathSlot(2),
            PathControl::CommitAck {
                generation: 2,
                token: TOKEN,
            },
            now,
        );
        assert!(host.accepts_application(PathSlot(1), now + Duration::from_millis(249)));
        assert!(!host.accepts_application(PathSlot(1), now + Duration::from_millis(250)));
        assert!(host.accepts_application(PathSlot(2), now + Duration::from_secs(3)));
        let actions = host.tick(now + Duration::from_millis(250));
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, MigrationAction::Retire))
                .count(),
            1
        );
        assert!(host.tick(now + Duration::from_secs(1)).is_empty());
        assert_eq!(
            drain_grace(Some(Duration::from_millis(200))),
            Duration::from_millis(600)
        );
        assert_eq!(
            drain_grace(Some(Duration::from_secs(10))),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn readiness_requires_new_ingress_proof_and_exact_safe_datagram_size() {
        let now = Instant::now();
        let mut host = MigrationController::new(Role::Host);
        host.start(MigrationTarget::OpaqueRelay, MigrationToken(TOKEN), now)
            .unwrap();
        host.opened(now);
        host.receive(
            PathSlot(1),
            PathControl::ProbeAck {
                generation: 2,
                token: TOKEN,
            },
            now,
        );
        host.receive(PathSlot(1), ready(), now);
        assert_eq!(host.state, MigrationState::Preparing);
        host.receive(
            PathSlot(2),
            PathControl::ProbeAck {
                generation: 2,
                token: TOKEN,
            },
            now,
        );
        assert_eq!(host.state, MigrationState::CommitPending);
        let (mut host, _) = prepared_pair(now);
        host.receive(
            PathSlot(1),
            PathControl::Ready {
                generation: 2,
                token: TOKEN,
                datagram_size: 1500,
            },
            now,
        );
        assert_eq!(host.state, MigrationState::Ready);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use openstream_transport::{FIRST_PATH_GENERATION, PathState, TransportPathKind, UdpTransport};

    use super::{GenerationAllocator, PathRuntime, PeerPathBackend};
    use crate::CandidateKind;

    async fn direct_backend() -> PeerPathBackend {
        PeerPathBackend::Direct {
            transport: Box::new(
                UdpTransport::bind("127.0.0.1:0".parse().expect("loopback address"))
                    .await
                    .expect("bind transport"),
            ),
            candidate: CandidateKind::Host,
        }
    }

    #[tokio::test]
    async fn initial_active_path_starts_at_first_generation() {
        let runtime = PathRuntime::initial_active(direct_backend().await, Instant::now());

        assert_eq!(runtime.active().generation(), FIRST_PATH_GENERATION);
        assert_eq!(runtime.active().state(), PathState::Active);
    }

    #[tokio::test]
    async fn snapshot_describes_the_active_path() {
        let started_at = Instant::now();
        let runtime = PathRuntime::initial_active(direct_backend().await, started_at);

        let snapshot = runtime.snapshot(started_at + Duration::from_millis(250));

        assert_eq!(snapshot.path, TransportPathKind::DirectUdp);
        assert_eq!(snapshot.path_generation, FIRST_PATH_GENERATION);
        assert_eq!(snapshot.state, PathState::Active);
        assert_eq!(snapshot.path_age_ms, 250);
        assert_eq!(snapshot.sample, None);
    }

    #[tokio::test]
    async fn generation_allocator_reserves_a_preparing_replacement_without_changing_active() {
        let mut allocator = GenerationAllocator::new(FIRST_PATH_GENERATION + 1);
        assert_eq!(
            allocator.reserve(),
            Some(FIRST_PATH_GENERATION + 1),
            "the first replacement follows the initial active generation"
        );
        assert_eq!(
            allocator.reserve(),
            Some(FIRST_PATH_GENERATION + 2),
            "replacement generations increase monotonically"
        );

        let mut runtime = PathRuntime::initial_active(direct_backend().await, Instant::now());
        let active_generation = runtime.active().generation();
        let reserved = runtime
            .reserve_generation(direct_backend().await, Instant::now())
            .expect("replacement generation available");
        assert_eq!(reserved.generation(), FIRST_PATH_GENERATION + 1);
        assert_eq!(reserved.state(), PathState::Preparing);

        runtime.prepared = None;
        assert_eq!(runtime.active().generation(), active_generation);
        assert_eq!(runtime.active().state(), PathState::Active);
    }

    #[tokio::test]
    async fn prepared_path_transitions_to_active_and_retires_the_previous_path() {
        let mut runtime = PathRuntime::initial_active(direct_backend().await, Instant::now());
        runtime
            .reserve_generation(direct_backend().await, Instant::now())
            .expect("replacement generation available");

        assert!(runtime.mark_ready());
        assert_eq!(
            runtime.prepared.as_ref().expect("prepared path").state(),
            PathState::Ready
        );
        assert!(runtime.mark_commit_pending());
        assert!(runtime.activate_prepared());
        assert_eq!(
            runtime.active().generation(),
            FIRST_PATH_GENERATION + 1,
            "the prepared generation becomes active"
        );
        assert_eq!(
            runtime.prepared.as_ref().expect("previous path").state(),
            PathState::Active
        );
        assert!(runtime.begin_drain());
        assert!(runtime.retire_old());
        assert!(runtime.prepared.is_none(), "the retired path is released");
    }

    #[tokio::test]
    async fn close_all_marks_active_and_prepared_paths_closed() {
        let mut runtime = PathRuntime::initial_active(direct_backend().await, Instant::now());
        runtime
            .reserve_generation(direct_backend().await, Instant::now())
            .expect("replacement generation available");

        runtime.close_all();

        assert_eq!(runtime.active().state(), PathState::Closed);
        assert_eq!(
            runtime.prepared.as_ref().expect("prepared path").state(),
            PathState::Closed
        );
    }
}
