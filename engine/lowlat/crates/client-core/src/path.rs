use std::fmt;
use std::time::Instant;

use openstream_transport::{
    FIRST_PATH_GENERATION, PathGeneration, PathMtuState, PathState, PeerTransportSnapshot,
    TransportPathKind, UdpTransport,
};

use crate::{CandidateKind, IcePath};

pub(crate) struct PeerPath {
    backend: PeerPathBackend,
    generation: PathGeneration,
    state: PathState,
    started_at: Instant,
    datagram_size: Option<usize>,
    path_mtu_state: PathMtuState,
}

impl PeerPath {
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
