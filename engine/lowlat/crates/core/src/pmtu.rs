//! Datagram Packetization Layer Path MTU Discovery (DPLPMTUD).
//!
//! The probed quantity is the encrypted UDP payload length, not the link MTU.
//! This module is deliberately sans-IO: it produces an authenticated probe
//! description and consumes an exact probe acknowledgement, while the socket
//! shell supplies the datagram and the clock. A probe is never inferred from
//! an ordinary data acknowledgement. That distinction matters because a lost
//! large data packet may be retransmitted later at a smaller packet size.
//!
//! The state machine follows the useful parts of RFC 8899 for this protocol:
//! a conservative BASE_PLPMTU, repeated probes before abandoning a rung,
//! explicit SEARCH_COMPLETE maintenance, and a black-hole path back to the
//! base size. The wire packet carrying the probe is defined in [`crate::packet`]
//! and is padded to the exact size returned here.

use crate::envelope::ENVELOPE_LEN;
use crate::packet::HEADER_LEN;

/// Default and base PLPMTU: 1200 bytes of cleartext plus the envelope.
pub const FLOOR: usize = crate::DEFAULT_DATAGRAM;

/// Absolute protocol ceiling. No path estimate or caller may raise it.
pub const CEILING: usize = crate::MAX_DATAGRAM;

/// IPv4 header plus UDP header, in bytes.
pub const IPV4_UDP_OVERHEAD: usize = 20 + 8;
/// IPv6 header plus UDP header, in bytes.
pub const IPV6_UDP_OVERHEAD: usize = 40 + 8;

/// An isolated lost probe is not enough to abandon a search rung.
pub const MAX_PROBES: u8 = 3;

/// Time allowed for a probe acknowledgement before the attempt is considered
/// lost. The caller may still use a shorter local timer to wake up; this is
/// the state machine's conservative loss decision.
pub const PROBE_TIMEOUT_MS: f64 = 1_000.0;

/// Time between upward searches after SEARCH_COMPLETE.
pub const REPROBE_INTERVAL_MS: f64 = 600_000.0;

/// Rungs, in the order they are attempted. The path ceiling and protocol
/// ceiling skip any rung that is not legal for the selected path. When the
/// derived path ceiling is above the last fixed rung, that exact ceiling is
/// attempted as the final candidate so path-specific headroom is not silently
/// left unused.
pub const LADDER: [usize; 3] = [1280, 1350, 1400];

/// Relay bytes added ahead of an OpenStream datagram.
pub const RELAY_INDICATION_OVERHEAD: usize = 36;
pub const RELAY_CHANNEL_OVERHEAD: usize = 4;

/// How the session currently reaches its peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    /// Relayed, framed as a TURN data indication.
    RelayIndication,
    /// Relayed, framed as TURN channel data.
    RelayChannel,
}

impl Path {
    /// Bytes consumed by this path's relay framing.
    pub const fn overhead(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::RelayIndication => RELAY_INDICATION_OVERHEAD,
            Self::RelayChannel => RELAY_CHANNEL_OVERHEAD,
        }
    }
}

/// IP family used by the outer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// Outer IP and UDP headers that do not belong to the OpenStream payload.
    pub const fn ip_udp_overhead(self) -> usize {
        match self {
            Self::V4 => IPV4_UDP_OVERHEAD,
            Self::V6 => IPV6_UDP_OVERHEAD,
        }
    }
}

/// Inputs used to derive the maximum encrypted UDP payload for one path.
///
/// `path_mtu` is the effective outer IP packet MTU for the route being used,
/// not necessarily the interface's link MTU. A caller that only knows the
/// interface MTU should pass that as a conservative upper bound. Relay
/// framing is subtracted after the outer IP/UDP headers, because it shares the
/// outer UDP payload with the OpenStream datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathConfig {
    pub path: Path,
    pub ip_version: IpVersion,
    pub path_mtu: usize,
}

impl PathConfig {
    /// Build a path configuration from an effective outer IP packet MTU.
    pub const fn new(path: Path, ip_version: IpVersion, path_mtu: usize) -> Self {
        Self {
            path,
            ip_version,
            path_mtu,
        }
    }

    /// The compatibility default used by [`PathMtu::new`].
    pub const fn default_for(path: Path) -> Self {
        Self::new(path, IpVersion::V4, 1500)
    }

    pub const fn direct_v4(path_mtu: usize) -> Self {
        Self::new(Path::Direct, IpVersion::V4, path_mtu)
    }

    pub const fn direct_v6(path_mtu: usize) -> Self {
        Self::new(Path::Direct, IpVersion::V6, path_mtu)
    }

    /// Largest OpenStream datagram that fits this path and the protocol
    /// ceiling. This can be below [`FLOOR`], which makes the path unusable.
    pub const fn max_datagram_size(self) -> usize {
        let size = self
            .path_mtu
            .saturating_sub(self.ip_version.ip_udp_overhead() + self.path.overhead());
        if size < CEILING { size } else { CEILING }
    }
}

/// State of one path's DPLPMTUD search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuState {
    /// Operating at BASE_PLPMTU while an upward search may be started.
    Base,
    /// An upward search is active or has another legal rung to try.
    Searching,
    /// The current size is usable and this search round has no more work.
    SearchComplete,
    /// BASE_PLPMTU does not fit the configured path, or the base path has
    /// black-holed and cannot be recovered by this state machine.
    Error,
}

/// A probe to encode as an exact-size authenticated packet.
///
/// `id` is independent of data-channel sequence numbers. `attempt` starts at
/// one and changes when the same rung is retried after a timeout. A peer must
/// echo both `id` and `size` in a probe acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub id: u32,
    pub size: usize,
    pub attempt: u8,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    probe: Probe,
    sent_ms: f64,
}

/// DPLPMTUD state for one selected network path.
#[derive(Debug, Clone, Copy)]
pub struct PathMtu {
    config: PathConfig,
    current: usize,
    clamp: usize,
    /// Index of the next ladder entry to consider.
    rung: usize,
    state: PathMtuState,
    next_probe_id: u32,
    probe_attempts: u8,
    probe: Option<InFlight>,
    /// Used for the SEARCH_COMPLETE maintenance timer and immediate retry
    /// after a timeout or black-hole recovery.
    next_action_ms: f64,
}

impl PathMtu {
    /// Start with the compatibility default: direct IPv4 over a 1500-byte
    /// effective path MTU.
    pub fn new(path: Path) -> Self {
        Self::new_with_config(PathConfig::default_for(path), 0.0)
    }

    /// Start a search using a path-specific outer MTU and IP family.
    pub fn new_with_config(config: PathConfig, now_ms: f64) -> Self {
        let clamp = config.max_datagram_size();
        let state = if clamp < FLOOR {
            PathMtuState::Error
        } else {
            PathMtuState::Base
        };
        Self {
            config,
            current: FLOOR,
            clamp,
            rung: 0,
            state,
            next_probe_id: 1,
            probe_attempts: 0,
            probe: None,
            next_action_ms: if now_ms.is_finite() { now_ms } else { 0.0 },
        }
    }

    /// Path inputs used to derive the current clamp.
    pub fn config(&self) -> PathConfig {
        self.config
    }

    /// Maximum legal datagram size for this path, before peer capacity is
    /// learned by probing.
    pub fn max_datagram_size(&self) -> usize {
        self.clamp
    }

    /// Datagram size currently in use.
    pub fn datagram_size(&self) -> usize {
        self.current
    }

    /// Bytes of message body one fragment can carry at the current size.
    pub fn body_capacity(&self) -> usize {
        self.current.saturating_sub(ENVELOPE_LEN + HEADER_LEN)
    }

    /// Current state of the search.
    pub fn state(&self) -> PathMtuState {
        self.state
    }

    /// True once the current search round has stopped, including an unusable
    /// path. [`Self::state`] distinguishes SEARCH_COMPLETE from ERROR.
    pub fn settled(&self) -> bool {
        matches!(
            self.state,
            PathMtuState::SearchComplete | PathMtuState::Error
        )
    }

    /// The currently reserved probe, if the shell has not acknowledged or
    /// timed it out yet.
    pub fn in_flight_probe(&self) -> Option<Probe> {
        self.probe.map(|attempt| attempt.probe)
    }

    /// Number of attempts already sent for the current ladder rung.
    pub fn probe_attempts(&self) -> u8 {
        self.probe_attempts
    }

    /// Size of the next legal probe, without reserving it.
    pub fn next_probe_size(&self) -> Option<usize> {
        if matches!(
            self.state,
            PathMtuState::Error | PathMtuState::SearchComplete
        ) || self.probe.is_some()
        {
            return None;
        }
        self.candidate()
    }

    /// Reserve and return the next probe when its timer is due.
    ///
    /// Reserving here prevents a shell that calls the method repeatedly before
    /// its socket write from generating multiple IDs for one search step. If
    /// the write fails locally, call [`Self::on_probe_send_failed`] so the
    /// reservation is returned without consuming a network-loss attempt.
    pub fn start_probe(&mut self, now_ms: f64) -> Option<Probe> {
        if !now_ms.is_finite() || self.state == PathMtuState::Error || self.probe.is_some() {
            return None;
        }

        if self.state == PathMtuState::SearchComplete {
            if now_ms < self.next_action_ms {
                return None;
            }
            self.state = PathMtuState::Searching;
            self.probe_attempts = 0;
        }
        if now_ms < self.next_action_ms {
            return None;
        }

        let size = match self.candidate() {
            Some(size) => size,
            None => {
                self.complete(now_ms);
                return None;
            }
        };
        self.state = PathMtuState::Searching;
        let attempt = self.probe_attempts.saturating_add(1);
        if attempt > MAX_PROBES {
            self.complete(now_ms);
            return None;
        }
        let id = self.allocate_probe_id();
        let probe = Probe { id, size, attempt };
        self.probe_attempts = attempt;
        self.probe = Some(InFlight {
            probe,
            sent_ms: now_ms,
        });
        self.next_action_ms = now_ms + PROBE_TIMEOUT_MS;
        Some(probe)
    }

    /// Alias emphasizing that the returned object is a protocol probe, not a
    /// socket operation.
    pub fn poll_probe(&mut self, now_ms: f64) -> Option<Probe> {
        self.start_probe(now_ms)
    }

    /// Milliseconds until the state machine needs a timer-driven call.
    pub fn next_timer_ms(&self, now_ms: f64) -> f64 {
        if !now_ms.is_finite() {
            return f64::INFINITY;
        }
        let deadline = if let Some(in_flight) = self.probe {
            in_flight.sent_ms + PROBE_TIMEOUT_MS
        } else {
            match self.state {
                PathMtuState::Error => return f64::INFINITY,
                PathMtuState::Base | PathMtuState::Searching => {
                    if self.candidate().is_some() {
                        self.next_action_ms
                    } else {
                        return f64::INFINITY;
                    }
                }
                PathMtuState::SearchComplete => self.next_action_ms,
            }
        };
        (deadline - now_ms).max(0.0)
    }

    /// Confirm the exact outstanding probe. An acknowledgement for another
    /// ID, another size, an old timed-out attempt, or an ordinary data packet
    /// proves nothing and is ignored.
    pub fn on_probe_ack(&mut self, id: u32, size: usize, now_ms: f64) -> bool {
        let Some(in_flight) = self.probe else {
            return false;
        };
        if in_flight.probe.id != id || in_flight.probe.size != size {
            return false;
        }
        if !now_ms.is_finite()
            || now_ms < in_flight.sent_ms
            || size < FLOOR
            || size > self.clamp
            || size > CEILING
        {
            return false;
        }

        self.probe = None;
        self.current = size;
        self.rung = self.rung.saturating_add(1).min(LADDER.len());
        self.probe_attempts = 0;
        if self.candidate().is_some() {
            self.state = PathMtuState::Searching;
            self.next_action_ms = now_ms;
        } else {
            self.complete(now_ms);
        }
        true
    }

    /// Handle an expired probe. Up to [`MAX_PROBES`] attempts are made for
    /// one size; a single loss does not terminate the search.
    pub fn on_probe_timeout(&mut self, now_ms: f64) -> bool {
        let Some(in_flight) = self.probe else {
            return false;
        };
        if !now_ms.is_finite() || now_ms < in_flight.sent_ms + PROBE_TIMEOUT_MS {
            return false;
        }
        self.probe = None;
        if self.probe_attempts >= MAX_PROBES {
            self.complete(now_ms);
        } else {
            self.state = PathMtuState::Searching;
            self.next_action_ms = now_ms;
        }
        true
    }

    /// A local socket/write failure is not network evidence. Release the
    /// reservation and allow the same attempt number to be sent again.
    pub fn on_probe_send_failed(&mut self) -> bool {
        if self.probe.take().is_none() {
            return false;
        }
        self.probe_attempts = self.probe_attempts.saturating_sub(1);
        self.next_action_ms = 0.0;
        true
    }

    /// Return the next timer action, handling a timeout and starting a retry
    /// in one deterministic call. A caller that wants separate accounting can
    /// call [`Self::on_probe_timeout`] and [`Self::start_probe`] itself.
    pub fn on_timer(&mut self, now_ms: f64) -> Option<Probe> {
        if self.probe.is_some() {
            let _ = self.on_probe_timeout(now_ms);
        }
        self.start_probe(now_ms)
    }

    /// A transport delivery watchdog reports that the current PLPMTU has
    /// black-holed while data was outstanding. Drop to BASE_PLPMTU and search
    /// again. If the base itself has failed, the path is unusable and enters
    /// ERROR rather than emitting endlessly larger or smaller guesses.
    pub fn on_black_hole(&mut self, now_ms: f64) -> bool {
        if self.state == PathMtuState::Error {
            return false;
        }
        self.probe = None;
        self.probe_attempts = 0;
        if self.current == FLOOR {
            self.state = PathMtuState::Error;
            self.next_action_ms = f64::INFINITY;
        } else {
            self.current = FLOOR;
            self.rung = 0;
            self.state = PathMtuState::Base;
            self.next_action_ms = if now_ms.is_finite() { now_ms } else { 0.0 };
        }
        true
    }

    /// The path changed. All learned capacity and any old probe are void.
    pub fn reset(&mut self, path: Path) {
        *self = Self::new(path);
    }

    /// Reset to a new path-specific configuration.
    pub fn reset_with_config(&mut self, config: PathConfig, now_ms: f64) {
        *self = Self::new_with_config(config, now_ms);
    }

    fn candidate(&self) -> Option<usize> {
        if let Some(size) = LADDER
            .iter()
            .skip(self.rung)
            .copied()
            .find(|&size| size > self.current && size <= self.clamp && size <= CEILING)
        {
            return Some(size);
        }

        // The final candidate is the exact path-derived ceiling. This covers
        // ordinary 1500-byte paths (1472/1452), relay-specific limits, and
        // jumbo paths up to the protocol ceiling without introducing a
        // universal IPv4-sized clamp.
        (self.clamp > self.current && self.clamp <= CEILING).then_some(self.clamp)
    }

    fn allocate_probe_id(&mut self) -> u32 {
        let id = if self.next_probe_id == u32::MAX {
            1
        } else {
            self.next_probe_id
        };
        self.next_probe_id = id.saturating_add(1);
        id
    }

    fn complete(&mut self, now_ms: f64) {
        self.probe = None;
        self.probe_attempts = 0;
        self.state = PathMtuState::SearchComplete;
        self.next_action_ms = if now_ms.is_finite() {
            now_ms + REPROBE_INTERVAL_MS
        } else {
            f64::INFINITY
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-9);
    }

    fn start(mtu: &mut PathMtu, now: f64) -> Probe {
        mtu.start_probe(now).unwrap()
    }

    #[test]
    fn starts_at_the_floor() {
        let mtu = PathMtu::new(Path::Direct);
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert_eq!(mtu.body_capacity(), 1193);
        assert_eq!(mtu.state(), PathMtuState::Base);
        assert!(!mtu.settled());
    }

    #[test]
    fn climbs_the_ladder_on_exact_probe_acknowledgements() {
        let mut mtu = PathMtu::new(Path::Direct);
        for (index, &expected) in LADDER.iter().enumerate() {
            assert_eq!(mtu.next_probe_size(), Some(expected), "rung {index}");
            let sent_at = index as f64 * 2_000.0;
            let probe = start(&mut mtu, sent_at);
            assert_eq!(probe.size, expected);
            let acknowledged_at = sent_at + 1.0;
            assert!(mtu.on_probe_ack(probe.id, probe.size, acknowledged_at));
            assert_eq!(mtu.datagram_size(), expected);
        }
        assert_eq!(mtu.next_probe_size(), Some(1472));
        let final_probe = start(&mut mtu, 6_002.0);
        assert_eq!(final_probe.size, 1472);
        assert!(mtu.on_probe_ack(final_probe.id, final_probe.size, 6_003.0));
        assert_eq!(mtu.datagram_size(), 1472);
        assert!(mtu.settled(), "ladder exhausted without settling");
        assert_eq!(mtu.state(), PathMtuState::SearchComplete);
        assert_eq!(mtu.next_probe_size(), None);
    }

    #[test]
    fn the_final_candidate_is_the_derived_ipv6_ceiling() {
        let mut mtu = PathMtu::new_with_config(PathConfig::direct_v6(1500), 0.0);
        for (index, &expected) in LADDER.iter().enumerate() {
            let probe = start(&mut mtu, index as f64 * 2_000.0);
            assert_eq!(probe.size, expected);
            assert!(mtu.on_probe_ack(probe.id, probe.size, (index as f64 + 1.0) * 2_000.0));
        }
        assert_eq!(mtu.next_probe_size(), Some(1452));
    }

    #[test]
    fn one_lost_probe_is_retried_at_the_same_size() {
        let mut mtu = PathMtu::new(Path::Direct);
        let first = start(&mut mtu, 0.0);
        assert!(!mtu.on_probe_timeout(PROBE_TIMEOUT_MS - 0.1));
        assert!(mtu.on_probe_timeout(PROBE_TIMEOUT_MS));
        let second = start(&mut mtu, PROBE_TIMEOUT_MS);
        assert_eq!(second.size, first.size);
        assert_eq!(second.attempt, 2);
        assert_ne!(second.id, first.id);
        assert!(mtu.on_probe_ack(second.id, second.size, 2_000.0));
        assert_eq!(mtu.datagram_size(), first.size);
    }

    #[test]
    fn three_probe_losses_stop_this_search_round() {
        let mut mtu = PathMtu::new(Path::Direct);
        for attempt in 1..=MAX_PROBES {
            let probe = start(&mut mtu, f64::from(attempt - 1) * PROBE_TIMEOUT_MS);
            assert_eq!(probe.attempt, attempt);
            assert!(mtu.on_probe_timeout(f64::from(attempt) * PROBE_TIMEOUT_MS));
        }
        assert_eq!(mtu.state(), PathMtuState::SearchComplete);
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert_eq!(mtu.next_probe_size(), None);
        assert_close(
            mtu.next_timer_ms(3.0 * PROBE_TIMEOUT_MS),
            REPROBE_INTERVAL_MS,
        );
    }

    #[test]
    fn mismatched_or_reordered_acknowledgements_prove_nothing() {
        let mut mtu = PathMtu::new(Path::Direct);
        let first = start(&mut mtu, 0.0);
        assert!(!mtu.on_probe_ack(first.id, first.size + 1, 10.0));
        assert!(!mtu.on_probe_ack(first.id.wrapping_add(1), first.size, 10.0));
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert!(mtu.on_probe_ack(first.id, first.size, 10.0));
    }

    #[test]
    fn an_ack_before_its_probe_was_sent_proves_nothing() {
        let mut mtu = PathMtu::new(Path::Direct);
        let probe = start(&mut mtu, 100.0);
        assert!(!mtu.on_probe_ack(probe.id, probe.size, 99.0));
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert!(mtu.on_probe_ack(probe.id, probe.size, 100.0));
    }

    #[test]
    fn an_old_ack_cannot_confirm_a_retried_probe() {
        let mut mtu = PathMtu::new(Path::Direct);
        let first = start(&mut mtu, 0.0);
        mtu.on_probe_timeout(PROBE_TIMEOUT_MS);
        let retry = start(&mut mtu, PROBE_TIMEOUT_MS);
        assert!(!mtu.on_probe_ack(first.id, first.size, 1_001.0));
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert!(mtu.on_probe_ack(retry.id, retry.size, 1_002.0));
    }

    #[test]
    fn local_send_failure_does_not_consume_a_probe_attempt() {
        let mut mtu = PathMtu::new(Path::Direct);
        let first = start(&mut mtu, 10.0);
        assert!(mtu.on_probe_send_failed());
        let retry = start(&mut mtu, 10.0);
        assert_eq!(retry.attempt, first.attempt);
        assert_ne!(retry.id, first.id);
    }

    #[test]
    fn v4_v6_and_relay_clamps_are_path_specific() {
        let v4 = PathMtu::new_with_config(PathConfig::direct_v4(1500), 0.0);
        let v6 = PathMtu::new_with_config(PathConfig::direct_v6(1500), 0.0);
        let indication = PathMtu::new_with_config(
            PathConfig::new(Path::RelayIndication, IpVersion::V4, 1500),
            0.0,
        );
        let channel = PathMtu::new_with_config(
            PathConfig::new(Path::RelayChannel, IpVersion::V6, 1500),
            0.0,
        );
        assert_eq!(v4.max_datagram_size(), 1472);
        assert_eq!(v6.max_datagram_size(), 1452);
        assert_eq!(indication.max_datagram_size(), 1436);
        assert_eq!(channel.max_datagram_size(), 1448);
    }

    #[test]
    fn a_path_below_the_base_enters_error() {
        let mtu = PathMtu::new_with_config(PathConfig::direct_v6(1276), 0.0);
        assert_eq!(mtu.state(), PathMtuState::Error);
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert!(mtu.next_timer_ms(0.0).is_infinite());
    }

    #[test]
    fn a_ceiling_below_the_first_rung_completes_without_an_illegal_probe() {
        let mut mtu = PathMtu::new_with_config(PathConfig::direct_v4(1257), 0.0);
        assert_eq!(mtu.max_datagram_size(), FLOOR);
        assert_eq!(mtu.next_probe_size(), None);
        assert_eq!(mtu.state(), PathMtuState::Base);
        assert_eq!(mtu.start_probe(0.0), None);
        assert_eq!(mtu.state(), PathMtuState::SearchComplete);
        assert_close(mtu.next_timer_ms(0.0), REPROBE_INTERVAL_MS);
    }

    #[test]
    fn search_complete_reprobes_after_the_maintenance_interval() {
        let mut mtu = PathMtu::new(Path::Direct);
        for attempt in 1..=MAX_PROBES {
            let _ = start(&mut mtu, f64::from(attempt - 1) * PROBE_TIMEOUT_MS);
            let _ = mtu.on_probe_timeout(f64::from(attempt) * PROBE_TIMEOUT_MS);
        }
        assert_eq!(mtu.start_probe(3.0 * PROBE_TIMEOUT_MS), None);
        let due = 3.0 * PROBE_TIMEOUT_MS + REPROBE_INTERVAL_MS;
        let probe = mtu.start_probe(due);
        assert!(probe.is_some());
        assert_eq!(mtu.probe_attempts(), 1);
    }

    #[test]
    fn black_hole_falls_back_then_errors_if_the_base_fails() {
        let mut mtu = PathMtu::new(Path::Direct);
        let probe = start(&mut mtu, 0.0);
        assert!(mtu.on_probe_ack(probe.id, probe.size, 1.0));
        assert_eq!(mtu.datagram_size(), 1280);
        assert!(mtu.on_black_hole(2.0));
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert_eq!(mtu.state(), PathMtuState::Base);
        assert!(mtu.next_probe_size().is_some());
        assert!(mtu.on_black_hole(3.0));
        assert_eq!(mtu.state(), PathMtuState::Error);
    }

    #[test]
    fn a_path_change_forgets_everything() {
        let mut mtu = PathMtu::new(Path::Direct);
        let probe = start(&mut mtu, 0.0);
        assert!(mtu.on_probe_ack(probe.id, probe.size, 1.0));
        assert_eq!(mtu.datagram_size(), 1280);

        mtu.reset_with_config(PathConfig::direct_v6(1500), 10.0);
        assert_eq!(mtu.datagram_size(), FLOOR);
        assert_eq!(mtu.max_datagram_size(), 1452);
        assert_eq!(mtu.state(), PathMtuState::Base);
        assert!(mtu.in_flight_probe().is_none());
    }

    #[test]
    fn probe_timeout_and_maintenance_timers_are_exact() {
        let mut mtu = PathMtu::new(Path::Direct);
        let _ = start(&mut mtu, 100.0);
        assert_close(mtu.next_timer_ms(100.0), PROBE_TIMEOUT_MS);
        assert_close(mtu.next_timer_ms(500.0), 600.0);
        assert!(mtu.on_timer(1_100.0).is_some());
        assert_eq!(mtu.probe_attempts(), 2);
    }

    #[test]
    fn maximum_path_mtu_still_respects_protocol_ceiling() {
        let mtu = PathMtu::new_with_config(PathConfig::direct_v4(9000), 0.0);
        assert_eq!(mtu.max_datagram_size(), CEILING);
    }

    #[test]
    fn body_capacity_tracks_the_current_datagram_size() {
        let mut mtu = PathMtu::new(Path::Direct);
        let probe = start(&mut mtu, 0.0);
        assert!(mtu.on_probe_ack(probe.id, probe.size, 1.0));
        assert_eq!(mtu.body_capacity(), 1280 - ENVELOPE_LEN - HEADER_LEN);
    }
}
