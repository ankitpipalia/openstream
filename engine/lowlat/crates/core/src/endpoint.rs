//! One peer, both state machines: connectivity first, then media.
//!
//! The shell drives this rather than the two engines separately. Classifying a
//! datagram and merging two timers are protocol decisions, not IO ones, and
//! keeping them here means they are exercised with injected time and replayable
//! from a seed. Left to the shell they would be the improvised glue that sinks
//! this kind of system: the part with no tests, written twice, once per
//! platform.
//!
//! The shell's whole job against this object is four calls:
//!
//! ```text
//! loop:
//!     timeout = endpoint.next_timer_ms(now)
//!     wait for a datagram, an application send, or that timeout
//!     for each datagram:  endpoint.process_input(bytes, from, now, scratch)
//!     endpoint.poll(now)
//!     drain:              while let Some(e) = endpoint.get_output(now, buf) { send(e) }
//! ```
//!
//! An output carries where it goes and how it must be sent, because a mapping
//! probe leaves at a TTL that must be restored afterwards and a shell cannot be
//! trusted to remember an obligation that is not in the type.

use core::net::SocketAddr;

use crate::conn::{self, Conn, Egress, Ttl};
use crate::demux::{self, Datagram};
use crate::error::Result;
use crate::pmtu::{self, PathConfig, PathMtu};
use crate::session::{self, Health, Session};

/// What an inbound datagram turned out to be.
///
/// The two engines keep their own vocabularies; nothing is gained by flattening
/// them into one enum that half the callers would have to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inbound {
    /// A connectivity check or its answer.
    Connectivity(conn::Inbound),
    /// An encrypted record.
    Media(session::Inbound),
}

/// Result of asking an endpoint to recover from a path black hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuRecovery {
    /// No path controller was configured for this endpoint.
    NotConfigured,
    /// The controller returned to BASE and the video send window was released.
    Recovered {
        previous_datagram_size: usize,
        datagram_size: usize,
        dropped_video_fragments: u32,
    },
    /// A reliable channel has an occupied fragment that cannot be represented
    /// at BASE. No send ring was changed; the owner should end the session or
    /// reconstruct that logical message at a higher layer.
    Blocked,
    /// BASE itself is unusable, so this path cannot be recovered.
    Unusable,
}

/// A peer: the punch and the session it hands over to.
#[derive(Debug)]
pub struct Endpoint<'a> {
    conn: Conn<'a>,
    session: Session<'a>,
    /// Optional path-specific DPLPMTUD controller. It is installed by the IO
    /// shell after connectivity nominates a destination, because only the
    /// shell knows the outer route/relay configuration.
    path_mtu: Option<PathMtu>,
}

impl<'a> Endpoint<'a> {
    /// Pair a connectivity attempt with the session that will use its path.
    ///
    /// Both are built by the caller, because the session needs ring storage and
    /// key material that arrive from different places at different times.
    pub fn new(conn: Conn<'a>, session: Session<'a>) -> Self {
        Self {
            conn,
            session,
            path_mtu: None,
        }
    }

    /// The connectivity engine, for candidates and outcome.
    pub fn conn(&mut self) -> &mut Conn<'a> {
        &mut self.conn
    }

    /// The session, for messages.
    pub fn session(&mut self) -> &mut Session<'a> {
        &mut self.session
    }

    /// The chosen path, once there is one. Media flows only after this.
    pub fn path(&self) -> Option<SocketAddr> {
        self.conn.path()
    }

    /// Liveness of the media session.
    pub fn health(&self, now_ms: f64) -> Health {
        self.session.health(now_ms)
    }

    /// Configure DPLPMTUD for the selected path.
    ///
    /// The initial BASE size is applied immediately. If the path cannot carry
    /// BASE or the caller's rings cannot represent it, the controller is not
    /// installed and the caller can make that policy decision explicitly.
    pub fn configure_path_mtu(&mut self, config: PathConfig, now_ms: f64) -> bool {
        let mtu = PathMtu::new_with_config(config, now_ms);
        if mtu.state() == pmtu::PathMtuState::Error
            || !self.session.set_path_datagram_size(mtu.datagram_size())
        {
            return false;
        }
        self.path_mtu = Some(mtu);
        true
    }

    /// The current path controller, when the shell has installed one.
    pub fn path_mtu(&self) -> Option<&PathMtu> {
        self.path_mtu.as_ref()
    }

    /// Recover the selected path after the delivery watchdog reports a
    /// black-hole. Only lossy video is discarded. Reliable control is
    /// preflighted first and blocks the transition if it would need unsafe
    /// re-fragmentation.
    pub fn recover_path_black_hole(&mut self, now_ms: f64) -> PathMtuRecovery {
        let Some(mtu) = self.path_mtu.as_mut() else {
            return PathMtuRecovery::NotConfigured;
        };
        let previous = mtu.datagram_size();
        if previous == pmtu::FLOOR {
            let _ = mtu.on_black_hole(now_ms);
            return PathMtuRecovery::Unusable;
        }

        if !self
            .session
            .can_recover_video_path_datagram_size(pmtu::FLOOR)
        {
            return PathMtuRecovery::Blocked;
        }
        if !mtu.on_black_hole(now_ms) {
            return PathMtuRecovery::Unusable;
        }
        let current = mtu.datagram_size();
        let Some(dropped_video_fragments) = self.session.recover_video_path_datagram_size(current)
        else {
            // The preflight above and the session's matching validation make
            // this unreachable. Keep the outcome explicit if a future ring
            // implementation adds another refusal condition.
            return PathMtuRecovery::Blocked;
        };
        // The reliable channels were intentionally retained. Give them a full
        // BASE-path delivery window before the host watchdog evaluates the
        // same old outstanding fragments a second time.
        self.session.reset_delivery_watchdog(now_ms);
        PathMtuRecovery::Recovered {
            previous_datagram_size: previous,
            datagram_size: current,
            dropped_video_fragments,
        }
    }

    /// Feed one received datagram, whatever it is.
    ///
    /// Classification happens here, on the first two bytes, before either
    /// engine sees the bytes. Anything not shaped like a check goes to the
    /// record layer, where authentication rejects it, so the check parser is
    /// never handed input that was not already check-shaped.
    pub fn process_input(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        now_ms: f64,
        scratch: &mut [u8],
    ) -> Result<Inbound> {
        match demux::classify(datagram) {
            Datagram::Check => Ok(Inbound::Connectivity(
                self.conn.process_input(datagram, from)?,
            )),
            Datagram::Record => {
                let inbound = self.session.process_input(datagram, now_ms, scratch)?;
                if let session::Inbound::ProbeAck { id, size } = inbound {
                    let new_size = self.path_mtu.as_mut().and_then(|mtu| {
                        let previous = mtu.datagram_size();
                        (mtu.on_probe_ack(id, size, now_ms) && mtu.datagram_size() != previous)
                            .then_some(mtu.datagram_size())
                    });
                    if let Some(new_size) = new_size
                        && !self.session.set_path_datagram_size(new_size)
                    {
                        // A peer has proved the path, but this caller's ring
                        // storage cannot represent the new packetization. Do
                        // not leave an active controller claiming a size the
                        // session cannot emit.
                        self.path_mtu = None;
                    }
                }
                Ok(Inbound::Media(inbound))
            }
        }
    }

    /// Housekeeping for both engines.
    pub fn poll(&mut self, now_ms: f64) {
        self.conn.poll(now_ms);
        self.session.poll(now_ms);
        if let Some(mtu) = self.path_mtu.as_mut()
            && mtu.in_flight_probe().is_some()
            && mtu.next_timer_ms(now_ms) <= 0.0
        {
            let _ = mtu.on_probe_timeout(now_ms);
        }
    }

    /// Milliseconds until either engine next needs attention.
    ///
    /// The shell arms one wait from this. Taking the minimum is the whole
    /// reason it lives here: a shell that armed from the session alone would
    /// miss every connectivity deadline, and one that armed from the
    /// connectivity engine alone would poll pointlessly once a path was chosen,
    /// because a finished attempt asks for no wakeups at all.
    pub fn next_timer_ms(&self, now_ms: f64) -> f64 {
        let path_mtu = self
            .path_mtu
            .as_ref()
            .map_or(f64::INFINITY, |mtu| mtu.next_timer_ms(now_ms));
        self.conn
            .next_timer_ms(now_ms)
            .min(self.session.next_timer_ms(now_ms))
            .min(path_mtu)
    }

    /// Emit the next datagram, with where it goes and how to send it.
    ///
    /// Connectivity drains first. Its datagrams are small, time critical, and
    /// owed to a peer that reads silence as unreachable; and until a path
    /// exists there is nowhere to send media anyway.
    pub fn get_output(&mut self, now_ms: f64, out: &mut [u8]) -> Option<Result<Egress>> {
        if let Some(result) = self.conn.get_output(now_ms, out) {
            return Some(result);
        }

        // No path, no destination. The session may have output ready; it waits.
        let to = self.conn.path()?;

        // Any acknowledgement is feedback for the peer's current send window
        // or PMTU search and must leave before we spend the output slot on a new
        // upward probe.
        if self.session.feedback_pending() {
            return Some(match self.session.get_output(now_ms, out)? {
                Ok(len) => Ok(Egress {
                    to,
                    ttl: Ttl::Default,
                    len,
                }),
                Err(error) => Err(error),
            });
        }

        if let Some(mtu) = self.path_mtu.as_mut()
            && let Some(probe) = mtu.start_probe(now_ms)
        {
            return Some(match self.session.emit_path_probe(probe, out) {
                Ok(len) => Ok(Egress {
                    to,
                    ttl: Ttl::Default,
                    len,
                }),
                Err(error) => {
                    let _ = mtu.on_probe_send_failed();
                    Err(error)
                }
            });
        }

        Some(match self.session.get_output(now_ms, out)? {
            Ok(len) => Ok(Egress {
                to,
                ttl: Ttl::Default,
                len,
            }),
            Err(error) => Err(error),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{RecvRing, SlotMeta};
    use crate::conn::{Credentials, State};
    use crate::envelope::{Direction, Envelope};
    use crate::send::{SendRing, SendSlot};
    use core::net::{IpAddr, Ipv4Addr};
    use std::vec::Vec;

    const SLOT: usize = 128;
    const SLOTS: usize = 64;
    const STORAGE_BODY: usize =
        crate::MAX_DATAGRAM - crate::envelope::ENVELOPE_LEN - crate::packet::HEADER_LEN;
    const ACTIVE_BODY: usize =
        crate::DEFAULT_DATAGRAM - crate::envelope::ENVELOPE_LEN - crate::packet::HEADER_LEN;
    const KEY: [u8; 32] = [0x2Bu8; 32];
    const CHANNEL: u8 = 1;

    const LEFT_UFRAG: &str = "aaaa";
    const LEFT_PWD: &str = "passwordforaaaa";
    const RIGHT_UFRAG: &str = "bbbb";
    const RIGHT_PWD: &str = "passwordforbbbb";

    struct Arena {
        recv_bodies: Vec<u8>,
        recv_meta: Vec<SlotMeta>,
        send_bodies: Vec<u8>,
        send_meta: Vec<SendSlot>,
    }

    impl Arena {
        fn new() -> Self {
            Self {
                recv_bodies: std::vec![0u8; SLOT * SLOTS],
                recv_meta: std::vec![SlotMeta::default(); SLOTS],
                send_bodies: std::vec![0u8; SLOT * SLOTS],
                send_meta: std::vec![SendSlot::default(); SLOTS],
            }
        }
    }

    struct WideArena {
        recv_bodies: Vec<u8>,
        recv_meta: Vec<SlotMeta>,
        send_bodies: Vec<u8>,
        send_meta: Vec<SendSlot>,
    }

    impl WideArena {
        fn new() -> Self {
            Self {
                recv_bodies: std::vec![0u8; STORAGE_BODY * SLOTS],
                recv_meta: std::vec![SlotMeta::default(); SLOTS],
                send_bodies: std::vec![0u8; STORAGE_BODY * SLOTS],
                send_meta: std::vec![SendSlot::default(); SLOTS],
            }
        }
    }

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)), port)
    }

    fn endpoint<'a>(
        arena: &'a mut Arena,
        ours: (&'a str, &'a str),
        theirs: (&'a str, &'a str),
        seed: u8,
    ) -> Endpoint<'a> {
        endpoint_directed(arena, ours, theirs, seed, Direction::Host)
    }

    fn endpoint_guest<'a>(
        arena: &'a mut Arena,
        ours: (&'a str, &'a str),
        theirs: (&'a str, &'a str),
        seed: u8,
    ) -> Endpoint<'a> {
        endpoint_directed(arena, ours, theirs, seed, Direction::Guest)
    }

    fn endpoint_directed<'a>(
        arena: &'a mut Arena,
        ours: (&'a str, &'a str),
        theirs: (&'a str, &'a str),
        seed: u8,
        direction: Direction,
    ) -> Endpoint<'a> {
        let conn = Conn::new(
            Credentials {
                local_ufrag: ours.0,
                local_pwd: ours.1,
                remote_ufrag: theirs.0,
                remote_pwd: theirs.1,
            },
            [seed; 16],
            0.0,
        );
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), direction, 1, 0.0);
        session
            .attach_recv(
                CHANNEL,
                RecvRing::new(&mut arena.recv_bodies, &mut arena.recv_meta, SLOT).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                CHANNEL,
                SendRing::new(&mut arena.send_bodies, &mut arena.send_meta, SLOT, CHANNEL).unwrap(),
            )
            .unwrap();
        Endpoint::new(conn, session)
    }

    fn wide_endpoint<'a>(
        arena: &'a mut WideArena,
        ours: (&'a str, &'a str),
        theirs: (&'a str, &'a str),
        seed: u8,
        direction: Direction,
    ) -> Endpoint<'a> {
        let conn = Conn::new(
            Credentials {
                local_ufrag: ours.0,
                local_pwd: ours.1,
                remote_ufrag: theirs.0,
                remote_pwd: theirs.1,
            },
            [seed; 16],
            0.0,
        );
        let mut session =
            Session::with_direction(Envelope::from_key(&KEY).unwrap(), direction, 1, 0.0);
        session
            .attach_recv(
                CHANNEL,
                RecvRing::new(&mut arena.recv_bodies, &mut arena.recv_meta, STORAGE_BODY).unwrap(),
            )
            .unwrap();
        session
            .attach_send(
                CHANNEL,
                SendRing::new_with_capacity(
                    &mut arena.send_bodies,
                    &mut arena.send_meta,
                    STORAGE_BODY,
                    ACTIVE_BODY,
                    CHANNEL,
                )
                .unwrap(),
            )
            .unwrap();
        Endpoint::new(conn, session)
    }

    /// Move everything one side wants to send to the other, as the shell would.
    fn pump(
        from: &mut Endpoint<'_>,
        from_addr: SocketAddr,
        to: &mut Endpoint<'_>,
        now: f64,
    ) -> usize {
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let mut moved = 0;
        while let Some(result) = from.get_output(now, &mut wire) {
            let egress = result.unwrap();
            to.process_input(&wire[..egress.len], from_addr, now, &mut scratch)
                .unwrap();
            moved += 1;
        }
        moved
    }

    fn pump_wide(
        from: &mut Endpoint<'_>,
        from_addr: SocketAddr,
        to: &mut Endpoint<'_>,
        now: f64,
        wire: &mut [u8],
        scratch: &mut [u8],
    ) -> usize {
        let mut moved = 0;
        while let Some(result) = from.get_output(now, wire) {
            let egress = result.unwrap();
            to.process_input(&wire[..egress.len], from_addr, now, scratch)
                .unwrap();
            moved += 1;
        }
        moved
    }

    /// The whole point of the facade: one object goes from punching to carrying
    /// media without the caller sequencing the two engines by hand.
    #[test]
    fn an_endpoint_punches_and_then_carries_a_message() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(
            &mut left_arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
        );
        let mut right = endpoint_guest(
            &mut right_arena,
            (RIGHT_UFRAG, RIGHT_PWD),
            (LEFT_UFRAG, LEFT_PWD),
            0xB2,
        );

        let left_addr = addr(10, 5000);
        let right_addr = addr(20, 6000);
        left.conn().add_candidate(right_addr).unwrap();
        right.conn().add_candidate(left_addr).unwrap();

        // Media queued before a path exists must wait, not vanish.
        left.session()
            .send_message(CHANNEL, b"hdr", b"body")
            .unwrap();

        let mut now = 0.0;
        while now < 2_000.0 && (left.path().is_none() || right.path().is_none()) {
            pump(&mut left, left_addr, &mut right, now);
            pump(&mut right, right_addr, &mut left, now);
            now += 10.0;
            left.poll(now);
            right.poll(now);
        }

        assert_eq!(left.path(), Some(right_addr), "left found no path");
        assert_eq!(right.path(), Some(left_addr), "right found no path");

        // Now the queued message crosses, addressed to the chosen path.
        for _ in 0..8 {
            pump(&mut left, left_addr, &mut right, now);
            pump(&mut right, right_addr, &mut left, now);
            now += 10.0;
            left.poll(now);
            right.poll(now);
        }

        let mut out = [0u8; 256];
        let len = right
            .session()
            .take_message(CHANNEL, &mut out)
            .expect("no message arrived")
            .unwrap();
        assert_eq!(&out[..len], b"hdrbody");
    }

    /// Media has nowhere to go before a path is chosen, and must not be emitted
    /// to some default destination or silently dropped.
    #[test]
    fn nothing_media_shaped_leaves_before_a_path_exists() {
        let mut arena = Arena::new();
        let mut endpoint = endpoint(
            &mut arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
        );
        endpoint.session().send_message(CHANNEL, &[], b"x").unwrap();

        // No candidate, so connectivity has nothing to emit either.
        let mut wire = [0u8; 512];
        assert!(endpoint.get_output(0.0, &mut wire).is_none());
        assert_eq!(endpoint.path(), None);
    }

    /// A shell arming from one engine alone gets the wrong answer in both
    /// directions, which is why the minimum is taken here rather than there.
    #[test]
    fn the_timer_is_the_sooner_of_the_two() {
        let mut arena = Arena::new();
        let mut endpoint = endpoint(
            &mut arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
        );

        // A fresh candidate is due immediately, well inside the acknowledgement
        // cadence, so connectivity sets the deadline.
        endpoint.conn().add_candidate(addr(20, 6000)).unwrap();
        assert!(endpoint.next_timer_ms(0.0).abs() < 1e-9);

        // Once the attempt is over it asks for nothing, and the session's
        // cadence is all that remains. An endpoint that kept the connectivity
        // timer here would poll forever.
        endpoint.poll(conn::PUNCH_WINDOW_MS);
        assert!(matches!(endpoint.conn().state(), State::Failed(_)));
        let timer = endpoint.next_timer_ms(conn::PUNCH_WINDOW_MS);
        assert!(
            timer.is_finite() && timer <= session::ACK_CADENCE_MS,
            "expected the session cadence, got {timer}"
        );
    }

    /// Classification decides which engine sees a datagram, and a record must
    /// never reach the check parser however it is shaped.
    #[test]
    fn a_record_and_a_check_reach_different_engines() {
        let mut left_arena = Arena::new();
        let mut right_arena = Arena::new();
        let mut left = endpoint(
            &mut left_arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
        );
        let mut right = endpoint_guest(
            &mut right_arena,
            (RIGHT_UFRAG, RIGHT_PWD),
            (LEFT_UFRAG, LEFT_PWD),
            0xB2,
        );

        let left_addr = addr(10, 5000);
        left.conn().add_candidate(addr(20, 6000)).unwrap();

        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let egress = left.get_output(0.0, &mut wire).unwrap().unwrap();
        assert!(matches!(
            right
                .process_input(&wire[..egress.len], left_addr, 0.0, &mut scratch)
                .unwrap(),
            Inbound::Connectivity(_)
        ));

        // And a sealed record classifies the other way.
        let mut left2_arena = Arena::new();
        let mut solo = endpoint(
            &mut left2_arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xC3,
        );
        solo.session().send_message(CHANNEL, &[], b"x").unwrap();
        let len = solo.session().get_output(0.0, &mut wire).unwrap().unwrap();
        assert!(matches!(
            right
                .process_input(&wire[..len], left_addr, 0.0, &mut scratch)
                .unwrap(),
            Inbound::Media(_)
        ));
    }

    /// The endpoint owns the complete PMTU feedback loop: a selected path
    /// emits an exact-size probe, the peer returns a probe acknowledgement, and
    /// the sender adopts that size for future packetization and pacing.
    #[test]
    fn a_selected_endpoint_probes_and_adopts_the_confirmed_size() {
        let mut left_arena = WideArena::new();
        let mut right_arena = WideArena::new();
        let mut left = wide_endpoint(
            &mut left_arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
            Direction::Host,
        );
        let mut right = wide_endpoint(
            &mut right_arena,
            (RIGHT_UFRAG, RIGHT_PWD),
            (LEFT_UFRAG, LEFT_PWD),
            0xB2,
            Direction::Guest,
        );
        let left_addr = addr(10, 5000);
        let right_addr = addr(20, 6000);
        left.conn().add_candidate(right_addr).unwrap();
        right.conn().add_candidate(left_addr).unwrap();

        let mut wire = [0u8; crate::MAX_DATAGRAM];
        let mut scratch = [0u8; crate::MAX_DATAGRAM];
        let mut now = 0.0;
        while now < 2_000.0 && (left.path().is_none() || right.path().is_none()) {
            pump_wide(
                &mut left,
                left_addr,
                &mut right,
                now,
                &mut wire,
                &mut scratch,
            );
            pump_wide(
                &mut right,
                right_addr,
                &mut left,
                now,
                &mut wire,
                &mut scratch,
            );
            now += 10.0;
            left.poll(now);
            right.poll(now);
        }
        assert!(left.path().is_some() && right.path().is_some());
        // Path nomination can happen while the answering STUN response is
        // still queued. Drain that connectivity tail before the PMTU test so
        // the first media-priority output is the probe, not a final check.
        while pump_wide(
            &mut left,
            left_addr,
            &mut right,
            now,
            &mut wire,
            &mut scratch,
        ) + pump_wide(
            &mut right,
            right_addr,
            &mut left,
            now,
            &mut wire,
            &mut scratch,
        ) > 0
        {}
        assert!(left.configure_path_mtu(PathConfig::direct_v4(1500), now));
        assert!(right.configure_path_mtu(PathConfig::direct_v4(1500), now));

        // A regular data arrival makes a group ACK due. Endpoint scheduling
        // must honor that feedback before reserving an upward PMTU probe.
        right
            .session()
            .send_message(CHANNEL, b"ack", b"data")
            .unwrap();
        let data = right
            .session()
            .get_output(now + 1.0, &mut wire)
            .unwrap()
            .unwrap();
        left.session()
            .process_input(&wire[..data], now + 1.0, &mut scratch)
            .unwrap();
        assert!(left.session().feedback_pending());
        let feedback = left.get_output(now + 2.0, &mut wire).unwrap().unwrap();
        assert_eq!(
            feedback.len,
            crate::envelope::ENVELOPE_LEN + crate::packet::ACK_LEN
        );
        assert!(!left.session().feedback_pending());

        let probe = left.get_output(now + 2.0, &mut wire).unwrap().unwrap();
        assert_eq!(probe.len, 1280);
        assert_eq!(
            left.path_mtu().unwrap().in_flight_probe().unwrap().size,
            1280
        );
        assert!(matches!(
            right
                .process_input(&wire[..probe.len], left_addr, now + 2.0, &mut scratch)
                .unwrap(),
            Inbound::Media(session::Inbound::Probe { size: 1280, .. })
        ));

        let ack = right.get_output(now + 3.0, &mut wire).unwrap().unwrap();
        assert!(matches!(
            left.process_input(&wire[..ack.len], right_addr, now + 3.0, &mut scratch)
                .unwrap(),
            Inbound::Media(session::Inbound::ProbeAck { size: 1280, .. })
        ));
        assert_eq!(left.path_mtu().unwrap().datagram_size(), 1280);
        assert_eq!(left.session().path_datagram_size(), 1280);
        assert_eq!(left.session().pacing_datagram_size(), 1280);
    }

    /// A delivery watchdog downgrade is integrated at the endpoint boundary:
    /// only queued video is abandoned, the sequence space remains monotonic,
    /// and the controller plus packetizer return to BASE together.
    #[test]
    fn a_black_hole_recovery_resets_video_at_the_endpoint_boundary() {
        let mut left_arena = WideArena::new();
        let mut right_arena = WideArena::new();
        let mut left = wide_endpoint(
            &mut left_arena,
            (LEFT_UFRAG, LEFT_PWD),
            (RIGHT_UFRAG, RIGHT_PWD),
            0xA1,
            Direction::Host,
        );
        let mut right = wide_endpoint(
            &mut right_arena,
            (RIGHT_UFRAG, RIGHT_PWD),
            (LEFT_UFRAG, LEFT_PWD),
            0xB2,
            Direction::Guest,
        );
        let left_addr = addr(10, 5000);
        let right_addr = addr(20, 6000);
        left.conn().add_candidate(right_addr).unwrap();
        right.conn().add_candidate(left_addr).unwrap();

        let mut wire = [0u8; crate::MAX_DATAGRAM];
        let mut scratch = [0u8; crate::MAX_DATAGRAM];
        let mut now = 0.0;
        while now < 2_000.0 && (left.path().is_none() || right.path().is_none()) {
            pump_wide(
                &mut left,
                left_addr,
                &mut right,
                now,
                &mut wire,
                &mut scratch,
            );
            pump_wide(
                &mut right,
                right_addr,
                &mut left,
                now,
                &mut wire,
                &mut scratch,
            );
            now += 10.0;
            left.poll(now);
            right.poll(now);
        }
        while pump_wide(
            &mut left,
            left_addr,
            &mut right,
            now,
            &mut wire,
            &mut scratch,
        ) + pump_wide(
            &mut right,
            right_addr,
            &mut left,
            now,
            &mut wire,
            &mut scratch,
        ) > 0
        {}
        assert!(left.configure_path_mtu(PathConfig::direct_v4(1500), now));
        assert!(right.configure_path_mtu(PathConfig::direct_v4(1500), now));

        let probe = left.get_output(now, &mut wire).unwrap().unwrap();
        right
            .process_input(&wire[..probe.len], left_addr, now, &mut scratch)
            .unwrap();
        let ack = right.get_output(now + 1.0, &mut wire).unwrap().unwrap();
        left.process_input(&wire[..ack.len], right_addr, now + 1.0, &mut scratch)
            .unwrap();
        assert_eq!(left.session().path_datagram_size(), 1280);

        left.session()
            .send_message(CHANNEL, &[], &[0x5A; 1200])
            .unwrap();
        assert_eq!(
            left.recover_path_black_hole(now + 2_000.0),
            PathMtuRecovery::Recovered {
                previous_datagram_size: 1280,
                datagram_size: crate::DEFAULT_DATAGRAM,
                dropped_video_fragments: 1,
            }
        );
        assert_eq!(left.session().path_datagram_size(), crate::DEFAULT_DATAGRAM);
        assert_eq!(
            left.path_mtu().unwrap().datagram_size(),
            crate::DEFAULT_DATAGRAM
        );
    }
}
