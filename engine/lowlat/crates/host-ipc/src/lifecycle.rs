//! The capture/login lifecycle: what the broker captures as the seat moves
//! from the greeter to a logged-in user, and how an approved peer survives that
//! transition.
//!
//! A machine-level host starts before anyone logs in. It must show the remote
//! client the login screen, let them type the OS password into the *native*
//! greeter, and then continue into that user's desktop **without dropping the
//! connection**. Two things vary independently:
//!
//!   - the **seat**: empty at early boot, then the greeter, then a user session
//!     (reported by logind on Linux, and by the equivalent session monitor on
//!     other platforms);
//!   - the **link**: whether an approved remote peer is connected and expects
//!     frames.
//!
//! This is a pure reducer over those two inputs (plus whether a session-agent
//! inside the user session is offering a PipeWire stream). It emits the capture
//! side effects the broker and machine service must perform. The invariant that
//! matters, and is unit-tested below, is that **no seat change ever emits an
//! action that tears down the peer**: a login re-points capture, it does not
//! drop the connection. The reducer holds no OS handles, so every transition is
//! verifiable off a live seat.

/// What the seat is showing, as observed from the platform session monitor
/// (logind on Linux). Deliberately platform-agnostic so the same lifecycle
/// drives every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seat {
    /// No graphical session on the seat yet: early boot, or the gap between one
    /// session ending and the next starting. Nothing to capture.
    Empty,
    /// The display manager's login/greeter screen, before any user logs in.
    Greeter,
    /// A logged-in user's graphical session.
    User,
}

/// How the active seat is being captured. The greeter is always a raw scanout
/// (the privileged broker reads DRM/KMS); a user session starts the same way
/// and can be upgraded to a PipeWire stream once a session-agent running inside
/// that session offers one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    /// DRM/KMS scanout read by the privileged broker. The only option that
    /// works before login, and a valid fallback after it.
    Scanout,
    /// A PipeWire stream handed over by a session-agent in the user session.
    /// Cleaner (portal-mediated, cursor-composited) but only after login.
    PipeWire,
}

/// Whether an approved remote peer is connected. Pending connections and the
/// approval decision live in the machine service; the lifecycle only needs to
/// know when a peer becomes streamable and when it goes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// No approved peer. Nothing should be streaming.
    Down,
    /// An approved peer is connected and expects frames.
    Up,
}

/// An observation that can move the lifecycle forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The session monitor reports the seat is now showing this.
    SeatObserved(Seat),
    /// A session-agent inside the active user session offers a PipeWire stream.
    /// Ignored unless a user session is actually active.
    AgentOffersPipeWire,
    /// The session-agent's PipeWire offer is withdrawn (it crashed, or the user
    /// logged out). Capture falls back to scanout while a user session remains.
    AgentGone,
    /// The machine service established and approved a remote peer.
    PeerApproved,
    /// The approved peer disconnected or was revoked.
    PeerLost,
}

/// A capture side effect for the broker and machine service to perform. There
/// is deliberately no "drop peer" action here: the peer's fate is driven only
/// by [`Event::PeerApproved`]/[`Event::PeerLost`], never by a seat change, so a
/// login transition cannot end the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Begin capturing the given seat with the given source (there was nothing
    /// capturing before).
    StartCapture(Seat, CaptureKind),
    /// Re-point the live capture to a new seat or source *without* dropping the
    /// peer. Emitted on a greeter->user login, a user->greeter logout, and a
    /// scanout->PipeWire upgrade.
    SwitchCapture(Seat, CaptureKind),
    /// Stop producing frames: the peer is gone, or the seat has nothing to show.
    StopCapture,
    /// Ask the encoder for an IDR/keyframe so the client's decoder recovers
    /// immediately after a source switch, rather than waiting for the next
    /// periodic keyframe on a stream whose reference frames just became invalid.
    RequestKeyframe,
}

/// The capture/login lifecycle reducer.
///
/// Feed it [`Event`]s; it returns the [`Action`]s to apply and updates its
/// state. Construct it with [`Lifecycle::new`] at boot (empty seat, no peer).
#[derive(Debug, Clone)]
pub struct Lifecycle {
    seat: Seat,
    link: Link,
    /// Whether a user session-agent currently offers PipeWire. Only meaningful
    /// while `seat == User`; cleared whenever the seat leaves a user session.
    agent_pipewire: bool,
    /// What the broker is capturing right now, or `None` when idle.
    capturing: Option<(Seat, CaptureKind)>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// A freshly booted host: empty seat, no peer, capturing nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seat: Seat::Empty,
            link: Link::Down,
            agent_pipewire: false,
            capturing: None,
        }
    }

    /// The seat currently observed.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// Whether an approved peer is connected.
    #[must_use]
    pub fn link(&self) -> Link {
        self.link
    }

    /// What the broker is capturing right now, if anything.
    #[must_use]
    pub fn capturing(&self) -> Option<(Seat, CaptureKind)> {
        self.capturing
    }

    /// Apply one event, returning the side effects to perform in order.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::SeatObserved(seat) => {
                if seat != Seat::User {
                    // A greeter or empty seat cannot have a user session-agent;
                    // any prior PipeWire offer belonged to a session that is now
                    // gone, so it must not carry over into the next one.
                    self.agent_pipewire = false;
                }
                self.seat = seat;
            }
            Event::AgentOffersPipeWire => {
                // Only a live user session can offer a session-agent stream.
                if self.seat == Seat::User {
                    self.agent_pipewire = true;
                }
            }
            Event::AgentGone => self.agent_pipewire = false,
            Event::PeerApproved => self.link = Link::Up,
            Event::PeerLost => self.link = Link::Down,
        }
        self.reconcile()
    }

    /// What the broker *should* be capturing given the current inputs: nothing
    /// while no peer is connected or the seat is empty, the greeter scanout at
    /// the login screen, and the user session as scanout until a session-agent
    /// upgrades it to PipeWire.
    fn desired(&self) -> Option<(Seat, CaptureKind)> {
        if self.link == Link::Down {
            return None;
        }
        match self.seat {
            Seat::Empty => None,
            Seat::Greeter => Some((Seat::Greeter, CaptureKind::Scanout)),
            Seat::User => {
                let kind = if self.agent_pipewire {
                    CaptureKind::PipeWire
                } else {
                    CaptureKind::Scanout
                };
                Some((Seat::User, kind))
            }
        }
    }

    /// Move the live capture toward what it should be, emitting the minimal set
    /// of actions. A change of target while already capturing is a `Switch`,
    /// never a stop-then-start, so the peer keeps receiving frames across it.
    fn reconcile(&mut self) -> Vec<Action> {
        let desired = self.desired();
        match (self.capturing, desired) {
            // Already where it should be (including both idle): nothing to do.
            (None, None) => Vec::new(),
            (Some(current), Some(target)) if current == target => Vec::new(),
            // Nothing was capturing: start, then a fresh keyframe for the peer.
            (None, Some(target)) => {
                self.capturing = Some(target);
                vec![
                    Action::StartCapture(target.0, target.1),
                    Action::RequestKeyframe,
                ]
            }
            // A different target while already live: re-point in place so the
            // peer keeps receiving frames, then a keyframe to reset references.
            (Some(_), Some(target)) => {
                self.capturing = Some(target);
                vec![
                    Action::SwitchCapture(target.0, target.1),
                    Action::RequestKeyframe,
                ]
            }
            // Nothing to show any more: stop, but the peer stays connected.
            (Some(_), None) => {
                self.capturing = None;
                vec![Action::StopCapture]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a fresh lifecycle through a list of events and return the actions
    /// from the final event, for the common "set up, then assert one step" case.
    fn after(events: &[Event]) -> (Lifecycle, Vec<Action>) {
        let mut life = Lifecycle::new();
        let mut last = Vec::new();
        for &event in events {
            last = life.on(event);
        }
        (life, last)
    }

    #[test]
    fn boots_idle_and_does_nothing_without_a_peer() {
        let mut life = Lifecycle::new();
        assert_eq!(life.capturing(), None);
        // Seats come and go before anyone connects; nothing should capture.
        assert_eq!(life.on(Event::SeatObserved(Seat::Greeter)), vec![]);
        assert_eq!(life.on(Event::SeatObserved(Seat::User)), vec![]);
        assert_eq!(life.capturing(), None);
        assert_eq!(life.link(), Link::Down);
    }

    #[test]
    fn peer_at_the_greeter_starts_scanout_capture() {
        let (life, actions) = after(&[Event::SeatObserved(Seat::Greeter), Event::PeerApproved]);
        assert_eq!(
            actions,
            vec![
                Action::StartCapture(Seat::Greeter, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
        assert_eq!(
            life.capturing(),
            Some((Seat::Greeter, CaptureKind::Scanout))
        );
    }

    #[test]
    fn login_switches_capture_without_dropping_the_peer() {
        // Connected at the greeter, then the user logs in.
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::Greeter));
        life.on(Event::PeerApproved);
        assert_eq!(life.link(), Link::Up);

        let actions = life.on(Event::SeatObserved(Seat::User));

        // Capture re-points to the user session; the peer is untouched.
        assert_eq!(
            actions,
            vec![
                Action::SwitchCapture(Seat::User, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
        assert!(
            !actions.contains(&Action::StopCapture),
            "a login must not stop-then-start; it switches"
        );
        assert_eq!(life.link(), Link::Up, "the peer survives the login");
        assert_eq!(life.capturing(), Some((Seat::User, CaptureKind::Scanout)));
    }

    #[test]
    fn session_agent_upgrades_scanout_to_pipewire() {
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        assert_eq!(life.capturing(), Some((Seat::User, CaptureKind::Scanout)));

        let actions = life.on(Event::AgentOffersPipeWire);
        assert_eq!(
            actions,
            vec![
                Action::SwitchCapture(Seat::User, CaptureKind::PipeWire),
                Action::RequestKeyframe,
            ]
        );
        assert_eq!(life.capturing(), Some((Seat::User, CaptureKind::PipeWire)));
        assert_eq!(life.link(), Link::Up);
    }

    #[test]
    fn losing_the_session_agent_falls_back_to_scanout() {
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        life.on(Event::AgentOffersPipeWire);
        assert_eq!(life.capturing(), Some((Seat::User, CaptureKind::PipeWire)));

        let actions = life.on(Event::AgentGone);
        assert_eq!(
            actions,
            vec![
                Action::SwitchCapture(Seat::User, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
        assert_eq!(life.link(), Link::Up);
    }

    #[test]
    fn logout_returns_to_greeter_capture_and_keeps_the_peer() {
        // A user is being streamed over PipeWire, then logs out. The host must
        // fall back to the greeter (pre-login screen) and keep the peer.
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        life.on(Event::AgentOffersPipeWire);

        let actions = life.on(Event::SeatObserved(Seat::Greeter));
        assert_eq!(
            actions,
            vec![
                Action::SwitchCapture(Seat::Greeter, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
        assert_eq!(life.link(), Link::Up, "logout must not drop the peer");
        assert_eq!(
            life.capturing(),
            Some((Seat::Greeter, CaptureKind::Scanout))
        );
    }

    #[test]
    fn a_pipewire_offer_from_the_previous_session_does_not_leak_across_logout() {
        // PipeWire on the user session, log out to greeter, then a new user logs
        // in. The new user's capture must start as scanout, not silently inherit
        // the old session's PipeWire offer.
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        life.on(Event::AgentOffersPipeWire);
        life.on(Event::SeatObserved(Seat::Greeter));

        let actions = life.on(Event::SeatObserved(Seat::User));
        assert_eq!(
            actions,
            vec![
                Action::SwitchCapture(Seat::User, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
        assert_eq!(life.capturing(), Some((Seat::User, CaptureKind::Scanout)));
    }

    #[test]
    fn peer_loss_stops_capture_and_reconnect_resumes_it() {
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        assert!(life.capturing().is_some());

        assert_eq!(life.on(Event::PeerLost), vec![Action::StopCapture]);
        assert_eq!(life.capturing(), None);
        assert_eq!(life.link(), Link::Down);

        // A later reconnect starts capture again from the seat as it stands now.
        let actions = life.on(Event::PeerApproved);
        assert_eq!(
            actions,
            vec![
                Action::StartCapture(Seat::User, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
    }

    #[test]
    fn an_empty_seat_holds_frames_but_keeps_the_peer() {
        // Approved at the greeter, then the greeter goes away (session teardown)
        // before the next one appears. Nothing to show, but the peer stays.
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::Greeter));
        life.on(Event::PeerApproved);

        let actions = life.on(Event::SeatObserved(Seat::Empty));
        assert_eq!(actions, vec![Action::StopCapture]);
        assert_eq!(
            life.link(),
            Link::Up,
            "an empty seat must not drop the peer"
        );
        assert_eq!(life.capturing(), None);

        // When a seat reappears, capture resumes for the still-connected peer.
        let actions = life.on(Event::SeatObserved(Seat::Greeter));
        assert_eq!(
            actions,
            vec![
                Action::StartCapture(Seat::Greeter, CaptureKind::Scanout),
                Action::RequestKeyframe,
            ]
        );
    }

    #[test]
    fn re_observing_the_same_seat_is_a_no_op() {
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::User));
        life.on(Event::PeerApproved);
        // logind re-emits the same active session repeatedly; it must not cause
        // a spurious switch or a redundant keyframe request.
        assert_eq!(life.on(Event::SeatObserved(Seat::User)), vec![]);
        assert_eq!(life.on(Event::SeatObserved(Seat::User)), vec![]);
    }

    #[test]
    fn a_pipewire_offer_at_the_greeter_is_ignored() {
        let mut life = Lifecycle::new();
        life.on(Event::SeatObserved(Seat::Greeter));
        life.on(Event::PeerApproved);
        // There is no user session, so an errant PipeWire offer changes nothing.
        assert_eq!(life.on(Event::AgentOffersPipeWire), vec![]);
        assert_eq!(
            life.capturing(),
            Some((Seat::Greeter, CaptureKind::Scanout))
        );
    }

    #[test]
    fn no_seat_event_ever_changes_the_link() {
        // The core safety property: whatever the seat does, it never flips the
        // link. Only PeerApproved/PeerLost may. Exhaustively drive seat and
        // agent events from an Up link and assert it stays Up.
        let seat_events = [
            Event::SeatObserved(Seat::Empty),
            Event::SeatObserved(Seat::Greeter),
            Event::SeatObserved(Seat::User),
            Event::AgentOffersPipeWire,
            Event::AgentGone,
        ];
        for &first in &seat_events {
            for &second in &seat_events {
                let mut life = Lifecycle::new();
                life.on(Event::SeatObserved(Seat::Greeter));
                life.on(Event::PeerApproved);
                assert_eq!(life.link(), Link::Up);
                life.on(first);
                life.on(second);
                assert_eq!(
                    life.link(),
                    Link::Up,
                    "seat/agent events {first:?} then {second:?} must not drop the link"
                );
            }
        }
    }
}
