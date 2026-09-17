//! Driving one Connect request from the desktop shell.
//!
//! # Why the decision logic is separate from the HTTP
//!
//! Asking a device for a session is a small state machine -- ask, wait, and
//! then either start a session, report a refusal, or give up -- wrapped in a
//! poll loop over a network call. The loop is untestable on a developer
//! machine without a running service and a second device; the state machine
//! is where the mistakes live.
//!
//! So the machine is a pure function over one observation, and the loop is
//! the thin part around it. A wrong verdict here is a session that never
//! starts or, worse, one that starts without an approval, and neither should
//! depend on having a control plane to hand in order to be tested.

use crate::control_plane::{ConnectObservation, ConnectState};
use openstream_client_core::{Role, RoleCredential};

/// How long to keep asking before giving up on a request.
///
/// Slightly under the broker's own request lifetime, so the shell reports
/// "nobody answered" rather than waiting for the service to expire the
/// request and then reporting "not found", which reads like a fault.
pub const CONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(110);

/// How often to ask.
///
/// Fast enough that approval feels immediate, slow enough that a forgotten
/// request costs a couple of hundred polls rather than tens of thousands.
pub const CONNECT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// What the shell should do next about a request it is waiting on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectStep {
    /// Nobody has answered yet. Ask again after the poll interval.
    KeepWaiting,
    /// Approved. Start the session with this capability.
    Start(Box<RoleCredential>),
    /// The person at the other machine said no.
    Refused,
    /// Nobody answered in time, or the request is gone.
    Abandoned,
}

/// Decide what one observation means.
///
/// `expires` is whether the shell's own deadline has passed. It is a
/// parameter rather than a clock read so the decision stays pure: a test
/// asserting what a timed-out request does should not have to wait for one.
#[must_use]
pub fn interpret(observation: ConnectObservation, expired: bool) -> ConnectStep {
    match observation {
        ConnectObservation::Granted(credential) => {
            // The broker answers the requester's endpoint, so this is always
            // the client end. Checked rather than assumed: acting on a host
            // capability here would start the wrong runner against the wrong
            // token, and the failure would surface much later.
            if credential.role != "client" {
                return ConnectStep::Abandoned;
            }
            ConnectStep::Start(Box::new(RoleCredential {
                session_id: credential.session_id,
                role: Role::Client,
                token: credential.token,
                websocket_path: credential.websocket_path,
                // The broker does not restate the session lifetime here; the
                // session's own expiry governs, and the runner learns it from
                // the service. Zero rather than a guess: a wrong number would
                // be treated as authoritative by whoever read it next.
                expires_in_seconds: 0,
                relay_address: credential.relay_address,
                relay_ticket: Some(credential.relay_ticket),
                turn: None,
                // What the host granted when it approved this request. The
                // broker returns it with the client credential too, so the
                // client scopes itself to the same ceiling the host enforces
                // rather than discovering the limit by being refused.
                permissions: credential
                    .permissions
                    .map(crate::control_plane::granted_permissions),
            }))
        }
        ConnectObservation::Waiting { state } => match state {
            ConnectState::Pending => {
                if expired {
                    ConnectStep::Abandoned
                } else {
                    ConnectStep::KeepWaiting
                }
            }
            ConnectState::Denied => ConnectStep::Refused,
            // An approval the shell polled for and did not receive as a
            // credential means another poll already collected it, or the
            // window closed. Either way there is nothing here to start with.
            ConnectState::Approved | ConnectState::Expired => ConnectStep::Abandoned,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, ConnectStep, CONNECT_POLL_INTERVAL, CONNECT_WAIT};
    use crate::control_plane::{ConnectCredential, ConnectObservation, ConnectState};
    use openstream_app_core::PermissionSet;

    fn granted(role: &str) -> ConnectObservation {
        granted_with(role, None)
    }

    fn granted_with(role: &str, permissions: Option<PermissionSet>) -> ConnectObservation {
        ConnectObservation::Granted(Box::new(ConnectCredential {
            session_id: "session-1".into(),
            role: role.into(),
            token: "CLIENT-CAPABILITY".into(),
            websocket_path: "/v1/signal/session-1/client".into(),
            relay_address: None,
            relay_ticket: "ticket".into(),
            permissions,
        }))
    }

    /// An approval becomes a session, carrying the capability through.
    #[test]
    fn an_approval_starts_a_session_with_the_client_capability() {
        let ConnectStep::Start(credential) = interpret(granted("client"), false) else {
            panic!("an approved request must start a session");
        };
        assert_eq!(credential.session_id, "session-1");
        assert_eq!(credential.token, "CLIENT-CAPABILITY");
        assert_eq!(credential.relay_ticket.as_deref(), Some("ticket"));
    }

    /// A narrowed grant survives every layer between the broker and the
    /// runner's own policy.
    ///
    /// This is the test the feature was missing. Permissions were negotiated
    /// by the broker, rendered by the approval modal and enforced by the host
    /// policy, but the desktop credential in the middle had no field for them:
    /// the decision parsed and was dropped, every conversion wrote `None`, and
    /// `None` means unscoped, so a host that granted keyboard-only still ran a
    /// session with the mouse live. Each layer passed its own test; only the
    /// seam was broken, so only a test that crosses the seam can catch it.
    #[test]
    fn a_narrowed_grant_reaches_the_runner_policy_with_mouse_denied() {
        // The request asked for keyboard + mouse; the host approved keyboard.
        let approved = PermissionSet {
            view: true,
            keyboard: true,
            mouse: false,
            ..PermissionSet::none()
        };

        // Broker response -> desktop credential -> role credential.
        let ConnectStep::Start(credential) =
            interpret(granted_with("client", Some(approved)), false)
        else {
            panic!("an approved request must start a session");
        };
        let carried = credential
            .permissions
            .expect("the granted set survives the credential conversion");
        assert!(carried.keyboard, "keyboard was granted");
        assert!(!carried.mouse, "mouse was not granted");

        // Role credential -> pairing file, including a real serde round trip,
        // because the pairing is handed to the runner as JSON on disk.
        let pairing = openstream_client_core::Pairing::from_role_credential(*credential);
        let encoded = serde_json::to_string(&pairing).expect("serialise the pairing");
        let decoded: openstream_client_core::Pairing =
            serde_json::from_str(&encoded).expect("read the pairing back");
        let from_disk = decoded
            .permissions
            .expect("the granted set survives the pairing file");

        // Pairing -> host policy. The owner's own machine policy allows both
        // classes here, so anything still enabled after scoping came from the
        // grant and not from the local default.
        let owner_allows_everything = openstream_platform::policy::HostPolicy {
            input: true,
            keyboard: true,
            mouse: true,
            clipboard: true,
            gamepad: true,
            microphone: true,
            approval: openstream_platform::policy::Approval::Auto,
        };
        let scoped = owner_allows_everything.scoped_to_session(
            openstream_client_core::Permissions::allows(Some(from_disk), |p| p.keyboard),
            openstream_client_core::Permissions::allows(Some(from_disk), |p| p.mouse),
            openstream_client_core::Permissions::allows(Some(from_disk), |p| p.gamepad),
            openstream_client_core::Permissions::allows(Some(from_disk), |p| p.clipboard),
            openstream_client_core::Permissions::allows(Some(from_disk), |p| p.microphone),
        );
        assert!(scoped.keyboard, "the granted class stays enabled");
        assert!(
            !scoped.mouse,
            "the class the host withheld must be denied at the runner, not merely hidden in the UI"
        );
    }

    /// A host capability arriving on the requester's endpoint is not acted on.
    ///
    /// It should be impossible -- the broker answers this endpoint with the
    /// client side -- which is exactly why it is checked here rather than
    /// assumed and discovered three layers down.
    #[test]
    fn a_host_capability_on_the_requester_endpoint_is_refused() {
        assert_eq!(interpret(granted("host"), false), ConnectStep::Abandoned);
    }

    /// Waiting is waiting, until the shell's own deadline passes.
    #[test]
    fn a_pending_request_is_waited_on_until_the_deadline() {
        let pending = || ConnectObservation::Waiting {
            state: ConnectState::Pending,
        };
        assert_eq!(interpret(pending(), false), ConnectStep::KeepWaiting);
        assert_eq!(interpret(pending(), true), ConnectStep::Abandoned);
    }

    /// A refusal is reported as a refusal, not as a timeout.
    ///
    /// The two mean different things to the person who pressed connect: one
    /// says somebody declined, the other says nobody was there.
    #[test]
    fn a_denial_is_distinguished_from_giving_up() {
        assert_eq!(
            interpret(
                ConnectObservation::Waiting {
                    state: ConnectState::Denied
                },
                false
            ),
            ConnectStep::Refused
        );
        assert_eq!(
            interpret(
                ConnectObservation::Waiting {
                    state: ConnectState::Expired
                },
                false
            ),
            ConnectStep::Abandoned
        );
    }

    /// The shell gives up before the broker does.
    ///
    /// Otherwise the request is reaped underneath it and the last thing the
    /// user sees is "not found", which reads like a fault rather than like
    /// nobody having answered.
    #[test]
    fn the_shell_stops_asking_before_the_broker_forgets() {
        // The broker's request lifetime; see `connect::REQUEST_TTL`.
        let broker_request_ttl = std::time::Duration::from_secs(120);
        assert!(
            CONNECT_WAIT < broker_request_ttl,
            "the shell must report 'nobody answered' rather than 'not found'"
        );
        assert!(CONNECT_POLL_INTERVAL < CONNECT_WAIT);
    }
}
