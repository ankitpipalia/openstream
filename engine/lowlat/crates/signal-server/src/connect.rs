//! The secure Connect broker: how a client reaches a host it is allowed to use.
//!
//! # Why this exists
//!
//! Without it the account system and the streaming system are two adjacent
//! systems rather than one product. An account can sign in, list its devices
//! and change their trust; a session can be created and streamed. Nothing
//! joins them, so the only way to start a session is to hand one caller
//! *both* role capabilities and let it distribute them out of band. That is a
//! developer workflow, not a product one, and it is why `/v1/session` is
//! reserved for provisioning.
//!
//! The flow this implements instead:
//!
//! ```text
//! host device signs in --> announces presence --> polls for requests
//!
//! client signs in --> lists devices --> POST /v1/connect {target_device_id}
//!                                              |
//!                                       pending request
//!                                              |
//!                                     host approves or denies
//!                                              |
//!                         +--------------------+--------------------+
//!                   host credential                          client credential
//!                   (target device only)                     (requester only)
//! ```
//!
//! # The property that matters
//!
//! Each role capability is readable by exactly one party. The host credential
//! only by the device that approved the request, the client credential only
//! by the device that made it. A capability that both ends can read is not an
//! authorisation boundary; it is a shared secret with extra steps, which is
//! what handing one caller both tokens amounted to.
//!
//! # Why retrieval is idempotent rather than once-only
//!
//! An earlier version deleted the credential as it was handed over, on the
//! theory that a single delivery limits replay. It does not: the value is a
//! bearer token, and anyone who captured the response already holds it
//! whether or not the server kept a copy. Deleting the server's copy prevents
//! nothing an attacker would do.
//!
//! What it does prevent is recovery. HTTP responses are lost -- a dropped
//! connection, a timed-out proxy, a client that crashed between receiving and
//! storing -- and under once-only delivery the retry returns a conflict, so a
//! perfectly good session exists that one of its two ends can never join. The
//! failure is silent, looks like a broker bug, and is unrecoverable without
//! starting over.
//!
//! So the same authenticated device may collect its own credential as many
//! times as it needs, and the whole request expires on [`APPROVAL_TTL`]
//! instead. The bound on exposure is the clock and the device check, which
//! are the two things that actually hold.
//!
//! # What this deliberately does not do
//!
//! It does not hold a socket open for the host. Presence is a heartbeat with
//! a TTL and requests are polled, because a broker that requires a live
//! connection per enrolled device makes device count a memory and file
//! descriptor cost, and makes every restart a thundering herd. Polling is
//! slower to deliver a request and much cheaper to operate; the latency that
//! matters is in the media path, not in the half-second before a prompt
//! appears.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a device stays "online" after its last heartbeat.
///
/// Generous relative to the heartbeat interval so one missed beat -- a
/// suspended laptop, a lost packet, a garbage collection pause -- does not
/// make a host vanish from its owner's device list.
pub(crate) const PRESENCE_TTL: Duration = Duration::from_secs(90);

/// How long an unanswered connection request lives.
///
/// Bounded because a request is a prompt on someone's screen. One that
/// outlives the person's attention is worse than none: it trains them to
/// approve stale prompts, and it lets a requester queue approvals to be
/// collected later.
pub(crate) const REQUEST_TTL: Duration = Duration::from_secs(120);

/// How long an approved request keeps its undelivered credentials.
///
/// Short. The two parties are both actively waiting by this point, so this
/// covers a round trip and a retry, not an absence.
pub(crate) const APPROVAL_TTL: Duration = Duration::from_secs(60);

/// Ceiling on simultaneously tracked requests.
///
/// Every request is authenticated, so this is not an anonymous flood surface;
/// it is still bounded, because "authenticated" is not "trusted" and one
/// compromised account must not be able to grow the broker without limit.
pub(crate) const MAX_PENDING_REQUESTS: usize = 1024;

/// Ceiling on simultaneously tracked online devices.
pub(crate) const MAX_TRACKED_PRESENCE: usize = 4096;

/// How many requests one account may have in flight at once.
///
/// Well below the global ceiling: a person connects to one machine at a time,
/// occasionally two. An account sitting at this limit is malfunctioning or
/// malicious, and either way must not be able to crowd out every other
/// account in the deployment.
pub(crate) const MAX_REQUESTS_PER_ACCOUNT: usize = 16;

/// Who is acting, as one value.
///
/// An account id and a device id are both opaque strings, so passing them as
/// adjacent parameters is an invitation to transpose them -- and a transposed
/// pair here would compare the wrong halves and let the wrong party act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Party<'a> {
    pub account_id: &'a str,
    pub device_id: &'a str,
}

/// The input and device classes a session is scoped to.
///
/// The requester asks for a set; the approving device grants a (possibly
/// smaller) one. Every field defaults to `false`, so an omitted or partial
/// object is the least-privilege reading, and a client or control plane that
/// predates the field negotiates no permissions rather than failing to parse.
/// Enforcement -- a session runner honouring only the granted classes -- is a
/// separate step; this type carries the negotiated decision through the broker
/// so the host decides against what was asked and each end learns what it got.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(default, rename_all = "snake_case")]
pub(crate) struct Permissions {
    pub view: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub gamepad: bool,
    pub clipboard: bool,
    pub microphone: bool,
    pub tablet: bool,
    pub virtual_usb: bool,
}

/// The session an approval creates, and its two role capabilities.
///
/// Passed in as one value and immediately split apart inside the broker, so
/// the pair exists together for as short a time as possible and never in a
/// type that leaves this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionGrant {
    pub session_id: String,
    pub host_credential: String,
    pub client_credential: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectState {
    /// Waiting for the target device to answer.
    Pending,
    /// The target approved. Credentials exist and are waiting to be taken.
    Approved,
    /// The target refused.
    Denied,
    /// Nobody answered in time.
    Expired,
}

/// Why a broker operation was refused.
///
/// Typed rather than stringly, because these map to distinct HTTP statuses
/// and to distinct things a user must be told. In particular `NotFound` and
/// `Forbidden` are deliberately separate internally and deliberately
/// *collapsed* at the HTTP boundary -- see `connect_error_response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectError {
    /// No such request, or it has been reaped.
    NotFound,
    /// The caller is not the party entitled to this.
    Forbidden,
    /// The request is not in a state where this makes sense.
    InvalidState,
    /// This party has already approved this request.
    ///
    /// Distinct from [`Self::InvalidState`] because it is not an error at
    /// all: it is a retry of an approval whose response was lost, and the
    /// caller should be handed the credential it never received rather than
    /// a conflict it cannot recover from.
    AlreadyApproved,
    /// The session behind an approval does not exist yet.
    ///
    /// A momentary state between minting the credentials and publishing the
    /// session. Handing a credential out in that window would name a session
    /// the peer cannot join, which a client cannot tell apart from a fault.
    NotPublished,
    /// The target device is not online.
    TargetOffline,
    /// The target is not a device this account may connect to.
    TargetNotConnectable,
    /// Too many requests in flight.
    Busy,
}

/// One in-flight connection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectRequest {
    pub request_id: String,
    pub account_id: String,
    pub requester_device_id: String,
    pub target_device_id: String,
    pub state: ConnectState,
    pub created_at: Instant,
    pub expires_at: Instant,
    /// The classes the requester asked for. Shown to the target so it approves
    /// against what was actually requested rather than a blanket grant.
    pub requested: Permissions,
    /// The classes the target granted, set on approval. Default (none) until
    /// then; carried into both role credentials so each end learns its scope.
    pub granted: Permissions,
    /// Set on approval. The session these credentials belong to.
    pub session_id: Option<String>,
    /// Whether that session actually exists yet.
    ///
    /// Approval mints the credentials; publishing the session is a separate
    /// step that can fail, or simply not have happened yet when a concurrent
    /// retry arrives. Until this is set there is nothing to join.
    published: bool,
    /// Retained until the request expires, so a lost response can be
    /// retried. See the module documentation.
    host_credential: Option<String>,
    client_credential: Option<String>,
}

impl ConnectRequest {
    /// Whether this request has outlived its deadline.
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// A device's last heartbeat.
#[derive(Debug, Clone, Copy)]
struct Presence {
    account_id_hash: u64,
    last_seen: Instant,
}

/// The broker's state: who is online, and what is being asked of them.
#[derive(Debug, Default)]
pub(crate) struct ConnectBroker {
    requests: HashMap<String, ConnectRequest>,
    presence: HashMap<String, Presence>,
}

/// A cheap, stable digest of an account id.
///
/// Presence entries are keyed by device id, and a device belongs to exactly
/// one account. Storing the account's identity as a hash rather than a string
/// keeps the presence table small while still letting a lookup refuse to
/// report one account's device to another -- which matters, because device
/// ids are not secret and a cross-account presence probe would otherwise tell
/// an attacker when a stranger's machine is switched on.
fn account_digest(account_id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    account_id.hash(&mut hasher);
    hasher.finish()
}

impl ConnectBroker {
    /// Record that a device is online and reachable.
    pub(crate) fn heartbeat(&mut self, account_id: &str, device_id: &str, now: Instant) {
        self.expire(now);
        if self.presence.len() >= MAX_TRACKED_PRESENCE && !self.presence.contains_key(device_id) {
            // Evict the stalest. Presence is soft state: losing an entry
            // costs one device an "offline" reading until its next
            // heartbeat, which is recoverable, whereas unbounded growth is
            // not.
            if let Some(stalest) = self
                .presence
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(device, _)| device.clone())
            {
                self.presence.remove(&stalest);
            }
        }
        self.presence.insert(
            device_id.to_string(),
            Presence {
                account_id_hash: account_digest(account_id),
                last_seen: now,
            },
        );
    }

    /// Whether a device is currently online, as far as this account may know.
    pub(crate) fn is_online(&self, account_id: &str, device_id: &str, now: Instant) -> bool {
        self.presence.get(device_id).is_some_and(|entry| {
            entry.account_id_hash == account_digest(account_id)
                && now.saturating_duration_since(entry.last_seen) < PRESENCE_TTL
        })
    }

    /// Stop reporting a device as online.
    pub(crate) fn go_offline(&mut self, device_id: &str) {
        self.presence.remove(device_id);
    }

    /// Ask a device for a session, requesting no permissions.
    ///
    /// Test-only thin default over [`Self::request_scoped`]; the live handler
    /// negotiates a set and goes through `request_scoped` directly.
    #[cfg(test)]
    pub(crate) fn request(
        &mut self,
        request_id: String,
        account_id: &str,
        requester_device_id: &str,
        target_device_id: &str,
        now: Instant,
    ) -> Result<ConnectRequest, ConnectError> {
        self.request_scoped(
            request_id,
            account_id,
            requester_device_id,
            target_device_id,
            Permissions::default(),
            now,
        )
    }

    /// Ask a device for a session, requesting a permission set.
    ///
    /// The caller has already established that `target_device_id` is an
    /// enrolled, trusted device of `account_id`; this refuses on presence and
    /// capacity, which are the broker's own concerns.
    pub(crate) fn request_scoped(
        &mut self,
        request_id: String,
        account_id: &str,
        requester_device_id: &str,
        target_device_id: &str,
        requested: Permissions,
        now: Instant,
    ) -> Result<ConnectRequest, ConnectError> {
        self.expire(now);
        if !self.is_online(account_id, target_device_id, now) {
            return Err(ConnectError::TargetOffline);
        }
        // A device cannot stream to itself, and a request that says otherwise
        // is a confused client rather than a legitimate loopback: the host
        // and client roles would be the same process holding both ends.
        if requester_device_id == target_device_id {
            return Err(ConnectError::TargetNotConnectable);
        }
        if self.requests.len() >= MAX_PENDING_REQUESTS {
            return Err(ConnectError::Busy);
        }
        let held = self
            .requests
            .values()
            .filter(|request| request.account_id == account_id)
            .count();
        if held >= MAX_REQUESTS_PER_ACCOUNT {
            return Err(ConnectError::Busy);
        }
        let request = ConnectRequest {
            request_id: request_id.clone(),
            account_id: account_id.to_string(),
            requester_device_id: requester_device_id.to_string(),
            target_device_id: target_device_id.to_string(),
            state: ConnectState::Pending,
            created_at: now,
            expires_at: now + REQUEST_TTL,
            requested,
            granted: Permissions::default(),
            session_id: None,
            published: false,
            host_credential: None,
            client_credential: None,
        };
        self.requests.insert(request_id, request.clone());
        Ok(request)
    }

    /// Requests a device should be prompting its user about.
    pub(crate) fn pending_for_target(
        &mut self,
        account_id: &str,
        target_device_id: &str,
        now: Instant,
    ) -> Vec<ConnectRequest> {
        self.expire(now);
        let mut pending: Vec<ConnectRequest> = self
            .requests
            .values()
            .filter(|request| {
                request.state == ConnectState::Pending
                    && request.account_id == account_id
                    && request.target_device_id == target_device_id
            })
            .cloned()
            .collect();
        // Oldest first: the person has been waiting longest for that one.
        pending.sort_by_key(|request| request.created_at);
        pending
    }

    /// Approve a request, granting no permissions.
    ///
    /// Test-only thin default over [`Self::approve_scoped`]; the live handler
    /// records the granted set and goes through `approve_scoped` directly.
    #[cfg(test)]
    pub(crate) fn approve(
        &mut self,
        request_id: &str,
        answered_by: Party<'_>,
        grant: SessionGrant,
        now: Instant,
    ) -> Result<ConnectRequest, ConnectError> {
        self.approve_scoped(request_id, answered_by, grant, Permissions::default(), now)
    }

    /// Approve a request, attaching the session and its two role credentials
    /// and recording the permission classes the target granted.
    ///
    /// The credentials go in here and come out one at a time, to one party
    /// each. This is the whole point of the type: there is no accessor that
    /// returns both.
    pub(crate) fn approve_scoped(
        &mut self,
        request_id: &str,
        answered_by: Party<'_>,
        grant: SessionGrant,
        granted: Permissions,
        now: Instant,
    ) -> Result<ConnectRequest, ConnectError> {
        let (account_id, target_device_id) = (answered_by.account_id, answered_by.device_id);
        let SessionGrant {
            session_id,
            host_credential,
            client_credential,
        } = grant;
        self.expire(now);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != account_id || request.target_device_id != target_device_id {
            // Only the device being asked may answer. Checked before the
            // state test so a stranger cannot learn a request's state by
            // comparing which error comes back.
            return Err(ConnectError::Forbidden);
        }
        if request.state == ConnectState::Approved {
            // A retry of an approval whose response was lost. Not an error:
            // the caller is entitled to the credential it never received.
            return Err(ConnectError::AlreadyApproved);
        }
        if request.state != ConnectState::Pending {
            return Err(ConnectError::InvalidState);
        }
        request.state = ConnectState::Approved;
        request.granted = granted;
        request.session_id = Some(session_id);
        request.host_credential = Some(host_credential);
        request.client_credential = Some(client_credential);
        // The clock restarts: both parties are actively waiting now, and the
        // approval window is about a round trip rather than about someone
        // noticing a prompt.
        request.expires_at = now + APPROVAL_TTL;
        Ok(request.clone())
    }

    /// Refuse a request.
    pub(crate) fn deny(
        &mut self,
        request_id: &str,
        account_id: &str,
        target_device_id: &str,
        now: Instant,
    ) -> Result<(), ConnectError> {
        self.expire(now);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != account_id || request.target_device_id != target_device_id {
            return Err(ConnectError::Forbidden);
        }
        if request.state != ConnectState::Pending {
            return Err(ConnectError::InvalidState);
        }
        request.state = ConnectState::Denied;
        // Kept briefly so the requester learns it was refused rather than
        // watching it time out; a denial the asker never sees reads as the
        // host being broken.
        request.expires_at = now + APPROVAL_TTL;
        Ok(())
    }

    /// Collect the host credential, as the device that approved.
    ///
    /// Idempotent: the same device may ask again if it never received the
    /// answer. See the module documentation for why that is safer than
    /// once-only delivery rather than less safe.
    pub(crate) fn collect_host_credential(
        &mut self,
        request_id: &str,
        answered_by: Party<'_>,
        now: Instant,
    ) -> Result<(String, String), ConnectError> {
        self.expire(now);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != answered_by.account_id
            || request.target_device_id != answered_by.device_id
        {
            return Err(ConnectError::Forbidden);
        }
        if request.state != ConnectState::Approved {
            return Err(ConnectError::InvalidState);
        }
        if !request.published {
            return Err(ConnectError::NotPublished);
        }
        let session_id = request
            .session_id
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        let credential = request
            .host_credential
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        Ok((session_id, credential))
    }

    /// Collect the client credential, as the device that asked.
    ///
    /// Idempotent, for the same reason.
    pub(crate) fn collect_client_credential(
        &mut self,
        request_id: &str,
        asked_by: Party<'_>,
        now: Instant,
    ) -> Result<(String, String), ConnectError> {
        self.expire(now);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != asked_by.account_id
            || request.requester_device_id != asked_by.device_id
        {
            return Err(ConnectError::Forbidden);
        }
        if request.state != ConnectState::Approved {
            return Err(ConnectError::InvalidState);
        }
        if !request.published {
            return Err(ConnectError::NotPublished);
        }
        let session_id = request
            .session_id
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        let credential = request
            .client_credential
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        Ok((session_id, credential))
    }

    /// The permissions the target granted for a request.
    ///
    /// Read after a credential collection has already authorised the caller and
    /// confirmed the request is approved, so it is a plain read of the
    /// negotiated set; an unknown request yields the empty, least-privilege
    /// default rather than an error.
    pub(crate) fn granted_permissions(&self, request_id: &str) -> Permissions {
        self.requests
            .get(request_id)
            .map(|request| request.granted)
            .unwrap_or_default()
    }

    /// The pair of credentials an approval just minted.
    ///
    /// Used once, by the approving request, to build the session the two
    /// credentials belong to. This is the only place both halves are visible
    /// together, and it is reachable only by the device that approved -- the
    /// two collection paths still hand out one each.
    pub(crate) fn minted_credentials(
        &self,
        request_id: &str,
        answered_by: Party<'_>,
    ) -> Result<(String, String), ConnectError> {
        let request = self
            .requests
            .get(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != answered_by.account_id
            || request.target_device_id != answered_by.device_id
        {
            return Err(ConnectError::Forbidden);
        }
        let host = request
            .host_credential
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        let client = request
            .client_credential
            .clone()
            .ok_or(ConnectError::InvalidState)?;
        Ok((host, client))
    }

    /// Record that the session behind an approval now exists.
    ///
    /// Until this is called the credentials exist but name nothing, so
    /// collection is refused. The window is short but reachable: a host
    /// retrying an approval can arrive between the mint and the publish.
    pub(crate) fn mark_published(&mut self, request_id: &str) {
        if let Some(request) = self.requests.get_mut(request_id) {
            request.published = true;
        }
    }

    /// Withdraw an approval whose session could not be published.
    ///
    /// Leaving it would hand out credentials for a session that does not
    /// exist, which a client cannot tell apart from a network fault.
    pub(crate) fn withdraw(&mut self, request_id: &str) {
        self.requests.remove(request_id);
    }

    /// What the requester is allowed to know about its own request.
    ///
    /// Deliberately not the whole record: no credentials, and nothing about
    /// the target beyond the id the caller already supplied.
    pub(crate) fn observe(
        &mut self,
        request_id: &str,
        account_id: &str,
        requester_device_id: &str,
        now: Instant,
    ) -> Result<ConnectState, ConnectError> {
        self.expire(now);
        let request = self
            .requests
            .get(request_id)
            .ok_or(ConnectError::NotFound)?;
        if request.account_id != account_id || request.requester_device_id != requester_device_id {
            return Err(ConnectError::Forbidden);
        }
        Ok(request.state)
    }

    /// Drop everything that has outlived its deadline.
    ///
    /// Called at the head of every operation rather than on a timer, so the
    /// broker cannot serve an expired request even if a reaper is wedged.
    /// An expired request is removed rather than marked: nothing may be taken
    /// from it, and a caller asking about one gets `NotFound`, which is the
    /// truth -- it is gone.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.requests.retain(|_, request| !request.is_expired(now));
        self.presence
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) < PRESENCE_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APPROVAL_TTL, ConnectBroker, ConnectError, ConnectState, MAX_REQUESTS_PER_ACCOUNT,
        PRESENCE_TTL, Party, REQUEST_TTL, SessionGrant,
    };
    use std::time::{Duration, Instant};

    const ACCOUNT: &str = "account-1";
    const CLIENT: &str = "device-client";
    const HOST: &str = "device-host";

    /// A broker with the host online and one pending request.
    fn pending(now: Instant) -> ConnectBroker {
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        broker
            .request("request-1".to_string(), ACCOUNT, CLIENT, HOST, now)
            .expect("request");
        broker
    }

    fn approve(broker: &mut ConnectBroker, now: Instant) {
        approve_only(broker, now);
        broker.mark_published("request-1");
    }

    fn approve_only(broker: &mut ConnectBroker, now: Instant) {
        broker
            .approve(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST,
                },
                SessionGrant {
                    session_id: "session-1".to_string(),
                    host_credential: "HOST-CREDENTIAL".to_string(),
                    client_credential: "CLIENT-CREDENTIAL".to_string(),
                },
                now,
            )
            .expect("approve");
    }

    /// Each role capability reaches exactly one party.
    ///
    /// This is the property the broker exists for. A capability both ends can
    /// read is not an authorisation boundary; it is a shared secret with
    /// extra steps, which is what handing one caller both tokens amounted to.
    #[test]
    fn each_role_credential_reaches_only_its_own_party() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);

        // The requester cannot take the host's capability...
        assert_eq!(
            broker.collect_host_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: CLIENT
                },
                now,
            ),
            Err(ConnectError::Forbidden)
        );
        // ...and the host cannot take the requester's.
        assert_eq!(
            broker.collect_client_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST
                },
                now,
            ),
            Err(ConnectError::Forbidden)
        );

        let (session, host_credential) = broker
            .collect_host_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST,
                },
                now,
            )
            .expect("the approving device takes the host credential");
        assert_eq!(session, "session-1");
        assert_eq!(host_credential, "HOST-CREDENTIAL");

        let (session, client_credential) = broker
            .collect_client_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: CLIENT,
                },
                now,
            )
            .expect("the requesting device takes the client credential");
        assert_eq!(session, "session-1");
        assert_eq!(client_credential, "CLIENT-CREDENTIAL");
    }

    /// A device that never received its answer can ask again.
    ///
    /// Deleting the credential on delivery prevented nothing -- the value is
    /// a bearer token, and anyone who captured the response already holds it
    /// whether or not the server kept a copy. What it did prevent was
    /// recovery: a dropped connection or a timed-out proxy left a perfectly
    /// good session that one of its two ends could never join, silently and
    /// unrecoverably.
    #[test]
    fn a_lost_response_can_be_retried_by_the_same_device() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);

        let host = Party {
            account_id: ACCOUNT,
            device_id: HOST,
        };
        let first = broker
            .collect_host_credential("request-1", host, now)
            .expect("first collection");
        // The response never arrived. The device asks again.
        let retry = broker
            .collect_host_credential("request-1", host, now)
            .expect("a retry must not be refused");
        assert_eq!(first, retry, "and must get the same session and credential");

        let client = Party {
            account_id: ACCOUNT,
            device_id: CLIENT,
        };
        let first = broker
            .collect_client_credential("request-1", client, now)
            .expect("first collection");
        let retry = broker
            .collect_client_credential("request-1", client, now)
            .expect("a retry must not be refused");
        assert_eq!(first, retry);
    }

    /// An approval whose response was lost is a retry, not a conflict.
    ///
    /// The host has no separate collection route: approval is how it receives
    /// its credential. Refusing the second attempt therefore leaves a live
    /// session that the host can never join, which is the same unrecoverable
    /// failure once-only collection produced -- just one layer up.
    #[test]
    fn re_approving_is_reported_as_already_approved_not_as_a_conflict() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);
        assert_eq!(
            broker.approve(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST
                },
                SessionGrant {
                    session_id: "session-2".to_string(),
                    host_credential: "H2".to_string(),
                    client_credential: "C2".to_string(),
                },
                now
            ),
            Err(ConnectError::AlreadyApproved),
            "the caller is entitled to the credential it never received"
        );
    }

    /// Nothing may be collected before the session exists.
    ///
    /// Between minting the credentials and publishing the session there is a
    /// window in which a concurrent retry could otherwise be handed a
    /// credential naming a session that is not there -- which a client cannot
    /// tell apart from a fault.
    #[test]
    fn no_credential_is_handed_out_before_its_session_exists() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve_only(&mut broker, now);

        let host = Party {
            account_id: ACCOUNT,
            device_id: HOST,
        };
        let client = Party {
            account_id: ACCOUNT,
            device_id: CLIENT,
        };
        assert_eq!(
            broker.collect_host_credential("request-1", host, now),
            Err(ConnectError::NotPublished)
        );
        assert_eq!(
            broker.collect_client_credential("request-1", client, now),
            Err(ConnectError::NotPublished)
        );

        broker.mark_published("request-1");
        assert!(
            broker
                .collect_host_credential("request-1", host, now)
                .is_ok()
        );
        assert!(
            broker
                .collect_client_credential("request-1", client, now)
                .is_ok()
        );
    }

    /// Retries do not extend the window. The clock is what bounds exposure.
    #[test]
    fn retrying_does_not_keep_a_request_alive() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);
        let host = Party {
            account_id: ACCOUNT,
            device_id: HOST,
        };

        let mut at = now;
        for _ in 0..5 {
            at += APPROVAL_TTL / 10;
            broker
                .collect_host_credential("request-1", host, at)
                .expect("still inside the window");
        }
        let past = now + APPROVAL_TTL + Duration::from_secs(1);
        assert_eq!(
            broker.collect_host_credential("request-1", host, past),
            Err(ConnectError::NotFound),
            "collection must not refresh the approval deadline"
        );
    }

    /// An approval whose session could not be published is withdrawn.
    #[test]
    fn a_withdrawn_approval_hands_out_nothing() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);
        broker.withdraw("request-1");
        assert_eq!(
            broker.collect_host_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST
                },
                now
            ),
            Err(ConnectError::NotFound),
            "a credential for a session that does not exist is worse than none"
        );
    }

    /// Only the device being asked may answer.
    #[test]
    fn only_the_target_device_can_approve_or_deny() {
        let now = Instant::now();
        let mut broker = pending(now);
        assert_eq!(
            broker.approve(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: CLIENT
                },
                SessionGrant {
                    session_id: "session-1".to_string(),
                    host_credential: "H".to_string(),
                    client_credential: "C".to_string(),
                },
                now
            ),
            Err(ConnectError::Forbidden),
            "the requester must not be able to approve its own request"
        );
        assert_eq!(
            broker.deny("request-1", ACCOUNT, CLIENT, now),
            Err(ConnectError::Forbidden)
        );
        assert_eq!(
            broker.approve(
                "request-1",
                Party {
                    account_id: "account-2",
                    device_id: HOST
                },
                SessionGrant {
                    session_id: "session-1".to_string(),
                    host_credential: "H".to_string(),
                    client_credential: "C".to_string(),
                },
                now
            ),
            Err(ConnectError::Forbidden),
            "another account must not be able to answer this account's request"
        );
    }

    /// A request nobody answers does not survive its deadline.
    #[test]
    fn an_unanswered_request_expires() {
        let now = Instant::now();
        let mut broker = pending(now);
        let later = now + REQUEST_TTL + Duration::from_secs(1);
        // The host is still online so presence is not what removes it.
        broker.heartbeat(ACCOUNT, HOST, later);
        assert_eq!(
            broker.observe("request-1", ACCOUNT, CLIENT, later),
            Err(ConnectError::NotFound),
            "a prompt that outlives someone's attention trains them to \
             approve stale prompts"
        );
    }

    /// Approval restarts the clock, and an uncollected approval still expires.
    #[test]
    fn an_uncollected_approval_expires_on_its_own_shorter_clock() {
        let now = Instant::now();
        let mut broker = pending(now);
        approve(&mut broker, now);

        let inside = now + APPROVAL_TTL - Duration::from_secs(1);
        assert_eq!(
            broker.observe("request-1", ACCOUNT, CLIENT, inside),
            Ok(ConnectState::Approved)
        );
        let past = now + APPROVAL_TTL + Duration::from_secs(1);
        assert_eq!(
            broker.collect_host_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: HOST
                },
                past
            ),
            Err(ConnectError::NotFound),
            "an uncollected credential must not wait indefinitely"
        );
    }

    /// A denial is visible to the asker rather than presented as a timeout.
    #[test]
    fn a_denial_is_reported_to_the_requester() {
        let now = Instant::now();
        let mut broker = pending(now);
        broker.deny("request-1", ACCOUNT, HOST, now).expect("deny");
        assert_eq!(
            broker.observe("request-1", ACCOUNT, CLIENT, now),
            Ok(ConnectState::Denied),
            "a refusal the asker never sees reads as the host being broken"
        );
        assert_eq!(
            broker.collect_client_credential(
                "request-1",
                Party {
                    account_id: ACCOUNT,
                    device_id: CLIENT
                },
                now
            ),
            Err(ConnectError::InvalidState),
            "a denied request has no credentials to hand out"
        );
    }

    /// An offline device cannot be asked.
    #[test]
    fn a_request_needs_the_target_to_be_online() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        assert_eq!(
            broker.request("r".to_string(), ACCOUNT, CLIENT, HOST, now),
            Err(ConnectError::TargetOffline)
        );

        broker.heartbeat(ACCOUNT, HOST, now);
        let stale = now + PRESENCE_TTL + Duration::from_secs(1);
        assert_eq!(
            broker.request("r".to_string(), ACCOUNT, CLIENT, HOST, stale),
            Err(ConnectError::TargetOffline),
            "presence must lapse rather than persist for the process lifetime"
        );
    }

    /// Presence is not a cross-account probe.
    ///
    /// Device ids are not secret, so without this a stranger could learn when
    /// somebody else's machine is switched on.
    #[test]
    fn presence_is_not_visible_across_accounts() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        assert!(broker.is_online(ACCOUNT, HOST, now));
        assert!(
            !broker.is_online("account-2", HOST, now),
            "one account must not be able to observe another's devices"
        );
        assert_eq!(
            broker.request("r".to_string(), "account-2", CLIENT, HOST, now),
            Err(ConnectError::TargetOffline)
        );
    }

    /// One account cannot crowd out every other.
    #[test]
    fn one_account_cannot_fill_the_broker() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        for index in 0..MAX_REQUESTS_PER_ACCOUNT {
            broker
                .request(format!("request-{index}"), ACCOUNT, CLIENT, HOST, now)
                .expect("within the per-account allowance");
        }
        assert_eq!(
            broker.request("one-too-many".to_string(), ACCOUNT, CLIENT, HOST, now),
            Err(ConnectError::Busy)
        );

        // A different account is unaffected by the first one's spending.
        broker.heartbeat("account-2", "device-host-2", now);
        broker
            .request(
                "other".to_string(),
                "account-2",
                "device-client-2",
                "device-host-2",
                now,
            )
            .expect("another account keeps its own allowance");
    }

    /// A device cannot stream to itself.
    #[test]
    fn a_device_cannot_connect_to_itself() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        assert_eq!(
            broker.request("r".to_string(), ACCOUNT, HOST, HOST, now),
            Err(ConnectError::TargetNotConnectable)
        );
    }

    /// The target sees requests addressed to it, oldest first, and no others.
    #[test]
    fn a_device_is_shown_only_the_requests_addressed_to_it() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        broker.heartbeat(ACCOUNT, "device-host-b", now);
        broker
            .request(
                "second".to_string(),
                ACCOUNT,
                CLIENT,
                HOST,
                now + Duration::from_secs(1),
            )
            .expect("request");
        broker
            .request("first".to_string(), ACCOUNT, CLIENT, HOST, now)
            .expect("request");
        broker
            .request(
                "elsewhere".to_string(),
                ACCOUNT,
                CLIENT,
                "device-host-b",
                now,
            )
            .expect("request");

        let pending = broker.pending_for_target(ACCOUNT, HOST, now + Duration::from_secs(2));
        let ids: Vec<&str> = pending
            .iter()
            .map(|request| request.request_id.as_str())
            .collect();
        assert_eq!(ids, vec!["first", "second"], "oldest first");

        assert!(
            broker
                .pending_for_target("account-2", HOST, now + Duration::from_secs(2))
                .is_empty(),
            "another account must not see this account's requests"
        );
    }

    /// Going offline deliberately stops presence immediately.
    #[test]
    fn an_explicit_offline_takes_effect_at_once() {
        let now = Instant::now();
        let mut broker = ConnectBroker::default();
        broker.heartbeat(ACCOUNT, HOST, now);
        broker.go_offline(HOST);
        assert!(!broker.is_online(ACCOUNT, HOST, now));
    }
}
