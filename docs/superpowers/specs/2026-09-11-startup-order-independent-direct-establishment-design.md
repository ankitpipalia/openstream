# Startup-Order-Independent Direct Establishment

**Status:** proposed; awaiting review before implementation planning.

**Baseline:** `65c1678514550ccbe11d237e7f38d56a50fb7f64`

**Goal:** Make the OpenStream direct UDP handshake independent of which peer starts first while preventing stale candidate and key messages from a previous connection attempt from affecting a reconnect.

## Problem

`PeerSession::establish_with_stun` currently starts the 15-second candidate-exchange deadline immediately after opening its role-scoped signaling WebSocket. The signaling service, however, permits one role to connect before the other and stores messages for the missing role in a bounded pending queue. This creates an incompatible lifecycle:

```text
host connects
  -> host sends candidates
  -> signaling service queues them because client is absent
  -> client does not arrive within 15 seconds
  -> host reports candidate-exchange timeout and exits
```

The service already tracks per-role WebSocket connection generations, but those generations only protect stale disconnect cleanup. They do not identify a shared establishment attempt, and the queued direct handshake records have no epoch. A reconnect can therefore expose an old candidate or key record to a new attempt.

The fix is a server-authoritative direct-establishment epoch. Waiting for both current role sockets is a separate state from candidate and key exchange. Each direct handshake record carries the epoch that the server published to the exact pair of current sockets.

## Scope and non-goals

This specification covers the project-owned direct UDP candidate path used by `establish_with_stun` and `establish`. It includes the signaling service's membership lifecycle, direct handshake envelopes, generation validation, signed direct key exchange, reconnect invalidation, and deterministic acceptance tests.

The following remain unchanged and outside this phase:

- Full ICE/TURN nomination, consent freshness, and ICE restart.
- `ice_credentials`, `ice_candidate`, `ice_candidate_done`, and the existing ICE `key` envelope.
- Interoperability between a new direct v2 endpoint and a pre-v2 direct endpoint.
- The encrypted OpenStream data packet format and `CipherSession`.
- Path migration after an authenticated UDP session has been returned.
- Relay protocol behavior and generic non-establishment signaling.
- Replacing the 15-second candidate/key deadlines once a direct establishment epoch has been accepted.

The server may send the new direct readiness/reset envelopes to an ICE client; the existing ICE choreography ignores unknown direct lifecycle records. ICE behavior is not changed by this specification.

## Terminology and invariants

### Two independent generations

The service maintains two different kinds of generation:

1. `host_generation` and `client_generation` remain **socket generations**. They increment on every admission of a role WebSocket and are used only to prevent an old connection task from clearing or mutating a replacement sender.
2. `establishment_generation` is a **shared direct-establishment epoch**. It identifies the pair of current host/client sockets participating in one direct handshake. It is monotonic per signaling session, starts at zero before the first pair exists, and the first ready pair receives generation `1`.

The two values must not be reused interchangeably. Socket-generation changes invalidate the current direct establishment immediately, but the establishment generation increments only when both current role sockets are simultaneously present and the service publishes a new `peer_ready` record.

A path or establishment generation is not a cryptographic session generation. During a reconnect before UDP authentication, the current direct handshake is discarded and a new ephemeral key exchange is performed. After a `PeerSession` has been returned, this specification does not replace its `CipherSession` or perform runtime path migration.

### One current pair

At most one host socket and one client socket are current for a session. A role replacement closes the old sender and makes the new socket current before any new readiness record is published. A stale socket task must not forward direct-establishment messages, clear a replacement sender, or change the current establishment membership.

### Readiness is a server fact

`peer_ready(N)` is generated only by the signaling service after it has installed both current role senders for the same session. It is delivered directly to those exact senders; it is never put into a generic pending queue and never accepted as a peer-originated message.

No direct candidate, candidate-complete, or direct-key record is valid before `peer_ready(N)` has been accepted by the receiving client for the same epoch.

## Lifecycle

The direct client state machine is:

```text
SIGNAL_CONNECTED
       |
       v
WAITING_FOR_PEER  <-----------------------------+
       |                                         |
       | peer_ready(N)                           | peer_reset / role replacement
       v                                         |
DIRECT_CANDIDATES(N) -- candidate_done(N) -->   |
       |                                         |
       v                                         |
DIRECT_KEY_EXCHANGE(N) -- authenticated UDP --> +
       |
       v
AUTHENTICATED_UDP
```

`WAITING_FOR_PEER` is not governed by `PHASE_TIMEOUT`. It is bounded by the signaling session's expiry and by cancellation/connection closure. The candidate-exchange deadline starts when `peer_ready(N)` is accepted. The key-exchange deadline starts only after the current-generation candidate exchange completes. Each of those two phases retains the existing 15-second deadline.

If a `peer_reset` arrives during either direct phase, the client abandons all candidate and key state for the old epoch, returns to `WAITING_FOR_PEER`, and does not report a handshake failure merely because the old peer was replaced. A later `peer_ready(N+1)` starts a fresh candidate/key exchange. If the role is replaced after `AUTHENTICATED_UDP` has been returned, runtime behavior remains governed by the existing session/path lifecycle and is outside this startup protocol.

Local socket binding, local candidate discovery, UPnP mapping, and optional STUN queries may run while waiting. They may not transmit `direct_candidate`, `direct_candidate_done`, or `direct_key` until a matching `peer_ready` has been accepted. Reusing already-discovered local candidates for a later epoch is allowed, but every transmitted record must carry the new epoch.

## Server-authoritative epoch algorithm

The signaling `Session` gains an establishment-generation value and enough readiness bookkeeping to associate it with the current `host_generation` and `client_generation`. The existing socket-generation fields and cleanup rules remain intact.

### Initial startup

1. The first role WebSocket is admitted and becomes current. No establishment generation is published and no direct message is queued for the absent role.
2. The second role WebSocket is admitted and becomes current. The service increments `establishment_generation` with checked arithmetic, removes stale direct-establishment records from any generic pending queues, and atomically enqueues `{"type":"peer_ready","establishment_generation":N}` to both current sockets. It records the current socket-generation pair as ready only after both enqueues succeed.
3. The two clients begin direct candidate exchange only after receiving `peer_ready(N)`.

This means a host can remain connected for more than 15 seconds before the client starts without consuming the candidate-exchange deadline.

### Atomic readiness and reset delivery

Publishing an establishment generation is a fail-closed operation. The server
must not mark `N` ready until it has successfully enqueued the exact
`peer_ready(N)` record to both current role senders. Queue acceptance is the
service's delivery boundary; the WebSocket writer remains responsible for
normal connection failure detection.

If enqueueing `peer_ready(N)` fails for either sender because that sender is
closed or its bounded queue is full, `N` is immediately invalidated and is
never usable. Any sender that accepted `peer_ready(N)` must receive a
compensating `peer_reset(N)` before it is allowed to remain current. If that
reset cannot be enqueued, the server closes/drops that socket. The other
current socket is also closed when necessary so no partially informed pair can
continue; a clean pair must form before another generation is published.

Reset delivery has the same fail-closed rule. During role replacement or
disconnect invalidation, the surviving socket must accept `peer_reset(N)`
before the service publishes `peer_ready(N+1)` to a new pair. If the reset
cannot be enqueued, the server drops the surviving socket and does not publish
`N+1` to it or to the replacement socket. Both roles must then reconnect and
form a clean current pair. A reset that was accepted before a later WebSocket
failure is sufficient; the failure itself also invalidates the epoch.

Readiness/reset delivery is ordered per current sender: reset for the
invalidated epoch is enqueued before readiness for the replacement epoch. The
server never reports a generation as ready merely because the two senders
exist or because one readiness record was accepted.

### Role replacement

When a new WebSocket replaces a current host or client:

1. The service marks the previous establishment epoch unusable before publishing the replacement sender. The old socket is closed through its bounded sender queue.
2. The service installs the new current sender, increments the relevant socket generation, and, if the other role still has a current socket and a previously published direct generation exists, enqueues `peer_reset` containing the invalidated generation and a bounded reason such as `role_replaced` to that surviving socket. If this enqueue fails, the surviving socket and replacement socket are dropped and no new generation is published.
3. Once both current role senders exist and reset delivery has succeeded where required, the service allocates the next establishment generation and atomically publishes `peer_ready(N+1)` to the exact new pair. The atomic readiness failure policy above applies.
4. Direct records from the old socket are rejected because the connection task's captured socket generation is no longer current. Direct records from the replacement socket are rejected until the new `peer_ready` has been published.

The reset must be enqueued before the replacement readiness message for the surviving role so the client cannot start a new epoch while still treating the old epoch as valid. If the replacement socket disappears before both roles are current, the remaining role stays in `WAITING_FOR_PEER` until another pair is formed.

### Role disconnect

On a socket close, cleanup compares the task's captured socket generation with the session's current socket generation. Only a matching cleanup may remove the sender. If it removes a current host or client while a peer remains and a previously published direct generation exists, it invalidates the direct epoch and sends `peer_reset` to that remaining current peer. A stale cleanup task does nothing to establishment membership.

When both roles are current again, the server publishes the next checked establishment generation. A generation is never reused, including after a failed candidate exchange or a failed key exchange.

### Counter exhaustion

If `establishment_generation` would overflow `u64`, the service must fail closed for that session rather than wrapping to zero or reusing an earlier epoch. The session is expired/closed through the existing bounded lifecycle.

## Direct signaling envelopes

The new messages are deliberately separate from ICE and from the historical untyped direct messages:

```json
{"type":"peer_ready","establishment_generation":N}
{"type":"peer_reset","establishment_generation":N,"reason":"role_replaced"}
{"type":"direct_candidate","establishment_generation":N,"kind":"host","ip":"192.0.2.10","port":40001}
{"type":"direct_candidate_done","establishment_generation":N,"count":2}
{"type":"direct_key","establishment_generation":N,"public_key":"...","identity_public_key":"...","signature":"..."}
```

The exact JSON field names above are part of the signaling protocol. `establishment_generation` is a positive integer. Candidate kinds remain `host`, `mapped`, `server_reflexive`, and `relay`; candidate IPs and ports retain the existing bounded validation rules. Candidate count remains between 1 and the existing maximum. Key fields retain their fixed hex widths.

### Server-generated records

`peer_ready` and `peer_reset` are service-generated records. A client-sent record with either type is rejected as an unsupported or unauthorized signaling message. The service sends them directly to current role queues rather than forwarding them through the generic peer-message branch.

`peer_reset` identifies the epoch that is no longer usable. Its reason is a bounded non-secret enum/string. It does not contain an address, token, credential, key, or socket generation.

### Direct records

The service accepts a `direct_*` record only when all of the following hold:

- the sender's captured socket generation is still current for its role;
- both current role sockets exist;
- the message's `establishment_generation` equals the session's currently published ready generation;
- the envelope passes the strict field and size validator.

If a direct record arrives while no ready pair exists, the service returns a bounded `direct_establishment_not_ready` error to the sender and does not queue the record. If the generation is stale, it is dropped without forwarding. If it is greater than the service's current ready generation, the service returns a bounded protocol error and does not buffer it for a future epoch.

The service must not use the generic pending queues for new `direct_candidate`, `direct_candidate_done`, or `direct_key` records. The queues may continue to carry other supported signaling envelopes. When a new establishment epoch is published, any legacy/direct-establishment records already present in those queues are removed selectively by message type; ICE records and unrelated supported envelopes are preserved. In particular, a cleanup must not clear an entire queue merely because a direct epoch changed.

Direct establishment is v2-only after this specification is implemented. The
new client always sends `direct_candidate`, `direct_candidate_done`, and
`direct_key`; the server and client do not provide an undefined legacy direct
compatibility gate. The historical `candidate` and `candidate_done` records
are not accepted as direct v2 records, and a pre-v2 direct endpoint is not
supported in the same pairing. The existing `key` record remains the ICE key
envelope and is not changed. If a deployment needs mixed-version direct
operation later, it must first add a separately specified, explicit
`direct_signaling_version` to pairing/session creation; this phase does not
silently infer or negotiate one.

### Client generation handling

The direct client tracks the latest accepted `peer_ready` generation and its phase:

- `generation < active_generation`: stale; discard silently without changing candidate, key, timeout, or socket state;
- `generation == active_generation`: eligible for the current phase's normal validation;
- `generation > active_generation`: protocol violation; fail the current direct establishment rather than buffering a future epoch;
- any direct candidate/key before a matching `peer_ready`: invalid and fail closed;
- `peer_reset(N)` for the current or newer epoch: abandon that epoch and return to `WAITING_FOR_PEER`; an older reset is stale and ignored.

Duplicate current-generation candidate records are idempotent when their complete contents match an already accepted candidate. A duplicate `direct_candidate_done` with the same count is harmless. A duplicate `direct_key` is harmless only when all key fields match the already accepted key; a conflicting key for the same generation is an authentication/protocol error.

No candidate or key from a prior generation may be used to complete a later generation. Candidate vectors, candidate-complete state, key exchange state, and phase deadlines are cleared on reset.

## Direct key authentication transcript

The v2 direct key signature must bind the session, epoch, role, and ephemeral key using deterministic binary encoding. It must not sign a JSON serialization or a map whose field order could vary.

The signed bytes are exactly:

```text
ASCII("OpenStream direct key v2")
|| u32_be(byte_length(session_id))
|| UTF8(session_id)
|| u64_be(establishment_generation)
|| u8(sender_role)
|| 32-byte ephemeral X25519 public key
```

The sender-role byte is the existing role value (`1` for host, `2` for client). The identity public key is carried in the envelope and is used to verify this signature; it is not substituted for the ephemeral key in the transcript.

The receiver derives the peer role from the authenticated role-scoped
WebSocket endpoint. There is deliberately no security-relevant `role` field
in the JSON envelope. For a local host, the expected sender role is client;
for a local client, the expected sender role is host. The receiver verifies
the signature using that expected role byte in the transcript, rather than
trusting a peer-advertised role.

The receiver verifies that:

- the message is `direct_key` for the currently accepted establishment generation;
- the signed role byte is the opposite of the authenticated local role;
- the signature verifies over the exact transcript above;
- the peer identity pin and existing non-loopback authentication policy pass;
- the X25519 public key is not a rejected low-order/all-zero value.

Only after this verification may the client derive `CipherSession` keys. The generation is not a second cipher nonce domain; it is an authentication-attempt binding that prevents an old signed key from being transplanted into a new reconnect.

## Candidate and key phase behavior

After `peer_ready(N)`:

1. Each role sends its complete local candidate set using `direct_candidate` records tagged `N`, then sends one `direct_candidate_done` tagged `N`.
2. Each role accepts only usable, non-self, non-duplicate candidates tagged `N`. Stale records are discarded and future records fail the attempt. The candidate deadline begins at readiness acceptance and remains 15 seconds.
3. After receiving `direct_candidate_done(N)`, each role generates a fresh ephemeral key exchange and identity signature, sends one `direct_key(N)`, and waits up to 15 seconds for the matching peer key.
4. A direct key arriving before the local candidate exchange completes is a protocol error for v2; it is not stashed as an ICE/legacy key.
5. After both key records authenticate, the existing deterministic candidate ordering, UDP probe, relay registration, and encrypted path proof run without changing the data packet format.

If a reset or WebSocket close interrupts any step, all records for `N` are discarded. The same `Endpoint` and UDP socket may be reused for the next epoch, but the key exchange must be regenerated and every signaling record must carry `N+1`.

## ICE isolation

The full ICE path remains an independent signaling choreography:

```text
ice_credentials
ice_candidate
ice_candidate_done
key
```

Those messages do not gain `establishment_generation`, and `establish_with_ice` does not wait for or emit direct candidate records. The server continues to validate and forward them under its existing rules. The direct lifecycle records may be delivered to an ICE endpoint by the shared service, but the ICE client ignores them as unrelated message types.

This separation is required because the existing `key` envelope is shared by the ICE implementation and the old direct path. A generation field must not be added to that envelope as a side effect of fixing direct startup order. The v2 direct path uses `direct_key` exclusively.

## Failure, resource, and security behavior

- Waiting for a peer consumes one authenticated WebSocket and one bounded server queue, not an unbounded task or message store. Session expiry and WebSocket idle/heartbeat policy remain the upper resource bound.
- Candidate/key phase timeouts continue to terminate a stalled current-generation attempt. They do not invalidate or increment the server generation by themselves; a later retry uses the next epoch only after socket membership changes or an explicit new pair is formed according to the server algorithm.
- Direct records are size-validated before forwarding. The server never logs their bearer token, key material, or peer address beyond the existing bounded protocol handling.
- A stale socket cannot submit a correctly signed old-generation key after a replacement because the server rejects its socket generation before forwarding, and the receiving client independently rejects the old establishment generation.
- A valid old key cannot authenticate a new epoch because the signed transcript contains both the session ID and the establishment generation.
- The protocol does not silently reconnect a new session and label it as continuation of the old one. A failure before UDP authentication is reported as a failed establishment only after the session lifetime/cancellation rules prevent a new current pair from forming.

## Verification contract

The implementation is not complete until the following tests pass.

### Pure protocol and validator tests

- `peer_ready` and `peer_reset` validate only as service-generated records and reject client-originated forms.
- `direct_candidate`, `direct_candidate_done`, and `direct_key` require a positive `establishment_generation` and their exact bounded fields.
- Missing, zero, stale, and future generations produce the specified outcomes.
- The old `key` validator remains valid for ICE messages without a generation field.
- The direct key signature verifies for the exact binary transcript and fails when the session ID, generation, role, or ephemeral key changes.
- JSON field order changes do not change the signed bytes because JSON is not the transcript.

### Signaling-service lifecycle tests

- The first role waits without receiving `peer_ready`; the second current role causes exactly one generation and readiness records to the exact current sockets.
- Direct records sent before readiness are rejected and never enter `pending_host` or `pending_client`.
- Selective direct-queue cleanup removes direct records but preserves ICE and unrelated supported records.
- Replacing the host or client invalidates the old generation immediately, sends one reset to the surviving current socket, and publishes only the next generation to the new pair.
- Partial `peer_ready` delivery never leaves a usable generation; accepted readiness is compensated with reset or socket closure, and reset delivery failure prevents the next generation from being published.
- A stale old socket cannot forward a correctly formed old-generation direct candidate or key after replacement.
- A stale disconnect cleanup cannot remove the replacement sender or emit a reset for the new pair.
- A socket replacement after `peer_ready(N)` but before `direct_candidate_done(N)` permits only `N+1` to proceed.
- A socket replacement after candidate completion but before direct key completion permits only `N+1` to proceed.
- Establishment-generation overflow fails closed without wrapping.

### Client state and integration tests

- Host-first startup with the client delayed beyond `PHASE_TIMEOUT` establishes successfully once the client joins.
- Client-first startup establishes successfully.
- Host and client can reconnect and establish a new epoch without reusing candidate or key state.
- A stale candidate, completion record, or signed key from `N` is ignored/rejected after `peer_ready(N+1)`.
- A future-generation direct message fails the attempt and is never buffered.
- A `peer_reset` during waiting, candidate exchange, and key exchange returns the client to waiting without leaking the UDP socket or leaving a phase timer active.
- Direct establishment and existing full ICE establishment continue to use their separate envelope sets.
- A completed direct session still produces the same authenticated UDP path and encrypted media behavior as the pre-change implementation.

### Acceptance evidence

The real Linux-NVIDIA host -> Apple-silicon macOS client fallback path remains the known-good functional baseline. The startup-order acceptance record must include a host-first run with a delay greater than 15 seconds, the selected direct path, authenticated key exchange, continuous H.264 media, and no second session identity or credential exposure.

## Implementation boundaries

The implementation plan should keep this change reviewable in the following areas:

- `engine/lowlat/crates/signal-server/src/main.rs`: establishment epoch state, exact-current-socket checks, direct envelope validation, selective queue handling, readiness/reset delivery, and lifecycle tests.
- `engine/lowlat/crates/client-core/src/lib.rs`: direct readiness wait, generation-filtered direct candidate/key choreography, binary key transcript, reset/retry state, and direct protocol tests.
- `engine/lowlat/crates/client-core/tests/`: delayed-start, replacement-race, stale-generation, reconnect, and direct-versus-ICE integration coverage.
- `docs/`: startup-order acceptance procedure and changelog after implementation.

No lowlat transport-policy, media, native capture, or ICE dependency changes are part of this specification.
