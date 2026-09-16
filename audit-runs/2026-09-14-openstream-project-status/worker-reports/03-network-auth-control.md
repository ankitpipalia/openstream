# Workstream 3 — Networking, authentication, and control plane

## Data flow

The intended architecture is substantially real:

1. REST creates an ephemeral session and issues host/client bearer
   capabilities.
2. Role-authenticated WebSockets exchange candidates, credentials, signed
   ephemeral keys, migration control, and liveness.
3. Direct mode probes host/server-reflexive/UPnP/application-relay candidates;
   full ICE mode uses host/server-reflexive/peer-reflexive/TURN candidates.
4. Once selected, media/input/control are OpenStream AES-256-GCM datagrams over
   direct UDP, a TURN `Conn`, or the application relay.

Therefore the signaling server is not in a successful direct media path, but
the WebSocket remains connected as a control/liveness path. TURN and the
application relay necessarily remain in the media path when selected.

## Strong implementation

- X25519 session establishment; Ed25519-signed ephemeral transcript;
  session/role binding; generation binding in direct-v2.
- AES-256-GCM, direction-separated keys, one replay domain, 64-counter replay
  window.
- Role bearer tokens in Authorization headers rather than URLs.
- Bounded message sizes, rates, candidate counts, session count, pending
  queues, relay packet/byte rates, TTLs, and relay idle cleanup.
- Direct-v2 server-authoritative establishment generations prevent stale
  reconnect records and remove peer-wait time from phase deadlines.
- Full ICE includes STUN/TURN, nomination, consent freshness, keepalives, IPv4
  and IPv6 candidate types.

## Critical gaps

- The signaling server is an in-memory session broker, not an account/device
  control plane. It has no durable users, enrolled devices, refresh tokens,
  trusted-device policies, presence database, invitations, or audit store.
- Identity keys can be ephemeral or loaded from environment/plain file; no OS
  secure-store provider is implemented.
- Full ICE still sends `ice_credentials` immediately and starts a 15-second
  candidate deadline. Its generic messages remain queued across absent peers,
  but have no establishment epoch. This preserves host-first timeout and stale
  queued ICE/key ambiguity that direct-v2 fixed.
- ICE restart/path migration is typed unsupported with `webrtc-ice 0.17.2`.
- All WAN/NAT/TURN cases remain unverified.
- Server restart drops in-memory sessions, WebSockets, relay registration, and
  tickets. Client retry can create a fresh session only if the external
  product control layer reissues credentials; that layer does not exist.

## Assessment

Direct LAN networking is implemented and physically exercised. Relay and ICE
are meaningful implementations with strong loopback tests, not production WAN
proof. Authentication primitives are good; user/device authentication and
trust are missing.
