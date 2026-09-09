# NAT traversal matrix

This records the expected OpenStream connectivity outcome per NAT combination
and how each case is verified. It is the acceptance record for the Phase 2
connectivity gate; entries marked "not yet run" are honest gaps, not claims.

## Path ladder

1. Direct authenticated nomination (host/srflx/peer-reflexive/mapped
   candidates, simultaneous low-TTL punch). Always attempted first.
2. UPnP-mapped candidate (`OPENSTREAM_UPNP=1`), opportunistic.
3. Application-owned UDP relay (built into the signal service).
4. Standards-based full ICE with TURN (`OPENSTREAM_ICE=1`), using either
   static `OPENSTREAM_TURN_USERNAME/PASSWORD` or session-scoped credentials
   from `GET /v1/session/{id}/turn`.

## Matrix

| Host NAT | Client NAT | Expected path | Verified by |
|---|---|---|---|
| Open / loopback | Open / loopback | Direct host candidate | Loopback + LAN tests, `full-ice-smoke.sh` |
| Full cone | Full cone | Direct srflx | Simulator + namespace fixtures |
| Restricted cone | Restricted cone | Direct srflx after first outbound | Simulator + namespace fixtures |
| Port-restricted cone | Port-restricted cone | Direct srflx | Simulator + namespace fixtures |
| Symmetric | Any cone | Peer-reflexive or relay | Namespace symmetric fixture; app relay forced test |
| Any cone | Symmetric | Peer-reflexive or relay | Namespace symmetric fixture; app relay forced test |
| Symmetric | Symmetric | Application relay, or TURN when `OPENSTREAM_ICE=1` | Forced-relay test; external coturn run (not yet run) |
| CGNAT (shared address space) | CGNAT, same provider | Direct only with opt-in shared-space candidates | Not yet run |
| Any | Any, UDP blocked | TURN/TCP or failure with typed outcome | Not yet run (UDP-only relay at present) |

## OpenStream-owned path migration

Direct and the application-owned opaque relay are separate OpenStream path
generations. The host prepares and authenticates the replacement, commits it
with `PATH_COMMIT`/`PATH_COMMIT_ACK`, keeps the old path receive-only for a
bounded drain, and preserves one cipher/replay domain and end-to-end frame
identity. The acceptance harness proves the complete sequence:

```sh
./scripts/path-migration-smoke.sh
```

Expected evidence is one session surviving:

```text
generation 1: direct_udp
generation 2: opaque_relay
generation 3: direct_udp
```

The harness also verifies frame acknowledgements across all three generations
and relay unregister cleanup. It does not prove TURN migration, public-NAT
reachability, or stock Parsec compatibility.

ICE/TURN migration is a separate capability boundary. With the repository's
current `webrtc-ice 0.17.2` dependency, the supported result is the typed
`UnsupportedIceRestart` outcome; no new cipher/session is created and the
active ICE path remains unchanged:

```sh
./scripts/ice-migration-capability.sh
```

This loopback check proves truthful capability reporting only. A future ICE
implementation may replace the result after it can satisfy the same
prepare/prove/commit/rollback contract. Until then, external coturn remains
an unverified connectivity and migration gate.

## External coturn interoperability

1. Install coturn and copy `deploy/turnserver.conf.example`, replacing
   `static-auth-secret` with a long random value.
2. Start the signal service with the same value in
   `OPENSTREAM_TURN_SECRET`, plus `OPENSTREAM_TURN_URLS` and
   `OPENSTREAM_TURN_REALM`.
3. Create a pairing with `scripts/create-session.sh`; the pairing JSON gains
   a `turn` object when issuance is configured.
4. Run both roles with `OPENSTREAM_ICE=1 OPENSTREAM_ICE_URLS=<turn: URL>`
   and confirm the selected path reports the relay candidate.
5. Confirm an expired credential (wait past `ttl_seconds`) is rejected by
   coturn with a fresh allocation attempt, and that credentials minted for
   one session id are not accepted for another.

## Non-goals

The service never proxies TURN media itself, never logs TURN passwords, and
never mints credentials for unknown or expired sessions. Per-user TURN quotas
remain planned alongside per-user identity.
