# M3 (server half): trust both ends of a connection

## The gaps

Two authorization holes on `main` at `c8bf194`, both found while planning the
headless machine service. Neither is reachable from outside the account; both
are wrong in the same way, in that a device its owner has not accepted, or has
explicitly revoked, gets further than it should.

### 1. `POST /v1/connect` never checks the asker

`connect_request` reads the requester's device id from `connect_principal`, then
verifies that the *target* is `Trusted`. The requester's own trust is never
consulted. Enrolment leaves a device `Pending` until its owner accepts it, so a
pending device could put a request in front of a trusted host, where it arrived
as an ordinary approval prompt naming an unaccepted device.

`POST /v1/presence` already gates on `can_create_session`. Connect did not, so
"may this device take part in sessions" had one answer for presence and another
for connect.

### 2. A revoked device is handed a token that is then evicted

`commit_device_auth` never looked at trust. `authorize_access` evicts a revoked
device's token the first time it is presented, so a revoked machine
authenticated successfully, was refused on its next call, re-authenticated, and
repeated that for as long as it ran. The token was useless, which is why this is
a robustness fault rather than a privilege escalation, but nothing ever told the
machine to stop.

## The changes

- `connect_request` calls `can_create_session` for the requester inside the
  account lock it already takes, before the existing target check.
- `commit_device_auth` refuses a `Revoked` device with `DeviceRevoked`, which
  renders as 403.

The revoked check sits **after** signature verification and before the nonce is
consumed. After, because answering "revoked" before verifying would tell any
caller which devices an account has revoked, and the decoy-key path exists
precisely to deny that. Before the nonce is burned, because a revoked device
that keeps trying should not consume the nonce table.

`Pending` deliberately still authenticates. A machine enrolled and waiting to be
accepted needs a token so it can discover it is not trusted yet and wait;
refusing it at the door would leave it unable to tell "not accepted yet" from
"bad key".

## Tests

- `an_untrusted_device_cannot_ask_for_a_session`: a pending device is refused
  403, the host's pending list stays empty, and the same device once accepted
  is allowed through, so the refusal is about trust rather than novelty.
- `a_revoked_device_cannot_mint_a_token`: a device authenticates, its owner
  revokes it, and the same valid proof is then refused 403.

Teeth: with the `can_create_session` call removed the first test sees 200 and a
`request_id`; with the revoked check removed the second is handed a token whose
own body reports `"trust":"revoked"`.

The client half of M3, the portable presence and connect modules in
`client-core`, follows separately.
