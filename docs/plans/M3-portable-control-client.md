# M3 (client half): one control-plane client, below both callers

## Why it exists

Every one of these endpoints already had a client: `ControlPlaneClient` in
`desktop/src-tauri/src/control_plane.rs`, built on `reqwest`. A Tauri
application cannot be a dependency of a headless service, so the machine
service needed its own. That guaranteed two implementations of the same wire
contract. Putting this one in `client-core`, below both, means the second
implementation is the shared one and the shell can eventually delete its copy
rather than the two drifting apart.

The drift is not hypothetical. The shell's `ConnectCredential` once parsed the
negotiated permission set and dropped it on the floor, so every session ran with
whatever the machine-wide policy allowed rather than what the host approved.

## What it covers

`client-core::control_plane`, on the crate's existing HTTP client rather than
`reqwest`:

- `announce_presence`, `withdraw_presence`
- `pending_connect_requests`, `approve_connect`, `deny_connect`
- `list_devices`, with `DeviceTrust`
- `ConnectCredential::into_host_pairing`, which refuses any role but host

One error type for the family rather than one per endpoint, with
`is_unauthorized` and `is_forbidden` on it. A control loop must tell those two
apart: 401 means the token is finished and a fresh proof should be made, 403
means this device is not permitted and proving again cannot change the answer.
That distinction is the whole difference between recovering and hammering.

`list_devices` is here because a headless host needs it. The service checks that
the *target* of a connection request is trusted; from the host's side that is
the requester, and nothing else checks it. The server-side half of M3 closes
that gap too, and the machine service repeats the check as defence in depth.

## Wire compatibility

The types are field-for-field the shell's and the service's. `Permissions`
already carries `#[serde(default)]` on every field, so an absent class reads as
denied: a partial object can only narrow a granted set, never widen it.
Unknown fields on `PublicDevice` are ignored rather than refused, so a service
that grows a field does not break a machine that has not been updated.

`ConnectCredential` has a hand-written `Debug` that redacts the session token,
the relay ticket and the grant. All three are bearer material.

## Tests

Offline, against the exact JSON the signal server's own tests pin.

- `a_host_credential_becomes_a_pairing_that_keeps_the_grant` is the important
  one. Teeth: setting `session_grant: None` in the conversion fails it with
  "the broker's approval must survive the conversion".
- `a_client_credential_is_refused_as_a_host_pairing`.
- `a_pending_request_without_a_requested_set_asks_for_nothing`.
- `an_older_service_still_parses`.
- `a_credential_never_prints_its_token`.
- `a_request_id_is_encoded_into_the_path`, including `a/../b`.
- `the_two_statuses_a_control_loop_must_tell_apart`.

The HTTP functions themselves are exercised against a real running
`openstream-signal-server` in M4's integration test, which is where a live
server is already being started.
