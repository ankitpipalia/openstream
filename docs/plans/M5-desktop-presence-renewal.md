# M5: keep a hosting desktop present

## The defect

`POST /v1/presence` is a heartbeat, not a registration. The server expires an
entry after `PRESENCE_TTL`, which is 90 seconds
(`engine/lowlat/crates/signal-server/src/connect.rs:75`), and only
`connect_presence` refreshes it (`main.rs:2615`).

The desktop announces presence exactly once, when hosting is enabled, and once
more to withdraw it when hosting is disabled
(`desktop/src-tauri/src/lib.rs`, `dispatch_command_with_session`). Nothing
re-announces. So a desktop host disappears from its owner's device list 90
seconds after it starts hosting, and every later Secure Connect request against
it is refused with `TargetOffline` even though the machine is sitting there
hosting.

This is not cosmetic. Presence is what makes a host connectable, so the product
feature "leave this machine hosting and connect to it later" does not work at
all today. That is why it is a 1.0 blocker rather than a nice-to-have.

## The change

A small pure scheduler, `desktop/src-tauri/src/presence.rs`, decides when the
next beat is due. The runtime spawns one task that polls it beside the two
watchers that already exist.

- Renew every 30 seconds against the 90-second server TTL, so two consecutive
  failures still leave a third attempt before the entry lapses.
- Add up to 5 seconds of jitter, so a fleet restarted together does not beat in
  lockstep. Because it is added it *narrows* the margin against the TTL rather
  than widening it: the worst case is a 35-second gap against a 90-second
  lifetime. That is why it is a small fixed bound and not a fraction of the
  interval. It is drawn from a seeded generator, so a test can pin it.
- Announce only while the host is `Ready`. The tempting rule is "anything but
  `Disabled`", which is what the hosting lifecycle asks elsewhere, and it is
  wrong here: `HostStatus` also has `Failed`, so a host whose agent crashed
  would keep announcing itself for as long as the shell stayed open, sitting in
  its owner's list looking connectable while every request to it timed out.
- Withdraw on sign-out *before* clearing the token, since withdrawal needs it.
  Clearing first leaves the device advertised for up to a full TTL by an
  account that has signed out.
- On failure, back off 2, 4, 8, capped at 15 seconds, and keep trying. A
  failed beat must never disable hosting: hosting is a local fact and the
  control plane's opinion of it is advisory.
- Stop beating when hosting stops or the account signs out, and beat
  immediately when hosting next starts.

Withdrawal stays where it is, on the explicit disable path. The renewal task
only announces. Racing the command path to withdraw would buy nothing: a host
that dies without withdrawing is exactly what the TTL is for.

## How it is tested

The scheduler takes `now` as an argument, so the tests advance a fake clock and
never sleep. Asserting on elapsed wall-clock time would be asserting on the OS
scheduler.

- `presence_is_renewed_before_the_server_ttl_expires` steps through three full
  TTL intervals and asserts no gap between beats ever reaches 90 seconds.
- `a_run_of_failures_still_beats_inside_the_server_ttl` fails every attempt and
  asserts the backoff never pushes an attempt past the TTL.
- `renewal_is_spread_without_drifting_past_the_ttl` asserts jitter varies and
  stays inside its bound.
- `hosting_that_stops_and_restarts_beats_immediately` covers the reset.

Teeth: revert `record_success` to schedule one beat and never another, which is
today's behaviour, and the first test fails on the second interval.
