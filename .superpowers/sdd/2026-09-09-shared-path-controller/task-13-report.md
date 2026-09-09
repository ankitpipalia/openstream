# Task 13 implementation report — bound relay cleanup deadline

## Status

Implemented the two Task 13 review findings on `codex/shared-path-controller`,
preserving base `b54891e` and all existing commits.

`UdpTransport::unregister_relay_socket` now bounds each unregister send by the
remaining 750 ms cleanup deadline, returns the existing `Error::Timeout` when
that send cannot finish in time, and recomputes the remaining deadline after
the send before waiting for an unregister ACK.

`close_releases_draining_path_before_deadline` now runs the close future inside
the prompt timeout. The relay withholds the first unregister ACK until the
test has observed the unregister, so a close that returns while cleanup is
still pending fails. The repeated-close assertion still requires exactly one
unregister.

No public wire format, cryptographic session state, migration protocol,
one-shot cleanup ownership, or relay role/idempotence behavior changed.

## Changed files

- `engine/lowlat/crates/transport/src/lib.rs` — deadline-bound unregister
  sends and post-send remaining-time recomputation.
- `engine/lowlat/crates/client-core/src/lib.rs` — close lifecycle regression
  assertion that observes cleanup before close completion.
- `.superpowers/sdd/2026-09-09-shared-path-controller/task-13-report.md` —
  this report.

## TDD evidence

### RED audit

The lifecycle regression was adjusted before the transport production edit and
run against the requested base implementation:

```sh
cd engine/lowlat
cargo test --locked -p openstream-client-core close_releases_draining_path -- --test-threads=1
```

Observed result on `b54891e` (exit 0):

```text
running 1 test
test tests::close_releases_draining_path_before_deadline ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out
```

This base already contains Task 12's synchronous draining-path close, so the
strengthened assertion was already GREEN. No valid lifecycle RED failure could
be honestly recorded against `b54891e`; the earlier test-harness compile
errors were corrected and were not behavioral RED evidence.

### GREEN

After the transport deadline change, the same close regression passed:

```text
running 1 test
test tests::close_releases_draining_path_before_deadline ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.12s
```

The focused unregister retry test also passed:

```sh
cargo test --locked -p openstream-transport relay_unregistration_retries_until_the_relay_acknowledges_it -- --test-threads=1
```

```text
running 1 test
test tests::relay_unregistration_retries_until_the_relay_acknowledges_it ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.11s
```

Formatting passed:

```sh
cargo fmt --all -- --check
```

Exit 0 with no output.

## Concerns

- The requested lifecycle RED state is unavailable because the supplied base
  already implements the behavior that the strengthened regression verifies.
- The focused transport test exercises retry/ACK behavior; the concrete
  `tokio::net::UdpSocket` API does not provide an injectable blocked-send seam,
  so no deterministic unit fixture was added solely to stall `send`.
