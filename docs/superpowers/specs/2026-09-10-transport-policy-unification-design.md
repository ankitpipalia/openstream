# Common Transport Policy Foundation

## Goal

Extract the pure pacing and congestion-policy state machines from
`lowlat-core` into a protocol-neutral, `no_std` crate that can later be used by
the portable `PeerSession` scheduler without importing lowlat packet, socket,
ICE, or platform assumptions.

## Scope

This phase changes policy ownership only. It preserves the current lowlat
wire behavior and does not add a portable outbound queue, change
`PeerSession::send`, change `UdpTransport`, alter migration, or add a new
runtime dependency.

The new crate is `openstream-transport-policy` at
`engine/lowlat/crates/transport-policy`. It has no dependencies, uses
`#![no_std]`, and contains only deterministic state machines and value types.
The lowlat crate keeps compatibility modules that re-export the extracted
types and constants, so existing lowlat callers do not change in this phase.

## Pacer contract

`PacerConfig` owns the protocol-independent bounds:

```rust
pub struct PacerConfig {
    pub min_datagram_bytes: usize,
    pub max_datagram_bytes: usize,
    pub max_burst_datagrams: usize,
    pub max_burst_time_ms: f64,
}
```

`PacerConfig::validate()` rejects zero sizes, a maximum below the minimum,
zero burst count, non-finite or non-positive burst time, and values where the
minimum datagram is greater than the maximum. The lowlat compatibility
configuration is exactly 1229 through 2000 bytes, four datagrams, and 5.0 ms.

`Pacer` retains the current API and semantics: decimal Mbps, caller-supplied
fractional milliseconds, no credit from a backward/non-finite clock, one
whole-datagram minimum credit, rate- and packet-bounded stored credit, and
credit clipping after datagram-size reduction. `Pacer::with_config` is the
validated constructor for future paths; `Pacer::new` uses the compatibility
default.

## Congestion contract

`CongestionObservation` is the neutral input type for a future shared
controller:

```rust
pub struct CongestionObservation {
    pub in_flight: Option<u32>,
    pub stale: Option<u32>,
    pub delivery_rate_mbps: Option<f64>,
    pub srtt_ms: Option<f64>,
}
```

Missing packet-level fields are not fabricated. The extracted controller
retains the lowlat-compatible `tick(window, stale, measured_mbps)` method and
adds `tick_observation`. `tick_observation` returns `None` and leaves
controller state unchanged unless both `in_flight` and `stale` are present;
the optional delivery rate is used only when supplied. This prevents a future
portable caller from treating local send rate as delivery capacity.

`AdaptiveBitrate` remains the separate end-to-end frame-feedback controller in
`openstream-media`; this phase does not merge frame ACK policy with packet
congestion policy.

## Compatibility and safety invariants

- No wire-format, packet-size, socket, or `PeerSession` behavior changes.
- The lowlat default Pacer configuration is byte-for-byte behavior-compatible.
- The new crate contains no Tokio, networking, crypto, allocation, or platform
  dependency.
- Path generation, PMTU, migration, and cipher/replay state remain outside
  the policy crate.
- Local portable transport rates remain diagnostic and cannot independently
  actuate `AdaptiveBitrate`.

## Verification gate

The phase is complete only when the new crate's unit tests, the unchanged
lowlat core tests, workspace Clippy with warnings denied, and the locked full
workspace test suite pass. The extracted crate must compile independently with
`cargo test -p openstream-transport-policy`.

