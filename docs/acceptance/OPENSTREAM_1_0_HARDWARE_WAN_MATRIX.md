# OpenStream 1.0 hardware and WAN acceptance matrix

This is an evidence ledger, not a claim that the gates have passed. Each
`PASS` row must link to an operator-owned log, capture hash, or CI artifact
that can be reviewed independently. Do not put pairing JSON, TURN passwords,
relay tickets, private keys, or input values in the linked evidence.

The release checker is:

```sh
scripts/wan-acceptance.sh --check
scripts/network-fault-matrix.sh --check-report docs/acceptance/OPENSTREAM_1_0_HARDWARE_WAN_MATRIX.md
```

`UNVERIFIED` is intentionally the initial state. A release cannot be called
production-ready 1.0 while any required row remains unverified.

## Physical hardware gate

| case | status | evidence | notes |
| --- | --- | --- | --- |
| linux-nvidia-to-apple-silicon | PASS | 2026-09-15, see "Run of 2026-09-15" below | Picture, keyboard, raw pointer, audio, fullscreen and a clean release on disconnect all observed in one session. Raw pointer capture and macOS fullscreen were implemented to close this row; keyboard delivery was fixed after the run found presses shorter than a frame being dropped. Capture is through the xdg-desktop-portal PipeWire node, not X11: Xwayland is rootless here, so x11grab sees nothing |
| apple-silicon-videotoolbox-metal | PASS | 2026-09-15, see "Run of 2026-09-15" below | Metal presentation confirmed, and the FFmpeg software decode that is the fallback with it. VideoToolbox decode is now selectable with OPENSTREAM_DECODER=videotoolbox and measured on the rig: about 18 percent of one core against about 22 percent for software, twice each over 20 s. The gap is small because the frame is downloaded to system memory for the presenter; closing it needs a zero-copy path from VideoToolbox to the Metal texture |
| input-release-watchdog | UNVERIFIED |  | focus loss, close, network loss, and permission revocation release every held key/button |
| background-host-restart | UNVERIFIED |  | host agent survives UI exit and restarts without two children |

## Network gate

| case | status | evidence | notes |
| --- | --- | --- | --- |
| direct-udp | PASS | 2026-09-15, see "Run of 2026-09-15" below | Authenticated role-scoped pairing over DirectUdp { candidate: Host }; media and control both flowed, 0.0% loss reported by the client |
| turn-relay | UNVERIFIED |  | coturn path with credentials redacted from evidence |
| application-relay | UNVERIFIED |  | OpenStream relay path and generation-scoped migration |
| ipv4-double-nat | UNVERIFIED |  | discovery and selected path recorded |
| ipv6 | UNVERIFIED |  | direct or relay selection recorded |
| symmetric-nat | UNVERIFIED |  | TURN or application relay selected |
| loss-jitter | UNVERIFIED |  | 5% loss and 30 ms jitter do not create unbounded queues |
| bandwidth-limit | UNVERIFIED |  | constrained egress remains bounded and recovers |
| wifi-ethernet-roam | UNVERIFIED |  | path migration preserves the authenticated session |
| router-restart | UNVERIFIED |  | reconnect is explicit and input state is released |

## Run of 2026-09-15

One session between a SteamOS/NVIDIA host at 192.168.1.69 and an
Apple-Silicon macOS client on the same LAN, signalling over an SSH-forwarded
loopback port. Every claim below was read off pixels or a captured sample,
not off a counter: the client's own telemetry reported frames decoded and
presented during an earlier run whose screen was blank, so counters are not
accepted here as evidence of a picture.

Method. The host desktop was given a recognisable moving picture (SMPTE bars
with a running elapsed counter and a wall clock) so that a correct frame and
a stale frame could be told apart. Frames were then sampled at three points:
the PipeWire node, the client's presenter (`OPENSTREAM_DUMP_FRAMES`), and the
macOS screen itself (`screencapture`).

| observation | result |
| --- | --- |
| host capture | Real desktop pixels from the portal ScreenCast node, 2560x1440 scaled to 1920x1080 at 30 fps |
| encode | h264_nvenc, 8 Mbps, 60 fps steady, 0 stalls over 17,992 frames |
| client decode | Pixel-accurate copy of the host desktop, colours correct |
| freshness | Wall clock inside a decoded frame matched the macOS menu bar clock to the second |
| keyboard | 13 synthesised key codes produced exactly "openstream ok" in a remote editor, confirmed by reading the text out of the decoded frame and by the editor's own column counter reaching 1:14 |
| pointer | Absolute motion moved the remote cursor into the editor; a click took focus there |
| audio | Host test tone recovered from the client's decoded PCM at 440 Hz, matching the source |
| presentation | Metal presented 45.6 fps with a 2.2 ms mean present call, against 32.1 fps and 9.3 ms for the software path |
| disconnect | Both ends ran their shutdown reporting to completion; no error path, no orphaned child |

### Second session, after the fixes

The run above exposed three gaps, each of which was fixed and then confirmed
in a single further session that exercised everything at once:

| capability | evidence |
| --- | --- |
| fullscreen | `run window=fullscreen requested from the platform`; the stream fills the display with no title bar and no menu bar |
| raw pointer | `run pointer=raw device capture`; a 1620 px sweep delivered across a 1280 px window, which the clamped path could not have produced |
| keyboard | 13 key codes at a 30 ms hold produced exactly `openstream ok`, with the editor's own column counter at 1:14. The same 30 ms hold delivered 3 of 13 before the fix |
| audio | host test tone recovered from decoded PCM at 440 Hz |
| disconnect | the session ended on its own and the client released pointer capture and keyboard while its window was still open; another application took focus normally |

VideoToolbox decode has since been added as a selectable path and measured;
the software decoder remains the default because the measured gain is modest
and the hardware path has not been through a long soak.

Still not established: every WAN row other than `direct-udp`.

## Release policy

The current repository has loopback and application-owned relay smoke tests,
but those are not substitutes for the rows above. If hardware, WAN, signing,
or notarization evidence is unavailable, publish a development build or a
release candidate with the exact missing gates listed; do not label it
OpenStream 1.0 production-ready.

## Cross-NAT WAN run of 2026-09-15 (PARTIAL — not a gate pass)

Client on a mobile carrier hotspot (public map `47.11.113.62`, LAN
unreachable); host on the home network reached only through the Cloudflare
Tunnel for signalling. Both used full ICE (`OPENSTREAM_ICE_URLS=stun:stun.l.google.com:19302`)
with mutual peer-identity pinning. Synthetic FFmpeg source (`lavfi testsrc2`)
to remove the capture rig as a variable, which had broken three prior runs.

What was proven:

| observation | result |
| --- | --- |
| signalling over tunnel | client and host both registered; server minted an establishment epoch and both received `ice_peer_ready` |
| direct cross-NAT ICE | a direct path was established between the carrier NAT and the home NAT via peer-reflexive discovery — no relay in the path |
| media delivery | 925 media datagrams and 82 decoded H264 frames received at the client (`stage client frames=82 rate=89.5/s`), first fragment to reassembled p95 ≤ 33 ms |
| path RTT | ICMP to the host's public map averaged ~11 ms; latency was never the constraint |

What terminated it, and what remains unverified:

- The direct session ended after ≈0.9 s — **terminated by the application, not
  by the transport.** The client's reliable-control window filled with
  unthrottled keyframe requests during initial packet loss; the 65th `send()`
  returned the control layer's `TooLarge`, which was (a) the same variant used
  for a genuinely oversized payload and (b) fatal. The client reported
  `invalid signaling message: ordered control payload is too large` and dropped.
- Reconnect then failed on every retry with `establishment phase timed out:
  ice credentials/candidates`. Root cause is host-side: after the client's
  unclean drop (no `openstream/end`), the host had no peer-liveness teardown on
  the ICE path and stayed in its media loop for the whole `OPENSTREAM_HOST_SECONDS`
  window, so it never re-registered for the new epoch the client was waiting on.
- Endpoint-dependent (symmetric) NAT was observed on the carrier: three STUN
  queries from one socket returned three different public ports
  (`59216`, `64701`, `62870`). Peer-reflexive discovery still established a
  direct path here, but a TURN relay remains **mandatory** as a production
  fallback for networks where it cannot.

Still unverified after this run, and required before `wan-turn` or any WAN row
may change from `UNVERIFIED`: sustained direct operation (minutes, not
seconds), clean reconnect to a fresh epoch, TURN relay fallback, and behaviour
when signalling is stopped during an active session. `wan-turn` is **not**
passed by this result.

### Post-fix validation of the control-window and host-liveness changes (2026-09-15)

After the fix in this change set, the failure mode was re-exercised on the LAN
(the cross-NAT confirmation on a mobile hotspot is still pending):

| check | result |
| --- | --- |
| sustained session (direct path) | A synthetic-source session ran ~2 minutes: the host encoded 7455 frames at 60.2 fps with 0 stalls, and the client session stayed up the whole time with no `session ended`, no `ordered control payload is too large`, and no spurious teardown. The pre-fix failure killed the session at ~0.9 s |
| clean teardown (direct path) | killing the client produced an immediate transport error and the host ended cleanly: `ended after peer disconnect` |
| authenticated ICE liveness backstop | an ICE session was established, then the client was killed **silently** (no `openstream/end`, no socket error the host could observe on the ICE path). Exactly 15 s later the host logged `ending session: no authenticated peer traffic for 15.04s; re-registering` and exited for its supervisor to restart. Before the fix the ICE host stayed in its media loop indefinitely and a reconnecting client timed out forever on `ice credentials/candidates` |
| unit regressions | a tiny payload never returns `TooLarge`; a full window is backpressure, never fatal; hundreds of gaps coalesce to one request per interval; stale-epoch ICE messages are ignored |

Not shown here: reconnect to the **same** `session_id` after teardown. Sessions
are reaped by server TTL once no peer holds them, so the static test pairing's
id returned 404 (absent), not 410 (expired). Production issues a fresh pairing
per connect, so this is a test-fixture limitation, not a regression. The
cross-NAT direct-media re-run and the signalling-outage-during-session test
remain to be repeated on a genuinely different network.
## TURN relay run of 2026-09-15 (turn-relay row: PROVEN over UDP; TCP/TLS: dependency gap)

A coturn TURN server was run on the LAN host (in podman, long-term credential
`osturn`, realm `openstream.test`, UDP/TCP 3478 and TLS 5349). An OpenStream
host (synthetic source) and a client on a second machine were both configured
with `OPENSTREAM_ICE=1`, the TURN URL and credentials, and
`OPENSTREAM_FORCE_RELAY=1` so only relay candidates could be used.

| check | result |
| --- | --- |
| force-relay honored on the ICE path | With the fix in this change set, `establish_with_ice` gathers relay candidates only when `OPENSTREAM_FORCE_RELAY=1`. Without it, same-LAN ICE nominated a direct host pair and never touched the relay |
| TURN relay over UDP (`turn:...:3478?transport=udp`) | **Media relays through the TURN server.** coturn's own accounting recorded ~1.26 MB relayed per allocation for `username=osturn` across host and client sessions, sustained for the run; the client reported `run path=Ice` with no teardown |
| TURN over TLS (`turns:...:5349`) and TURN over TCP (`?transport=tcp`) | **Not attempted by the client** -- coturn logged no connection on the TLS listener. Root cause is the ICE dependency, not configuration: `webrtc-ice 0.17.2` `gather_candidates_relay` implements only `proto == Udp && scheme == Turn`; the TURNS and TURN-over-TCP cases are a commented-out `TODO` and fall through to "Unable to handle URL in gather_candidates_relay", so no relay candidate is gathered |

What this establishes and what it does not:

- OpenStream's TURN relay path works for the common case -- a symmetric NAT that
  still permits UDP to the relay. That is a substantive part of the `wan-turn`
  gate and de-risks it to deployment (a public TURN server).
- The **UDP-blocked** case still requires **TURN over TCP/TLS on 443**, which
  the earlier analysis flagged as unproven. It is now shown to be *unimplemented*
  in the `webrtc-ice 0.17.2` dependency, not merely unconfigured. Closing it needs
  either a `webrtc-ice` version that implements the TCP/TLS relay gather (its own
  `TODO`) or a TURN-over-TCP transport supplied outside the ICE agent.

This run used a LAN-local TURN server to prove the code path; it does **not**
change the `wan-turn` gate status, which still requires a public TURN server and
a genuine WAN. No release-gate TSV is updated.
