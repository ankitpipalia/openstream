# macOS host to Windows client, live session

**Date:** 2026-09-19 (UTC 22:5x)
**SHA:** `c8bf1949a5ed77cef5ebbe7bc821ceecf179d4a4` (`c8bf194`, `main`)
**Host:** this Apple Silicon Mac, ScreenCaptureKit into VideoToolbox
**Client:** Windows 10 Home 19045, GTX 970, Media Foundation in-process decode
**Transport:** direct UDP on the LAN, no relay
**Profile:** `--release` both ends

**This is the first live session involving Windows, in either direction.** Until now
Windows had subsystem evidence only.

## What ran

Host, from its own log (`mac-host.log`):

```text
OpenStream run path=DirectUdp { candidate: Host }
OpenStream run capture=native
OpenStream run encoder=videotoolbox-h264
```

Client, from its log:

```text
OpenStream run decoder=media-foundation in-process h264 (no ffmpeg subprocess)
OpenStream in-process decoder: Media Foundation H.264 on this thread (software MFT)
```

The client's own title bar, read off the Windows screen:

```text
OpenStream -- 1920x1080 @ 60fps -- DirectUdp ( candidate: Host )
-- audio=false input=false -- loss 0.0% -- shown 373/380
```

Host frame heartbeat reached `streaming 824`.

## Evidence of pixels, not counters

Two screenshots of the Windows desktop were taken ten seconds apart, in session 1. They
differ, and the client window shows the Mac's actual desktop, legibly: the terminal content
rendered on the Windows screen is readable and matches what was on the Mac at that moment.
This is pixel evidence rather than a frame count.

**The screenshots are deliberately not committed.** They show the operator's screen, which
included private network addresses, and this is a public repository. They are held outside
the repository; see `OPERATOR-NOTES.md`.

## No FFmpeg was involved

Capture and encode were `native` / `videotoolbox-h264`; decode was the in-process Media
Foundation path, which the client names explicitly as "no ffmpeg subprocess". This is the
Parsec-style path end to end, on a pair that had never been exercised.

Note the qualifier: the decoder selected was the **software MFT**. Hardware decode exists and
was proven separately on this machine, but this session did not force it.

## Three things blocked the session first, and all three were correct

1. **`InsecureOrigin`.** The host refuses to send bearer tokens to a non-loopback `http://`
   origin. Resolved by `OPENSTREAM_LOCAL_NO_AUTH=1`, the sanctioned trusted-LAN mode, rather
   than by weakening anything.
2. **`PeerIdentityRequired`.** Both ends refuse a non-loopback session without a pinned peer
   fingerprint. Resolved by exchanging fingerprints out of band and setting
   `OPENSTREAM_EXPECT_PEER_IDENTITY` on each end. Working as designed: this is the
   signalling-MITM defence.
3. **`NoReachableCandidate`.** This one is a **product finding**, not an operator error.

## The candidate finding, which is worth acting on

The Mac has three addresses: one on the LAN, and two on Parallels bridge interfaces that no
other machine on the LAN can reach. ICE offered candidates from the bridges, the peer could
not reach them, and the session failed with `NoReachableCandidate` and nothing pointing at
the cause.

Raw UDP between the two machines worked throughout, so this was not a firewall.

Binding the host explicitly with `OPENSTREAM_UDP_BIND=<lan-address>:0` fixed it immediately
and the session established on the first try.

Any machine running a hypervisor has interfaces like these, so this will affect ordinary
users, not just this rig. Two things would help: prefer or at least include the route-to-peer
interface when gathering host candidates, and name the candidates that were tried in the
`NoReachableCandidate` error so the failure is diagnosable without packet capture.

## What this does not establish

Audio and input were off in this run (`audio=false input=false`). No sustained ten-minute
run, no resolution change, no abrupt-termination recovery, no signalling-outage test. The
reverse direction, Windows host to macOS client, has not been run. Hardware decode was not
forced on the client.
