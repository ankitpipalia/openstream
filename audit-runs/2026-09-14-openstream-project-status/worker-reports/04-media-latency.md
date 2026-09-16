# Workstream 4 — Media and latency

## Current measured path

The physical rig used Linux/NVIDIA capture/encode through an external pipeline,
authenticated direct UDP, and an Apple-Silicon client with FFmpeg decode to
CPU BGRA. Repository documentation retains approximately 220–240 ms P50 as
the defensible display-latency range, with about ±30 ms uncertainty. Earlier
1,000 ms, 447 ms, and 165 ms figures are diagnostic history, not current
release claims.

PR #18 added stage and frame-age instrumentation, but
`docs/research/evidence/latency-rig-runs.md:217-233` explicitly says no physical
Run F has yet measured the corrected release stamps. Current end-to-end stage
attribution is therefore unverified.

## Pipeline status

- Capture: X11 and PipeWire FFmpeg profiles; native DRM/KMS foundation. The
  tested Wayland/NVIDIA machine exposed black Xwayland capture, lacked FFmpeg's
  PipeWire demuxer, and rejected `ABGR2101010` in kmsgrab. Native DRM also has
  unresolved PRIME/export interoperability.
- Encode: H.264/H.265 FFmpeg profiles, per-codec NVENC/VAAPI probes, low-delay
  NVENC/x264 settings, live control only through bounded process restart in the
  portable path. Whole access units are emitted; no slice/sub-frame transport.
- Transport: bounded fragmentation/reassembly, packet scheduler, authenticated
  transport ACKs, delivery estimator, pacer, congestion policy, DPLPMTUD in the
  native tier, frame ACKs and keyframe requests.
- Decode/render: desktop FFmpeg subprocess writes BGRA through a pipe; CPU
  per-pixel conversion and minifb/wgpu upload follow. The wgpu Metal backend is
  GPU presentation, not zero copy.
- iOS has an H.264 `AVSampleBufferDisplayLayer` source seam; Android has H.264
  `MediaCodec`. Neither is device-tested.
- Audio: Opus framing, jitter buffer and PLC are integration-tested; platform
  endpoint behavior is not physically verified.
- Input: HID keyboard, mouse/buttons/wheel, gamepad envelope and host adapters
  exist. Desktop mouse motion comes from sampled cursor positions and all
  events are sent through reliable control; raw/immersive latest-wins motion is
  missing.

## Main latency blockers

1. capture bridge/process copies and no reliable native Wayland path;
2. FFmpeg subprocess decode plus CPU BGRA copy/conversion/upload;
3. whole-frame rather than slice/sub-frame encode and transmission;
4. lack of refresh-aware native session window/presentation;
5. reliable ordered high-rate mouse motion;
6. no current corrected physical instrumentation run.

Parsec artifact symbols directly show native VideoToolbox/CoreVideo/IOSurface/
Metal and raw HID input capabilities. Exact runtime policy remains inference.
