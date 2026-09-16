# Pre-login host (Linux): the privilege-split machine service and broker

A machine-level OpenStream host that is reachable at the login screen before any
user logs in, without running the network-facing process as root.

## Architecture

Two boot-time system services (see the unit files beside this doc):

- **`openstream-host-broker`** -- the only privileged process. It holds the two
  privileges that need elevation: reading the DRM/KMS scanout to capture and
  hardware-encode the screen (needs `CAP_SYS_ADMIN`), and injecting input through
  `/dev/uinput`. It is **not** network-facing, so its unit confines it to Unix
  sockets. It listens on `/run/openstream/broker.sock`, authorises the connecting
  machine service by `SO_PEERCRED`, and enforces the login-screen policy itself
  (at the greeter it grants keyboard and mouse -- so the remote user can type the
  OS password into the *native* login screen -- but never clipboard).

- **`openstream-machine-service`** -- the network-facing peer session
  (signaling, ICE, transport, negotiation, approval), run **unprivileged**. It
  drives the broker over the socket for capture and input, so the process an
  attacker can reach over the network never runs as root. It watches the logind
  seat and, on a login (greeter -> user) or logout, tells the broker to re-point
  capture through a state machine that never drops the approved peer -- the
  connection survives the login transition.

The OS password is entered into the native greeter, never an OpenStream form,
and is never sent, saved, or logged through the backend.

## Crates

- `openstream-host-ipc` -- the shared contract: wire protocol, the capture/login
  lifecycle state machine, per-session capability tokens, `SO_PEERCRED` auth, and
  the async socket transport. Pure and unit-tested (39 tests).
- `openstream-host-broker` -- the broker: a protocol core over device traits (11
  unit tests) plus the native DRM capture (`lowlat-host`), `uinput` injection
  (`lowlat-inject`), and the socket server.
- `openstream-machine-service` -- the service: the broker client, the logind seat
  reader, and the peer loop.

## Bring-up (both privileged, to prove the pipeline)

The broker must run as root for `CAP_SYS_ADMIN` and `/dev/uinput`. During
bring-up run the machine service as root too, so the socket (root-owned `0660`)
is reachable and `SO_PEERCRED` admits uid 0; the broker's `OPENSTREAM_BROKER_SERVICE_UID`
defaults to `0`. On the NVIDIA test box the broker also needs the driver
userspace on its library path (it comes from a flatpak runtime there):

```
LD_LIBRARY_PATH=$(cat ~/nvlib.path)   # NVENC/Vulkan libs
HOME=/root                            # driver caches for a root service
```

For the fully unprivileged deployment the broker gives the socket to the
machine-service account's group with `OPENSTREAM_BROKER_SOCKET_GID` (owner stays
root, mode stays `0660`) and admits that account's uid with
`OPENSTREAM_BROKER_SERVICE_UID`; the machine service then runs as
`User=openstream` with no elevation. **Verified 2026-09-16 on the GTX 970:** with
those set, a non-root (uid 1000) consumer connected to the root broker (socket
came up `root:<gid> 0660`) and captured the live session end to end
(`{"frames":4,"bytes":70125,"keyframes":1,"streaming":true}`).

## Runtime evidence (2026-09-16, GTX 970 / KDE Wayland)

The `broker_smoke` example (an unprivileged consumer that talks to the broker
exactly as the machine service does) drove the root broker end to end and got
encoded H.264 back from the live session:

```
broker_smoke: connected, broker capabilities Capabilities(31)
broker_smoke: current seat is User
broker_smoke: capture started 1920x1080, granted Capabilities(1)
{"frames": 4, "bytes": 70108, "keyframes": 1, "streaming": true}
```

i.e. `SO_PEERCRED` admit(root) -> handshake -> `OpenCapture` -> DRM scanout
(HDMI-A-1 on card0, nvidia) -> Vulkan NV12 + NVENC (Vendor) -> encoded H.264 over
the IPC. (The frame count is low because the desktop was static; the encoder
skips unchanged content. Throughput/latency profiling is a separate step.)

## Acceptance procedure

### 1. Pre-login capture (greeter)

With the broker installed and the box at the display-manager greeter (no user
logged in):

```
# The broker runs at boot as a system service; confirm the seat is the greeter
# and that capture works there. broker_smoke is an example in the
# openstream-machine-service crate (target/release/examples/broker_smoke).
cat /run/systemd/sessions/$(sed -n 's/^ACTIVE=//p' /run/systemd/seats/seat0)  # CLASS=greeter
OPENSTREAM_BROKER_SOCKET=/run/openstream/broker.sock \
  cargo run --release -p openstream-machine-service --example broker_smoke
  # expects "current seat is Greeter" and streaming: true
```

A reboot brings the box here automatically; SSH is available pre-login, so the
capture can be checked before anyone logs in.

### 2. Full reboot -> pre-login -> login continuity (interactive)

1. Cold reboot the host. No user logs in.
2. From the client, connect and approve: the remote screen shows the **native**
   login screen.
3. Type the OS password into that login screen (keyboard is granted at the
   greeter; clipboard is not).
4. The session continues into the desktop **without disconnecting** -- the
   machine service sees the seat change greeter -> user and re-points the broker's
   capture through the lifecycle, keeping the peer.
5. Lock, unlock, and log out should each re-point capture the same way, never
   dropping the connection.

The pieces for steps 1 and 4 are implemented and unit-tested; the live reboot
run is the remaining physical acceptance.
