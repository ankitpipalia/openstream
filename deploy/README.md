# Self-hosting deployment templates

These templates are intentionally explicit about the current boundary:

- `openstream-signal-server.service` runs the application-owned HTTPS/WebSocket
  signaling process behind a TLS reverse proxy;
- `openstream-ffmpeg-host.service` runs the desktop host adapter as a user
  service, where it can access the graphical session and FFmpeg capture source;
- `openstream-host-agent.service` owns and supervises the FFmpeg host child,
  exposes bounded health/lifecycle IPC, and survives a desktop-shell restart;
  use this unit for persistent hosting;
- `openstream-linux-host.service` runs the native Linux display/encoder and
  optional uinput adapter as a user service inside the graphical session;
  `openstream-linux-host-system.service` is the unattended variant that runs
  as the dedicated `openstream-host` system user outside any login session
  (scanout capture keeps working; compositor-mediated capture does not).
  Both grant only the `video`, `render`, and `input` groups required by the
  selected host policy;
- `openstream-signal-server.service` can also host the application-owned
  opaque UDP relay when `OPENSTREAM_RELAY_BIND` and
  `OPENSTREAM_RELAY_ENDPOINT` are configured;
- `turnserver.conf.example` provides a coturn deployment profile for the
  optional full-ICE/TURN client path in `openstream-client-core`.

Build release binaries from `engine/lowlat`, install
`openstream-signal-server`, `openstream-ffmpeg-host`, and
`openstream-host-agent`, then copy the units into the appropriate systemd
unit directory. The agent unit is the persistent entrypoint; the direct
FFmpeg unit remains useful for compatibility and diagnostics. Create
`%h/.config/openstream/host.env` with mode `0600` and put only short-lived
runtime values there; do not commit it. Pairing JSON is passed to the child
through the protected environment boundary and is never placed in an
`ExecStart` argument or ordinary settings.

For a user service, enable the persistent agent with:

```sh
install -m 0755 target/release/openstream-host-agent ~/.local/bin/
install -m 0755 target/release/openstream-ffmpeg-host ~/.local/bin/
install -m 0644 deploy/openstream-host-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now openstream-host-agent.service
```

The agent socket defaults to `%t/openstream/host-agent.sock`; override it
with `OPENSTREAM_HOST_AGENT_SOCKET` only when the parent directory remains
private. The agent rejects an active endpoint and safely removes only a
refused stale socket after a crash; it never unlinks an active or unrelated
path.

Set `OPENSTREAM_ADMIN_TOKEN` in `/etc/openstream/signal.env` for any deployment
that is reachable beyond a trusted local development machine. Send
`Authorization: Bearer <token>` (or the equivalent
`X-OpenStream-Admin-Token` header) when creating a session with `POST
/v1/session` and when revoking one with `DELETE /v1/session/{id}`. If the
variable is unset, management requests are refused by default. For an
explicit loopback-only development server, set `OPENSTREAM_ALLOW_NO_AUTH=1`;
the service rejects that mode on a non-loopback bind and prints a warning.
The administrator token must be at least 16 bytes; use a randomly generated
value and keep it in the protected environment file rather than in a unit
file or command-line argument.

For a trusted private LAN without an account flow, use the separate,
explicitly opt-in mode below. The bind must be one real numeric LAN address;
wildcard, loopback, public, and shared-CGNAT binds are rejected:

```text
OPENSTREAM_LOCAL_NO_AUTH=1
OPENSTREAM_SIGNAL_BIND=192.168.1.69:8080
# Leave OPENSTREAM_ADMIN_TOKEN and OPENSTREAM_ALLOW_NO_AUTH unset.
```

This disables only management/admin authentication for devices on that
trusted LAN. Anyone who can reach the bind can create or revoke sessions, so
do not expose it through port forwarding, a reverse proxy, or a public
interface. Role-scoped session capabilities, encrypted peer identity, and
relay/TURN authorization remain required. Clients using an `http://` origin
must also set `OPENSTREAM_LOCAL_NO_AUTH=1`; plaintext is accepted there only
for numeric RFC1918/ULA/link-local origins. Use the admin-token HTTPS/WSS mode
before leaving a trusted LAN.

For the built-in relay, bind one UDP socket privately and advertise its
reachable numeric endpoint:

```text
OPENSTREAM_RELAY_BIND=0.0.0.0:40000
OPENSTREAM_RELAY_ENDPOINT=203.0.113.10:40000
# Optional but recommended for stable relay tickets across service restarts.
# It must contain at least 16 bytes and must be stored as a secret.
OPENSTREAM_RELAY_SECRET=REPLACE_WITH_A_LONG_RANDOM_SECRET
```

The service includes the endpoint in new pairing responses. Both peers
register with their role-scoped session token; the relay forwards only the
already-encrypted OpenStream datagrams. This application relay is distinct
from the standards-based TURN path below.

The host environment normally contains:

```text
OPENSTREAM_SIGNAL_ORIGIN=https://signal.example.invalid
OPENSTREAM_PAIRING_FILE=/run/user/1000/openstream/pairing.json
OPENSTREAM_UDP_BIND=0.0.0.0:0
OPENSTREAM_FFMPEG=/usr/bin/ffmpeg
# Optional direct-path router mapping. This changes local router state and is
# deliberately disabled unless explicitly enabled.
OPENSTREAM_UPNP=0
OPENSTREAM_UPNP_LEASE_SECONDS=3600
OPENSTREAM_FFMPEG_ARGS=-f x11grab -framerate 60 -video_size 1920x1080 -i :0.0
# Optional host keyboard/pointer/wheel injection. Linux needs /dev/uinput;
# macOS needs Accessibility permission; Windows uses the interactive account.
OPENSTREAM_ENABLE_INPUT=1
# Optional bidirectional UTF-8 clipboard sync. Requires a supported local
# adapter (pbcopy/pbpaste, clip.exe/PowerShell, or wl-copy/xclip/xsel).
# Keep this disabled unless the session's clipboard policy permits it.
OPENSTREAM_CLIPBOARD=0
# Optional full ICE/TURN profile; keep credentials out of pairing JSON.
OPENSTREAM_ICE=1
OPENSTREAM_ICE_URLS='stun:stun.example.invalid:3478,turn:turn.example.invalid:3478?transport=udp'
OPENSTREAM_TURN_USERNAME=openstream
OPENSTREAM_TURN_PASSWORD=REPLACE_WITH_A_LONG_RANDOM_PASSWORD
# Native Linux host bitrate ceiling/floor and ACK feedback policy.
OPENSTREAM_VIDEO_MBPS=10
OPENSTREAM_VIDEO_MIN_MBPS=1
OPENSTREAM_ADAPTIVE_BITRATE=1
# Optional hardware encoder profile: libx264/libx265 (default), h264_nvenc,
# hevc_nvenc, h264_vaapi, hevc_vaapi, or auto (NVENC-first detection with a
# software fallback). Requires the matching driver/FFmpeg build.
OPENSTREAM_VIDEO_ENCODER=auto
# Optional pixel format: yuv420p (default), yuv444p, or yuv420p10le. Values
# beyond yuv420p require OPENSTREAM_ALLOW_444/OPENSTREAM_ALLOW_10BIT=1 on the
# host and a client that negotiates the same profile.
OPENSTREAM_ALLOW_444=0
OPENSTREAM_ALLOW_10BIT=0
# Optional rolling-restart bitrate control for the external encoder.
# Arbitrary FFmpeg processes expose no in-place rate API, so significant
# adaptive decisions respawn the encoder (which starts with an IDR frame).
OPENSTREAM_FFMPEG_RECONFIGURE=0
OPENSTREAM_RECONFIGURE_MIN_INTERVAL_SECS=10
# Session-scoped TURN credentials (preferred over static TURN variables when
# the service mints them; create-session.sh embeds them automatically).
OPENSTREAM_FETCH_TURN=1
# Host permission grants; every capability defaults to off.
OPENSTREAM_GAMEPAD=0
OPENSTREAM_MIC=0
OPENSTREAM_APPROVAL=auto
```

Pairing JSON contains role bearer capabilities. Treat it as a secret and never
commit it, put it in a public issue, or include it in logs. The normal
launcher/client boundary reads the JSON from the private file named by
OPENSTREAM_PAIRING_FILE and requires an absolute, owner-only path. For
developer-only compatibility, OPENSTREAM_PAIRING_JSON requires
OPENSTREAM_DEVELOPER_OVERRIDE=1; do not use that override in a service unit.

For Wayland, use the PipeWire/portal native adapter once enabled rather than
passing an X11 display. The external FFmpeg service is a development backend;
it does not provide the permission UI, hardware zero-copy path, or TURN
fallback required for a production release. `OPENSTREAM_ICE_INSECURE=1` is
available only for local development with private/self-signed TURN TLS; never
enable it in a production deployment.

When `OPENSTREAM_UPNP=1` is used, the host and client attempt bounded SSDP
discovery and map the same UDP port that carries the session. The mapping is
best-effort; ordinary host/STUN candidates remain available when the router
does not expose an IGD. Validate this only on a network whose router policy
you control.

After deploying coturn, validate the standards path from the repository root
with `OPENSTREAM_ICE_URLS` and separate credentials, for example:

```sh
OPENSTREAM_ICE_URLS='turn:turn.example.invalid:3478?transport=udp' \
OPENSTREAM_TURN_USERNAME=openstream \
OPENSTREAM_TURN_PASSWORD='REPLACE_WITH_A_LONG_RANDOM_PASSWORD' \
./scripts/full-ice-smoke.sh
```

The smoke output is intentionally only pass/fail text; do not enable shell
tracing around this command because the environment contains credentials.

The signal service applies a fixed global limit of 60 new sessions per minute.
This bounds accidental or compromised-admin-token churn; deployments needing
tenant-specific quotas still need an identity-aware admission layer.
Expired sessions are reaped independently of new requests and optional relay
traffic. HTTP and relay tasks also stop on SIGTERM/CTRL-C so systemd shutdown
does not leave a relay or stale WebSocket state running in the process.
