# Deferred features: what each one actually requires

Each entry records what the work involves and, where an approach looks
obvious but is wrong, why -- so the next attempt does not start by
rediscovering it.

## OS-backed custody for the device identity key

Status: not implemented.

### What exists now

The device identity is a PKCS#8 key at `device-identity.pk8` under the XDG
state directory, created by `load_or_create_identity` in
`engine/lowlat/crates/client-core/src/lib.rs`. The containing directory is
forced to `0700` and the file is published atomically through a hard link, so
two peers starting at the same instant cannot observe a half-written key.

That is a reasonable file-based posture. What it does not give is protection
from any process running as the same user, which is what an OS keystore adds.

### The approach that looks easy and is wrong

macOS `security add-generic-password -w <secret>` and Linux
`secret-tool store` both take the secret as a command-line argument. Arguments
are visible in `/proc` and to `ps` for every process on the machine, for as
long as the call runs. Routing the identity key through either would make it
readable by processes that cannot read the `0600` file today.

Do not use the command-line tools. The leak is the whole point of the feature
running backwards.

### The approach that is correct

macOS: `SecItemAdd` and `SecItemCopyMatching` from Security.framework, with a
`kSecClassGenericPassword` item and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
The secret is passed as a `CFData` inside a `CFDictionary`, never as text in an
argument list. `core-foundation` is already in the dependency tree, so the
dictionary construction does not need hand-rolled CF calls; only the `SecItem*`
entry points and the `kSec*` constants need declaring.

Linux: libsecret's C API, or the Secret Service D-Bus interface directly.

Windows: DPAPI, or the Credential Manager.

### Constraints the implementation has to meet

- **Opt-in.** The file path stays the default until the keystore path has
  soaked. Losing a device identity is a worse failure than not having
  hardware-backed custody.
- **Never delete the file on migration.** Import it into the keystore and
  leave it. A keystore entry that turns out to be unreadable on the next boot
  must not mean the identity is gone.
- **Fall back, loudly.** Any keystore error falls back to the file with a
  line saying which path is in use, the way the decoder and pointer paths
  already report themselves.
- **Test the denial path.** Keychain access from a freshly signed binary
  prompts for authorization, and the user can refuse. That refusal is the
  primary failure mode and is the one most likely to be left untested,
  because exercising it needs a real interactive session rather than CI.

### Why this is not just a dependency away

`security-framework` would supply the macOS half. Note that
`engine/lowlat/deny.toml` only recently began checking Apple targets at all,
so a new macOS-only dependency should be introduced with `cargo deny check`
run against the Apple triples, not only the Linux and Windows ones.

## Runtime ICE restart

Status: blocked upstream, and the codebase is already correct about it.

`PathMigrationError::UnsupportedIceRestart` is returned rather than attempted.
That is not an unfinished branch; it is the accurate answer, and it was
checked against the upstream source rather than taken from the comment.

`webrtc-ice 0.17.2` is the newest published release, so the project is already
current. Its `Agent::restart` exists but tears the connection down in place:

```
self.internal.set_selected_pair(None).await;
self.internal.delete_all_candidates().await;
```

It also clears the checklist and the remote credentials. So after calling it
the agent has no selected pair and no candidates, and the existing `Conn`
cannot carry traffic while a replacement is prepared. OpenStream's migration
choreography is make-before-break: it needs the old path live until the new
one is confirmed. `Agent::restart` cannot provide that shape at any version
currently published.

The one design that would work without upstream changes is a second `Agent`
for the replacement path, brought to a selected pair before the old one is
retired -- which is what OpenStream already does for its direct and opaque
relay paths. Adopting it for ICE means moving the ICE restart boundary, which
`docs/superpowers/plans/2026-09-09-shared-path-controller.md` deliberately
placed in the ICE backend. That is an architecture decision, not an
implementation gap, and should be taken as one.

## PipeWire DMA-BUF capture

Status: not implemented, not investigated in depth.

The Linux host currently converts captured frames to raw BGRA before the
encoder. A DMA-BUF path would keep the frame on the GPU from the portal's
PipeWire node through to the encoder. This is a capture-pipeline rewrite
rather than a flag, and it interacts with the encoder selection and the
NVIDIA runtime, so it wants its own design pass.
