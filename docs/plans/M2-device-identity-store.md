# M2 (first half): an identity store that takes a path

## The problem

`device_auth::authenticate` needs an `&IdentityKey`, and nothing outside
`client-core` could obtain one. The only public accessors were
`local_identity_public_key` and `local_device_id`, both of which return
derived, non-signing values.

The obvious fix was to make the existing `local_identity()` public. That would
have been wrong. It resolves where the key lives from process-global
environment, `OPENSTREAM_IDENTITY_KEY`, `OPENSTREAM_IDENTITY_KEY_FILE` and
`OPENSTREAM_IDENTITY_STORE`, and otherwise from a home-derived directory.

For a desktop application that is right: one installation, one user, one
location. For a system service it is wrong in three ways. The account the
machine service runs as has `/nonexistent` for a home, so the fallback resolves
to a path that cannot be used. `ProtectHome=true` would hide a home directory
even if one existed. And a service whose key location depends on ambient
environment is a service whose identity can move because something edited a
unit file, which for a device identity means silently becoming a different
device.

## The API

```rust
DeviceIdentityStore::open(path) -> Result<OpenedIdentity, Error>
OpenedIdentity { key(), into_key(), source(), was_created() }
IdentitySource::{Loaded, Created}
```

`path` is explicit and must be absolute. `local_identity()` keeps its current
behaviour and is now a wrapper, so the desktop is unaffected.

**The key is opened once and held.** Re-reading it per signature would parse a
private key off disk on a timer for no benefit, and would let the identity
change underneath a running process. Rotation is an explicit restart.

**`IdentitySource` is not decoration.** Enrolment registers a *public key* with
the control plane. A tool that silently minted a second identity would enrol
the machine as a different device and strand the first, so a caller that
expected to find an identity and is told `Created` has learned something it
must stop on. The variant is threaded out of the real code paths rather than
inferred by checking whether the file existed first, which would be a race: in
a publication race the loser correctly reports `Loaded`, because it did not
publish the key it is holding.

Every existing protection is unchanged, because this reuses the same
implementation: `0700` directory, `0600` file written through a private staging
path and published with `link` so concurrent creators converge on one identity,
`O_NOFOLLOW`, and on Unix a refusal unless the file is owned by this user with
no group or other bits. Keystore custody is honoured where it was asked for.

## Tests

- `the_store_creates_once_and_loads_afterwards`: `Created` then `Loaded`, same
  public key, and the file lands where the caller said.
- `the_store_refuses_a_relative_path`.
- `the_store_refuses_a_key_others_can_read`: widen to `0640` and it is refused.
- `an_opened_identity_does_not_print_its_key`.
- `an_existing_identity_is_reused_rather_than_replaced` now asserts the source.

Teeth: reporting `Created` where an existing file is loaded fails both
source-asserting tests.

## What is not in this change

The rest of M2: `openstream-enrol` taking `--identity-store`,
`--machine-env-file` and `--identity-owner`, and closing the enrolment
response-loss window. Both belong on the packaging branch, which owns the
enrolment tool's environment-file handling, and the response-loss work needs
its own design note first.
