# Workstream 5 — Security, testing, and release

## Security strengths

- authenticated encryption and replay protection for direct packets;
- signed identity transcript and optional/required peer pinning rules;
- role-scoped, expiring session/TURN/relay credentials;
- pairing-file loader requires an absolute regular file, rejects symlinks,
  bounds content, and enforces Unix ownership/private permissions;
- raw pairing JSON requires an explicit developer override;
- host agent removes raw pairing JSON and propagates only the pairing-file
  reference;
- diagnostics perform field-aware redaction and adversarial export tests;
- local IPC is bounded, secret-free, 0700/0600 on Unix, and rejects symlinks;
- gitleaks, ASan, Loom, fuzz compilation, cargo-deny, Clippy and cross-target
  builds are required by CI.

## Security/release gaps

- No durable account/device authentication service or recovery/MFA/passkey
  flow.
- No Keychain, DPAPI/Credential Manager, or Secret Service provider. `SecretRef`
  is only a reference type; `local_identity()` still accepts environment or a
  plain file and generates a new key when absent.
- Private-LAN no-auth is intentionally constrained but must remain an explicit
  advanced mode, not the production trust model.
- Windows local host-agent IPC is unsupported; installers/services are not a
  complete cross-platform security boundary.
- No signed updater, staged rollback mechanism, release SBOM, production
  checksums, or notarized/signed package evidence.
- Signal/relay state is single-process memory, with no durable audit trail or
  multi-tenant quota/account model.

## Test evidence

The exact merged `main` tree passed GitHub run `34816872196` (27/27 jobs), local
workspace tests, 39 Tauri Rust tests, 16 frontend tests, and a frontend bundle.
Hardware-required Rust tests are ignored on ordinary CI. Mobile acceptance is
host-checkable source/ABI validation, not a device run. The WAN checker reports
all ten cases unverified. The release checker reports eleven missing artifacts
or evidence items.

## Release conclusion

The security primitives and fail-closed release machinery are credible. The
product identity layer, secure key custody, physical/WAN evidence, packages,
signatures, SBOM, updates, and rollback are not present. OpenStream 1.0 is a
clear **NO-GO** today.
