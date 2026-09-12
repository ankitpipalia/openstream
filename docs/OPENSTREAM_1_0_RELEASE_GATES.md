# OpenStream 1.0 release gates

OpenStream 1.0 is not claimable from a successful compile alone. The
authoritative release contract is [`release/openstream-1.0-gates.tsv`](../release/openstream-1.0-gates.tsv),
and the fail-closed checker is:

```sh
./scripts/check-openstream-1-0-release.sh
```

The checker expects a staged candidate under `dist/openstream-1.0.0/`. Use
`--artifact-root`, `--manifest`, and `--report` when validating another
staging directory. It requires every manifest artifact, a SHA-256 entry for
each artifact, recognizable SPDX or CycloneDX SBOM evidence, a `VERIFIED`
signing row for each artifact, and a report containing all three exact gate
IDs:

- `physical-linux-nvidia-to-apple-silicon`: a real Linux NVIDIA host to Apple
  Silicon client session, including the shipped capture/encode path.
- `wan-turn`: a real public-network session using the configured external
  TURN service, with the expected direct/relay behavior recorded.
- `package-launch-upgrade`: install/package launch followed by upgrade and
  rollback or downgrade smoke on the supported platforms.

The report format is tab-separated:

```text
gate_id<TAB>result<TAB>observed_at<TAB>evidence
```

Only an exact `PASS` result with a non-placeholder timestamp and evidence is
accepted. The report and signing templates are deliberately `TBD`/
`UNVERIFIED`; they keep an unverified checkout fail-closed.

Run deterministic checker fixtures with:

```sh
./scripts/test-openstream-1-0-release.sh
```

Do not create a v1.0 tag, publish installers, or describe the build as
production-ready until the checker prints `OpenStream 1.0 release gates:
READY` and the underlying evidence has been independently reviewed.
