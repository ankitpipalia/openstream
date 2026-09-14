# OpenStream 1.0 release staging

Stage a candidate release under `dist/openstream-1.0.0/` using the paths in
[`openstream-1.0-gates.tsv`](openstream-1.0-gates.tsv). Keep checksums, SBOM,
signing receipt, and the completed gate report inside that staged root.

The staging helpers are deliberately split by trust boundary:

```sh
./scripts/build-release-artifacts.sh
./scripts/generate-sbom.sh
./scripts/verify-package-install.sh PATH_TO_PACKAGE
```

`build-release-artifacts.sh` accepts only real, already-built inputs (or
build outputs present at the documented paths), generates SHA-256 entries and
a source SPDX SBOM, and refuses to create missing platform artifacts. The
package verifier performs read-only structure checks. Neither command signs,
notarizes, installs, launches, upgrades, rolls back, or writes a physical/WAN
`PASS` result. Those observations must be produced by the protected release
environment and recorded separately.

The templates in this directory are intentionally non-passing. They document
the required evidence shape but must not be copied unchanged into a release.

The JSON shape for tooling integrations is described by
[`manifest.schema.json`](manifest.schema.json). The authoritative checker uses
the tab-separated manifest so it can run on minimal packaging hosts.
