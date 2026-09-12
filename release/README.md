# OpenStream 1.0 release staging

Stage a candidate release under `dist/openstream-1.0.0/` using the paths in
[`openstream-1.0-gates.tsv`](openstream-1.0-gates.tsv). Keep checksums, SBOM,
signing receipt, and the completed gate report inside that staged root.

The templates in this directory are intentionally non-passing. They document
the required evidence shape but must not be copied unchanged into a release.

The JSON shape for tooling integrations is described by
[`manifest.schema.json`](manifest.schema.json). The authoritative checker uses
the tab-separated manifest so it can run on minimal packaging hosts.
