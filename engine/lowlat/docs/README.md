# Imported lowlat documentation boundary

This directory is retained with the independently developed MIT-licensed
`nomi-san/lowlat` engine as provenance and engineering reference. Its protocol
notes, design decisions, changelog, and historical acceptance statements are
not a specification published by Parsec and are not automatically claims about
the OpenStream implementation.

In particular:

- the exact BUD wire layout and constants remain provisional for OpenStream;
- historical "stock client" entries describe the upstream project's own test
  history and have not been independently re-established from the supplied
  artifacts in this workspace;
- OpenStream uses the separate `OS`-magic AES-GCM protocol documented at the
  repository root in [`docs/OPENSTREAM_PROTOCOL.md`](../../../docs/OPENSTREAM_PROTOCOL.md);
- the current compatibility status and artifact evidence are maintained in
  [`docs/FACT_CHECK.md`](../../../docs/FACT_CHECK.md) and
  [`docs/REVERSE_ENGINEERING.md`](../../../docs/REVERSE_ENGINEERING.md).

The OpenStream crates live beside this imported engine in the same Cargo
workspace, but they are project-owned code paths and do not silently claim
stock-Parsec interoperability.

The distinction matters for connectivity: the imported `lowlat-core` and
`lowlat-net` documents below describe their deterministic sans-IO direct-punch
engine. The current OpenStream peer session lives in
`crates/client-core`; its default is the same small direct path, while
`OPENSTREAM_ICE=1` or `OPENSTREAM_ICE_URLS` selects the optional
`webrtc-ice` full-ICE/TURN implementation. The repository-root
`docs/OPENSTREAM_PROTOCOL.md` and `docs/IMPLEMENTATION_PLAN.md` are the
authoritative documents for that application path.
