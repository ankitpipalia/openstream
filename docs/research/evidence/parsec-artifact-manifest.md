# Parsec artifact manifest

Evidence index for
[`../parsec-display-input-latency-gap.md`](../parsec-display-input-latency-gap.md).

The artifacts themselves are **not in this repository**. `analysis/` is
gitignored (`.gitignore:45`) because it holds vendor binaries and multi-megabyte
extracted string tables, and `analysis/README.md` states the policy: they are
evidence inputs, never executed, patched, published, linked, or shipped.

That makes any link from a committed document into `analysis/` a dead link for
anyone reading a clean clone. This manifest exists so the report's reasoning
stays checkable without redistributing anything: it records what was examined,
how to confirm it is the same file, and the specific symbols the conclusions
rest on.

## Method

Static inspection only:

- `shasum -a 256` for identity;
- `strings(1)` output, already extracted into `analysis/strings_*.txt`;
- symbol and configuration-key matching against those extracts.

No artifact was executed, loaded, disassembled into this repository, or linked
against. Nothing below is copied Parsec code; these are imported-symbol and
configuration-key names, which is what an import table is for.

## Artifacts

| File | SHA-256 | Size | Local extract |
|---|---|---|---|
| `parsecd-arm64.dylib` (macOS arm64 payload) | `2ff41665ab1ca6ad2c6159646b9c1143f2f932ce08c348342b71feadc5fbb9a9` | 2,926,096 | `analysis/strings_arm64.txt` |
| `parsecd-x86_64.dylib` (macOS x86-64 payload) | `04d7a5e797b9fdd24c737b82fd3185a2b2c16b8505cf487d3f2b14b4ba83b49d` | 3,286,480 | — |
| `parsecd-launcher-arm64` | `75803981f05c37c6befe4eeea5dd39a5e9286975702334a36fe1ffb6e2eb626f` | 134,928 | `analysis/strings_launcher.txt` |
| `win/skel/parsecd-150-104a.dll` | `8c8c4299ddf503b2c25c0905b0a0820f3e8238c252e9ace37bf25964ef4a8f6f` | — | `analysis/strings_win_dll.txt` |
| `win/parsecd.exe` | `e1181c0ee31fb49e19038081c111387fc70be880fa1e3a783e6ec62004c5b4e0` | — | — |
| `win/pservice.exe` | `566f3dfd079b1c3129aae68645f0005a869544078aa86b0a14864a36ad7aa9cf` | — | — |
| `deb/usr/share/parsec/skel/parsecd-150-104a.so` (Linux payload) | `708bc4e7194333dd16da64ae1c822dd973d0f647b39588351ea2b226bac09a07` | — | `analysis/strings_linux.txt` |

Versions are as supplied; the macOS payload and the Windows/Linux payloads are
from the 150-104a series.

## Display pipeline symbols — macOS arm64 payload

Observed verbatim in the payload's strings. **High confidence**: these are
imported framework entry points, not incidental text.

```text
VTDecompressionSessionCreate
VTDecompressionSessionDecodeFrame
CVPixelBufferCreateWithIOSurface
CVPixelBufferPoolCreatePixelBuffer
CVMetalTextureCacheCreateTextureFromImage
IOSurface
CGDisplayStream
```

Together these describe hardware decode into a `CVPixelBuffer` backed by an
`IOSurface`, wrapped as a Metal texture — a GPU-resident path in which the CPU
never touches decoded pixels.

## Input pipeline symbols

macOS arm64 payload — **high confidence**:

```text
IOHIDManagerCreate
IOHIDManagerOpen
IOHIDManagerClose
IOHIDDeviceGetValue
IOHIDDeviceGetReport
IOHIDDeviceSetReport
IOHIDSystem
```

Windows DLL — **high confidence**:

```text
RegisterRawInputDevices
GetRawInputData
ClipCursor
SetWindowsHookEx
```

Event-driven device input on both platforms, rather than polling a window
toolkit.

## Configuration keys

From the payload's configuration-key table. **High confidence** that the keys
exist; what each one *does* is inferred from its name and is marked as such in
the report.

```text
client_zero_copy
client_decoder_index
client_png_cursor
encoder_slices
encoder_vbv_max
encoder_vbv_initial
encoder_vbv_multi
encoder_idr_interval
host_capture_timeout
client_audio_poll_rate
host_audio_poll_rate
```

## Confidence and its limits

- **High** — a symbol or key string is present in a named artifact with a
  recorded hash. Reproducible by anyone holding the same file.
- **Medium** — behaviour inferred from a name. `client_png_cursor` shows that
  cursor images are handled specially; it does **not** establish local cursor
  prediction, and the report says so.
- **Not established** — anything about Parsec's wire formats, packet layouts,
  or rate-control algorithms. None of that is inspected, inferred, or
  implemented, and OpenStream deliberately does not claim stock compatibility.

## Reproducing

With the artifacts in place, `scripts/audit-parsec-artifacts.sh` prints the
read-only inventory; `OPENSTREAM_ARTIFACT_ROOT` points it at the directory
holding them. Confirm identity with the hashes above before relying on any
extract.
