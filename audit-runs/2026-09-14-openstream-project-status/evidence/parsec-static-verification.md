# Parsec static-evidence verification

The exact `/workspace/scratch/...` paths named in the audit request were not
present. Equivalent authorized local artifacts under gitignored `analysis/`
were inspected read-only. All seven SHA-256 values matched
`docs/research/evidence/parsec-artifact-manifest.md`:

```text
2ff41665ab1ca6ad2c6159646b9c1143f2f932ce08c348342b71feadc5fbb9a9  parsecd-arm64.dylib
04d7a5e797b9fdd24c737b82fd3185a2b2c16b8505cf487d3f2b14b4ba83b49d  parsecd-x86_64.dylib
75803981f05c37c6befe4eeea5dd39a5e9286975702334a36fe1ffb6e2eb626f  parsecd-launcher-arm64
8c8c4299ddf503b2c25c0905b0a0820f3e8238c252e9ace37bf25964ef4a8f6f  parsecd-150-104a.dll
e1181c0ee31fb49e19038081c111387fc70be880fa1e3a783e6ec62004c5b4e0  parsecd.exe
566f3dfd079b1c3129aae68645f0005a869544078aa86b0a14864a36ad7aa9cf  pservice.exe
708bc4e7194333dd16da64ae1c822dd973d0f647b39588351ea2b226bac09a07  parsecd-150-104a.so
```

Observed directly in static import/string evidence:

- macOS: `VTDecompressionSessionCreate`,
  `VTDecompressionSessionDecodeFrame`,
  `CVPixelBufferCreateWithIOSurface`,
  `CVMetalTextureCacheCreateTextureFromImage`, `IOSurface`, `IOHIDManagerCreate`;
- Windows: `RegisterRawInputDevices`, `GetRawInputData`, `ClipCursor`,
  `SetWindowsHookEx`;
- configuration keys: `client_zero_copy`, `client_decoder_index`,
  `client_png_cursor`, `encoder_slices`, `encoder_vbv_max`,
  `encoder_vbv_initial`, `encoder_vbv_multi`, `encoder_idr_interval`,
  `host_capture_timeout`, and audio poll-rate keys.

Classification:

- Symbol/key presence: **Observed directly**.
- A VideoToolbox → CVPixelBuffer/IOSurface → Metal pipeline: **Strong
  inference** from multiple native imports.
- Raw/event-driven platform input paths: **Strong inference**.
- Local cursor prediction, exact zero-copy coverage, queue depth, packet format,
  congestion behavior, and proprietary protocol details: **Unknown**.

No artifact was executed, patched, authenticated, contacted, or redistributed.
