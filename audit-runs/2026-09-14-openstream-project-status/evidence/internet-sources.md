# Internet sources

Accessed 2026-09-14. These sources inform standards and comparison analysis;
they are not evidence that OpenStream implements a feature.

1. RFC 8445, Interactive Connectivity Establishment (ICE): https://www.rfc-editor.org/rfc/rfc8445.html
2. RFC 8656, TURN: https://www.rfc-editor.org/rfc/rfc8656.html
3. RFC 9221, QUIC DATAGRAM: https://www.rfc-editor.org/rfc/rfc9221.html
4. RFC 8831, WebRTC Data Channels: https://www.rfc-editor.org/rfc/rfc8831.html
5. RFC 9000, QUIC: https://www.rfc-editor.org/rfc/rfc9000.html
6. RFC 9002, QUIC Loss Detection and Congestion Control: https://www.rfc-editor.org/rfc/rfc9002.html
7. Apple, `CVMetalTextureCacheCreateTextureFromImage`: https://developer.apple.com/documentation/corevideo/cvmetaltexturecachecreatetexturefromimage(_:_:_:_:_:_:_:_:_:)
8. Apple, `VTDecompressionSession`: https://developer.apple.com/documentation/videotoolbox/vtdecompressionsession
9. NVIDIA, NVENC Video Encoder API Programming Guide: https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-video-encoder-api-prog-guide/
10. Parsec, Hardware and Software Compatibility: https://support.parsec.app/hc/en-us/articles/32381568346644-Hardware-and-Software-Compatibility
11. Parsec, Security at Parsec: https://support.parsec.app/hc/en-us/articles/32361366289940-Security-At-Parsec
12. Parsec, Connectivity Requirements: https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements
13. Parsec, Feature Matrix: https://support.parsec.app/hc/en-us/articles/32381463419924-Feature-Matrix
14. Parsec, Software vs Hardware Decode: https://support.parsec.app/hc/en-us/articles/32381511532820-Using-software-decoding-instead-of-hardware-decoding

Key standards conclusions:

- ICE combines host, server-reflexive, peer-reflexive, and relayed candidates;
  changing an established destination requires ICE restart.
- TURN is a relay and therefore remains in the data path when selected.
- QUIC DATAGRAM supplies encrypted, congestion-controlled, unreliable datagrams,
  but adopting it would not remove NAT traversal, relay, media scheduling, or
  platform integration work.
- WebRTC has strong browser/platform interoperability, but its data-channel and
  media stacks bring a larger policy surface than the existing project-owned
  UDP protocol.
