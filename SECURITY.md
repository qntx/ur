# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.6.x   | Yes       |
| 1.5.x   | Yes       |
| 1.4.x   | Yes       |
| 1.3.x   | Yes       |
| 1.2.x   | Yes       |
| 1.1.x   | Yes       |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories on
[qntx/ur](https://github.com/qntx/ur/security/advisories/new), or email
`security@qntx.org` if that channel is unavailable.

Please include:

- Affected version and runtime (Node/Bun/browser)
- Minimal reproduction (URI/part bytes preferred)
- Impact assessment (e.g. decoder resource exhaustion, CRC bypass)

Do not open public issues for unfixed vulnerabilities.

## Threat model (summary)

This library is a **UR transport codec**. L5 `@qntx/ur/registry` adds structured
dCBOR objects (`seed`, `hdkey`, `keypath`, `coin-info`, `sskr`, `psbt`, `envelope`).
It does not implement application cryptography or trust policies. L5 output is
untrusted structured data; signing and key use are host policy.

| Threat                                         | Severity             | Mitigation                                                                                                               |
| ---------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| QR stream resource exhaustion                  | High                 | `DecoderLimits` + session poison including `uri_len`, UR-layer `fragment_data`/`fragment_count`, fountain `DecoderState` |
| Public `Part.fromCbor` huge `K` allocation     | High                 | `maxFragmentCount` on decode                                                                                             |
| Seed / PSBT / SSKR share logged                | High                 | Codecs never stringify payloads. Switch on `CborError.code`. Never pass payload hex into `CborError.custom`              |
| Treating recovered L5 objects as trusted       | High (host)          | L5 output is untrusted structured data. Signing and key use are host policy                                              |
| `seqNum` wrap recycling simple parts           | Medium (theoretical) | Fail-closed at `0xffffffff`; `maxReceivedParts` 8_000                                                                    |
| Non-canonical Part CBOR                        | Medium               | Keep shortest-form decoder                                                                                               |
| Mixing single-part and fountain in one session | Medium               | `InconsistentPart`                                                                                                       |
| Duplicate single-part different body           | Low                  | First wins, same type; documented                                                                                        |
| Type confusion across parts                    | Medium               | Type stickiness after successful ingest; `expectedType`                                                                  |
| Type confusion (`ur:bytes` as seed)            | Medium               | `fromUr` calls `ur.checkType` → `UnexpectedType`. `fromUrStringWith` unknown type is `UnexpectedType`                    |
| v1/v2 mixup (`crypto-seed` / tag 300)          | Medium               | v1 tokens fail `UnexpectedType` against v2 codecs. Nested HDKey tag 304 is `WrongTag`                                    |
| PSBT not actually a PSBT                       | Medium               | Magic-byte prefix `70736274ff` only. No input/output parse                                                               |
| SSKR share claimed as full seed                | Medium               | Type token `sskr` ≠ `seed`. No combine in this package                                                                   |
| Envelope recursion                             | Medium               | `ENVELOPE_MAX_DEPTH = 64`. Depths 0..=64 accepted (65 frames); 65 is `OutOfRange`                                        |
| Zero-copy alias of decoder or caller buffer    | Medium               | `copyBytes` on decode; `copyBuf` on encode                                                                               |
| Invalid CRC                                    | Low                  | Bytewords CRC + message CRC on fountain join                                                                             |
| Application payload treated as trusted         | High (host)          | L4 `CborDecode`/`CborType` for typed hosts; L5 objects still untrusted; L3 recovered bytes still untrusted               |

Hosts scanning untrusted QR streams must keep default limits (or tighter) and
treat recovered payloads as untrusted input. A poisoned `Decoder` is discarded;
construct a new instance.
