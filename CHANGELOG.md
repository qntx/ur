# Changelog

## Unreleased

### Added

- New Rust crate `bcur-registry`: BCR-2020-006 registry types `Seed`, `HdKey`/`MasterKey`/`DerivedKey`, `Keypath`/`PathComponent`, `CoinInfo`, `EcKey`, `Address`, `Psbt`, and `SskrShare`, plus the descriptor types `DescriptorKey`, `OutputDescriptor`, and `AccountDescriptor` on the `bcur` typed dCBOR layer — byte- and error-compatible with `@qntx/ur/registry`, including v1 tag reads, `Seed`/`HdKey` digests (BCR-2021-002), v1 `crypto-output`/`crypto-account` script-expression conversion (BCR-2020-010, with BIP-380 nesting rules and the lenient KeystoneHQ forms), zeroizing secret types, and the 31-tag `tags` module with `register_tags`/`register_tags_in`.

## 2.0.0 - 2026-10-10

### Breaking

- Unified error model in both languages. TS `UrError` carries a discriminated `info` (`{ code, limit }` for `ResourceLimit`, `{ code, expected: UrType[], found: UrType }` for `UnexpectedType`, `{ code }` otherwise) plus `code` and `fatal` getters; `failPoison`, `DecoderPoison`, and the flat `expected`/`found`/`limit` fields are gone. Rust `bcur::Error` is an opaque struct with `kind()`, `is_fatal()`, `limit()`, `expected_types()`, `found_type()`, and `std::error::Error::source()` for wrapped dCBOR errors; `ErrorKind` and `Limit` replace the enum variants, `ResourceKind`, `CborError`, and `CborErrorKind`. Renamed codes: `EmptyPart`/`InvalidSequence` -> `InvalidPart`, `InvalidFragmentLen` -> `InvalidFragmentLength`, `DecoderState` -> `Internal`, `Cbor` -> `CborDecode`/`CborType`; limit names are camelCase (`messageLength`, `fragmentCount`, `fragmentLength`, `uriLength`) and the `sequence` limit is gone.
- `Part` is plain data. TS exports `type Part`, `encodePart` (validates its argument, `InvalidPart`), and `decodePart`; the `Part` class with `fromFields`/`fromCbor`/`toCbor`/`indexes`/`isSimple`/`sequenceId` is removed. Rust `Part` has private fields with `Part::new` validating constructor, accessors, `to_cbor`, and `from_cbor(bytes, &DecoderLimits)`; `indexes`/`is_simple`/`sequence_id`/`from_cbor_with_max` are removed.
- Part CBOR decodes leniently (any definite-width integers and headers, values <= u32) and encodes in shortest form; malformed CBOR is `InvalidPartCbor`, invalid fields are `InvalidPart`, and fragment/count limits map to `ResourceLimit(fragmentLength)`/`ResourceLimit(fragmentCount)`.
- `FountainEncoder` is an iterator: TS `new FountainEncoder(message, { maxFragmentLength, minFragmentLength?, firstSequence? })` implements `IterableIterator<Part>` (replaces `FountainEncoder.create`/`nextPart`/`nextSequence`/`complete` with `next()`/`isComplete`/`sequence`/`lastFragmentIndexes`); Rust `fountain::Encoder::new(message, EncoderOptions)` implements `Iterator<Item = Part>` + `FusedIterator` (replaces `next_part`). Iteration ends after sequence `0xFFFFFFFF`; `firstSequence` out of range is a `RangeError` (TS).
- Fragment sizing follows URKit `findNominalFragmentLength` with a `minFragmentLength`/`min_fragment_len` default of 10: `K` is capped at `floor(len / 10)`, so whenever `maxFragmentLength` alone would give fragments shorter than 10 bytes the message splits into fewer, longer fragments than in 1.x (fragments may then exceed `maxFragmentLength`). `bcur encode --type bytes` now needs about `--max-chars 85` to fit a fountain part (1.x accepted 80).
- `K == 1` encoders repeat the same single-part output on every call instead of throwing `SinglePartExhausted` (removed in both languages).
- Decoders are rebuilt around incremental GF(2) Gauss-Jordan elimination. TS `FountainDecoder` and the renamed `UrDecoder` (was `Decoder`) expose `receive()` returning `{ status: "accepted" | "duplicate" | "rejected" | "fatal" }` instead of throwing, plus `state` (`empty`/`collecting`/`complete`/`failed`), `progress` (`fragmentCount`, `rank`, `recovered`, `processed`, `ratio`), `lastIndexes`, and `reset()`; `complete`, `message()`, `resolvedFragmentCount`, `isPoisoned`, `poisonState`, and `expectedType` are gone — type admission is the `accept` option and terminal sessions report `duplicate`. Rust mirrors this: `fountain::Decoder::receive` returns `Result<Received>` with `state()`/`progress()`/`last_indexes()`/`into_message()`/`reset()`, and `ur::Decoder` replaces `with_expected_type` with `accept()` and adds `into_decoded()` returning the new `Decoded` value (`ur_type()`/`message()`/`into_parts()`).
- `DecoderLimits` shrinks to four limits (`maxMessageLength`, `maxFragmentCount`, `maxFragmentLength`, `maxUriLength`); `receivedParts` and `bufferParts` are gone, and there is no poison state. Frames are admitted in a fixed order in both languages — scheme, type, type admission (`accept` list, then the locked type), ASCII, `maxUriLength`, then the body — and a limit violation fails the session (`fatal`, `State::Failed`) only for an admitted frame: a foreign-type frame is rejected `UnexpectedType` whatever its size, and once a fountain stream is locked a part that disagrees with it is rejected `InconsistentPart`. `parseUr`/`ur::parse` use the same order without admission and still apply the part limits.
- The typed multipart wrappers are removed. TS `MultipartEncoder`/`MultipartDecoder` are replaced by `Ur.encoder(options)` (returns the L3 `UrEncoder`) and `Ur.fromDecoded(decoded)`; Rust drops `typed::MultipartEncoder`/`typed::MultipartDecoder` for `typed::Ur::encoder()` and `impl TryFrom<ur::Decoded> for typed::Ur`.
- Bytewords is a flat function API with a required style argument. TS replaces the `bytewords` namespace export and `encodeRaw` with `encodeBytewords(data, style)`, `decodeBytewords(text, style)`, `bytewordsChecksum(data, style)`, `bytewordsEncodedLength(length, style)`, `bytewordsIdentifier(digest)`, `canonicalizeByteword(token)`, `bytemojiIdentifier(digest)`, and the `WORDS`/`MINIMALS`/`BYTEMOJIS` tables; `style` (`"standard" | "uri" | "minimal"`, type `BytewordsStyle`, was `Style`) is required everywhere. Rust mirrors this with `bytewords::{encode, decode, checksum, encoded_len, identifier, canonicalize, WORDS, MINIMALS}` taking `Style`, plus the new `bytemoji::identifier`.
- `UrType` is validated data, not a free-form string. TS replaces the `UrType` class with a branded string and `parseUrType`/`isUrType` (lowercases and validates `[a-z0-9-]+`); Rust `UrType` is a `Cow<'static, str>` newtype with `new`/`new_static`/`as_str` and the `ur_type!("seed")` macro that makes invalid literals compile errors. `IntoUrType` and `UrType::bytes` are removed.
- `parseUr`/`ur::parse` replace the decode family. TS removes `decode`, `decodeWithType`, `decodeMessage`, `normalizeUr`, `parse`, `parseNormalized`, `Kind`, and the old `ParsedUr`; the new `parseUr(text, limits?)` returns `{ kind: "single"; type; message } | { kind: "multi"; type; part }`. Rust removes `ur::decode`, `decode_message`, `decode_with_type`, `normalize_ur`, and `Kind`; `ur::parse(text, &DecoderLimits)` returns the new `ParsedUr::{Single, Multi}` enum. Encoding is `encodeUr`/`ur::encode` and `toQrString`/`ur::to_qr_string`.
- `UrEncoder`/`ur::Encoder` are iterators of UR strings. TS `new UrEncoder(type, message, options)` (was `Encoder`; `Encoder.create`, `Encoder.bytes`, and `nextPart` are removed) implements `IterableIterator<string>` with `type`/`fragmentCount`/`isSinglePart`/`isComplete`/`lastFragmentIndexes`; K = 1 repeats the single-part UR. Rust `ur::Encoder::new(ur_type, message, EncoderOptions)` implements `Iterator<Item = String>` + `FusedIterator`; `next_part`, `Encoder::bytes`, `Encoder::with_options`, and `qr_string` are removed.
- UR part headers follow a strict grammar `seq = 1*DIGIT "-" 1*DIGIT` with both fields in `1..=0xFFFFFFFF`: no signs, no whitespace, no extra separators; leading zeros are allowed.
- `UrCodec<T>` is a flat `{ tags: readonly [Tag, ...Tag[]], encode(value): Cbor, decode(cbor): T }` contract: `tags[0]` is written, every named tag is accepted on read, and every tag name must be a valid UR type (`InvalidType`). The codec helpers are `codecUrTypes`, `toUr`, `fromUr`, `toTagged`, `fromTagged`, `codecMap`, and `fromUrWith`; `toUrString`, `fromUrString`, `firstTagUrType`, `tagUrTypes`, and the registry's `fromUrStringWith` are removed.
- `Ur` is the single L4 value type. TS: `Ur.fromCbor`/`fromCborData`/`fromDecoded`/`parse`, `type`/`cbor`, `toCborData`/`toString`/`toQrString`/`encoder(options)`; `Ur.create`, `Ur.fromUrString`, `string()`, `qrString()`, and `checkType()` are removed. Rust `typed::Ur` keeps `new`/`from_cbor_data`/`ur_type`/`cbor`/`into_cbor`/`to_cbor_data`/`to_qr_string`/`encoder` plus `Display`, `FromStr` (single-part only, `NotSinglePart`), and `TryFrom<ur::Decoded>`; `string`, `from_ur_string`, `ur`, `check_type`, and `UrCodable` are removed. Rust `UrEncodable`/`UrDecodable` blanket-impl over `dcbor`'s tagged traits: writes use the first tag name, reads accept any `cbor_tags()` name.
- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- Read-only decode of deprecated BCR-2020-006 v1 tokens/tags: `crypto-seed` (300), `crypto-hdkey` (303), `crypto-keypath` (304), `crypto-coin-info` (305), `crypto-sskr` (309), `crypto-psbt` (310). Writes always emit v2. `codecUrTypes` validates and returns every `UrCodec.tags` name as a `UrType`.
- Hermes smoke test in CI: `packages/ur` sources are bundled to a classic script and run on the Hermes V1 CLI that React Native ships. Runtime requirements on Hermes: the root transport needs only `TextEncoder`; `@qntx/ur/typed` and `@qntx/ur/registry` additionally need a WHATWG `TextDecoder` supporting `{ fatal: true }` (Expo provides one; bare React Native needs a polyfill).
- New registry types/codecs: `eckey` (40306), `address` (40307), `output-descriptor` (40308), and `account-descriptor` (40311), with `EcKey`, `Address`/`AddressType`, `OutputDescriptor`/`DescriptorKey`, and `AccountDescriptor` value types.
- Read-only v1 decode of `crypto-output` (308) and `crypto-account` (311): tagged script-expression trees (tags 400–410) convert to v2 text descriptors with `@n` key placeholders; writes always emit v2. The `crypto-eckey` (306), `crypto-address` (307) and untagged KeystoneHQ spellings are also accepted on read.

### Changed

- Encode-side validation now mirrors decode-side validation across the registry: caller-built values are checked against the same shape, length, placeholder and tag rules that wire input must satisfy (including hdkey private `0x00` key-data prefix and the `@n` placeholder set of `output-descriptor`).
- `@qntx/ur` engine requirement is now Node `>=20.19.0` (was `>=22.12`), the real floor of the ES2022 + ESM root transport; `@qntx/ur/typed` and `@qntx/ur/registry` still need Node `>=22.12` through `@blockchaincommons/dcbor`.
- Fountain decoding needs ~35–50% fewer frames at K ≥ 20 (measured frames-to-complete ÷ K, random start, no loss: K=50 → 1.129, K=100 → 1.044, K=200 → 1.055) and is much faster: K=2000, fragLen 200, 20% loss decodes in ~0.57 s in TypeScript (was ~18.3 s) and ~40 ms in Rust (was ~223 ms).
- `fromTagged` accepts any tag in `codec.tags`, so v1 nested keypath/coin-info tags 304/305 decode; `codecMap` registers every accepted name, including the v1 tokens.
- License is now `MIT OR Apache-2.0` (1.8.0 and earlier remain MIT). New `LICENSE-MIT` / `LICENSE-APACHE` files replace `LICENSE`.
- Repository moved to `github.com/qntx/ur` (was `qntx/ur.js`).
- Fountain index sorting no longer uses ES2023 `Array.prototype.toSorted`, so the package runs on Hermes V1 (React Native).
- Rust crates `bcur` and `bcur-cli` moved into this repository from qntx-labs/bcur (b2c1fb1); their earlier history lives in that repository's CHANGELOG. Workspace version is lockstep with `@qntx/ur`, so `bcur` and `bcur-cli` go from 1.0.0 on crates.io straight to 2.0.0; MSRV is Rust 1.99, edition 2024.
- Rust fragment selection builds the degree sampler once per stream and stops shuffling once enough indexes are drawn: 3.8× faster at K=50, 7× at K=500, 8.3× at K=2000.
- Test vectors moved to a shared repository-root `vectors/` tree consumed by both the TypeScript and Rust suites, and capabilities are tracked in `parity.json`. No user-facing API change.

### Fixed

- `seedCodec` now reads a creation date tagged 1 **or** the historical tag 100 (days since epoch, per the BCR-2020-006 `100(18394)` example); writes always emit tag 1.
- The fountain chooser converts random integers to `[0, 1)` with round-to-nearest, matching BCR-2024-001, URKit, and bc-ur; 1.x truncated, which could in rare cases pick different fragments than other implementations and fail the final checksum. When the value rounds to exactly 1.0 the index is clamped to `n - 1` (the reference implementations index out of bounds there).
- Rust `bytewords::decode("")` reports `InvalidBytewordsChecksum` like TypeScript and the official vectors (was `InvalidWord`).
- Rust `UrDecodable::from_ur` accepted only the first `cbor_tags()` name; it now accepts every named tag, matching the TS `fromUr` semantics.
- TypeScript case folding is now ASCII-only in `parseUr`, `parseUrType`, `decodeBytewords`, `canonicalizeByteword`, and `toQrString`, matching the Rust behavior — `ur:\u212Aey/…` and `parseUrType("\u212Aey")` now throw `InvalidType` instead of folding U+212A KELVIN SIGN to `k`.
- `bcur decode` no longer aborts on a rejected line: it prints `bcur: skipped line N: <error>` to stderr and continues. Fatal errors still abort, and input ending before completion still exits nonzero.

## 1.8.0 - 2026-09-27

### Fixed

- `FountainEncoder.create` rejects non-positive-int `maxFragmentLength` (`NaN`, negatives, fractions, `Infinity`, `0`) with `InvalidFragmentLen` instead of a raw `RangeError` or silent acceptance.

### Changed

- Fountain index selection uses a per-stream `FragmentChooser` (BCR-2024-001 §4): harmonic degree sampler built once, remove-shuffle stops at `degree`, indexes computed once per received part and returned sorted. Decode of a K=2000 stream at 20% simple-part loss: ~8 s → ~1 s (same part count; wire output unchanged).
- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- `THIRD_PARTY.md` covers test vectors derived from ur-rs, bcur, and bc-ur.

## 1.7.0 - 2026-09-27

### Changed

- Optional peer `@blockchaincommons/dcbor` is `1.0.0-beta.3`.
- Exported object shapes are `type` aliases instead of `interface`: `UrCodec`, `ParsedUr`, `DecoderLimits`, `Seed`, `Psbt`, `Keypath`, `CoinInfo`, `MasterHdKey`, `DerivedHdKey`, `SskrShare`. Structurally identical; declaration merging is no longer possible.
- `UrError.expected` / `found` / `limit` are typed `?: string | undefined` (`exactOptionalPropertyTypes`).
- Tooling: Vite+ `0.3.3`; lint, format, and TS configs come from `@qntx/oxlint`, `@qntx/oxfmt`, and `@qntx/tsconfig` (`strictest`). Lint and format live only in the root `vite.config.ts`.

### Fixed

- Alias sampler keeps ur-rs float evaluation order (`weights[g] += weights[a] - 1.0`) so degree tables stay bit-identical to ur-rs.

## 1.6.0 - 2026-09-16

- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L5 `codecMap` / `fromUrStringWith`. Host-provided dispatch. Duplicate `tags[0].name` is `TypeError`. Unknown type is `UnexpectedType`. No global registry.

## 1.5.0 - 2026-09-16

- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L5 `envelopeCodec`, `assertEnvelopeContent`, `ENVELOPE_MAX_DEPTH`. Validating identity over untagged envelope-content. Depths 0..=64 accepted; 65 is `OutOfRange`. No elide/encrypt/digest-sort.

## 1.4.0 - 2026-09-16

- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L5 `sskrCodec`. Packed 5-byte header; domain stores N not N-1. Official BCR-2020-011 third share golden.

## 1.3.0 - 2026-09-16

- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L5 `hdKeyCodec`, `keypathCodec`, `coinInfoCodec`, `hdKeyDigestSource`, `hdKeyDigest`. Nested tags 40304/40305. Official HDKey vectors 1–2.

## 1.2.0 - 2026-09-16

- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L5 `@qntx/ur/registry`: `seedCodec`, `psbtCodec`, `seedDigest`. Triple pack entry. Optional dcbor peer. v2 type tokens only.
- Vendored `tests/vectors/` contract goldens, byte-identical to bcur `crates/bcur/tests/vectors/contract/`.

### Changed

- Drop the CI `node` matrix job and `scripts/ci-node-*.mjs`.
- Convert the repo to a vite-plus bun workspace. `@qntx/ur` lives at `packages/ur`. CI is `bun run ready`.
- Fountain `seqNum` fail-closed at `0xffffffff` (`ResourceLimit` `limit: "sequence"`) is the documented contract; wrap-to-0 is rejected.

## 1.1.0 - 2026-09-13

### Breaking

- `engines.node` is `>=22.12`, matching `@blockchaincommons/dcbor`. Node 20 is not a supported runtime.
- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- L4 `@qntx/ur/typed`: `Ur` value, `UrCodec`, and typed `MultipartEncoder` / `MultipartDecoder`. Dual-entry pack; dcbor stays external. Root `@qntx/ur` does not import dcbor.
- `CborDecode` / `CborType` error codes (L4-only; exhaustive `switch (error.code)` needs a default).

### Fixed

- Pin `devEngines.packageManager` to bun `1.3.14` with `onFail: ignore`. Tag-triggered `publish-npm.yml@v2` still runs `npm publish` on Node 24; npm 11 treats `onFail: download` plus `name: bun` as `EBADDEVENGINES`. Vite+ rewrites an absent field to `onFail: download`. CI `npm publish --dry-run` on Node 24 guards this.

### Notes

- Optional peer `@blockchaincommons/dcbor@1.0.0-beta.2`. Upstream has no stable `1.0.0`; pin stays on `beta.2`.

## 1.0.0 - 2026-09-12

### Breaking

- `Encoder.nextPart()` when `fragmentCount === 1` emits a single-part `ur:<type>/<body>` instead of fountain `1-1`.
- `Decoder.receive` accepts single-part URIs and completes the session.
- `NotMultiPart` removed.
- Type is pinned after successful ingest, not on parse.
- Exceeding `maxUriLen`, UR-layer `Part.fromCbor` `ResourceLimit`, and fountain `DecoderState` poison the session; later `receive` / `message` throw the same code.
- `Part.fromCbor` caps `sequenceCount` at `maxFragmentCount`.
- First-part padding wider than one fragment (`product - ml >= fragLen`) is `InconsistentPart`.
- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- `Encoder.isSinglePart`, `Encoder.complete`
- `decodeMessage(uri)` — single-part payload or `NotSinglePart`
- `SinglePartExhausted` — fountain encoder `K == 1` second `nextPart`

### Changed

- Duplicate single-part of the same type is ignored (first payload wins; body is not compared).
- `DEFAULT_LIMITS` integers frozen (same as bcur 1.0 Default). Override with `new Decoder({ limits })`.

### Notes

- Public API is transport-only: opaque payload bytes plus a type token. No dCBOR parse, no type registry.
- ur-rs `Decoder` will not consume K==1 outbound single-part URIs. This `Decoder` still accepts ur-rs fountain `1-1`.

## 0.1.0

### Changed

- Package name is `@qntx/ur` (npm name `ur` is already taken by an unrelated package).
- `@qntx/ur/registry` no longer exports the numeric `TAG_*` constants; tags are reached through `TAGS` (UR-type tags, e.g. `TAGS.seed.value`) and `SCRIPT_TAGS` (BCR-2020-010 script-expression tags).

### Added

- Bytes-first Uniform Resources transport aligned with bcur / ur-rs:
  - Bytewords (BCR-2020-012): standard, uri, minimal
  - Fountain codes (MUR): Xoshiro256**, Walker alias sampling, fixed-schema Part CBOR
  - UR encode/decode and multi-part `Encoder` / `Decoder`
- `DecoderLimits` with fail-closed poison on resource exceed
- UR type stickiness and full-URI case-fold for QR uppercase
- Structured `UrError` with stable `code` field
- Interop goldens from ur-rs (MIT) and adversarial decoder tests

### Notes

- Public API is transport-only (no application type registry).
- Default `DecoderLimits` numeric values are provisional until 1.0.
