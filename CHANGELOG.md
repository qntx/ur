# Changelog

## Unreleased

## 1.7.0 - 2026-09-27

### Changed

- Optional peer `@blockchaincommons/dcbor` is `1.0.0-beta.3`.
- Exported object shapes are `type` aliases instead of `interface`: `UrCodec`, `ParsedUr`, `DecoderLimits`, `Seed`, `Psbt`, `Keypath`, `CoinInfo`, `MasterHdKey`, `DerivedHdKey`, `SskrShare`. Structurally identical; declaration merging is no longer possible.
- `UrError.expected` / `found` / `limit` are typed `?: string | undefined` (`exactOptionalPropertyTypes`).
- Tooling: Vite+ `0.3.3`; lint, format, and TS configs come from `@qntx/oxlint`, `@qntx/oxfmt`, and `@qntx/tsconfig` (`strictest`). Lint and format live only in the root `vite.config.ts`.

### Fixed

- Alias sampler keeps ur-rs float evaluation order (`weights[g] += weights[a] - 1.0`) so degree tables stay bit-identical to ur-rs.

## 1.6.0 - 2026-09-16

### Added

- L5 `codecMap` / `fromUrStringWith`. Host-provided dispatch. Duplicate `tags[0].name` is `TypeError`. Unknown type is `UnexpectedType`. No global registry.

## 1.5.0 - 2026-09-16

### Added

- L5 `envelopeCodec`, `assertEnvelopeContent`, `ENVELOPE_MAX_DEPTH`. Validating identity over untagged envelope-content. Depths 0..=64 accepted; 65 is `OutOfRange`. No elide/encrypt/digest-sort.

## 1.4.0 - 2026-09-16

### Added

- L5 `sskrCodec`. Packed 5-byte header; domain stores N not N-1. Official BCR-2020-011 third share golden.

## 1.3.0 - 2026-09-16

### Added

- L5 `hdKeyCodec`, `keypathCodec`, `coinInfoCodec`, `hdKeyDigestSource`, `hdKeyDigest`. Nested tags 40304/40305. Official HDKey vectors 1–2.

## 1.2.0 - 2026-09-16

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
