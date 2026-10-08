# Shared test vectors

Frozen golden data consumed by both implementations: the TypeScript tests in
`packages/ur/tests/` and the Rust tests in `crates/bcur/tests/` and
`crates/bcur/src/` read exactly these files. Do not reformat, re-wrap, or
normalize them; any change is a deliberate contract change and must land in
both languages in the same commit.

Line files (`.txt`, `.hex`) are data-only: UTF-8, LF line endings, a trailing
newline, and no `#` header comments — provenance lives in this README instead.
Runners must not need comment skipping. If a vector mismatch is ever an
implementation bug rather than a stale golden, that is what these files are
for: they pin behavior, not the implementations' bugs.

## Layout

| Path                         | Contents                                                        |
| ---------------------------- | --------------------------------------------------------------- |
| `bytewords/contract.json`    | ByteWords encode/decode contract (standard, uri, minimal)       |
| `fountain/part-cbor.json`    | Fountain `Part` CBOR round trip + non-shortest rejection        |
| `ur/k1.json`                 | Single-part encoder/decoder contract                            |
| `ur/published-singles.txt`   | Three published single-part UR goldens                          |
| `typed/test-array.json`      | Typed-layer `[1, 2, 3]` UR golden (L4 test array)               |
| `limits/defaults.json`       | `DecoderLimits` default values                                  |
| `limits/poison.json`         | Resource-limit → poison-session contract                        |
| `ur-rs/multipart-20.txt`     | ur-rs `test_ur_encoder` 20-URI table (Wolf/256, max frag 30)    |
| `ur-rs/choose-fragments.txt` | ur-rs `test_choose_fragments` sorted indexes, seq 1..=30        |
| `ur-rs/wolf256-fragments.hex` | ur-rs `test_partition_and_join` hex (Wolf/1024, max frag 100)  |
| `official/published-from-refs.txt` | Pinned `ur:` literals quoted by URKit / bc-ur sources    |

## Provenance

- `ur-rs/` — golden tables from [ur-rs](https://github.com/dspicher/ur-rs)
  0.5 (MIT). `multipart-20.txt` additionally matches the URKit/bc-ur 20-URI
  table. See `THIRD_PARTY.md`; only goldens are vendored, no source.
- `ur/published-singles.txt` — published single-part UR goldens from
  BCR docs, bc-ur docs, and the ur-rs Wolf/50 example.
- `official/published-from-refs.txt` — sorted-unique extract of every `ur:`
  literal quoted in the pinned URKit/bc-ur reference files. Regenerate with:

  ```bash
  scripts/vectors/extract-published-urs.sh > vectors/official/published-from-refs.txt
  ```

- `bytewords/`, `fountain/`, `ur/k1.json`, `typed/`, `limits/` — contract
  vectors authored for this repository's ur.js + bcur interop suite.

## Registration

`scripts/parity/check.ts` requires every file under `vectors/` to be
registered in `parity.json` and cited by at least one of the capability's
test files; stable capabilities must have tests on both sides.
