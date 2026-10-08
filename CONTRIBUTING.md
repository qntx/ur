# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust 1.99** — via `rust-toolchain.toml` (kept in sync with
  `[workspace.package].rust-version`).
- **cargo-deny** for the supply-chain check (`cargo install cargo-deny`).
- **Optional**, for local portable builds: the cross-compilation rustup
  targets CI builds.

  ```bash
  rustup target add wasm32-unknown-unknown thumbv7m-none-eabi aarch64-linux-android x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
  ```

- **Optional**, for fuzzing: a nightly toolchain and cargo-fuzz
  (`cargo install cargo-fuzz`), then `cd fuzz && cargo +nightly fuzz run <target>`.

## Repository layout

```text
packages/ur/    @qntx/ur — pure-TypeScript UR library; builds with vp pack
apps/website/   playground website
crates/bcur/    bcur — no_std + alloc Rust UR transport and typed dCBOR layer
crates/bcur-cli/  bcur-cli — `bcur` CLI encoder/decoder with terminal QR output
fuzz/           libFuzzer targets for bcur (separate workspace, nightly)
scripts/vectors/  test-vector maintenance (extract-published-urs.sh)
```

## Local gate

Run before opening a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo fmt --check
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is public documentation mirrored to docs.qntx.org. `docs/internal/` is
local-only design material and must never be committed.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
