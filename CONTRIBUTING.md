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
vectors/        shared golden data consumed by both languages (see vectors/README.md)
parity.json     capability ledger: every shared capability and the vectors/tests behind it
scripts/        repository checks (version lockstep, crate layers, parity) and vector maintenance
```

## Local gate

Run before opening a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo, version,
                                                    # layer and parity checks
bun run test:parity                                 # seeded TS→Rust differential replay
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

## Versioning and release

`@qntx/ur`, `bcur`, and `bcur-cli` share one lockstep version. `bun run release`
runs `bumpp` (`bump.config.ts`), which bumps `packages/ur/package.json` and the
Cargo workspace version together, refreshes `Cargo.lock`, and opens a
`release/v<version>` pull request. `scripts/check-version.ts` (part of `bun run
lint`) guards against drift: every published package version must equal
`[workspace.package].version`, internal path dependencies must pin `=<version>`,
and the version string may appear nowhere else in `Cargo.toml`.

After the release PR merges, tag the merge commit `v*.*.*` and push it by hand;
one tag publishes npm (`@qntx/ur`), crates.io (`bcur`, `bcur-cli`), and the
GitHub Release (`bcur` binaries).

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
