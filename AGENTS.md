# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- `packages/ur/src` is platform-neutral and Hermes V1-safe (no Node/browser-only globals, no `node:*` imports, no ES2023+ array methods).
- Only `packages/ur/src/typed` and `packages/ur/src/registry` may import `@blockchaincommons/dcbor`; the root transport never does.
- `bcur` is `no_std` + `alloc` and must build for `wasm32-unknown-unknown` and `thumbv7m-none-eabi` with `--no-default-features`; `getrandom` must not appear in that dependency tree.
- No panics and no `unwrap`/`expect` in library code.
- No third-party types in public APIs, except `dcbor` types in the typed layer.
- npm and crate versions are lockstep (`@qntx/ur` and `bcur`/`bcur-cli` share one version; `bump.config.ts` bumps `packages/ur/package.json` + `Cargo.toml` together, `scripts/check-version.ts` guards drift).
- Shared test vectors live in `vectors/` and every capability is tracked in `parity.json`; both languages run the same files.
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt` and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo, version,
                                                    # layer and parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```
