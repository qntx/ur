import { defineConfig } from "bumpp";

// npm package and Cargo workspace versions are lockstep; bumpp rewrites every
// `1.x.y` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and the `bcur = "=x.y.z"` dep.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["packages/ur/package.json", "Cargo.toml"],
  // The fuzz crate is its own workspace with a path dependency on bcur, so
  // its lockfile records the bcur version too.
  execute: "cargo update --workspace && cargo update --workspace --manifest-path fuzz/Cargo.toml",
  // execute rewrites both lockfiles; commit them too.
  all: true,
  commit: true,
  // main is protected: release through a `release/v<version>` pull request
  // opened via `gh`. No tag is created; after the release PR merges, tag the
  // merge commit by hand (GITHUB_TOKEN tags do not trigger publish workflows).
  pr: true,
  push: true,
});

export default config;
