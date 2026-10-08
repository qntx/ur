import { describe, expect, test } from "vite-plus/test";

import { checkVersion } from "./check-version.ts";

const CARGO_TOML = `[workspace]
members = ["crates/*"]

[workspace.package]
version = "1.8.0"

[workspace.dependencies]
bcur = { version = "=1.8.0", path = "crates/bcur" }
hex = "0.4"
`;

const PARSED = {
  workspace: {
    package: { version: "1.8.0" },
    dependencies: {
      bcur: { version: "=1.8.0", path: "crates/bcur" },
      hex: "0.4",
    },
  },
};

const UR = {
  path: "packages/ur/package.json",
  pkg: { name: "@qntx/ur", version: "1.8.0" },
};

const PRIVATE_PKG = {
  path: "packages/sandbox/package.json",
  pkg: { name: "@qntx/sandbox", version: "0.0.1", private: true },
};

const CRATES = [
  {
    path: "crates/bcur/Cargo.toml",
    manifest: { package: { name: "bcur", version: { workspace: true } } },
  },
  {
    path: "crates/bcur-cli/Cargo.toml",
    manifest: { package: { name: "bcur-cli", version: { workspace: true } } },
  },
];

const PACKAGES = [UR, PRIVATE_PKG];

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML, CRATES)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion(
      [{ ...UR, pkg: { ...UR.pkg, version: "1.8.1" } }, PRIVATE_PKG],
      PARSED,
      CARGO_TOML,
      CRATES,
    );
    expect(errors).toStrictEqual([
      "version mismatch: packages/ur/package.json has 1.8.1, Cargo.toml has 1.8.0",
    ]);
  });

  test("ignores private packages", () => {
    const pkg = { name: "@qntx/sandbox", version: "9.9.9", private: true };
    const errors = checkVersion([UR, { ...PRIVATE_PKG, pkg }], PARSED, CARGO_TOML, CRATES);
    expect(errors).toStrictEqual([]);
  });

  test("rejects a crate manifest that hard-codes a version", () => {
    const crates = [
      {
        path: "crates/bcur/Cargo.toml",
        manifest: { package: { name: "bcur", version: { workspace: true } } },
      },
      {
        path: "crates/bcur-cli/Cargo.toml",
        manifest: { package: { name: "bcur-cli", version: "1.8.0" } },
      },
    ];
    const errors = checkVersion(PACKAGES, PARSED, CARGO_TOML, crates);
    expect(errors).toStrictEqual([
      'crates/bcur-cli/Cargo.toml: package version must be "version.workspace = true"',
    ]);
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.bcur.version = "=1.7.0";
    const errors = checkVersion(PACKAGES, parsed, CARGO_TOML, CRATES);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("bcur");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('hex = "0.4"', 'hex = "1.8.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.hex = "1.8.0";
    const errors = checkVersion(PACKAGES, parsed, toml, CRATES);
    expect(errors).toStrictEqual([
      'Cargo.toml: "1.8.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });
});
