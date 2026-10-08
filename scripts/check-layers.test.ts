import { describe, expect, test } from "vite-plus/test";

import { checkLayers, crateFromManifest } from "./check-layers.ts";
import type { CrateInfo } from "./check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers", () => {
  test("accepts the allowed edges", () => {
    const crates = [
      crate("bcur", []),
      crate("bcur-cli", ["bcur"]),
      crate("bcur-registry", ["bcur"]),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("bcur", ["bcur-cli"]), crate("bcur-cli", ["bcur"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["bcur: must not depend on bcur-cli"]);
  });

  test("rejects a bcur edge hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "bcur" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { "bcur-cli": { path: "../bcur-cli" } } } },
      },
      "bcur",
    );
    expect(checkLayers([info])).toStrictEqual(["bcur: must not depend on bcur-cli"]);
  });

  test("rejects a published crate depending on an unpublished crate", () => {
    const crates = [
      crate("bcur", []),
      crate("bcur-cli", ["bcur", "bcur-registry"]),
      crate("bcur-registry", ["bcur"], false),
    ];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual([
      "bcur-cli: must not depend on bcur-registry",
      "bcur-cli: published crate must not depend on bcur-registry",
    ]);
  });

  test("rejects an unknown bcur* crate", () => {
    const errors = checkLayers([crate("bcur-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "bcur-mystery"']);
  });

  test("ignores third-party dependencies", () => {
    const crates = [
      crate("bcur", ["crc", "thiserror"]),
      crate("bcur-cli", ["bcur", "clap", "minicbor"]),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });
});
