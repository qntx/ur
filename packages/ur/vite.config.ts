import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    dts: {},
    // ESM-only sugar flattens to a string; keep types/import/default for pack entries.
    exports: {
      customExports(exports) {
        for (const [key, value] of Object.entries(exports)) {
          if (typeof value === "string" && value.endsWith(".mjs")) {
            exports[key] = {
              types: value.replace(/\.mjs$/, ".d.mts"),
              import: value,
              default: value,
            };
          }
        }
        return exports;
      },
    },
    entry: {
      index: "src/index.ts",
      typed: "src/typed/index.ts",
      registry: "src/registry/index.ts",
    },
    // optional peer is not auto-externalized
    deps: {
      neverBundle: ["@blockchaincommons/dcbor"],
    },
  },
});
