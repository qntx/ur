import { defineConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { merge, react } from "@qntx/oxlint";

export default defineConfig({
  defaultPackage: {
    dev: "./apps/website",
    build: "./apps/website",
    preview: "./apps/website",
    pack: "./packages/ur",
  },
  staged: { "*": "vp check --fix" },
  fmt,
  lint: merge(react, {
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
      // Vite idiom: CSS is imported for side effects.
      "import/no-unassigned-import": ["error", { allow: ["**/*.css"] }],
      // oxfmt canonicalizes hex digits to lowercase; this rule demands uppercase, so fmt always wins.
      "unicorn/number-literal-case": "off",
    },
    overrides: [
      {
        // Bit manipulation is intrinsic to the codecs (crc32, xoshiro, bytewords, fountain XOR).
        files: ["packages/ur/src/**", "packages/ur/tests/**"],
        rules: { "eslint/no-bitwise": "off" },
      },
    ],
  }),
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
});
