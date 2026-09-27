import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { expect, test } from "vite-plus/test";

const root = resolve(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
  exports: Record<string, unknown>;
  publishConfig?: { exports?: unknown };
};

function exportTarget(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && "default" in value) {
    const next = value.default;
    if (typeof next === "string") {
      return next;
    }
  }
  throw new Error(`unexpected export entry: ${JSON.stringify(value)}`);
}

const dist = (name: string) => pathToFileURL(resolve(root, "dist", name)).href;

test("package exports resolve to packed files, not source", () => {
  expect(exportTarget(pkg.exports["."])).toBe("./dist/index.mjs");
  expect(exportTarget(pkg.exports["./typed"])).toBe("./dist/typed.mjs");
  expect(exportTarget(pkg.exports["./registry"])).toBe("./dist/registry.mjs");
  expect(pkg.publishConfig?.exports).toBeUndefined();
});

test("packed index.mjs does not mention dcbor", () => {
  const src = readFileSync(resolve(root, "dist/index.mjs"), "utf8");
  expect(src).not.toContain("@blockchaincommons/dcbor");
});

test("packed registry.mjs imports dcbor as external", () => {
  const registry = readFileSync(resolve(root, "dist/registry.mjs"), "utf8");
  expect(registry).toContain("@blockchaincommons/dcbor");
  expect(/from\s*["']@blockchaincommons\/dcbor["']/.test(registry)).toBe(true);
});

test("packed UrError is one class across entries", async () => {
  const index = (await import(dist("index.mjs"))) as { UrError: unknown };
  const typed = (await import(dist("typed.mjs"))) as { UrError: unknown };
  const registry = (await import(dist("registry.mjs"))) as {
    UrError: unknown;
    seedCodec: unknown;
    psbtCodec: unknown;
    seedDigest: unknown;
    keypathCodec: unknown;
    coinInfoCodec: unknown;
    hdKeyCodec: unknown;
    hdKeyDigestSource: unknown;
    hdKeyDigest: unknown;
    sskrCodec: unknown;
    envelopeCodec: unknown;
    assertEnvelopeContent: unknown;
    ENVELOPE_MAX_DEPTH: unknown;
    codecMap: unknown;
    fromUrStringWith: unknown;
  };
  expect(index.UrError).toBe(typed.UrError);
  expect(index.UrError).toBe(registry.UrError);
  expect(registry.seedCodec).toBeDefined();
  expect(registry.psbtCodec).toBeDefined();
  expect(registry.seedDigest).toBeDefined();
  expect(registry.keypathCodec).toBeDefined();
  expect(registry.coinInfoCodec).toBeDefined();
  expect(registry.hdKeyCodec).toBeDefined();
  expect(registry.hdKeyDigestSource).toBeDefined();
  expect(registry.hdKeyDigest).toBeDefined();
  expect(registry.sskrCodec).toBeDefined();
  expect(registry.envelopeCodec).toBeDefined();
  expect(registry.assertEnvelopeContent).toBeDefined();
  expect(registry.ENVELOPE_MAX_DEPTH).toBe(64);
  expect(registry.codecMap).toBeTypeOf("function");
  expect(registry.fromUrStringWith).toBeTypeOf("function");
});
