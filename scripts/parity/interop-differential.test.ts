import { describe, expect, test } from "vite-plus/test";

import { generateInteropFile } from "./interop-differential.ts";
import type { InteropCase, InteropMutation } from "./interop-differential.ts";

const DEFAULT_CLI = {
  seed: 377401,
  cases: 300,
  out: "target/parity/interop-differential.json",
};

const isDefined = <T>(value: T | undefined): value is T => value !== undefined;

const isAccepted = (c: InteropCase): boolean => c.outcome.accepted;

const acceptedShape = (c: InteropCase): boolean => {
  if (!c.outcome.accepted) {
    return false;
  }
  return c.outcome.cborHex.length % 2 === 0 && c.outcome.ur.startsWith(`ur:${c.codec}/`);
};

const rejectedShape = (c: InteropCase): boolean => {
  if (c.outcome.accepted) {
    return false;
  }
  return typeof c.outcome.code === "string";
};

const hwMutation = (c: InteropCase): boolean =>
  c.codec === "qr-hardware-call" && c.mutation !== undefined;

describe("generateInteropFile", () => {
  const file = generateInteropFile(DEFAULT_CLI);

  test("same seed produces identical output", () => {
    expect(generateInteropFile(DEFAULT_CLI)).toStrictEqual(file);
  });

  test("different seeds diverge", () => {
    expect(generateInteropFile({ ...DEFAULT_CLI, seed: DEFAULT_CLI.seed + 1 })).not.toStrictEqual(
      file,
    );
  });

  test("shape follows the schema", () => {
    expect(file.schema).toBe(1);
    expect(file.seed).toBe(DEFAULT_CLI.seed);
    expect(file.cases).toHaveLength(DEFAULT_CLI.cases);
    expect(file.cases.every((c) => c.inputCborHex.length % 2 === 0)).toBe(true);
    const accepted = file.cases.filter(isAccepted);
    expect(accepted.length).toBeGreaterThan(0);
    expect(accepted.every(acceptedShape)).toBe(true);
    const rejected = file.cases.filter((c) => !isAccepted(c));
    expect(rejected.length).toBeGreaterThan(0);
    expect(rejected.every(rejectedShape)).toBe(true);
  });

  test("every unmutated case is accepted", () => {
    const unmutated = file.cases.filter((c) => c.mutation === undefined);
    expect(unmutated.length).toBeGreaterThan(0);
    expect(unmutated.every(isAccepted)).toBe(true);
  });

  test("every mutation kind is exercised over the default run", () => {
    const mutations = file.cases.map((c) => c.mutation).filter(isDefined);
    expect(new Set(mutations.map((m: InteropMutation) => m.kind))).toStrictEqual(
      new Set(["drop-key", "unknown-key", "wrong-type", "byte-length", "enum-range"]),
    );
  });

  test("every codec and qr-hardware-call context appears", () => {
    expect(new Set(file.cases.map((c) => c.codec))).toStrictEqual(
      new Set(["btc-sign-request", "btc-signature", "qr-hardware-call"]),
    );
    const contexts = file.cases.filter(hwMutation).map((c) => c.mutation?.context);
    expect(new Set(contexts)).toStrictEqual(new Set(["call", "params", "schema"]));
  });
});
