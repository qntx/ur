import { describe, expect, test } from "vite-plus/test";

import { UrError } from "../../packages/ur/src/index.ts";
import type { CaseOptions, MutatedFrame } from "./differential.ts";
import {
  caseOptions,
  encodeAll,
  flipBodyChar,
  foreignFrame,
  generateFile,
  makeRng,
  messageLength,
  mutateFrames,
  outcomeOf,
  parseArgs,
  swapHeader,
  toHex,
} from "./differential.ts";

const MAX_U32 = 0xffffffff;
const FRAME = "ur:bytes/3-5/aebygdmkwrhd";
const SINGLE = "ur:bytes/aebygdmkwrhd";

const draws = <T>(seed: number, n: number, f: (rng: ReturnType<typeof makeRng>) => T): T[] => {
  const rng = makeRng(seed);
  return Array.from({ length: n }, () => f(rng));
};

const validOptions = (options: CaseOptions): boolean => {
  const minOk =
    options.minFragmentLength === undefined ||
    options.minFragmentLength <= options.maxFragmentLength;
  const seqOk = options.firstSequence === 0 || options.firstSequence > MAX_U32 - 51;
  return (
    options.maxFragmentLength >= 10 &&
    options.maxFragmentLength <= 500 &&
    minOk &&
    seqOk &&
    (options.minFragmentLength === undefined || options.minFragmentLength >= 1)
  );
};

const allUr = (frames: MutatedFrame[]): boolean =>
  frames.every((f) => f.text.toLowerCase().startsWith("ur:"));

const inUnitInterval = (v: number): boolean => v >= 0 && v < 1;

describe("makeRng", () => {
  test("deterministic for a fixed seed", () => {
    const a = draws(42, 8, (r) => r.int(0, 100));
    const b = draws(42, 8, (r) => r.int(0, 100));
    expect(a).toStrictEqual(b);
  });

  test("different seeds diverge", () => {
    const a = draws(1, 8, (r) => r.int(0, 1000000));
    const b = draws(2, 8, (r) => r.int(0, 1000000));
    expect(a).not.toStrictEqual(b);
  });

  test("float stays in [0, 1)", () => {
    const values = draws(7, 500, (r) => r.float());
    expect(values.every(inUnitInterval)).toBe(true);
  });

  test("int stays inside bounds", () => {
    const values = draws(9, 500, (r) => r.int(3, 17));
    expect(Math.min(...values)).toBeGreaterThanOrEqual(3);
    expect(Math.max(...values)).toBeLessThanOrEqual(17);
  });
});

describe("parseArgs", () => {
  test("defaults", () => {
    expect(parseArgs([])).toStrictEqual({
      seed: 377401,
      cases: 200,
      out: "target/parity/differential.json",
    });
  });

  test("overrides", () => {
    expect(parseArgs(["--seed", "9", "--cases", "3", "--out", "x.json"])).toStrictEqual({
      seed: 9,
      cases: 3,
      out: "x.json",
    });
  });

  test("rejects unknown and malformed flags", () => {
    expect(() => parseArgs(["--bogus"])).toThrow("unknown argument");
    expect(() => parseArgs(["--seed", "abc"])).toThrow("--seed expects a u32");
    expect(() => parseArgs(["--seed"])).toThrow("requires a value");
    expect(() => parseArgs(["--seed", "4294967296"])).toThrow("u32");
  });
});

describe("messageLength", () => {
  const lengths = draws(5, 800, (r) => messageLength(r, 50));

  test("stays within 1..8192 and covers the edges", () => {
    expect(Math.min(...lengths)).toBe(1);
    expect(Math.max(...lengths)).toBeLessThanOrEqual(8192);
    expect(lengths).toContain(1);
  });

  test("includes exact multiples of the fragment length", () => {
    expect(lengths.some((l) => l % 50 === 0)).toBe(true);
  });
});

describe("caseOptions", () => {
  const specs = draws(11, 400, caseOptions);

  test("constraints hold", () => {
    expect(specs.every(validOptions)).toBe(true);
  });

  test("minFragmentLength is sometimes absent", () => {
    expect(specs.some((o) => o.minFragmentLength === undefined)).toBe(true);
    expect(specs.some((o) => o.minFragmentLength !== undefined)).toBe(true);
  });

  test("firstSequence is usually zero, sometimes near wrap", () => {
    expect(specs.some((o) => o.firstSequence === 0)).toBe(true);
    expect(specs.some((o) => o.firstSequence > MAX_U32 - 51)).toBe(true);
  });
});

describe("frame mutations", () => {
  test("flipBodyChar changes exactly one body character", () => {
    const out = flipBodyChar(FRAME, makeRng(3));
    expect(out).toHaveLength(FRAME.length);
    expect(out.slice(0, FRAME.lastIndexOf("/") + 1)).toBe(
      FRAME.slice(0, FRAME.lastIndexOf("/") + 1),
    );
    expect(out).not.toBe(FRAME);
  });

  test("swapHeader swaps seq and count", () => {
    expect(swapHeader(FRAME)).toBe("ur:bytes/5-3/aebygdmkwrhd");
    expect(swapHeader("ur:bytes/2-2/aeby")).toBe("ur:bytes/2-3/aeby");
    expect(swapHeader(SINGLE)).toBe(SINGLE);
    expect(swapHeader("UR:BYTES/3-5/AEBY")).toBe("UR:BYTES/5-3/AEBY");
  });

  test("foreignFrame uses a different type", () => {
    const out = foreignFrame(makeRng(4), "bytes");
    expect(out.startsWith("ur:")).toBe(true);
    expect(out.startsWith("ur:bytes/")).toBe(false);
  });

  test("mutateFrames is deterministic and only emits ur: strings", () => {
    const encoded = Array.from({ length: 40 }, (_, i) => `ur:bytes/${i + 1}-10/body${i}`);
    const a = mutateFrames(encoded, makeRng(8), "bytes");
    const b = mutateFrames(encoded, makeRng(8), "bytes");
    expect(a).toStrictEqual(b);
    expect(allUr(a)).toBe(true);
  });

  test("encodeAll produces the requested stream", () => {
    const spec = {
      options: { maxFragmentLength: 50, firstSequence: 0 },
      urType: "bytes",
      messageLength: 200,
    };
    const encoded = encodeAll(spec, new Uint8Array(200).fill(7));
    expect(encoded.length).toBeGreaterThan(3);
    expect(encoded.every((f) => f.startsWith("ur:bytes/"))).toBe(true);
  });
});

describe("outcomeOf", () => {
  test("maps each status", () => {
    expect(outcomeOf({ status: "accepted" })).toStrictEqual({ status: "accepted" });
    expect(outcomeOf({ status: "duplicate" })).toStrictEqual({ status: "duplicate" });
    expect(
      outcomeOf({ status: "rejected", error: new UrError({ code: "InvalidType" }) }),
    ).toStrictEqual({ status: "rejected", error: { code: "InvalidType" } });
    expect(
      outcomeOf({
        status: "fatal",
        error: new UrError({ code: "ResourceLimit", limit: "uriLength" }),
      }),
    ).toStrictEqual({
      status: "fatal",
      error: { code: "ResourceLimit", limit: "uriLength" },
    });
  });
});

describe("generateFile", () => {
  test("same seed produces identical output", () => {
    const cli = { seed: 123, cases: 4, out: "unused.json" };
    expect(generateFile(cli)).toStrictEqual(generateFile(cli));
  });

  test("shape follows the schema", () => {
    const file = generateFile({ seed: 123, cases: 4, out: "unused.json" });
    expect(file.schema).toBe(1);
    expect(file.seed).toBe(123);
    expect(file.cases).toHaveLength(4);
    expect(file.cases.every((c) => c.outcomes.length === c.frames.length)).toBe(true);
  });
});

describe("toHex", () => {
  test("encodes bytes", () => {
    expect(toHex(new Uint8Array([0, 15, 255]))).toBe("000fff");
  });
});
