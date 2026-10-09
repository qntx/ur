/**
 * Generates `vectors/consensus/next-double.json`: raw u64 → `Double(v) / 2^64` conversion edge
 * cases (round-to-nearest-even, including the v >= 2^64 - 2^10 inputs whose result rounds to
 * exactly 1.0 and must be clamped by `nextInt`).
 *
 * Every expected `f64` bit pattern is cross-checked against Python's exact `float(v) / 2**64`
 * conversion — the script exits non-zero on any mismatch and never writes a stale file.
 *
 * Usage: bun scripts/vectors/generate-next-double.ts
 */
/// <reference types="node" />
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { scaledInt, unitInterval } from "../../packages/ur/src/consensus/xoshiro.ts";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  spawnSync: (opts: { cmd: string[]; stdin: Buffer }) => {
    exitCode: number;
    stdout: Buffer;
    stderr: Buffer;
  };
};

/**
 * The dropped "low 11 bits" only exist for inputs >= 2^63 (the f64 significand keeps the top 53 of
 * 64 bits); the round/tie cases below live in that region.
 */
const RAWS: Array<[string, bigint]> = [
  ["0", 0x0n],
  ["1", 0x1n],
  ["2^11 - 1", 0x7ffn],
  ["2^11", 0x800n],
  ["2^63 + 2^10 - 1 (low 11 bits round down)", 0x80000000000003ffn],
  ["2^63 + 2^10 + 1 (low 11 bits round up)", 0x8000000000000401n],
  ["2^63 + 2^10 (tie, kept bit even -> down)", 0x8000000000000400n],
  ["2^63 + 3 * 2^10 (tie, kept bit odd -> up)", 0x8000000000000c00n],
  ["2^53", 0x20000000000000n],
  ["2^53 + 1 (unrepresentable, ties to even)", 0x20000000000001n],
  ["2^63", 0x8000000000000000n],
  ["2^64 - 2^11", 0xfffffffffffff800n],
  ["2^64 - 2^10 (rounds to 1.0, nextInt clamps)", 0xfffffffffffffc00n],
  ["2^64 - 1", 0xffffffffffffffffn],
];

const NEXT_INT_RANGE: [number, number] = [1, 10];
const [NEXT_INT_LOW, NEXT_INT_HIGH] = NEXT_INT_RANGE;

type Case = {
  name: string;
  rawHex: string;
  nextDoubleBitsHex: string;
  nextIntRange: [number, number];
  nextInt: number;
};

const cases: Case[] = RAWS.map(([name, raw]) => {
  const d = unitInterval(raw);
  const [bits] = new BigUint64Array(new Float64Array([d]).buffer);
  return {
    name,
    rawHex: raw.toString(16).padStart(16, "0"),
    nextDoubleBitsHex: (bits ?? 0n).toString(16).padStart(16, "0"),
    nextIntRange: NEXT_INT_RANGE,
    nextInt: scaledInt(d, NEXT_INT_LOW, NEXT_INT_HIGH),
  };
});

// Independent cross-check: Python's exact bigint -> float conversion.
const py = Bun.spawnSync({
  cmd: [
    "python3",
    "-c",
    `import json, struct, sys, math
raws = json.load(sys.stdin)
out = []
for h in raws:
    v = int(h, 16)
    d = float(v) / 2**64
    bits = struct.unpack(">Q", struct.pack(">d", d))[0]
    out.append({"bits": format(bits, "016x"), "unclamped": math.floor(d * 10) + 1})
print(json.dumps(out))`,
  ],
  stdin: Buffer.from(JSON.stringify(cases.map((c) => c.rawHex))),
});
if (py.exitCode !== 0) {
  throw new Error(`python3 cross-check failed: ${py.stderr.toString()}`);
}

const pyResults: unknown = JSON.parse(py.stdout.toString());
if (!Array.isArray(pyResults) || pyResults.length !== cases.length) {
  throw new Error("python3 cross-check returned a wrong case count");
}
for (const [i, c] of cases.entries()) {
  const p: unknown = pyResults[i];
  if (typeof p !== "object" || p === null || !("bits" in p) || !("unclamped" in p)) {
    throw new Error(`malformed python result for case ${i}`);
  }
  const { bits: pyBits, unclamped: pyUnclamped } = p;
  if (typeof pyBits !== "string" || typeof pyUnclamped !== "number") {
    throw new TypeError(`malformed python result for case ${i}`);
  }
  if (pyBits !== c.nextDoubleBitsHex) {
    throw new Error(`python float() disagrees on ${c.name}: ${pyBits} != ${c.nextDoubleBitsHex}`);
  }
  // `pyUnclamped` is the unclamped reference result; the clamp fires exactly
  // when it would exceed `high`.
  const expectedNextInt = Math.min(pyUnclamped, c.nextIntRange[1]);
  if (expectedNextInt !== c.nextInt) {
    throw new Error(`python nextInt disagrees on ${c.name}: ${expectedNextInt} != ${c.nextInt}`);
  }
}

const doc = {
  schema: 1,
  capability: "consensus.xoshiro",
  source: {
    kind: "generated",
    name: "scripts/vectors/generate-next-double.ts",
    crossCheck: "python float()",
  },
  cases,
};

const out = join(import.meta.dirname, "../../vectors/consensus/next-double.json");
mkdirSync(join(out, ".."), { recursive: true });
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${cases.length} cases -> ${out} (python cross-check passed)`);
