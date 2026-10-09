import { expect, test } from "vite-plus/test";

import { Xoshiro256, FragmentChooser } from "../src/consensus/index.ts";
import { FountainDecoder, FountainEncoder } from "../src/fountain/index.ts";
import type { Part } from "../src/fountain/index.ts";
import { makeMessage } from "./message.ts";

/**
 * Independent naive GF(2) rank tracker: BigInt masks, an insertion-order row list, and byte-wise
 * data XOR — deliberately different data structures from `FountainDecoder` (Uint32Array masks keyed
 * by pivot).
 */
class NaiveDecoder {
  k = 0;
  rows: Array<{ pivot: number; mask: bigint }> = [];
  terminal = false;

  lock(part: Part): void {
    this.k = part.sequenceCount;
  }

  ingest(indexes: ReadonlyArray<number>): "accepted" | "duplicate" {
    if (this.terminal) {
      return "duplicate";
    }
    let mask = 0n;
    for (const i of indexes) {
      mask |= 1n << BigInt(i);
    }
    for (const row of this.rows) {
      if (((mask >> BigInt(row.pivot)) & 1n) !== 0n) {
        mask ^= row.mask;
      }
    }
    if (mask === 0n) {
      return "duplicate";
    }
    let pivot = 0;
    while (((mask >> BigInt(pivot)) & 1n) === 0n) {
      pivot += 1;
    }
    for (const row of this.rows) {
      if (((row.mask >> BigInt(pivot)) & 1n) !== 0n) {
        row.mask ^= mask;
      }
    }
    this.rows.push({ pivot, mask });
    if (this.rows.length === this.k) {
      this.terminal = true;
    }
    return "accepted";
  }
}

function indexesOf(part: Part): ReadonlyArray<number> {
  return new FragmentChooser(part.sequenceCount, part.checksum).choose(part.sequence);
}

function nextInt(rng: Xoshiro256, low: number, high: number): number {
  return low + (rng.nextInt(0, 0xffff) % (high - low + 1));
}

function runTrial(rng: Xoshiro256, t: number): void {
  const length = nextInt(rng, 1, 400);
  const maxFragmentLength = nextInt(rng, 5, 100);
  const message = makeMessage(`prop-${t}`, length);
  const encoder = new FountainEncoder(message, {
    maxFragmentLength,
    minFragmentLength: 5,
  });
  const k = encoder.fragmentCount;

  // Collect parts, then deliver with reordering, ~20% loss and ~10% duplicates.
  const pool: Part[] = [];
  for (let i = 0; i < k * 3; i += 1) {
    const { value } = encoder.next();
    if (value === undefined) {
      break;
    }
    pool.push(value);
  }
  const order: number[] = [];
  for (const [i] of pool.entries()) {
    if (rng.nextInt(0, 9) >= 2) {
      order.push(i);
    }
    if (rng.nextInt(0, 9) === 0) {
      order.push(i);
    }
  }
  // Fisher-Yates shuffle (forward form used elsewhere in the codebase).
  for (let i = order.length - 1; i > 0; i -= 1) {
    const j = rng.nextInt(0, i);
    const a = order[i] ?? 0;
    order[i] = order[j] ?? 0;
    order[j] = a;
  }

  const decoder = new FountainDecoder();
  const naive = new NaiveDecoder();
  let naiveLocked = false;
  let naiveCompleteAt: number | undefined;
  let implCompleteAt: number | undefined;
  for (const [i, idx] of order.entries()) {
    const part = pool[idx];
    if (part === undefined) {
      continue;
    }
    const result = decoder.receive(part);
    expect(result.status === "accepted" || result.status === "duplicate").toBe(true);
    if (!naiveLocked) {
      naive.lock(part);
      naiveLocked = true;
    }
    const want = naive.ingest(indexesOf(part));
    expect(result.status).toBe(want);
    expect(decoder.progress.rank).toBeLessThanOrEqual(k);
    expect(decoder.progress.recovered).toBeLessThanOrEqual(decoder.progress.rank);
    expect(decoder.progress.rank).toBe(naive.rows.length);
    if (naive.terminal) {
      naiveCompleteAt ??= i;
    }
    if (decoder.state.phase === "complete") {
      implCompleteAt ??= i;
    }
  }
  expect(implCompleteAt).toBe(naiveCompleteAt);
  const { state } = decoder;
  const decoded = state.phase === "complete" ? state.value : undefined;
  expect(decoded).toStrictEqual(implCompleteAt === undefined ? undefined : message);
}

test("fountain decoder matches the naive rank tracker under loss, reorder, duplicates", () => {
  expect.hasAssertions();
  const rng = Xoshiro256.fromString("fountain-property");
  for (let t = 0; t < 200; t += 1) {
    runTrial(rng, t);
  }
});
