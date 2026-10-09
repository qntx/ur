/** GF(2) fountain decoder benchmarks (decoder.mdx gates). Run with `bun run bench`. */
import { describe, expect, test } from "vite-plus/test";

import { FountainDecoder, FountainEncoder } from "../src/index.ts";

const MAX_MESSAGE = 1024 * 1024;
const TRIALS = 200;

function messageFor(targetK: number, fragLen: number): Uint8Array {
  const len = Math.min(targetK * fragLen, MAX_MESSAGE);
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    bytes[i] = i % 251;
  }
  return bytes;
}

function xorshift(seed: number): () => number {
  let s = seed % 4294967296;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

/** One decode run: parts consumed from `startSeq`, `loss` fraction dropped. Returns frames fed. */
function decodeRun(
  message: Uint8Array,
  maxFragmentLength: number,
  startSeq: number,
  loss: number,
): number {
  const encoder = new FountainEncoder(message, {
    maxFragmentLength,
    firstSequence: startSeq,
  });
  const decoder = new FountainDecoder();
  const rand = xorshift(0x9e_37_79_b9 + startSeq);
  let fed = 0;
  for (const part of encoder) {
    if (rand() >= loss) {
      const result = decoder.receive(part);
      if (result.status === "rejected" || result.status === "fatal") {
        throw result.error;
      }
      fed += 1;
    }
    if (decoder.state.phase === "complete") {
      return fed;
    }
  }
  throw new Error("encoder exhausted");
}

function percentile(sorted: number[], p: number): number {
  const i = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, i)] ?? 0;
}

describe("fountain decoder bench", () => {
  test("K=2000 fragLen=200, 20% loss: total decode ≤ 1.0 s", () => {
    const message = messageFor(2000, 200);
    const t0 = performance.now();
    const fed = decodeRun(message, 200, 0, 0.2);
    const ms = performance.now() - t0;
    console.log(`[decoder] k2000_frag200 loss20: ${ms.toFixed(1)}ms total, ${fed} frames fed`);
    expect(ms).toBeLessThanOrEqual(1000);
  }, 120_000);

  test("K=128 (1 MiB cap) fragLen=8192, 20% loss", () => {
    const message = messageFor(2000, 8192);
    const t0 = performance.now();
    const fed = decodeRun(message, 8192, 0, 0.2);
    const ms = performance.now() - t0;
    console.log(`[decoder] k128_frag8192 loss20: ${ms.toFixed(1)}ms total, ${fed} frames fed`);
    expect(Number.isFinite(ms)).toBe(true);
  }, 120_000);

  test("K=100 fragLen=200: per-frame P99 ≤ 1 ms", () => {
    const message = messageFor(100, 200);
    const times: number[] = [];
    // Reuse one decoder session per trial; measure each receive() call.
    for (let t = 0; t < TRIALS; t += 1) {
      const encoder = new FountainEncoder(message, { maxFragmentLength: 200 });
      const decoder = new FountainDecoder();
      for (const part of encoder) {
        const t0 = performance.now();
        decoder.receive(part);
        times.push(performance.now() - t0);
        if (decoder.state.phase === "complete") {
          break;
        }
      }
    }
    times.sort((a, b) => a - b);
    const p99 = percentile(times, 99);
    console.log(`[decoder] k100 per-frame: n=${times.length} p99=${p99.toFixed(3)}ms`);
    expect(p99).toBeLessThanOrEqual(1);
  }, 120_000);

  test("frames to complete vs research.mdx Gauss column", () => {
    // research.mdx Gauss column (loss 0): K=50 → 1.103K, K=100 → 1.073K, K=200 → 1.047K.
    const refs: Record<number, number> = { 50: 1.103, 100: 1.073, 200: 1.047 };
    const rng = xorshift(0xde_ad_be_ef);
    for (const k of [50, 100, 200]) {
      const message = messageFor(k, 100);
      const counts: number[] = [];
      for (let t = 0; t < TRIALS; t += 1) {
        const startSeq = Math.floor(rng() * (2 * k));
        counts.push(decodeRun(message, 100, startSeq, 0));
      }
      counts.sort((a, b) => a - b);
      const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
      const p95 = percentile(counts, 95);
      const ref = refs[k] ?? 1;
      const ratio = mean / k;
      console.log(
        `[decoder] K=${k}: mean=${mean.toFixed(1)} (${ratio.toFixed(3)}K, ref ${ref}K), p95=${p95} (${(p95 / k).toFixed(3)}K)`,
      );
      expect(ratio).toBeLessThanOrEqual(ref * 1.05);
    }
  }, 120_000);
});
