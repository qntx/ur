import { sha256 } from "@noble/hashes/sha2.js";

import { checksum } from "../crc32.ts";
import { Weighted } from "./sampler.ts";

const MASK64 = (1n << 64n) - 1n;

function rotl(x: bigint, k: number): bigint {
  const v = x & MASK64;
  return ((v << BigInt(k)) | (v >> BigInt(64 - k))) & MASK64;
}

function unitInterval(value: bigint): number {
  // value >> 11 * (1 / 2^53) — must stay in [0, 1)
  const SCALE = 1 / 2 ** 53;
  const shifted = Number(value >> 11n);
  return shifted * SCALE;
}

/** Xoshiro256** with SHA-256 seeding matching URKit / ur-rs / bcur. */
export class Xoshiro256 {
  private s0: bigint;
  private s1: bigint;
  private s2: bigint;
  private s3: bigint;

  private constructor(s0: bigint, s1: bigint, s2: bigint, s3: bigint) {
    this.s0 = s0;
    this.s1 = s1;
    this.s2 = s2;
    this.s3 = s3;
  }

  /** Seed from arbitrary bytes via SHA-256 + BE-limb→LE packing. */
  static fromBytes(bytes: Uint8Array): Xoshiro256 {
    return Xoshiro256.fromDigest(sha256(bytes));
  }

  static fromString(value: string): Xoshiro256 {
    return Xoshiro256.fromBytes(new TextEncoder().encode(value));
  }

  /** Seed from CRC-32 BE bytes of `bytes` (test helper path). */
  static fromCrc(bytes: Uint8Array): Xoshiro256 {
    const c = checksum(bytes);
    const seed = new Uint8Array(4);
    seed[0] = (c >>> 24) & 0xff;
    seed[1] = (c >>> 16) & 0xff;
    seed[2] = (c >>> 8) & 0xff;
    seed[3] = c & 0xff;
    return Xoshiro256.fromBytes(seed);
  }

  static fromDigest(seed32: Uint8Array): Xoshiro256 {
    // ur-rs packs each 8-byte BE limb, stores LE, then from_seed LE-loads —
    // net effect: each state word is the big-endian u64 of that hash limb.
    const view = new DataView(seed32.buffer, seed32.byteOffset, seed32.byteLength);
    return new Xoshiro256(
      view.getBigUint64(0),
      view.getBigUint64(8),
      view.getBigUint64(16),
      view.getBigUint64(24),
    );
  }

  nextU64(): bigint {
    const result = (rotl((this.s1 * 5n) & MASK64, 7) * 9n) & MASK64;
    const t = (this.s1 << 17n) & MASK64;
    this.s2 = (this.s2 ^ this.s0) & MASK64;
    this.s3 = (this.s3 ^ this.s1) & MASK64;
    this.s1 = (this.s1 ^ this.s2) & MASK64;
    this.s0 = (this.s0 ^ this.s3) & MASK64;
    this.s2 = (this.s2 ^ t) & MASK64;
    this.s3 = rotl(this.s3, 45);
    return result;
  }

  nextDouble(): number {
    return unitInterval(this.nextU64());
  }

  /**
   * Inclusive `[low, high]` via double scaling (normative float path). Truncation toward zero
   * matches Rust `as u64`.
   */
  nextInt(low: number, high: number): number {
    const span = high - low + 1;
    return Math.trunc(this.nextDouble() * span) + low;
  }

  /** Remove-order shuffle (not Fisher–Yates); stops after `count` picks. */
  shuffled<T>(items: T[], count: number = items.length): T[] {
    const pool = [...items];
    const out: T[] = [];
    while (pool.length > 0 && out.length < count) {
      const index = this.nextInt(0, pool.length - 1);
      const [item] = pool.splice(index, 1);
      if (item === undefined) {
        throw new Error("unreachable: splice returned empty");
      }
      out.push(item);
    }
    return out;
  }

  chooseDegree(length: number): number {
    const weights: number[] = [];
    for (let x = 1; x <= length; x++) {
      weights.push(1 / x);
    }
    const sampler = Weighted.new(weights);
    return sampler.next(this) + 1;
  }

  nextByte(): number {
    return this.nextInt(0, 255);
  }

  nextBytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      out[i] = this.nextByte();
    }
    return out;
  }
}

/** Deterministic test message: seed string → `size` bytes via Xoshiro. */
export function makeMessage(seed: string, size: number): Uint8Array {
  return Xoshiro256.fromString(seed).nextBytes(size);
}
