import { Xoshiro256 } from "../src/consensus/index.ts";

/** Deterministic test message: seed string → `size` bytes via Xoshiro. */
export function makeMessage(seed: string, size: number): Uint8Array {
  return Xoshiro256.fromString(seed).nextBytes(size);
}
