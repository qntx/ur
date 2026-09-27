import { Xoshiro256 } from "../rng/xoshiro.ts";

function divCeil(a: number, b: number): number {
  return Math.trunc((a + b - 1) / b);
}

/** Optimal equal fragment length under a max cap. */
export function fragmentLength(dataLength: number, maxFragmentLength: number): number {
  const fragmentCount = divCeil(dataLength, maxFragmentLength);
  return divCeil(dataLength, fragmentCount);
}

/** Pad and split message into equal fragments. */
export function partition(data: Uint8Array, fragLen: number): Uint8Array[] {
  const pad = (fragLen - (data.length % fragLen)) % fragLen;
  const padded = new Uint8Array(data.length + pad);
  padded.set(data);
  const out: Uint8Array[] = [];
  for (let i = 0; i < padded.length; i += fragLen) {
    out.push(padded.subarray(i, i + fragLen));
  }
  return out;
}

/**
 * Fragment indexes mixed into sequence `sequence` (1-based). Normative: simple if sequence <= K;
 * else degree + remove-shuffle.
 */
export function chooseFragments(
  sequence: number,
  fragmentCount: number,
  checksum: number,
): number[] {
  if (sequence <= fragmentCount) {
    return [sequence - 1];
  }
  const seed = new Uint8Array(8);
  seed[0] = (sequence >>> 24) & 0xff;
  seed[1] = (sequence >>> 16) & 0xff;
  seed[2] = (sequence >>> 8) & 0xff;
  seed[3] = sequence & 0xff;
  seed[4] = (checksum >>> 24) & 0xff;
  seed[5] = (checksum >>> 16) & 0xff;
  seed[6] = (checksum >>> 8) & 0xff;
  seed[7] = checksum & 0xff;
  const xoshiro = Xoshiro256.fromBytes(seed);
  const degree = xoshiro.chooseDegree(fragmentCount);
  const indexes = Array.from({ length: fragmentCount }, (_, i) => i);
  return xoshiro.shuffled(indexes).slice(0, degree);
}
