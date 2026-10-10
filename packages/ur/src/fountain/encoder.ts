import { FragmentChooser } from "../consensus/chooser.ts";
import { checksum } from "../consensus/crc32.ts";
import { fail } from "../error.ts";
import type { Part } from "./part.ts";

/** XOR `src` into `target`; buffers are equal-length by construction. */
function xorInto(target: Uint8Array, src: Uint8Array): void {
  for (const [i, a] of target.entries()) {
    target[i] = a ^ (src[i] ?? 0);
  }
}

function divCeil(a: number, b: number): number {
  return Math.trunc((a + b - 1) / b);
}

const MAX_U32 = 0xff_ff_ff_ff;
const DEFAULT_MIN_FRAGMENT_LENGTH = 10;

/**
 * URKit `findNominalFragmentLength` in closed form: the smallest fragment count that fits `max` is
 * `ceil(len / max)`, bounded above by `floor(len / min)` (and at least 1). When `min` binds,
 * fragments may exceed `maxFragmentLength` — that is the reference behavior.
 */
export function fragmentLength(
  dataLength: number,
  maxFragmentLength: number,
  minFragmentLength: number = DEFAULT_MIN_FRAGMENT_LENGTH,
): number {
  const count = Math.min(
    divCeil(dataLength, maxFragmentLength),
    Math.max(1, Math.floor(dataLength / minFragmentLength)),
  );
  return divCeil(dataLength, count);
}

/** Pad and split a message into `fragmentLength`-sized fragments. */
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

export type FountainEncoderOptions = Readonly<{
  /** Required; fragments are at most this long unless `minFragmentLength` binds. */
  maxFragmentLength: number;
  /** Lower bound on fragment length (default 10). */
  minFragmentLength?: number;
  /** Sequence number before the first emitted part (default 0). */
  firstSequence?: number;
}>;

/**
 * Fountain encoder. An infinite iterator: produces parts with sequence `firstSequence + 1`, `+2`, …
 * and ends after `0xFFFFFFFF` (UR-ADR-028). For `K == 1` it keeps producing identical parts with
 * rising sequences.
 */
export class FountainEncoder implements IterableIterator<Part> {
  readonly #parts: Uint8Array[];
  readonly #chooser: FragmentChooser;
  readonly #fragLen: number;
  readonly #msgLen: number;
  readonly #seqCount: number;
  readonly #messageChecksum: number;
  #seq: number;
  #lastIndexes: ReadonlyArray<number> = [];

  constructor(message: Uint8Array, options: FountainEncoderOptions) {
    const {
      maxFragmentLength,
      minFragmentLength = DEFAULT_MIN_FRAGMENT_LENGTH,
      firstSequence = 0,
    } = options;
    if (message.length === 0) {
      fail("EmptyMessage");
    }
    if (message.length > MAX_U32) {
      fail("MessageTooLong");
    }
    if (
      !Number.isSafeInteger(maxFragmentLength) ||
      maxFragmentLength < 1 ||
      !Number.isSafeInteger(minFragmentLength) ||
      minFragmentLength < 1 ||
      minFragmentLength > maxFragmentLength
    ) {
      fail("InvalidFragmentLength");
    }
    if (!Number.isSafeInteger(firstSequence) || firstSequence < 0 || firstSequence > MAX_U32) {
      throw new RangeError("firstSequence must be an integer in 0..=0xFFFFFFFF");
    }
    const fragLen = fragmentLength(message.length, maxFragmentLength, minFragmentLength);
    const fragments = partition(message, fragLen);
    const messageChecksum = checksum(message);
    this.#parts = fragments;
    this.#chooser = new FragmentChooser(fragments.length, messageChecksum);
    this.#fragLen = fragLen;
    this.#msgLen = message.length;
    this.#seqCount = fragments.length;
    this.#messageChecksum = messageChecksum;
    this.#seq = firstSequence;
  }

  get fragmentCount(): number {
    return this.#seqCount;
  }

  get fragmentLength(): number {
    return this.#fragLen;
  }

  get messageLength(): number {
    return this.#msgLen;
  }

  /** Last emitted sequence number, or `firstSequence` before any part. */
  get sequence(): number {
    return this.#seq;
  }

  get isComplete(): boolean {
    return this.#seq >= this.#seqCount;
  }

  /** Fragment indexes mixed into the most recently produced part. */
  get lastFragmentIndexes(): ReadonlyArray<number> {
    return this.#lastIndexes;
  }

  next(): IteratorResult<Part, undefined> {
    if (this.#seq === MAX_U32) {
      return { value: undefined, done: true };
    }
    this.#seq += 1;
    const indexes = this.#chooser.choose(this.#seq);
    const mixed = new Uint8Array(this.#fragLen);
    for (const i of indexes) {
      const fragment = this.#parts[i];
      if (fragment !== undefined) {
        xorInto(mixed, fragment);
      }
    }
    const part: Part = {
      sequence: this.#seq,
      sequenceCount: this.#seqCount,
      messageLength: this.#msgLen,
      checksum: this.#messageChecksum,
      data: mixed,
    };
    this.#lastIndexes = indexes;
    return { value: part, done: false };
  }

  [Symbol.iterator](): this {
    return this;
  }
}
