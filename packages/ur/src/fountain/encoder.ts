import { checksum } from "../crc32.ts";
import { fail } from "../error.ts";
import { chooseFragments, fragmentLength, partition } from "./choose.ts";
import { Part } from "./part.ts";

function xorInto(target: Uint8Array, src: Uint8Array): void {
  if (target.length !== src.length) {
    fail("DecoderState");
  }
  for (const [i, a] of target.entries()) {
    const b = src[i];
    if (b === undefined) {
      fail("DecoderState");
    }
    target[i] = a ^ b;
  }
}

/** Next 1-based fountain seqNum. Does not wrap. */
export function nextSequence(current: number): number {
  if (current === 0xff_ff_ff_ff) {
    fail("ResourceLimit", { limit: "sequence" });
  }
  return current + 1;
}

/** Fountain encoder. */
export class FountainEncoder {
  private readonly parts: Uint8Array[];
  private readonly sequenceCount: number;
  private readonly messageLength: number;
  private readonly messageChecksum: number;
  private currentSequence = 0;

  private constructor(
    parts: Uint8Array[],
    sequenceCount: number,
    messageLength: number,
    messageChecksum: number,
  ) {
    this.parts = parts;
    this.sequenceCount = sequenceCount;
    this.messageLength = messageLength;
    this.messageChecksum = messageChecksum;
  }

  static create(message: Uint8Array, maxFragmentLength: number): FountainEncoder {
    if (message.length === 0) {
      fail("EmptyMessage");
    }
    if (maxFragmentLength === 0) {
      fail("InvalidFragmentLen");
    }
    if (message.length > 0xff_ff_ff_ff) {
      fail("ResourceLimit", { limit: "message_length" });
    }
    const fragLen = fragmentLength(message.length, maxFragmentLength);
    const fragments = partition(message, fragLen);
    if (fragments.length > 0xff_ff_ff_ff) {
      fail("ResourceLimit", { limit: "fragment_count" });
    }
    return new FountainEncoder(fragments, fragments.length, message.length, checksum(message));
  }

  get currentSequenceNum(): number {
    return this.currentSequence;
  }

  get fragmentCount(): number {
    return this.sequenceCount;
  }

  get complete(): boolean {
    return this.currentSequence >= this.sequenceCount;
  }

  nextPart(): Part {
    if (this.sequenceCount === 1 && this.currentSequence >= 1) {
      fail("SinglePartExhausted");
    }
    this.currentSequence = nextSequence(this.currentSequence);
    const indexes = chooseFragments(this.currentSequence, this.parts.length, this.messageChecksum);
    const [first] = this.parts;
    if (first === undefined) {
      fail("DecoderState");
    }
    const mixed = new Uint8Array(first.length);
    for (const idx of indexes) {
      const fragment = this.parts[idx];
      if (fragment === undefined) {
        fail("DecoderState");
      }
      xorInto(mixed, fragment);
    }
    return Part.fromFields(
      this.currentSequence,
      this.sequenceCount,
      this.messageLength,
      this.messageChecksum,
      mixed,
    );
  }
}
