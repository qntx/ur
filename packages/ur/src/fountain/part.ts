import { chooseFragments } from "./choose.ts";
import { DEFAULT_LIMITS } from "./limits.ts";
import { decodePart, encodePart } from "./part-cbor.ts";

/** A fountain part (wire metadata + fragment data). */
export class Part {
  readonly sequence: number;
  readonly sequenceCount: number;
  readonly messageLength: number;
  readonly checksum: number;
  readonly data: Uint8Array;

  private constructor(
    sequence: number,
    sequenceCount: number,
    messageLength: number,
    checksum: number,
    data: Uint8Array,
  ) {
    this.sequence = sequence;
    this.sequenceCount = sequenceCount;
    this.messageLength = messageLength;
    this.checksum = checksum;
    this.data = data;
  }

  static fromFields(
    sequence: number,
    sequenceCount: number,
    messageLength: number,
    checksum: number,
    data: Uint8Array,
  ): Part {
    return new Part(sequence, sequenceCount, messageLength, checksum, data);
  }

  indexes(): number[] {
    return chooseFragments(this.sequence, this.sequenceCount, this.checksum);
  }

  isSimple(): boolean {
    return this.indexes().length === 1;
  }

  toCbor(): Uint8Array {
    return encodePart(this);
  }

  static fromCbor(
    bytes: Uint8Array,
    maxDataLen: number = DEFAULT_LIMITS.maxFragmentDataLength,
    maxFragmentCount: number = DEFAULT_LIMITS.maxFragmentCount,
  ): Part {
    const f = decodePart(bytes, maxDataLen, maxFragmentCount);
    return Part.fromFields(f.sequence, f.sequenceCount, f.messageLength, f.checksum, f.data);
  }

  sequenceId(): string {
    return `${this.sequence}-${this.sequenceCount}`;
  }
}
