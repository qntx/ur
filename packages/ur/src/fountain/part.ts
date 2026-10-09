import { fail } from "../error.ts";

/**
 * A fountain part: wire metadata plus the (possibly mixed) fragment data. Produced by
 * `FountainEncoder` or `decodePart`; consumed by `FountainDecoder`.
 */
export type Part = Readonly<{
  /** 1-based sequence number. */
  sequence: number;
  /** Total source fragment count `K`. */
  sequenceCount: number;
  /** Original message length in bytes. */
  messageLength: number;
  /** CRC-32 of the original message. */
  checksum: number;
  /** Part payload bytes (a fragment, or an XOR mix for complex parts). */
  data: Uint8Array;
}>;

const MAX_U32 = 0xff_ff_ff_ff;

function isU32(v: number): boolean {
  return Number.isSafeInteger(v) && v >= 0 && v <= MAX_U32;
}

/**
 * Semantic part validation shared by `decodePart`, the encoder, and the decoder ingest path:
 * `sequence`, `sequenceCount`, and `messageLength` are nonzero u32; `checksum` is a u32; `data` is
 * nonempty; and `data.length` is a consistent fragment length, i.e. `K · fragLen ≥ messageLength`
 * with padding under one fragment.
 */
export function validatePart(part: Part): void {
  const fragLen = part.data.length;
  if (
    !isU32(part.sequence) ||
    part.sequence === 0 ||
    !isU32(part.sequenceCount) ||
    part.sequenceCount === 0 ||
    !isU32(part.messageLength) ||
    part.messageLength === 0 ||
    !isU32(part.checksum) ||
    fragLen === 0
  ) {
    fail("InvalidPart");
  }
  const product = BigInt(part.sequenceCount) * BigInt(fragLen);
  const length = BigInt(part.messageLength);
  if (product < length || product - length >= BigInt(fragLen)) {
    fail("InvalidPart");
  }
}
