import { fail } from "../error.ts";
import { mergeLimits } from "./limits.ts";
import type { DecoderLimits } from "./limits.ts";
import type { Part } from "./part.ts";
import { validatePart } from "./part.ts";

const MAX_U32 = 0xff_ff_ff_ff;

/**
 * Encode a part as fixed-schema deterministic CBOR: `array(5) [sequence, sequenceCount,
 * messageLength, checksum, data]` with shortest-form integers.
 */
export function encodePart(part: Part): Uint8Array {
  validatePart(part);
  const out: number[] = [0x85];
  encodeU32(out, part.sequence);
  encodeU32(out, part.sequenceCount);
  encodeU32(out, part.messageLength);
  encodeU32(out, part.checksum);
  encodeBstr(out, part.data);
  return new Uint8Array(out);
}

/**
 * Decode a part from CBOR. Lenient on integer width (UR-ADR-017): any well-formed definite-length
 * encoding is accepted; re-encode with {@link encodePart} for the shortest form. `limits` apply
 * `maxFragmentLength` to the bstr and `maxFragmentCount` to `sequenceCount`.
 */
export function decodePart(bytes: Uint8Array, limits?: Partial<DecoderLimits>): Part {
  return decodePartInner(bytes, mergeLimits(limits));
}

/**
 * Part decode without `maxFragmentLength`/`maxFragmentCount` checks, for callers whose input is
 * already bounded (the `UrDecoder` URI-length budget). Semantic validation still applies.
 */
export function decodePartRaw(bytes: Uint8Array): Part {
  return decodePartInner(bytes, undefined);
}

function decodePartInner(bytes: Uint8Array, limits: DecoderLimits | undefined): Part {
  const cur = { i: 0 };
  if (decodeLen(bytes, cur, 4) !== 5) {
    fail("InvalidPartCbor");
  }
  const sequence = decodeU32(bytes, cur);
  const sequenceCount = decodeU32(bytes, cur);
  const messageLength = decodeU32(bytes, cur);
  const checksum = decodeU32(bytes, cur);
  const data = decodeBstr(bytes, cur, limits?.maxFragmentLength);
  if (cur.i !== bytes.length) {
    fail("InvalidPartCbor");
  }
  const part: Part = { sequence, sequenceCount, messageLength, checksum, data };
  validatePart(part);
  if (limits !== undefined && sequenceCount > limits.maxFragmentCount) {
    fail({ code: "ResourceLimit", limit: "fragmentCount" });
  }
  return part;
}

function encodeU32(out: number[], v: number): void {
  if (v <= 23) {
    out.push(v);
  } else if (v <= 0xff) {
    out.push(0x18, v);
  } else if (v <= 0xffff) {
    out.push(0x19, (v >>> 8) & 0xff, v & 0xff);
  } else {
    out.push(0x1a, (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
}

function encodeBstr(out: number[], data: Uint8Array): void {
  const len = data.length;
  if (len <= 23) {
    out.push(0x40 | len);
  } else if (len <= 0xff) {
    out.push(0x58, len);
  } else if (len <= 0xffff) {
    out.push(0x59, (len >>> 8) & 0xff, len & 0xff);
  } else {
    out.push(0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
  }
  for (const b of data) {
    out.push(b);
  }
}

/**
 * Reads a definite-length argument for the given major type in any width (including 8-byte u64).
 * Values above 2^53 lose low bits — callers only order or bound-check such values; equality is only
 * demanded of values <= u32::MAX.
 */
function decodeLen(bytes: Uint8Array, cur: { i: number }, major: number): number {
  const head = read(bytes, cur);
  if (head >> 5 !== major) {
    fail("InvalidPartCbor");
  }
  const ai = head & 0x1f;
  if (ai <= 23) {
    return ai;
  }
  if (ai === 24) {
    return read(bytes, cur);
  }
  if (ai === 25) {
    return (read(bytes, cur) << 8) | read(bytes, cur);
  }
  if (ai === 26) {
    return (
      ((read(bytes, cur) << 24) |
        (read(bytes, cur) << 16) |
        (read(bytes, cur) << 8) |
        read(bytes, cur)) >>>
      0
    );
  }
  if (ai === 27) {
    const hi =
      ((read(bytes, cur) << 24) |
        (read(bytes, cur) << 16) |
        (read(bytes, cur) << 8) |
        read(bytes, cur)) >>>
      0;
    const lo =
      ((read(bytes, cur) << 24) |
        (read(bytes, cur) << 16) |
        (read(bytes, cur) << 8) |
        read(bytes, cur)) >>>
      0;
    return hi * 0x1_00_00_00_00 + lo;
  }
  // ai 28-30 reserved, ai 31 indefinite length.
  return fail("InvalidPartCbor");
}

function decodeU32(bytes: Uint8Array, cur: { i: number }): number {
  const v = decodeLen(bytes, cur, 0);
  if (v > MAX_U32) {
    fail("InvalidPartCbor");
  }
  return v;
}

function decodeBstr(
  bytes: Uint8Array,
  cur: { i: number },
  maxDataLen: number | undefined,
): Uint8Array {
  const len = decodeLen(bytes, cur, 2);
  if (maxDataLen !== undefined && len > maxDataLen) {
    fail({ code: "ResourceLimit", limit: "fragmentLength" });
  }
  if (cur.i + len > bytes.length) {
    fail("InvalidPartCbor");
  }
  const data = bytes.slice(cur.i, cur.i + len);
  cur.i += len;
  return data;
}

function read(bytes: Uint8Array, cur: { i: number }): number {
  const b = bytes[cur.i];
  if (b === undefined) {
    fail("InvalidPartCbor");
  }
  cur.i += 1;
  return b;
}
