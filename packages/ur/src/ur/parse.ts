import { decodeBytewords } from "../bytewords/index.ts";
import { fail } from "../error.ts";
import { decodePart, mergeLimits } from "../fountain/index.ts";
import type { DecoderLimits, Part } from "../fountain/index.ts";
import { parseUrType } from "./type.ts";
import type { UrType } from "./type.ts";

/** A decoded UR: a single-part message or one validated fountain part. */
export type ParsedUr =
  | Readonly<{ kind: "single"; type: UrType; message: Uint8Array }>
  | Readonly<{ kind: "multi"; type: UrType; part: Part }>;

/**
 * Parse and decode a UR string. Case-insensitive for the URI and bytewords content. `limits` bounds
 * the URI length and the multi-part CBOR fields. Throws `UrError`.
 */
export function parseUr(text: string, limits?: Partial<DecoderLimits>): ParsedUr {
  const merged = mergeLimits(limits);
  if (text.length > merged.maxUriLength) {
    fail({ code: "ResourceLimit", limit: "uriLength" });
  }
  const uri = text.toLowerCase();
  if (!uri.startsWith("ur:")) {
    fail("InvalidScheme");
  }
  const rest0 = uri.slice(3);
  const slash = rest0.indexOf("/");
  if (slash === -1) {
    fail("TypeUnspecified");
  }
  const type = parseUrType(rest0.slice(0, slash));
  const rest = rest0.slice(slash + 1);

  const lastSlash = rest.lastIndexOf("/");
  if (lastSlash === -1) {
    return { kind: "single", type, message: decodeBytewords(rest, "minimal") };
  }
  const { seq, count } = decodeIndices(rest.slice(0, lastSlash));
  const part = decodePart(decodeBytewords(rest.slice(lastSlash + 1), "minimal"), merged);
  if (part.sequence !== seq || part.sequenceCount !== count) {
    fail("InvalidIndices");
  }
  return { kind: "multi", type, part };
}

/** UR-ADR-029: `seq = 1*DIGIT "-" 1*DIGIT`, both in `1..=0xFFFFFFFF`. */
function decodeIndices(indices: string): { seq: number; count: number } {
  const dash = indices.indexOf("-");
  if (dash === -1) {
    fail("InvalidIndices");
  }
  const a = indices.slice(0, dash);
  const b = indices.slice(dash + 1);
  if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) {
    fail("InvalidIndices");
  }
  const seq = Number(a);
  const count = Number(b);
  if (
    !Number.isSafeInteger(seq) ||
    !Number.isSafeInteger(count) ||
    seq === 0 ||
    count === 0 ||
    seq > 0xff_ff_ff_ff ||
    count > 0xff_ff_ff_ff
  ) {
    fail("InvalidIndices");
  }
  return { seq, count };
}
