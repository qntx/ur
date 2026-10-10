import { asciiLower, isAscii } from "../ascii.ts";
import { decodeBytewords } from "../bytewords/index.ts";
import { fail } from "../error.ts";
import { decodePart, mergeLimits } from "../fountain/index.ts";
import type { DecoderLimits, Part } from "../fountain/index.ts";
import { decodePartRaw } from "../fountain/part-cbor.ts";
import { parseUrType } from "./type.ts";
import type { UrType } from "./type.ts";

/** A decoded UR: a single-part message or one validated fountain part. */
export type ParsedUr =
  | Readonly<{ kind: "single"; type: UrType; message: Uint8Array }>
  | Readonly<{ kind: "multi"; type: UrType; part: Part }>;

/** The `type` token and the text after `ur:<type>/`, without folding the whole input. */
export type UrHead = Readonly<{ type: UrType; rest: string }>;

/**
 * Scheme and type: an ASCII case-insensitive `ur:` prefix (`InvalidScheme`), then the token up to
 * the first `/` (`TypeUnspecified` if none, `InvalidType` if illegal). Only the type token is
 * lowercased — the body keeps its original case (bytewords decode is itself case-insensitive).
 */
export function parseUrHead(text: string): UrHead {
  if (text.length < 3 || asciiLower(text.slice(0, 3)) !== "ur:") {
    fail("InvalidScheme");
  }
  const rest0 = text.slice(3);
  const slash = rest0.indexOf("/");
  if (slash === -1) {
    fail("TypeUnspecified");
  }
  return { type: parseUrType(rest0.slice(0, slash)), rest: rest0.slice(slash + 1) };
}

/**
 * Text admission after type admission: the whole URI must be ASCII (`NonAscii`, so `.length` is the
 * byte count), then the URI-length budget (`ResourceLimit: uriLength`).
 */
export function checkUriText(text: string, limits: DecoderLimits): void {
  if (!isAscii(text)) {
    fail("NonAscii");
  }
  if (text.length > limits.maxUriLength) {
    fail({ code: "ResourceLimit", limit: "uriLength" });
  }
}

/** Indices grammar, bytewords, and part CBOR for the text after `ur:<type>/`. */
export function parseUrBody(
  type: UrType,
  rest: string,
  decode: (bytes: Uint8Array) => Part,
): ParsedUr {
  const lastSlash = rest.lastIndexOf("/");
  if (lastSlash === -1) {
    return { kind: "single", type, message: decodeBytewords(rest, "minimal") };
  }
  const { seq, count } = decodeIndices(rest.slice(0, lastSlash));
  const part = decode(decodeBytewords(rest.slice(lastSlash + 1), "minimal"));
  if (part.sequence !== seq || part.sequenceCount !== count) {
    fail("InvalidIndices");
  }
  return { kind: "multi", type, part };
}

/**
 * Parse and decode a UR string. Case-insensitive for the URI and bytewords content. `limits` bounds
 * the URI length and the multi-part CBOR fields. Throws `UrError`.
 */
export function parseUr(text: string, limits?: Partial<DecoderLimits>): ParsedUr {
  const merged = mergeLimits(limits);
  const { type, rest } = parseUrHead(text);
  checkUriText(text, merged);
  return parseUrBody(type, rest, (bytes) => decodePart(bytes, merged));
}

/**
 * Decoder frame parse after type admission: same text budget, but the part decodes without
 * count/length caps — `maxUriLength` already bounds the frame.
 */
export function parseUrFrame(head: UrHead, text: string, limits: DecoderLimits): ParsedUr {
  checkUriText(text, limits);
  return parseUrBody(head.type, head.rest, decodePartRaw);
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
