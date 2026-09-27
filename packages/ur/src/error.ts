/** Discriminated error codes for the UR transport stack. */
export type UrErrorCode =
  | "InvalidWord"
  | "InvalidBytewordsChecksum"
  | "InvalidBytewordsLength"
  | "NonAscii"
  | "EmptyMessage"
  | "EmptyPart"
  | "InvalidFragmentLen"
  | "InvalidSequence"
  | "InconsistentPart"
  | "InvalidPadding"
  | "InvalidMessageChecksum"
  | "InvalidPartCbor"
  | "DecoderState"
  | "SinglePartExhausted"
  | "ResourceLimit"
  | "InvalidScheme"
  | "TypeUnspecified"
  | "InvalidType"
  | "InvalidIndices"
  | "NotSinglePart"
  | "UnexpectedType"
  | "CborDecode"
  | "CborType";

const MESSAGES: Record<UrErrorCode, string> = {
  InvalidWord: "invalid bytewords word",
  InvalidBytewordsChecksum: "invalid bytewords checksum",
  InvalidBytewordsLength: "invalid bytewords length",
  NonAscii: "bytewords string is not ASCII",
  EmptyMessage: "empty message",
  EmptyPart: "empty fountain part",
  InvalidFragmentLen: "invalid maximum fragment length",
  InvalidSequence: "invalid sequence number",
  InconsistentPart: "fountain part inconsistent with previous parts",
  InvalidPadding: "invalid fountain part padding",
  InvalidMessageChecksum: "invalid fountain message checksum",
  InvalidPartCbor: "invalid fountain part CBOR",
  DecoderState: "fountain decoder internal state error",
  SinglePartExhausted: "single-part fountain encoder exhausted",
  ResourceLimit: "resource limit exceeded",
  InvalidScheme: "invalid UR scheme",
  TypeUnspecified: "UR type unspecified",
  InvalidType: "invalid UR type",
  InvalidIndices: "invalid multi-part indices",
  NotSinglePart: "expected single-part UR",
  UnexpectedType: "unexpected UR type",
  CborDecode: "dCBOR decode failed",
  CborType: "dCBOR type mismatch",
};

/** Structured error thrown by the UR stack. */
export class UrError extends Error {
  readonly code: UrErrorCode;
  readonly expected?: string | undefined;
  readonly found?: string | undefined;
  readonly limit?: string | undefined;

  constructor(
    code: UrErrorCode,
    options?: { expected?: string; found?: string; limit?: string; cause?: unknown },
  ) {
    const expected = options?.expected;
    const found = options?.found;
    const limit = options?.limit;
    let message = MESSAGES[code];
    if (code === "ResourceLimit" && limit !== undefined && limit !== "") {
      message = `${message}: ${limit}`;
    } else if (
      code === "UnexpectedType" &&
      expected !== undefined &&
      expected !== "" &&
      found !== undefined &&
      found !== ""
    ) {
      message = `${message}: expected ${expected}, found ${found}`;
    }
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "UrError";
    this.code = code;
    this.expected = expected;
    this.found = found;
    this.limit = limit;
  }
}

/** Throws a {@link UrError} with the given code. */
export function fail(
  code: UrErrorCode,
  options?: { expected?: string; found?: string; limit?: string; cause?: unknown },
): never {
  throw new UrError(code, options);
}

/** Fail-closed decoder poison reason. */
export type DecoderPoison = { code: "ResourceLimit"; limit: string } | { code: "DecoderState" };

/** Rethrows the stored poison as a {@link UrError}. */
export function failPoison(p: DecoderPoison): never {
  if (p.code === "ResourceLimit") {
    fail("ResourceLimit", { limit: p.limit });
  }
  fail("DecoderState");
}
