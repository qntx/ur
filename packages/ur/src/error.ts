import type { UrType } from "./ur/type.ts";

/** Discriminated error codes for the UR transport stack. Mirrors `bcur::ErrorKind`. */
export type UrErrorCode =
  | "NonAscii"
  | "InvalidWord"
  | "InvalidBytewordsLength"
  | "InvalidBytewordsChecksum"
  | "InvalidScheme"
  | "TypeUnspecified"
  | "InvalidType"
  | "InvalidIndices"
  | "UnexpectedType"
  | "InvalidPartCbor"
  | "InvalidPart"
  | "InconsistentPart"
  | "ResourceLimit"
  | "InvalidPadding"
  | "InvalidMessageChecksum"
  | "EmptyMessage"
  | "InvalidFragmentLength"
  | "MessageTooLong"
  | "NotSinglePart"
  | "CborDecode"
  | "CborType"
  | "Internal";

/** Decoder budget names carried by `ResourceLimit` errors. Mirrors `bcur::Limit`. */
export type UrLimit = "messageLength" | "fragmentCount" | "fragmentLength" | "uriLength";

/** Per-code error detail; `switch (info.code)` narrows the payload. */
export type UrErrorInfo =
  | Readonly<{ code: "ResourceLimit"; limit: UrLimit }>
  | Readonly<{ code: "UnexpectedType"; expected: ReadonlyArray<UrType>; found: UrType }>
  | Readonly<{ code: Exclude<UrErrorCode, "ResourceLimit" | "UnexpectedType"> }>;

const MESSAGES: Record<UrErrorCode, string> = {
  NonAscii: "bytewords string is not ASCII",
  InvalidWord: "invalid bytewords word",
  InvalidBytewordsLength: "invalid bytewords length",
  InvalidBytewordsChecksum: "invalid bytewords checksum",
  InvalidScheme: "invalid UR scheme",
  TypeUnspecified: "UR type unspecified",
  InvalidType: "invalid UR type",
  InvalidIndices: "invalid multi-part indices",
  UnexpectedType: "unexpected UR type",
  InvalidPartCbor: "invalid fountain part CBOR",
  InvalidPart: "invalid fountain part",
  InconsistentPart: "fountain part inconsistent with previous parts",
  ResourceLimit: "resource limit exceeded",
  InvalidPadding: "invalid fountain part padding",
  InvalidMessageChecksum: "invalid fountain message checksum",
  EmptyMessage: "empty message",
  InvalidFragmentLength: "invalid fragment length",
  MessageTooLong: "message too long",
  NotSinglePart: "expected single-part UR",
  CborDecode: "dCBOR decode failed",
  CborType: "dCBOR type mismatch",
  Internal: "internal error",
};

const FATAL_CODES: ReadonlySet<UrErrorCode> = new Set([
  "ResourceLimit",
  "InvalidPadding",
  "InvalidMessageChecksum",
  "Internal",
]);

function describe(info: UrErrorInfo): string {
  if (info.code === "ResourceLimit") {
    return `${MESSAGES.ResourceLimit}: ${info.limit}`;
  }
  if (info.code === "UnexpectedType") {
    const names = info.expected.join(", ");
    return `${MESSAGES.UnexpectedType}: expected ${names}, found ${info.found}`;
  }
  return MESSAGES[info.code];
}

/** Structured error thrown by the UR stack. */
export class UrError extends Error {
  readonly info: UrErrorInfo;

  constructor(info: UrErrorInfo, options?: { cause?: unknown }) {
    super(describe(info), options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "UrError";
    this.info = info;
  }

  get code(): UrErrorCode {
    return this.info.code;
  }

  get fatal(): boolean {
    return FATAL_CODES.has(this.info.code);
  }
}

/** Codes whose info carries no detail beyond `code`. */
type PlainCode = Exclude<UrErrorCode, "ResourceLimit" | "UnexpectedType">;

/** Throws a {@link UrError}; a bare code builds `{ code }` info. */
export function fail(arg: PlainCode | UrErrorInfo, options?: { cause?: unknown }): never {
  throw new UrError(typeof arg === "string" ? { code: arg } : arg, options);
}

/** Converts a thrown value to {@link UrError}; non-`UrError` values become `Internal` with `cause`. */
export function toUrError(error: unknown): UrError {
  return error instanceof UrError ? error : new UrError({ code: "Internal" }, { cause: error });
}
