/**
 * Generates `vectors/fountain/part-cbor-decode.json`: lenient-decode / strict-encode contract cases
 * for the fixed-schema fountain-part CBOR form (UR-ADR-017).
 *
 * Every accepted case is structurally cross-checked by the Rust runner with `minicbor` (independent
 * CBOR parser); the generator itself verifies canonical re-encoding against the reference
 * `encodePart` implementation.
 *
 * Usage: bun scripts/vectors/generate-part-cbor-decode.ts
 */
/// <reference types="node" />
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { encodePart } from "../../packages/ur/src/fountain/part-cbor.ts";
import type { Part } from "../../packages/ur/src/fountain/part.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "vectors");

// Golden part fields, sourced from the existing contract vector.
type Golden = {
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  dataHex: string;
  cborHex: string;
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function numberField(v: Record<string, unknown>, key: string): number {
  const value = v[key];
  if (typeof value !== "number") {
    throw new TypeError(`fountain/part-cbor.json: ${key} is not a number`);
  }
  return value;
}

function stringField(v: Record<string, unknown>, key: string): string {
  const value = v[key];
  if (typeof value !== "string") {
    throw new TypeError(`fountain/part-cbor.json: ${key} is not a string`);
  }
  return value;
}

const goldenJson: unknown = JSON.parse(
  readFileSync(join(VECTORS, "fountain/part-cbor.json"), "utf8"),
);
if (!isRecord(goldenJson)) {
  throw new Error("fountain/part-cbor.json: not an object");
}
const golden: Golden = {
  sequence: numberField(goldenJson, "sequence"),
  sequenceCount: numberField(goldenJson, "sequenceCount"),
  messageLength: numberField(goldenJson, "messageLength"),
  checksum: numberField(goldenJson, "checksum"),
  dataHex: stringField(goldenJson, "dataHex"),
  cborHex: stringField(goldenJson, "cborHex"),
};
const DATA = Uint8Array.from(
  (golden.dataHex.match(/.{2}/g) ?? []).map((b) => Number.parseInt(b, 16)),
);

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- CBOR writers (any width, including non-shortest) -------------------------------

/** Argument bytes for `ai` width 0..4 (0 = value inlined in the head byte). */
function argBytes(width: number, v: bigint): number[] {
  const hex = v.toString(16).padStart(width * 2, "0");
  if (hex.length !== width * 2) {
    throw new Error(`argument ${v} does not fit ${width} bytes`);
  }
  return Array.from(hex.matchAll(/../g), (m) => Number.parseInt(m[0], 16));
}

function uint(v: bigint | number, width: 0 | 1 | 2 | 4 | 8): Uint8Array {
  const ai = width === 0 ? 0 : width === 1 ? 24 : width === 2 ? 25 : width === 4 ? 26 : 27;
  const bytes = width === 0 ? [Number(v)] : [ai, ...argBytes(width, BigInt(v))];
  return new Uint8Array(bytes);
}

function head(major: number, len: bigint | number, width: 0 | 1 | 2 | 4 | 8): Uint8Array {
  const ai =
    width === 0 ? Number(len) : width === 1 ? 24 : width === 2 ? 25 : width === 4 ? 26 : 27;
  const bytes =
    width === 0 ? [major * 32 + Number(len)] : [major * 32 + ai, ...argBytes(width, BigInt(len))];
  return new Uint8Array(bytes);
}

function bstr(data: Uint8Array, width: 0 | 1 | 2 | 4 | 8): Uint8Array {
  const h = head(2, data.length, width);
  const out = new Uint8Array(h.length + data.length);
  out.set(h);
  out.set(data, h.length);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Canonical encoding of the golden part (baseline for mutated cases). */
function canonical(): Uint8Array {
  return concat(
    head(4, 5, 0),
    uint(golden.sequence, 0),
    uint(golden.sequenceCount, 0),
    uint(golden.messageLength, 2),
    uint(golden.checksum, 4),
    bstr(DATA, 1),
  );
}

function partBytes(
  seq: number,
  count: number,
  len: number,
  csum: number,
  data: Uint8Array,
): Uint8Array {
  return encodePart({
    sequence: seq,
    sequenceCount: count,
    messageLength: len,
    checksum: csum,
    data,
  });
}

// --- cases -------------------------------------------------------------------------

type Case = {
  name: string;
  cborHex: string;
  limits?: Record<string, number>;
  part?: {
    sequence: number;
    sequenceCount: number;
    messageLength: number;
    checksum: number;
    dataHex: string;
  };
  reencodedHex?: string;
  error?: { code: string; limit?: string };
};

const goldenPart = {
  sequence: golden.sequence,
  sequenceCount: golden.sequenceCount,
  messageLength: golden.messageLength,
  checksum: golden.checksum,
  dataHex: golden.dataHex,
};
const canonicalHex = golden.cborHex;

// Self-check: our hand-rolled writers reproduce the golden canonical encoding.
if (hex(canonical()) !== canonicalHex) {
  throw new Error(`canonical mismatch: ${hex(canonical())} != ${canonicalHex}`);
}

function accept(name: string, cbor: Uint8Array, part = goldenPart): Case {
  const reencoded = hex(
    encodePart({
      sequence: part.sequence,
      sequenceCount: part.sequenceCount,
      messageLength: part.messageLength,
      checksum: part.checksum,
      data: DATA,
    }),
  );
  return { name, cborHex: hex(cbor), part, reencodedHex: reencoded };
}

function reject(name: string, cbor: Uint8Array, code: string, limit?: string): Case {
  return { name, cborHex: hex(cbor), error: limit === undefined ? { code } : { code, limit } };
}

const cases: Case[] = [
  // Lenient integer widths accepted, re-encoded shortest.
  accept(
    "non-shortest-uint8-sequence",
    concat(
      head(4, 5, 0),
      uint(1, 1),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
    ),
  ),
  accept(
    "non-shortest-uint16-sequence",
    concat(
      head(4, 5, 0),
      uint(1, 2),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
    ),
  ),
  accept(
    "non-shortest-uint32-sequence-count",
    concat(
      head(4, 5, 0),
      uint(golden.sequence, 0),
      uint(golden.sequenceCount, 4),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
    ),
  ),
  accept(
    "non-shortest-uint64-all-fields",
    concat(
      head(4, 5, 1),
      uint(BigInt(golden.sequence), 8),
      uint(BigInt(golden.sequenceCount), 8),
      uint(BigInt(golden.messageLength), 8),
      uint(BigInt(golden.checksum), 8),
      bstr(DATA, 8),
    ),
  ),
  accept(
    "wide-bstr-header-16",
    concat(
      head(4, 5, 0),
      uint(golden.sequence, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 2),
    ),
  ),
  accept(
    "wide-bstr-header-32",
    concat(
      head(4, 5, 0),
      uint(golden.sequence, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 4),
    ),
  ),

  // Malformed CBOR: InvalidPartCbor.
  reject(
    "indefinite-array",
    concat(
      new Uint8Array([0x9f]),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
      new Uint8Array([0xff]),
    ),
    "InvalidPartCbor",
  ),
  reject(
    "indefinite-bstr",
    concat(
      head(4, 5, 0),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      new Uint8Array([0x5f]),
      bstr(DATA, 1),
      new Uint8Array([0xff]),
    ),
    "InvalidPartCbor",
  ),
  reject("tag-wrapped-array", concat(new Uint8Array([0xc1]), canonical()), "InvalidPartCbor"),
  reject(
    "negative-int-sequence",
    concat(
      head(4, 5, 0),
      new Uint8Array([0x20]),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
    ),
    "InvalidPartCbor",
  ),
  reject(
    "array-too-short",
    concat(
      head(4, 4, 0),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
    ),
    "InvalidPartCbor",
  ),
  reject(
    "array-too-long",
    concat(
      head(4, 6, 0),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
      uint(0, 0),
    ),
    "InvalidPartCbor",
  ),
  reject(
    "uint-overflow-u64",
    concat(
      head(4, 5, 0),
      uint(0x1_00_00_00_00n, 8),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      bstr(DATA, 1),
    ),
    "InvalidPartCbor",
  ),
  reject("truncated-input", canonical().subarray(0, 3), "InvalidPartCbor"),
  reject("trailing-bytes", concat(canonical(), new Uint8Array([0x00])), "InvalidPartCbor"),
  reject(
    "bstr-overrun",
    concat(
      head(4, 5, 0),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      head(2, DATA.length + 1, 1),
      DATA,
    ),
    "InvalidPartCbor",
  ),
  reject(
    "text-instead-of-bstr",
    concat(
      head(4, 5, 0),
      uint(1, 0),
      uint(golden.sequenceCount, 0),
      uint(golden.messageLength, 2),
      uint(golden.checksum, 4),
      new Uint8Array([0x61, 0x61]),
    ),
    "InvalidPartCbor",
  ),

  // Semantic failures: InvalidPart.
  reject(
    "zero-sequence",
    partBytes(0, golden.sequenceCount, golden.messageLength, golden.checksum, DATA),
    "InvalidPart",
  ),
  reject(
    "zero-sequence-count",
    partBytes(1, 0, golden.messageLength, golden.checksum, DATA),
    "InvalidPart",
  ),
  reject(
    "zero-message-length",
    partBytes(1, golden.sequenceCount, 0, golden.checksum, DATA),
    "InvalidPart",
  ),
  reject("empty-data", partBytes(1, 1, 1, 0, new Uint8Array()), "InvalidPart"),
  reject("padding-wider-than-fragment", partBytes(1, 2, 1, 0, new Uint8Array(8)), "InvalidPart"),
  reject("message-exceeds-capacity", partBytes(1, 1, 100, 0, new Uint8Array(8)), "InvalidPart"),

  // Limits: ResourceLimit.
  {
    name: "data-over-limit",
    cborHex: canonicalHex,
    limits: { maxFragmentLength: DATA.length - 1 },
    error: { code: "ResourceLimit", limit: "fragmentLength" },
  },
  {
    name: "count-over-limit",
    cborHex: canonicalHex,
    limits: { maxFragmentCount: golden.sequenceCount - 1 },
    error: { code: "ResourceLimit", limit: "fragmentCount" },
  },
];

// Verify our writers/expectations agree with the reference encoder for accepted cases.
for (const c of cases) {
  if (c.reencodedHex !== undefined && c.part !== undefined) {
    const p: Part = {
      sequence: c.part.sequence,
      sequenceCount: c.part.sequenceCount,
      messageLength: c.part.messageLength,
      checksum: c.part.checksum,
      data: Uint8Array.from(
        (c.part.dataHex.match(/.{2}/g) ?? []).map((b) => Number.parseInt(b, 16)),
      ),
    };
    const actual = hex(encodePart(p));
    if (actual !== c.reencodedHex) {
      throw new Error(`${c.name}: reencode mismatch`);
    }
  }
}

const doc = {
  schema: 1,
  capability: "fountain.part-cbor",
  source: {
    kind: "generated",
    name: "scripts/vectors/generate-part-cbor-decode.ts",
    crossCheck: "rust runner decodes accepted cases with minicbor",
  },
  cases,
};

mkdirSync(join(VECTORS, "fountain"), { recursive: true });
writeFileSync(join(VECTORS, "fountain/part-cbor-decode.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote vectors/fountain/part-cbor-decode.json (${cases.length} cases)`);
