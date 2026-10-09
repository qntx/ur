/**
 * Interop vectors derived from ur-rs 0.5 tests (MIT License). Source:
 * https://github.com/dspicher/ur-rs
 *
 * Message payloads for single-part UR goldens are CBOR byte-string wrappers of Xoshiro("Wolf")
 * output, matching ur-rs `make_message_ur`.
 */

import { expect, test } from "vite-plus/test";

import { encodeBytewords } from "../src/bytewords/index.ts";
import type { Part } from "../src/fountain/index.ts";
import { FountainEncoder, encodePart } from "../src/fountain/index.ts";
import type { ParsedUr } from "../src/ur/index.ts";
import {
  UrDecoder,
  UrEncoder,
  encodeUr,
  parseUr,
  parseUrType,
  toQrString,
} from "../src/ur/index.ts";
import { makeMessage } from "./message.ts";
import { vectorJson, vectorLines } from "./vectors.ts";

/** Feeds one UR; frame errors become thrown errors. */
function feedUr(decoder: UrDecoder, text: string): void {
  const result = decoder.receive(text);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
}

function decodedMessage(decoder: UrDecoder): Uint8Array {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value.message;
}

function nextUr(encoder: UrEncoder): string {
  const { done, value } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("ur encoder exhausted");
  }
  return value;
}

function bytesEncoder(data: Uint8Array, maxFragmentLength: number): UrEncoder {
  return new UrEncoder(parseUrType("bytes"), data, { maxFragmentLength });
}

function parsedMessage(parsed: ParsedUr): Uint8Array {
  if (parsed.kind !== "single") {
    throw new Error(`expected single, got ${parsed.kind}`);
  }
  return parsed.message;
}

function nextPart(fountain: FountainEncoder): Part {
  const { done, value } = fountain.next();
  if (done === true || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

/** CBOR bstr header + payload (ur-rs ByteVec). */
function cborBstr(message: Uint8Array): Uint8Array {
  const len = message.length;
  let header: number[];
  if (len <= 23) {
    header = [0x40 | len];
  } else if (len <= 0xff) {
    header = [0x58, len];
  } else if (len <= 0xffff) {
    header = [0x59, (len >>> 8) & 0xff, len & 0xff];
  } else {
    header = [0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header);
  out.set(message, header.length);
  return out;
}

function makeMessageUr(length: number, seed: string): Uint8Array {
  return cborBstr(makeMessage(seed, length));
}

/** Full 20-URI table from ur-rs `test_ur_encoder` (max_frag 30, 256-byte Wolf bstr). */
const UR_ENCODER_20 = vectorLines("ur-rs/multipart-20.txt");

const PUBLISHED_SINGLES = vectorLines("ur/published-singles.txt");

const PUBLISHED_REFS = vectorLines("official/published-from-refs.txt");

const L4 = vectorJson<{ type: string; cborHex: string; uri: string }>("typed/test-array.json");

test("ur-rs test_ur_encoder: full 20 URI goldens", () => {
  const ur = makeMessageUr(256, "Wolf");
  const encoder = bytesEncoder(ur, 30);
  expect(encoder.fragmentCount).toBe(9);
  for (const expected of UR_ENCODER_20) {
    expect(nextUr(encoder)).toBe(expected);
  }
});

test("ur-rs test_single_part_ur", () => {
  const ur = makeMessageUr(50, "Wolf");
  const encoded = encodeUr(parseUrType("bytes"), ur);
  expect(encoded).toBe(
    "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch",
  );
  const parsed = parseUr(encoded);
  expect(parsed.kind).toBe("single");
  expect(parsedMessage(parsed)).toStrictEqual(ur);
});

test("decode full-uppercase multipart URIs", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(8));
  const encoder = bytesEncoder(data, 10);
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    feedUr(decoder, toQrString(nextUr(encoder)));
  }
  expect(decodedMessage(decoder)).toStrictEqual(data);
});

test("test_foreign_1_1_fountain_uri_decodes", () => {
  const message = new TextEncoder().encode("hello");
  const fountain = new FountainEncoder(message, { maxFragmentLength: 64 });
  expect(fountain.fragmentCount).toBe(1);
  const body = encodeBytewords(encodePart(nextPart(fountain)), "minimal");
  const uri = `ur:bytes/1-1/${body}`;
  const decoder = new UrDecoder();
  expect(decoder.receive(uri).status).toBe("accepted");
  expect(decodedMessage(decoder)).toStrictEqual(message);
});

test("bc-ur golden: ur:test array", () => {
  const cbor = new Uint8Array(Buffer.from(L4.cborHex, "hex"));
  expect(encodeUr(parseUrType(L4.type), cbor)).toBe(L4.uri);
});

test("published-from-refs: pinned literals contain the in-tree goldens", () => {
  const refSet = new Set(PUBLISHED_REFS);
  for (const uri of UR_ENCODER_20) {
    expect(refSet.has(uri)).toBe(true);
  }
  const wolf = PUBLISHED_SINGLES.find((uri) => uri.includes("hdeymejtswhh"));
  expect(wolf).toBeDefined();
  expect(PUBLISHED_REFS).toContain(wolf);
  // Sorted unique, matching the extraction script's ordering contract.
  expect(PUBLISHED_REFS).toStrictEqual([...new Set(PUBLISHED_REFS)].toSorted());
  for (const uri of PUBLISHED_REFS) {
    parseUr(uri);
  }
});
