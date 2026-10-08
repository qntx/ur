/**
 * Interop vectors derived from ur-rs 0.5 tests (MIT License). Source:
 * https://github.com/dspicher/ur-rs
 *
 * Message payloads for single-part UR goldens are CBOR byte-string wrappers of Xoshiro("Wolf")
 * output, matching ur-rs `make_message_ur`.
 */

import { expect, test } from "vite-plus/test";

import * as bytewords from "../src/bytewords/index.ts";
import { FountainEncoder } from "../src/fountain/index.ts";
import { makeMessage } from "../src/rng/index.ts";
import { Decoder, Encoder, UrType, decode, encode, parse, toQrString } from "../src/ur/index.ts";
import { vectorJson, vectorLines } from "./vectors.ts";

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
  const encoder = Encoder.bytes(ur, 30);
  expect(encoder.fragmentCount).toBe(9);
  for (let i = 0; i < UR_ENCODER_20.length; i++) {
    expect(encoder.currentIndex).toBe(i);
    expect(encoder.nextPart()).toBe(UR_ENCODER_20[i]);
  }
});

test("ur-rs test_single_part_ur", () => {
  const ur = makeMessageUr(50, "Wolf");
  const encoded = encode(ur, UrType.bytes());
  expect(encoded).toBe(
    "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch",
  );
  const { kind, payload } = decode(encoded);
  expect(kind).toBe("single");
  expect(payload).toStrictEqual(ur);
});

test("decode full-uppercase multipart URIs", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(8));
  const encoder = Encoder.bytes(data, 10);
  const decoder = new Decoder();
  while (!decoder.complete) {
    decoder.receive(toQrString(encoder.nextPart()));
  }
  expect(decoder.message()).toStrictEqual(data);
});

test("test_foreign_1_1_fountain_uri_decodes", () => {
  const message = new TextEncoder().encode("hello");
  const fountain = FountainEncoder.create(message, 64);
  expect(fountain.fragmentCount).toBe(1);
  const part = fountain.nextPart();
  const body = bytewords.encode(part.toCbor(), "minimal");
  const uri = `ur:bytes/1-1/${body}`;
  const decoder = new Decoder();
  decoder.receive(uri);
  expect(decoder.complete).toBe(true);
  expect(decoder.message()).toStrictEqual(message);
});

test("bc-ur golden: ur:test array", () => {
  const cbor = new Uint8Array(Buffer.from(L4.cborHex, "hex"));
  expect(encode(cbor, UrType.parse(L4.type))).toBe(L4.uri);
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
    parse(uri);
  }
});
