/**
 * Interop vectors derived from ur-rs 0.5 tests (MIT License). Source:
 * https://github.com/dspicher/ur-rs
 *
 * Message payloads for single-part UR goldens are CBOR byte-string wrappers of Xoshiro("Wolf")
 * output, matching ur-rs `make_message_ur`.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vite-plus/test";

import * as bytewords from "../src/bytewords/index.ts";
import { FountainEncoder } from "../src/fountain/index.ts";
import { makeMessage } from "../src/rng/index.ts";
import { Decoder, Encoder, UrType, decode, encode, toQrString } from "../src/ur/index.ts";

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
const UR_ENCODER_20 = readFileSync(join(import.meta.dirname, "vectors/fountain-mixed.txt"), "utf8")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line.length > 0);

const L4 = JSON.parse(
  readFileSync(join(import.meta.dirname, "vectors/l4-test-array.json"), "utf8"),
) as {
  type: string;
  cborHex: string;
  uri: string;
};

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
