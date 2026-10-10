import { hexToBytes } from "@blockchaincommons/dcbor";
import { expect, expectTypeOf, test } from "vite-plus/test";

import { decodeBytewords, encodeBytewords } from "../src/bytewords/index.ts";
import { FountainEncoder, encodePart } from "../src/fountain/index.ts";
import type { Part } from "../src/fountain/index.ts";
import {
  codecMap,
  fromUrWith,
  hdKeyCodec,
  hdKeyDigest,
  hdKeyDigestSource,
  seedCodec,
  seedDigest,
} from "../src/registry/index.ts";
import type { CodecMap, CodecValue, HdKey, Seed } from "../src/registry/index.ts";
import { Ur } from "../src/typed/index.ts";
import { hdkey2, seedC709 } from "./registry/goldens.ts";

function nextPart(encoder: FountainEncoder): Part {
  const { value, done } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

test("freshly allocated byte results are ArrayBuffer-backed", () => {
  const message = new Uint8Array([1, 2, 3]);

  const decoded = decodeBytewords(encodeBytewords(message, "minimal"), "minimal");
  expectTypeOf(decoded).toEqualTypeOf<Uint8Array<ArrayBuffer>>();
  expect(decoded.buffer).toBeInstanceOf(ArrayBuffer);

  const part = nextPart(new FountainEncoder(message, { maxFragmentLength: 10 }));
  const wire = encodePart(part);
  expectTypeOf(wire).toEqualTypeOf<Uint8Array<ArrayBuffer>>();
  expect(wire.buffer).toBeInstanceOf(ArrayBuffer);

  const ur = Ur.fromCbor("seed", seedCodec.encode({ payload: message }));
  expectTypeOf(ur.toCborData()).toEqualTypeOf<Uint8Array<ArrayBuffer>>();

  expectTypeOf(seedDigest({ payload: message })).toEqualTypeOf<Uint8Array<ArrayBuffer>>();

  const key = {
    kind: "master" as const,
    keyData: hexToBytes(hdkey2.keyDataHex),
    chainCode: hexToBytes(hdkey2.chainCodeHex),
  };
  expectTypeOf(hdKeyDigestSource(key)).toEqualTypeOf<Uint8Array<ArrayBuffer>>();
  expectTypeOf(hdKeyDigest(key)).toEqualTypeOf<Uint8Array<ArrayBuffer>>();
});

test("codecMap and fromUrWith carry the union of codec value types", () => {
  const map = codecMap([seedCodec, hdKeyCodec]);
  expectTypeOf(map).toEqualTypeOf<CodecMap<Seed | HdKey>>();
  expectTypeOf<CodecValue<typeof seedCodec>>().toEqualTypeOf<Seed>();

  const result = fromUrWith(Ur.parse(seedC709.ur), map);
  expectTypeOf(result.value).toEqualTypeOf<Seed | HdKey>();
  expect(result.type).toBe("seed");
});
