import { bytesToHex, decodeCbor, expectBytes, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  TAGS,
  Ur,
  UrType,
  UrError,
  codecMap,
  coinInfoCodec,
  fromUrStringWith,
  hdKeyCodec,
  keypathCodec,
  psbtCodec,
  seedCodec,
  sskrCodec,
} from "../../src/registry/index.ts";
import type { Psbt, Seed, UrCodec } from "../../src/registry/index.ts";
import { psbt167, psbt167V1Ur, seedC709 } from "./goldens.ts";

function errorOf(fn: () => void): UrError {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected UrError");
}

test("duplicate tags[0].name is TypeError not InvalidType", () => {
  const call = () => codecMap([seedCodec, seedCodec]);
  expect(call).toThrow(TypeError);
  expect(call).not.toThrow(UrError);
  expect(call).toThrow("duplicate codec for UR type seed");
});

test("duplicate v1 name is TypeError", () => {
  const v1Only: UrCodec<unknown> = { ...seedCodec, tags: [TAGS["crypto-seed"]] };
  const call = () => codecMap([seedCodec, v1Only]);
  expect(call).toThrow(TypeError);
  expect(call).toThrow("duplicate codec for UR type crypto-seed");
});

test("fromUrStringWith unknown type is UnexpectedType", () => {
  const uri = Ur.create("bytes", new Uint8Array([1, 2, 3])).string();
  const err = errorOf(() => fromUrStringWith(uri, codecMap([seedCodec])));
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [UrType.parse("seed"), UrType.parse("crypto-seed")],
    found: UrType.parse("bytes"),
  });
});

test("codecMap seed+psbt dispatch", () => {
  const map = codecMap([seedCodec, psbtCodec]);
  expect([...map.keys()]).toStrictEqual(["seed", "crypto-seed", "psbt", "crypto-psbt"]);

  const seed = fromUrStringWith(seedC709.ur, map);
  expect(seed.type).toBe("seed");
  expect(bytesToHex((seed.value as Seed).payload)).toBe(seedC709.payloadHex);

  const psbt = fromUrStringWith(psbt167.ur, map);
  expect(psbt.type).toBe("psbt");
  expect(bytesToHex((psbt.value as Psbt).bytes)).toBe(
    bytesToHex(new Uint8Array(expectBytes(decodeCbor(hexToBytes(psbt167.cborHex))))),
  );
});

test("codecMap dispatches v1 token and reports inbound type", () => {
  const map = codecMap([seedCodec, hdKeyCodec, keypathCodec, coinInfoCodec, sskrCodec, psbtCodec]);
  const result = fromUrStringWith(psbt167V1Ur, map);
  expect(result.type).toBe("crypto-psbt");
  expect(result.value).toStrictEqual(fromUrStringWith(psbt167.ur, map).value);
});
