import { decodeCbor, expectBytes, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  TAGS,
  Ur,
  parseUrType,
  UrError,
  codecMap,
  coinInfoCodec,
  fromUrWith,
  hdKeyCodec,
  keypathCodec,
  psbtCodec,
  seedCodec,
  sskrCodec,
} from "../../src/registry/index.ts";
import type { UrCodec } from "../../src/registry/index.ts";
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

test("duplicate tags[0].name is InvalidType", () => {
  const err = errorOf(() => codecMap([seedCodec, seedCodec]));
  expect(err.code).toBe("InvalidType");
});

test("duplicate v1 name is InvalidType", () => {
  const v1Only: UrCodec<unknown> = { ...seedCodec, tags: [TAGS["crypto-seed"]] };
  const err = errorOf(() => codecMap([seedCodec, v1Only]));
  expect(err.code).toBe("InvalidType");
});

test("fromUrWith unknown type is UnexpectedType", () => {
  const uri = Ur.fromCbor("bytes", new Uint8Array([1, 2, 3])).toString();
  const err = errorOf(() => fromUrWith(Ur.parse(uri), codecMap([seedCodec])));
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [parseUrType("seed"), parseUrType("crypto-seed")],
    found: parseUrType("bytes"),
  });
});

test("codecMap seed+psbt dispatch", () => {
  const map = codecMap([seedCodec, psbtCodec]);
  expect([...map.keys()]).toStrictEqual(["seed", "crypto-seed", "psbt", "crypto-psbt"]);

  const seed = fromUrWith(Ur.parse(seedC709.ur), map);
  expect(seed).toStrictEqual({ type: "seed", value: { payload: hexToBytes(seedC709.payloadHex) } });

  const psbt = fromUrWith(Ur.parse(psbt167.ur), map);
  expect(psbt).toStrictEqual({
    type: "psbt",
    value: { bytes: new Uint8Array(expectBytes(decodeCbor(hexToBytes(psbt167.cborHex)))) },
  });
});

test("codecMap dispatches v1 token and reports inbound type", () => {
  const map = codecMap([seedCodec, hdKeyCodec, keypathCodec, coinInfoCodec, sskrCodec, psbtCodec]);
  const result = fromUrWith(Ur.parse(psbt167V1Ur), map);
  expect(result.type).toBe("crypto-psbt");
  expect(result.value).toStrictEqual(fromUrWith(Ur.parse(psbt167.ur), map).value);
});
