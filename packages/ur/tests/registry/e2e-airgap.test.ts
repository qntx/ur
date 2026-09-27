import { bytesToHex, decodeCbor, expectBytes, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  MultipartDecoder,
  MultipartEncoder,
  UrType,
  fromUr,
  psbtCodec,
  seedCodec,
  toUr,
} from "../../src/registry/index.ts";
import { psbt167 } from "./goldens.ts";

test("64-byte seed is single-part through MultipartEncoder", () => {
  const payload = new Uint8Array(64);
  for (let i = 0; i < payload.length; i++) {
    payload[i] = i;
  }
  const ur = toUr({ payload }, seedCodec);
  const enc = MultipartEncoder.create(ur, 200);
  expect(enc.isSinglePart).toBe(true);
  const dec = new MultipartDecoder({ expectedType: UrType.parse("seed") });
  dec.receive(enc.nextPart());
  expect(dec.complete).toBe(true);
  const recovered = fromUr(dec.message()!, seedCodec);
  expect(bytesToHex(recovered.payload)).toBe(bytesToHex(payload));
});

test("167-byte PSBT multipart at maxFragmentLength 50", () => {
  const bytes = new Uint8Array(expectBytes(decodeCbor(hexToBytes(psbt167.cborHex))));
  const ur = toUr({ bytes }, psbtCodec);
  expect(MultipartEncoder.create(ur, 200).isSinglePart).toBe(true);
  const enc = MultipartEncoder.create(ur, 50);
  expect(enc.isSinglePart).toBe(false);
  const dec = new MultipartDecoder({ expectedType: UrType.parse("psbt") });
  while (!dec.complete) {
    dec.receive(enc.nextPart());
  }
  const recovered = fromUr(dec.message()!, psbtCodec);
  expect(bytesToHex(recovered.bytes)).toBe(bytesToHex(bytes));
});
