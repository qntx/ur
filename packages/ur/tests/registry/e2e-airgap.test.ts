import { bytesToHex, decodeCbor, expectBytes, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { UrType, fromUr, psbtCodec, seedCodec, toUr } from "../../src/registry/index.ts";
import { Ur } from "../../src/typed/index.ts";
import type { DecodedUr } from "../../src/ur/index.ts";
import { UrDecoder } from "../../src/ur/index.ts";
import { psbt167 } from "./goldens.ts";

/** Feeds one part; frame errors become thrown errors. */
function feedUr(decoder: UrDecoder, text: string): void {
  const result = decoder.receive(text);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
}

function completedDecoded(decoder: UrDecoder): DecodedUr {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

test("64-byte seed is single-part through Ur.encoder", () => {
  const payload = new Uint8Array(64);
  for (let i = 0; i < payload.length; i++) {
    payload[i] = i;
  }
  const ur = toUr({ payload }, seedCodec);
  const enc = ur.encoder({ maxFragmentLength: 200 });
  expect(enc.isSinglePart).toBe(true);
  const dec = new UrDecoder({ accept: [UrType.parse("seed")] });
  const result = dec.receive(enc.nextPart());
  expect(result.status).toBe("accepted");
  const recovered = fromUr(Ur.fromDecoded(completedDecoded(dec)), seedCodec);
  expect(bytesToHex(recovered.payload)).toBe(bytesToHex(payload));
});

test("167-byte PSBT multipart at maxFragmentLength 50", () => {
  const bytes = new Uint8Array(expectBytes(decodeCbor(hexToBytes(psbt167.cborHex))));
  const ur = toUr({ bytes }, psbtCodec);
  expect(ur.encoder({ maxFragmentLength: 200 }).isSinglePart).toBe(true);
  const enc = ur.encoder({ maxFragmentLength: 50 });
  expect(enc.isSinglePart).toBe(false);
  const decoder = new UrDecoder({ accept: [UrType.parse("psbt")] });
  while (decoder.state.phase !== "complete") {
    feedUr(decoder, enc.nextPart());
  }
  const recovered = fromUr(Ur.fromDecoded(completedDecoded(decoder)), psbtCodec);
  expect(bytesToHex(recovered.bytes)).toBe(bytesToHex(bytes));
});
