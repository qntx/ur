import { decodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  cryptoMultiAccountsCodec,
  ethSignRequestCodec,
  ethSignatureCodec,
  oneKeyTronSignRequestCodec,
  solSignRequestCodec,
  solSignatureCodec,
  tronSignRequestCodec,
  tronSignatureCodec,
} from "../../src/interop/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { vectorJson } from "../vectors.ts";

type InvalidCase = {
  readonly name: string;
  readonly codec: string;
  readonly inputCborHex: string;
  readonly tsError: string;
};

const INVALID = vectorJson<{ cases: ReadonlyArray<InvalidCase> }>("interop/invalid.json").cases;

const CODECS: Record<string, UrCodec<unknown>> = {
  "eth-sign-request": ethSignRequestCodec,
  "eth-signature": ethSignatureCodec,
  "sol-sign-request": solSignRequestCodec,
  "sol-signature": solSignatureCodec,
  "tron-sign-request": tronSignRequestCodec,
  "onekey-tron-sign-request": oneKeyTronSignRequestCodec,
  "tron-signature": tronSignatureCodec,
  "crypto-multi-accounts": cryptoMultiAccountsCodec,
};

function mustCodec(name: string): UrCodec<unknown> {
  const codec = CODECS[name];
  if (codec === undefined) {
    throw new Error(`no codec for ${name}`);
  }
  return codec;
}

test.each(INVALID)("interop-invalid $codec $name", (c) => {
  const codec = mustCodec(c.codec);
  let thrown: unknown;
  try {
    codec.decode(decodeCbor(hexToBytes(c.inputCborHex)));
  } catch (error) {
    thrown = error;
  }
  expect(thrown, `${c.name}: expected ${c.tsError}`).toBeDefined();
  expect((thrown as { code?: string }).code).toBe(c.tsError);
});
