import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { decodeBytewords } from "../../src/bytewords/index.ts";
import {
  hdKeyCodec,
  hdKeyDigest,
  hdKeyDigestSource,
  psbtCodec,
  seedCodec,
  sskrCodec,
  toUr,
} from "../../src/registry/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { vectorJson } from "../vectors.ts";

type RegistryCase = {
  name: string;
  urType: string;
  tag?: number;
  cborHex?: string;
  ur?: string;
  diagnostic?: string;
  digestSourceHex?: string;
  digestHex?: string;
  masterSecretHex?: string;
  shares?: Array<{
    index: number;
    group: number;
    cborHex: string;
    taggedCborHex: string;
    bytewords: string;
    ur: string;
  }>;
};

const SEED = vectorJson<{ cases: RegistryCase[] }>("official/registry/seed.json").cases;
const PSBT = vectorJson<{ cases: RegistryCase[] }>("official/registry/psbt.json").cases;
const HDKEY = vectorJson<{ cases: RegistryCase[] }>("official/registry/hdkey.json").cases;
const SSKR = vectorJson<{ cases: RegistryCase[] }>("official/registry/sskr.json").cases;

const CODECS: Record<string, UrCodec<unknown>> = {
  seed: seedCodec,
  psbt: psbtCodec,
  hdkey: hdKeyCodec,
  sskr: sskrCodec,
};

function codecFor(c: RegistryCase): UrCodec<unknown> {
  const codec = CODECS[c.urType];
  if (codec === undefined) {
    throw new Error(`no codec for ${c.urType}`);
  }
  return codec;
}

function cborBytes(c: RegistryCase): Uint8Array {
  const { cborHex } = c;
  if (cborHex === undefined) {
    throw new Error(`${c.name}: missing cborHex`);
  }
  return hexToBytes(cborHex);
}

const digestCases = HDKEY.filter(
  (c) => c.digestSourceHex !== undefined && c.digestHex !== undefined,
);
const shareRows = SSKR.flatMap((c) =>
  (c.shares ?? []).map((share) => ({ name: c.name, ...share })),
);

test.each([...SEED.slice(1), ...PSBT, ...HDKEY])("registry.$urType $name", (c) => {
  const codec = codecFor(c);
  const value = codec.decode(decodeCbor(cborBytes(c)));
  expect(bytesToHex(encodeCbor(codec.encode(value)))).toBe(c.cborHex);
  expect(toUr(value, codec).toString()).toBe(c.ur);
});

test.each(digestCases)("registry.hdkey $name digest", (c) => {
  const value = hdKeyCodec.decode(decodeCbor(cborBytes(c)));
  expect(bytesToHex(hdKeyDigestSource(value))).toBe(c.digestSourceHex);
  expect(bytesToHex(hdKeyDigest(value))).toBe(c.digestHex);
});

// UR-ADR-019 (was F-01): the tag-100 creation date reads as the tag-1 date and
// re-encodes as tag 1 — the official vector's input is the tag-100 form.
function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`missing ${what}`);
  }
  return value;
}

const SEED_V2 = must(SEED[0], "seed tag-100 case");
const SEED_V2_TAG1_CBOR_HEX = "a20150c7098580125e2ab0981253468b2dbc5202c11a5eb9e700";
const SEED_V2_TAG1_UR = "ur:seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaosecyhyrhvdaednlbbywe";

test(`registry.seed ${SEED_V2.name} round trip`, () => {
  const codec = codecFor(SEED_V2);
  const value = codec.decode(decodeCbor(cborBytes(SEED_V2)));
  expect(bytesToHex(encodeCbor(codec.encode(value)))).toBe(SEED_V2_TAG1_CBOR_HEX);
  expect(toUr(value, codec).toString()).toBe(SEED_V2_TAG1_UR);
});

test.each(shareRows)("registry.sskr $name share $index", (share) => {
  const value = sskrCodec.decode(decodeCbor(hexToBytes(share.cborHex)));
  expect(bytesToHex(encodeCbor(sskrCodec.encode(value)))).toBe(share.cborHex);
  // Tagged share as standard bytewords (the doc's display form).
  const tagged = decodeBytewords(share.bytewords, "standard");
  expect(bytesToHex(tagged)).toBe(share.taggedCborHex);
  expect(toUr(value, sskrCodec).toString()).toBe(share.ur);
});
