import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { decode as decodeBytewords } from "../../src/bytewords/index.ts";
import {
  hdKeyCodec,
  hdKeyDigest,
  hdKeyDigestSource,
  psbtCodec,
  seedCodec,
  sskrCodec,
  toUrString,
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
  const value = codec.fromUntaggedCbor(decodeCbor(cborBytes(c)));
  expect(bytesToHex(encodeCbor(codec.untaggedCbor(value)))).toBe(c.cborHex);
  expect(toUrString(value, codec)).toBe(c.ur);
});

test.each(digestCases)("registry.hdkey $name digest", (c) => {
  const value = hdKeyCodec.fromUntaggedCbor(decodeCbor(cborBytes(c)));
  expect(bytesToHex(hdKeyDigestSource(value))).toBe(c.digestSourceHex);
  expect(bytesToHex(hdKeyDigest(value))).toBe(c.digestHex);
});

// F-01: seedCodec rejects the v2 creation-date form (CBOR tag 100); decode round-trip cannot
// succeed until the seed schema is redesigned (R4).
const [SEED_V2] = SEED;
if (SEED_V2 !== undefined) {
  test.fails(`registry.seed ${SEED_V2.name} [F-01]`, () => {
    const codec = codecFor(SEED_V2);
    const value = codec.fromUntaggedCbor(decodeCbor(cborBytes(SEED_V2)));
    expect(bytesToHex(encodeCbor(codec.untaggedCbor(value)))).toBe(SEED_V2.cborHex);
    expect(toUrString(value, codec)).toBe(SEED_V2.ur);
  });
}

test.each(shareRows)("registry.sskr $name share $index", (share) => {
  const value = sskrCodec.fromUntaggedCbor(decodeCbor(hexToBytes(share.cborHex)));
  expect(bytesToHex(encodeCbor(sskrCodec.untaggedCbor(value)))).toBe(share.cborHex);
  // Tagged share as standard bytewords (the doc's display form).
  const tagged = decodeBytewords(share.bytewords, "standard");
  expect(bytesToHex(tagged)).toBe(share.taggedCborHex);
  expect(toUrString(value, sskrCodec)).toBe(share.ur);
});
