import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { decodeBytewords } from "../../src/bytewords/index.ts";
import {
  Ur,
  accountDescriptorCodec,
  addressCodec,
  ecKeyCodec,
  fromUr,
  hdKeyCodec,
  hdKeyDigest,
  hdKeyDigestSource,
  keypathCodec,
  outputDescriptorCodec,
  psbtCodec,
  seedCodec,
  sskrCodec,
  toTagged,
  toUr,
} from "../../src/registry/index.ts";
import type { DescriptorKey } from "../../src/registry/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { vectorJson } from "../vectors.ts";

type RegistryCase = {
  name: string;
  urType: string;
  textDescriptor?: string;
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
const ECKEY = vectorJson<{ cases: RegistryCase[] }>("official/registry/eckey.json").cases;
const ADDRESS = vectorJson<{ cases: RegistryCase[] }>("official/registry/address.json").cases;
const OUTDESC = vectorJson<{ cases: RegistryCase[] }>(
  "official/registry/output-descriptor.json",
).cases;
const ACCTDESC = vectorJson<{ cases: RegistryCase[] }>(
  "official/registry/account-descriptor.json",
).cases;
const CRYPTO_OUTPUT = vectorJson<{ cases: RegistryCase[] }>(
  "official/registry/crypto-output.json",
).cases;
const CRYPTO_ACCOUNT = vectorJson<{ cases: RegistryCase[] }>(
  "official/registry/crypto-account.json",
).cases;
const KS_OUTPUT = vectorJson<{ cases: RegistryCase[] }>("keystone/crypto-output.json").cases;
const KS_ACCOUNT = vectorJson<{ cases: RegistryCase[] }>("keystone/crypto-account.json").cases;
const CONVERSION = vectorJson<{ cases: ConversionCase[] }>(
  "registry/crypto-output-conversion.json",
).cases;
const INVALID = vectorJson<{ cases: InvalidCase[] }>("registry/invalid.json").cases;

type ConversionCase = {
  name: string;
  source?: string;
  keys?: Array<{ kind: string; taggedCborHex: string }>;
  entries?: Array<{ name: string; source: string }>;
  v1?: { urType: string; cborHex: string; ur?: string };
  v2?: { cborHex: string; ur: string };
  crossCheck?: {
    matches?: boolean;
    method?: string;
    substituted?: string;
    textDescriptor?: string;
  };
};

type InvalidCase = {
  name: string;
  codec: string;
  cborHex: string;
  dcbor: string;
};

const CODECS: Record<string, UrCodec<unknown>> = {
  seed: seedCodec,
  psbt: psbtCodec,
  hdkey: hdKeyCodec,
  sskr: sskrCodec,
  eckey: ecKeyCodec,
  address: addressCodec,
  "output-descriptor": outputDescriptorCodec,
  "account-descriptor": accountDescriptorCodec,
  keypath: keypathCodec,
  "crypto-output": outputDescriptorCodec,
  "crypto-account": accountDescriptorCodec,
};

function codecFor(c: RegistryCase): UrCodec<unknown> {
  const codec = CODECS[c.urType];
  if (codec === undefined) {
    throw new Error(`no codec for ${c.urType}`);
  }
  return codec;
}

function cborBytes(c: { name: string; cborHex?: string }): Uint8Array {
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

// R3-2: eckey / address / descriptors. `cborHex` is the untagged body; v2
// examples must re-encode byte-identically.
test.each([...ECKEY, ...ADDRESS, ...OUTDESC, ...ACCTDESC])("registry v2 $name", (c) => {
  const codec = codecFor(c);
  const value = codec.decode(decodeCbor(cborBytes(c)));
  expect(bytesToHex(encodeCbor(codec.encode(value)))).toBe(c.cborHex);
});

test.each([...ECKEY, ...ADDRESS, ...ACCTDESC])("registry v2 ur $name", (c) => {
  const codec = codecFor(c);
  const value = codec.decode(decodeCbor(cborBytes(c)));
  const ur = must(c.ur, `${c.name} ur`);
  expect(toUr(value, codec).toString()).toBe(ur);
  expect(fromUr(Ur.parse(ur), codec)).toStrictEqual(value);
});

function taggedKeyHex(key: DescriptorKey): string {
  const perKind: Record<DescriptorKey["kind"], UrCodec<unknown>> = {
    hdkey: hdKeyCodec,
    eckey: ecKeyCodec,
    address: addressCodec,
  };
  const codec = perKind[key.kind];
  const value = key.kind === "address" ? key.address : key.key;
  return bytesToHex(encodeCbor(toTagged(value, codec)));
}

// v1 crypto-output: decode the tagged script-expression body, then re-encode
// as v2 and compare against the project-owned conversion vector.
test.each(CRYPTO_OUTPUT)("registry v1 $name", (c) => {
  const conv = must(CONVERSION[CRYPTO_OUTPUT.indexOf(c)], "conversion case");
  const value = outputDescriptorCodec.decode(decodeCbor(cborBytes(c)));
  expect(value.source).toBe(conv.source);
  expect(value.keys.map(taggedKeyHex)).toStrictEqual(conv.keys?.map((k) => k.taggedCborHex));
  expect(bytesToHex(encodeCbor(outputDescriptorCodec.encode(value)))).toBe(conv.v2?.cborHex);
  expect(toUr(value, outputDescriptorCodec).toString()).toBe(conv.v2?.ur);
});

test.each(CONVERSION.filter((c) => c.crossCheck?.matches === true))(
  "registry v1 conversion cross-check $name",
  (conv) => {
    expect(conv.crossCheck?.method).toBe("placeholder-substitution");
    expect(conv.crossCheck?.substituted).toBe(conv.crossCheck?.textDescriptor);
  },
);

// v1 crypto-account (official + keystone): decode and re-encode as v2.
test.each(CRYPTO_ACCOUNT)("registry v1 account $name", (c) => {
  const value = accountDescriptorCodec.decode(decodeCbor(cborBytes(c)));
  expect(value.outputDescriptors.length).toBeGreaterThan(0);
  for (const d of value.outputDescriptors) {
    expect(d.source).toMatch(/@\d+|^raw\(/);
  }
});

test.each(KS_ACCOUNT)("registry v1 keystone account $name", (c) => {
  const value = fromUr(Ur.parse(must(c.ur, "keystone ur")), accountDescriptorCodec);
  expect(value.outputDescriptors.length).toBeGreaterThan(0);
  for (const d of value.outputDescriptors) {
    expect(d.source).toMatch(/@\d+|^raw\(/);
  }
});

// KeystoneHQ ur-registry (second source): the 5 crypto-output URs decode to
// the same sources as the official conversion cases; their account omits tr.
test.each(KS_OUTPUT)("keystone crypto-output $name", (c) => {
  const value = fromUr(Ur.parse(must(c.ur, "keystone ur")), outputDescriptorCodec);
  expect(value.source).toBe(CONVERSION[KS_OUTPUT.indexOf(c)]?.source);
});

test("keystone crypto-account matches official sources", () => {
  const official = accountDescriptorCodec.decode(
    decodeCbor(cborBytes(must(CRYPTO_ACCOUNT[0], "crypto-account"))),
  );
  const ks = fromUr(
    Ur.parse(must(must(KS_ACCOUNT[0], "keystone account").ur, "keystone account ur")),
    accountDescriptorCodec,
  );
  expect(ks.masterFingerprint).toBe(official.masterFingerprint);
  expect(ks.outputDescriptors.map((d) => d.source)).toStrictEqual(
    official.outputDescriptors.slice(0, -1).map((d) => d.source),
  );
});

const KS_ECKEY = KS_OUTPUT.filter(
  (c) => c.textDescriptor !== undefined && !c.textDescriptor.includes("xpub"),
);
const KS_XPUB = KS_OUTPUT.filter((c) => c.textDescriptor?.includes("xpub") === true);

function substituteEcKeys(source: string, keys: ReadonlyArray<DescriptorKey>): string {
  return source.replaceAll(/@(\d+)/g, (m, d) => {
    const key = keys[Number(d)];
    if (key?.kind !== "eckey") {
      throw new Error(`key ${m} is not an eckey`);
    }
    return bytesToHex(key.key.data);
  });
}

test.each(KS_ECKEY)("keystone $name textDescriptor cross-check", (c) => {
  const value = fromUr(Ur.parse(must(c.ur, "keystone ur")), outputDescriptorCodec);
  expect(substituteEcKeys(value.source, value.keys)).toBe(c.textDescriptor);
});

// hdkey keys need BIP32 xpub/base58 rendering — substitution impossible;
// assert only that the keystone source matches the official conversion case.
test.each(KS_XPUB)("keystone $name xpub key (unchecked text)", (c) => {
  const value = fromUr(Ur.parse(must(c.ur, "keystone ur")), outputDescriptorCodec);
  expect(value.keys.every((k) => k.kind === "hdkey")).toBe(true);
  expect(value.source).toBe(CONVERSION[KS_OUTPUT.indexOf(c)]?.source);
});

const INVALID_CODECS: Record<string, UrCodec<unknown>> = {
  eckey: ecKeyCodec,
  address: addressCodec,
  "output-descriptor": outputDescriptorCodec,
  "account-descriptor": accountDescriptorCodec,
  seed: seedCodec,
  keypath: keypathCodec,
  hdkey: hdKeyCodec,
  psbt: psbtCodec,
};

test.each(INVALID)("registry invalid: $name", (c) => {
  const codec = INVALID_CODECS[c.codec];
  expect(codec, `no codec for ${c.codec}`).toBeDefined();
  let thrown: unknown;
  try {
    codec?.decode(decodeCbor(cborBytes(c)));
  } catch (error) {
    thrown = error;
  }
  expect(thrown, `${c.name}: expected ${c.dcbor}`).toBeDefined();
  expect((thrown as { code?: string }).code).toBe(c.dcbor);
});
