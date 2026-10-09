/**
 * Generates:
 *
 * - `vectors/registry/crypto-output-conversion.json` — project-owned expectations for the v1
 *   `crypto-output`/`crypto-account` → v2 descriptor conversion (source text, v2-tagged keys,
 *   re-encoded v2 CBOR/UR), with an independent placeholder-substitution cross-check wherever every
 *   key is an eckey (or `raw`, which carries no key).
 * - `vectors/registry/invalid.json` — malformed bodies that every codec must reject.
 *
 * Usage: bun packages/ur/scripts/vectors/generate-registry.ts
 */
/// <reference types="node" />
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  CborMap,
  Tag,
  bytesToHex,
  cbor,
  decodeCbor,
  encodeCbor,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor, CborInput } from "@blockchaincommons/dcbor";

import {
  SCRIPT_TAGS,
  TAGS,
  accountDescriptorCodec,
  addressCodec,
  ecKeyCodec,
  hdKeyCodec,
  outputDescriptorCodec,
  toTagged,
  toUr,
} from "../../src/registry/index.ts";
import type { DescriptorKey } from "../../src/registry/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";

const ROOT = join(import.meta.dirname, "..", "..", "..", "..");
const VECTORS = join(ROOT, "vectors");

type Json = Record<string, unknown>;

function vector(rel: string): { source: Json; cases: Json[] } {
  const parsed: unknown = JSON.parse(readFileSync(join(VECTORS, rel), "utf8"));
  // oxlint-disable-next-line no-unsafe-type-assertion -- vector files declare their own shape
  return parsed as { source: Json; cases: Json[] };
}

function str(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`vector case: expected string ${label}`);
  }
  return value;
}

function strOrUndef(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function strList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function hex(cbor: Cbor): string {
  return bytesToHex(encodeCbor(cbor));
}

function decodeBody(cborHex: string): Cbor {
  return decodeCbor(hexToBytes(cborHex));
}

const KEY_CODECS: Record<"hdkey" | "eckey" | "address", UrCodec<unknown>> = {
  hdkey: hdKeyCodec,
  eckey: ecKeyCodec,
  address: addressCodec,
};

function taggedKeyHex(key: DescriptorKey): string {
  const codec = KEY_CODECS[key.kind];
  const value = key.kind === "address" ? key.address : key.key;
  return hex(toTagged(value, codec));
}

function keySubstitute(key: DescriptorKey): string | undefined {
  // Only eckey renders to bare hex inside descriptor text; hdkey needs BIP32
  // xpub/base58 and address needs bech32 — left to the textDescriptor fields.
  if (key.kind === "eckey") {
    return bytesToHex(key.key.data);
  }
  return undefined;
}

type DescriptorValue = { readonly source: string; readonly keys: ReadonlyArray<DescriptorKey> };

function conversionEntry(c: Json, value: DescriptorValue): Json {
  const keys = value.keys.map((k) => ({ kind: k.kind, taggedCborHex: taggedKeyHex(k) }));
  const substitutes = value.keys.map(keySubstitute);
  const crossCheck: Json = {};
  const text = strOrUndef(c["textDescriptor"]);
  if (typeof text === "string") {
    if (substitutes.every((s) => s !== undefined)) {
      const substituted = value.source.replaceAll(
        /@(\d+)/g,
        (_, d) => substitutes[Number(d)] ?? "",
      );
      crossCheck["method"] = "placeholder-substitution";
      crossCheck["textDescriptor"] = text;
      crossCheck["substituted"] = substituted;
      crossCheck["matches"] = substituted === text;
    } else {
      crossCheck["method"] = "none";
      crossCheck["textDescriptor"] = text;
      crossCheck["reason"] =
        "key rendering needs BIP32 xpub/base58 or bech32; only the tagged-CBOR keys are asserted";
    }
  }
  return { name: str(c["name"], "name"), source: value.source, keys, crossCheck };
}

function outputDescriptorCase(c: Json): Json {
  const cborHex = str(c["cborHex"], "cborHex");
  const value = outputDescriptorCodec.decode(decodeBody(cborHex));
  const v2Cbor = outputDescriptorCodec.encode(value);
  const entry = conversionEntry(c, value);
  return {
    ...entry,
    v1: { urType: c["urType"], cborHex, ur: c["ur"] },
    v2: { cborHex: hex(v2Cbor), ur: toUr(value, outputDescriptorCodec).toString() },
  };
}

function accountCase(c: Json): Json {
  const cborHex = str(c["cborHex"], "cborHex");
  const value = accountDescriptorCodec.decode(decodeBody(cborHex));
  const v2Cbor = accountDescriptorCodec.encode(value);
  const textDescriptors = strList(c["textDescriptors"]);
  const name = str(c["name"], "name");
  return {
    name,
    masterFingerprint: value.masterFingerprint,
    entries: value.outputDescriptors.map((d, i) =>
      conversionEntry({ name: `${name}[${i}]`, textDescriptor: textDescriptors[i] }, d),
    ),
    v1: { urType: c["urType"], cborHex, ur: c["ur"] },
    v2: { cborHex: hex(v2Cbor), ur: toUr(value, accountDescriptorCodec).toString() },
  };
}

const cryptoOutput = vector("official/registry/crypto-output.json");
const cryptoAccount = vector("official/registry/crypto-account.json");

const conversion = {
  schema: 1,
  capability: "registry.output-descriptor",
  source: {
    name: "project-owned v1 -> v2 conversion expectations",
    derivedFrom: [cryptoOutput.source, cryptoAccount.source],
    rule: "docs/internal/registry.mdx interface design (R3-0): script-expression tags 400-410 -> BIP-380 text with @n placeholders in order of appearance",
  },
  cases: [...cryptoOutput.cases.map(outputDescriptorCase), ...cryptoAccount.cases.map(accountCase)],
};

writeFileSync(
  join(VECTORS, "registry/crypto-output-conversion.json"),
  `${JSON.stringify(conversion, null, 2)}\n`,
);
console.log(`wrote registry/crypto-output-conversion.json (${conversion.cases.length} cases)`);

// Invalid cases

function mapCbor(entries: Array<[number, CborInput]>): Cbor {
  const map = new CborMap();
  for (const [k, v] of entries) {
    map.set(k, v);
  }
  return cbor(map);
}

function body(entries: Array<[number, CborInput]>): string {
  return hex(mapCbor(entries));
}

function multikeyMap(
  threshold: number,
  keys: CborInput[],
  extra: Array<[number, CborInput]> = [],
): Cbor {
  const map = new CborMap();
  map.set(1, threshold);
  map.set(2, keys);
  for (const [k, v] of extra) {
    map.set(k, v);
  }
  return cbor(map);
}

const B32 = "02".repeat(33); // 33-byte compressed-pubkey-shaped data
const EC_PUB = taggedValue(TAGS["crypto-eckey"], decodeBody(`a1035821${B32}`)); // 306 eckey
const EC_PUB_V2 = taggedValue(TAGS.eckey, decodeBody(`a1035821${B32}`));
const HDKEY_V1_TAGGED = taggedValue(TAGS["crypto-hdkey"], decodeBody("a1034100"));

const INVALID: Json[] = [
  // eckey — curve 0 lengths: private 32, public 33 or 65; other curves non-empty
  {
    name: "eckey empty data",
    codec: "eckey",
    cborHex: body([[3, new Uint8Array()]]),
    dcbor: "OutOfRange",
  },
  {
    name: "eckey private 31 bytes",
    codec: "eckey",
    cborHex: body([
      [2, true],
      [3, new Uint8Array(31)],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "eckey public 34 bytes",
    codec: "eckey",
    cborHex: body([[3, new Uint8Array(34)]]),
    dcbor: "OutOfRange",
  },
  {
    name: "eckey unknown key 4",
    codec: "eckey",
    cborHex: body([
      [3, new Uint8Array(33)],
      [4, 0],
    ]),
    dcbor: "WrongType",
  },
  {
    name: "eckey is-private non-bool",
    codec: "eckey",
    cborHex: body([
      [2, 1],
      [3, new Uint8Array(33)],
    ]),
    dcbor: "WrongType",
  },
  {
    name: "eckey curve non-uint",
    codec: "eckey",
    cborHex: body([
      [1, false],
      [3, new Uint8Array(33)],
    ]),
    dcbor: "WrongType",
  },
  // address
  {
    name: "address typed data 19 bytes",
    codec: "address",
    cborHex: body([
      [2, 2],
      [3, new Uint8Array(19)],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "address type out of range (3)",
    codec: "address",
    cborHex: body([
      [2, 3],
      [3, new Uint8Array(20)],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "address data empty without type",
    codec: "address",
    cborHex: body([[3, new Uint8Array()]]),
    dcbor: "OutOfRange",
  },
  {
    name: "address unknown key 4",
    codec: "address",
    cborHex: body([
      [3, new Uint8Array(20)],
      [4, 0],
    ]),
    dcbor: "WrongType",
  },
  {
    name: "address info wrong tag (crypto-hdkey 303)",
    codec: "address",
    cborHex: body([
      [1, HDKEY_V1_TAGGED],
      [3, new Uint8Array(20)],
    ]),
    dcbor: "CborType",
  },
  // output-descriptor (v2 map): placeholder set must equal 0..keys.length-1
  {
    name: "output-descriptor placeholder @1 missing @0",
    codec: "output-descriptor",
    cborHex: body([
      [1, "pk(@1)"],
      [2, [EC_PUB_V2]],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "output-descriptor placeholder @2 with one key",
    codec: "output-descriptor",
    cborHex: body([
      [1, "pk(@2)"],
      [2, [EC_PUB_V2]],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "output-descriptor key present but no placeholder",
    codec: "output-descriptor",
    cborHex: body([
      [1, "pk(03beef)"],
      [2, [EC_PUB_V2]],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "output-descriptor source non-text",
    codec: "output-descriptor",
    cborHex: body([[1, 1]]),
    dcbor: "WrongType",
  },
  {
    name: "output-descriptor unknown key 5",
    codec: "output-descriptor",
    cborHex: body([
      [1, "pk(03beef)"],
      [5, 0],
    ]),
    dcbor: "WrongType",
  },
  {
    name: "output-descriptor key entry untagged",
    codec: "output-descriptor",
    cborHex: body([
      [1, "pk(@0)"],
      [2, [decodeBody(`a1035821${B32}`)]],
    ]),
    dcbor: "WrongType",
  },
  // v1 crypto-output script expressions
  {
    name: "crypto-output tr with multikey (script tree unsupported)",
    codec: "output-descriptor",
    cborHex: hex(taggedValue(SCRIPT_TAGS.tr, multikeyMap(1, [EC_PUB]))),
    dcbor: "WrongType",
  },
  {
    name: "crypto-output multi threshold 0",
    codec: "output-descriptor",
    cborHex: hex(taggedValue(SCRIPT_TAGS.multi, multikeyMap(0, [EC_PUB]))),
    dcbor: "OutOfRange",
  },
  {
    name: "crypto-output multi threshold > keys",
    codec: "output-descriptor",
    cborHex: hex(taggedValue(SCRIPT_TAGS.multi, multikeyMap(2, [EC_PUB]))),
    dcbor: "OutOfRange",
  },
  {
    name: "crypto-output multikey unknown key 3",
    codec: "output-descriptor",
    cborHex: hex(taggedValue(SCRIPT_TAGS.multi, multikeyMap(1, [EC_PUB], [[3, 0]]))),
    dcbor: "WrongType",
  },
  {
    name: "crypto-output sh nested in sh",
    codec: "output-descriptor",
    cborHex: hex(
      taggedValue(
        SCRIPT_TAGS.sh,
        taggedValue(SCRIPT_TAGS.sh, taggedValue(SCRIPT_TAGS.pkh, EC_PUB)),
      ),
    ),
    dcbor: "WrongType",
  },
  {
    name: "crypto-output sh nested in wsh",
    codec: "output-descriptor",
    cborHex: hex(
      taggedValue(
        SCRIPT_TAGS.wsh,
        taggedValue(SCRIPT_TAGS.sh, taggedValue(SCRIPT_TAGS.pkh, EC_PUB)),
      ),
    ),
    dcbor: "WrongType",
  },
  {
    name: "crypto-output wsh nested in wsh",
    codec: "output-descriptor",
    cborHex: hex(
      taggedValue(
        SCRIPT_TAGS.wsh,
        taggedValue(SCRIPT_TAGS.wsh, taggedValue(SCRIPT_TAGS.pkh, EC_PUB)),
      ),
    ),
    dcbor: "WrongType",
  },
  {
    name: "crypto-output unknown script tag 411",
    codec: "output-descriptor",
    cborHex: hex(taggedValue(Tag.from(411, "x-unknown"), 0)),
    dcbor: "WrongType",
  },
  // account-descriptor
  {
    name: "account-descriptor empty descriptors",
    codec: "account-descriptor",
    cborHex: body([
      [1, 0x37b5eed4],
      [2, []],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "account-descriptor fingerprint > u32",
    codec: "account-descriptor",
    cborHex: body([
      [1, 0x1_00_00_00_00],
      [2, [taggedValue(TAGS["output-descriptor"], mapCbor([[1, "pk(03beef)"]]))]],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "account-descriptor unknown key 3",
    codec: "account-descriptor",
    cborHex: body([
      [1, 0x37b5eed4],
      [2, []],
      [3, 0],
    ]),
    dcbor: "WrongType",
  },
  {
    name: "account-descriptor entry untagged",
    codec: "account-descriptor",
    cborHex: body([
      [1, 0x37b5eed4],
      [2, [mapCbor([[1, "pk(03beef)"]])]],
    ]),
    dcbor: "CborType",
  },
  // shared types
  {
    name: "seed payload 65 bytes",
    codec: "seed",
    cborHex: body([[1, new Uint8Array(65)]]),
    dcbor: "OutOfRange",
  },
  {
    name: "keypath fully empty",
    codec: "keypath",
    cborHex: body([[1, []]]),
    dcbor: "WrongType",
  },
  {
    name: "hdkey derived key-data 32 bytes",
    codec: "hdkey",
    cborHex: body([
      [3, new Uint8Array(32)],
      [4, new Uint8Array(32)],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "hdkey private key-data missing 0x00 prefix",
    codec: "hdkey",
    cborHex: body([
      [2, true],
      [3, new Uint8Array(33).fill(2)],
      [4, new Uint8Array(32)],
    ]),
    dcbor: "OutOfRange",
  },
  {
    name: "psbt bad magic",
    codec: "psbt",
    cborHex: hex(cbor(new Uint8Array([0x70, 0x73, 0x62, 0x74, 0x00, ...new Uint8Array(107)]))),
    dcbor: "WrongType",
  },
];

const invalid = {
  schema: 1,
  capability: "registry.invalid",
  source: {
    name: "project-owned negative vectors",
    rule: "every listed body must be rejected by the named codec (UrError code CborType / CborError)",
  },
  cases: INVALID,
};

writeFileSync(join(VECTORS, "registry/invalid.json"), `${JSON.stringify(invalid, null, 2)}\n`);
console.log(`wrote registry/invalid.json (${INVALID.length} cases)`);
