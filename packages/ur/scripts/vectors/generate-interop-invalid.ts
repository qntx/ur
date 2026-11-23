/**
 * Generates `vectors/interop/invalid.json`: feeds each malformed _untagged body_ through the
 * codec's `decode` and records the thrown `CborError.code` as `tsError`. Run: `bun
 * packages/ur/scripts/vectors/generate-interop-invalid.ts`.
 */

import { writeFileSync } from "node:fs";

import {
  CborError,
  CborMap,
  Tag,
  bytesToHex,
  cbor,
  decodeCbor,
  encodeCbor,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

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
import { INTEROP_TAGS } from "../../src/interop/tags.ts";
import type { UrCodec } from "../../src/typed/index.ts";

const ROOT = new URL("../../../../vectors/interop/", import.meta.url).pathname;

const hex = bytesToHex;
const uuid = (b: Uint8Array): Cbor => taggedValue(INTEROP_TAGS.uuid, cbor(b));
const UUID16 = new Uint8Array(16).fill(0x9b);
const tag = (n: number, inner: Cbor): Cbor => taggedValue(Tag.from(n), inner);

// A concrete path body `{1: [i, hardened...], 2: xfp, 3: depth}` and its #6.304 wrapper.
function pathBody(components: Cbor[]): Cbor {
  const map = new CborMap();
  map.set(1, components);
  map.set(2, 0x73c5da0a);
  map.set(3, components.length);
  return cbor(map);
}
const indexStep = (index: number, hardened: boolean): Cbor[] => [cbor(index), cbor(hardened)];
const PATH = tag(304, pathBody([...indexStep(44, true), ...indexStep(60, true)]));
const PATH_WILDCARD = tag(304, pathBody([cbor([])]));
const PATH_RANGE = tag(304, pathBody([cbor([0, 3]), cbor(false)]));
const PATH_PAIR = tag(304, pathBody([cbor([0, false, 1, false])]));
const PATH_EMPTY = tag(
  304,
  (() => {
    const map = new CborMap();
    map.set(1, []);
    map.set(2, 0x73c5da0a);
    return cbor(map);
  })(),
);

const BODY = (
  ...entries: Array<[number, Cbor | number | string | Uint8Array | boolean]>
): string => {
  const map = new CborMap();
  for (const [k, v] of entries) {
    map.set(k, v instanceof Uint8Array ? cbor(v) : v);
  }
  return hex(encodeCbor(cbor(map)));
};

const ETH_FULL: Array<[number, Cbor | number | string | Uint8Array]> = [
  [1, uuid(UUID16)],
  [2, new Uint8Array([1, 2, 3])],
  [3, 1],
  [4, 1],
  [5, PATH],
  [6, new Uint8Array(20).fill(0xab)],
  [7, "MetaMask"],
];

const invalid: Array<{ name: string; codec: string; inputCborHex: string; tsError: string }> = [];

function push<T>(name: string, codec: UrCodec<T>, codecName: string, body: string): void {
  let tsError = "";
  try {
    const bytes = new Uint8Array(body.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
    }
    codec.decode(decodeCbor(bytes));
  } catch (error) {
    tsError = error instanceof CborError ? error.code : "";
  }
  if (tsError === "") {
    throw new Error(`${name}: decode unexpectedly succeeded`);
  }
  invalid.push({ name, codec: codecName, inputCborHex: body, tsError });
}

// ── eth-sign-request ──
const E = (name: string, body: string): void =>
  push(name, ethSignRequestCodec, "eth-sign-request", body);
E("unknown key", BODY(...ETH_FULL, [8, 1]));
E("signData wrong type", BODY([2, cbor("text")], [3, 1], [5, PATH]));
E("empty signData", BODY([2, new Uint8Array(0)], [3, 1], [5, PATH]));
E("missing signData", BODY([3, 1], [5, PATH]));
E(
  "requestId 15 bytes",
  BODY([1, uuid(new Uint8Array(15))], [2, new Uint8Array([1])], [3, 1], [5, PATH]),
);
E(
  "requestId 17 bytes",
  BODY([1, uuid(new Uint8Array(17))], [2, new Uint8Array([1])], [3, 1], [5, PATH]),
);
E("requestId untagged", BODY([1, cbor(UUID16)], [2, new Uint8Array([1])], [3, 1], [5, PATH]));
E(
  "requestId wrong tag",
  BODY([1, tag(38, cbor(UUID16))], [2, new Uint8Array([1])], [3, 1], [5, PATH]),
);
E("dataType 0", BODY([2, new Uint8Array([1])], [3, 0], [5, PATH]));
E("dataType 5", BODY([2, new Uint8Array([1])], [3, 5], [5, PATH]));
E("dataType wrong type", BODY([2, new Uint8Array([1])], [3, cbor("x")], [5, PATH]));
E("chainId 0", BODY([2, new Uint8Array([1])], [3, 1], [4, 0], [5, PATH]));
E("chainId negative", BODY([2, new Uint8Array([1])], [3, 1], [4, cbor(-1)], [5, PATH]));
E(
  "chainId 2^53",
  BODY([2, new Uint8Array([1])], [3, 1], [4, cbor(0x20_00_00_00_00_00_00)], [5, PATH]),
);
E("address 19 bytes", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH], [6, new Uint8Array(19)]));
E("address 21 bytes", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH], [6, new Uint8Array(21)]));
E("missing derivationPath", BODY([2, new Uint8Array([1])], [3, 1]));
E(
  "derivationPath untagged",
  BODY([2, new Uint8Array([1])], [3, 1], [5, pathBody([...indexStep(0, false)])]),
);
E(
  "derivationPath foreign tag",
  BODY([2, new Uint8Array([1])], [3, 1], [5, tag(305, pathBody([...indexStep(0, false)]))]),
);
E("derivationPath wildcard", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH_WILDCARD]));
E("derivationPath range", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH_RANGE]));
E("derivationPath pair", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH_PAIR]));
E("derivationPath empty", BODY([2, new Uint8Array([1])], [3, 1], [5, PATH_EMPTY]));

// ── eth-signature ──
const ES = (name: string, body: string): void =>
  push(name, ethSignatureCodec, "eth-signature", body);
ES("signature 64 bytes", BODY([2, new Uint8Array(64)]));
ES("signature 73 bytes", BODY([2, new Uint8Array(73)]));
ES("signature missing", BODY([1, uuid(UUID16)]));

// ── sol-sign-request ──
const S = (name: string, body: string): void =>
  push(name, solSignRequestCodec, "sol-sign-request", body);
S("signType 0", BODY([2, new Uint8Array([1])], [3, PATH], [6, 0]));
S("signType 5", BODY([2, new Uint8Array([1])], [3, PATH], [6, 5]));
S("missing signType", BODY([2, new Uint8Array([1])], [3, PATH]));
S("empty address", BODY([2, new Uint8Array([1])], [3, PATH], [4, new Uint8Array(0)], [6, 1]));

// ── sol-signature ──
const SS = (name: string, body: string): void =>
  push(name, solSignatureCodec, "sol-signature", body);
SS("signature 63 bytes", BODY([2, new Uint8Array(63)]));
SS("signature 65 bytes", BODY([2, new Uint8Array(65)]));

// ── tron-sign-request ──
const T = (name: string, body: string): void =>
  push(name, tronSignRequestCodec, "tron-sign-request", body);
const TO = (name: string, body: string): void =>
  push(name, oneKeyTronSignRequestCodec, "onekey-tron-sign-request", body);
T("keystone dataType 3", BODY([2, new Uint8Array([1])], [3, 3], [4, PATH]));
T("keystone dataType 0", BODY([2, new Uint8Array([1])], [3, 0], [4, PATH]));
T("keystone missing path", BODY([2, new Uint8Array([1])], [3, 1]));
T("key3 wrong type", BODY([2, new Uint8Array([1])], [3, cbor("x")], [6, 1]));
T("onekey messageV1 rejected by keystone codec", BODY([2, new Uint8Array([1])], [3, PATH], [6, 2]));
TO("onekey requestType 0", BODY([2, new Uint8Array([1])], [3, PATH], [6, 0]));
TO("onekey requestType 4", BODY([2, new Uint8Array([1])], [3, PATH], [6, 4]));
TO("onekey missing requestType", BODY([2, new Uint8Array([1])], [3, PATH]));
TO(
  "empty address onekey",
  BODY([2, new Uint8Array([1])], [3, PATH], [4, new Uint8Array(0)], [6, 1]),
);

// ── tron-signature ──
const TS = (name: string, body: string): void =>
  push(name, tronSignatureCodec, "tron-signature", body);
TS("signature 64 bytes", BODY([2, new Uint8Array(64)]));
TS("signature 66 bytes", BODY([2, new Uint8Array(66)]));

// ── crypto-multi-accounts ──
const M = (name: string, body: string): void =>
  push(name, cryptoMultiAccountsCodec, "crypto-multi-accounts", body);
const hdkeyBody = (
  keyData: Uint8Array,
  extra: Array<[number, Cbor | number | Uint8Array | boolean]> = [],
): Cbor => {
  const map = new CborMap();
  for (const [k, v] of extra) {
    map.set(k, v instanceof Uint8Array ? cbor(v) : v);
  }
  map.set(3, cbor(keyData));
  return cbor(map);
};
const key303 = (inner: Cbor): Cbor => tag(303, inner);
const pub33 = new Uint8Array(33).fill(0x02);
const priv33 = new Uint8Array(33).fill(0xaa);
priv33[0] = 0;
M("empty keys", BODY([1, 0x73c5da0a], [2, cbor([])]));
M("missing keys", BODY([1, 0x73c5da0a]));
M("unknown key", BODY([1, 0x73c5da0a], [2, cbor([key303(hdkeyBody(pub33))])], [6, 1]));
M(
  "master key",
  BODY(
    [1, 0x73c5da0a],
    [
      2,
      cbor([
        key303(
          (() => {
            const map = new CborMap();
            map.set(1, true);
            map.set(3, cbor(pub33));
            map.set(4, cbor(new Uint8Array(32)));
            return cbor(map);
          })(),
        ),
      ]),
    ],
  ),
);
M(
  "private secp256k1 key",
  BODY([1, 0x73c5da0a], [2, cbor([key303(hdkeyBody(priv33, [[2, true]]))])]),
);
M("key-data 31 bytes", BODY([1, 0x73c5da0a], [2, cbor([key303(hdkeyBody(new Uint8Array(31)))])]));
M("key tag 302", BODY([1, 0x73c5da0a], [2, cbor([tag(302, hdkeyBody(pub33))])]));
M(
  "ed25519 isPrivate true",
  BODY([1, 0x73c5da0a], [2, cbor([key303(hdkeyBody(new Uint8Array(32), [[2, true]]))])]),
);
M(
  "ed25519 chain code wrong length",
  BODY(
    [1, 0x73c5da0a],
    [2, cbor([key303(hdkeyBody(new Uint8Array(32), [[4, new Uint8Array(16)]]))])],
  ),
);

const doc = {
  schema: "interop-invalid/v1",
  capability: "interop.* (all seven decoders)",
  source: {
    name: "malformed untagged bodies: `codec`.decode(inputCborHex) must throw `tsError` (a CborError code)",
  },
  cases: invalid,
};
writeFileSync(`${ROOT}invalid.json`, `${JSON.stringify(doc, null, 2)}\n`);
console.error(`wrote ${invalid.length} invalid cases`);
