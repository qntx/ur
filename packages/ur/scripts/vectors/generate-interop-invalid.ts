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
  btcSignRequestCodec,
  btcSignatureCodec,
  cryptoMultiAccountsCodec,
  ethSignRequestCodec,
  ethSignatureCodec,
  oneKeyTronSignRequestCodec,
  qrHardwareCallCodec,
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
// A decodable wildcard (`[]` component + hardened flag): rejected only by the concrete-path check.
const pathWildcardConcrete = tag(304, pathBody([cbor([]), cbor(false)]));
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

const MAP = (
  ...entries: Array<[number | string, Cbor | number | string | Uint8Array | boolean]>
): Cbor => {
  const map = new CborMap();
  for (const [k, v] of entries) {
    map.set(k, v instanceof Uint8Array ? cbor(v) : v);
  }
  return cbor(map);
};

const BODY = (
  ...entries: Array<[number | string, Cbor | number | string | Uint8Array | boolean]>
): string => hex(encodeCbor(MAP(...entries)));

const ETH_FULL: Array<[number, Cbor | number | string | Uint8Array]> = [
  [1, uuid(UUID16)],
  [2, new Uint8Array([1, 2, 3])],
  [3, 1],
  [4, 1],
  [5, PATH],
  [6, new Uint8Array(20).fill(0xab)],
  [7, "MetaMask"],
];

const invalid: Array<{
  name: string;
  codec: string;
  inputCborHex: string;
  tsError: string;
  source?: string;
}> = [];

function push<T>(
  name: string,
  codec: UrCodec<T>,
  codecName: string,
  body: string,
  source?: string,
): void {
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
  invalid.push({
    name,
    codec: codecName,
    inputCborHex: body,
    tsError,
    ...(source === undefined ? {} : { source }),
  });
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
// cbor-sync (Keystone JS) emits an fb-float for chainId >= 2^53; dcbor cannot produce one, so the
// body is asserted literally. Rejected at the dCBOR layer, before the codec runs.
push(
  "chainId 2^53 as float64 (exact bytes cbor-sync emits for chainId >= 2^53)",
  ethSignRequestCodec,
  "eth-sign-request",
  "a4024101030104fb434000000000000005d90130a30184182cf5183cf5021a73c5da0a0304",
  "@keystonehq/bc-ur-registry-eth 0.23.0 emits fb-float for chainId >= 2^53; dCBOR rejects non-canonical numerics",
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

// btc-sign-request
const B = (name: string, body: string): void =>
  push(name, btcSignRequestCodec, "btc-sign-request", body);
const BTC_REQ: Array<[number, Cbor | number | Uint8Array]> = [
  [1, uuid(UUID16)],
  [2, new Uint8Array([1, 2, 3])],
  [3, 1],
  [4, cbor([PATH])],
];
B("unknown key", BODY(...BTC_REQ, [7, 0]));
B("text key", BODY(...BTC_REQ, ["x", 0]));
B("missing requestId", BODY(...BTC_REQ.slice(1)));
B("requestId untagged", BODY([1, cbor(UUID16)], ...BTC_REQ.slice(1)));
B("requestId tag 38", BODY([1, tag(38, cbor(UUID16))], ...BTC_REQ.slice(1)));
B("requestId 15 bytes", BODY([1, uuid(new Uint8Array(15))], ...BTC_REQ.slice(1)));
B("empty signData", BODY(...BTC_REQ.slice(0, 1), [2, new Uint8Array(0)], ...BTC_REQ.slice(2)));
B("signData text", BODY(...BTC_REQ.slice(0, 1), [2, cbor("x")], ...BTC_REQ.slice(2)));
B("missing signData", BODY(...BTC_REQ.slice(0, 1), ...BTC_REQ.slice(2)));
B("dataType 0", BODY(...BTC_REQ.slice(0, 2), [3, 0], ...BTC_REQ.slice(3)));
B("dataType 2", BODY(...BTC_REQ.slice(0, 2), [3, 2], ...BTC_REQ.slice(3)));
B("missing dataType", BODY(...BTC_REQ.slice(0, 2), ...BTC_REQ.slice(3)));
B("derivationPaths empty", BODY(...BTC_REQ.slice(0, 3), [4, cbor([])]));
B("derivationPaths not array", BODY(...BTC_REQ.slice(0, 3), [4, PATH]));
B(
  "derivationPath untagged",
  BODY(...BTC_REQ.slice(0, 3), [4, cbor([pathBody([...indexStep(0, false)])])]),
);
B(
  "derivationPath tag 303",
  BODY(...BTC_REQ.slice(0, 3), [4, cbor([tag(303, pathBody([...indexStep(0, false)]))])]),
);
B("derivationPath wildcard", BODY(...BTC_REQ.slice(0, 3), [4, cbor([PATH_WILDCARD])]));
B(
  "derivationPath wildcard component",
  BODY(...BTC_REQ.slice(0, 3), [4, cbor([pathWildcardConcrete])]),
);
B("derivationPath range", BODY(...BTC_REQ.slice(0, 3), [4, cbor([PATH_RANGE])]));
B("derivationPath pair", BODY(...BTC_REQ.slice(0, 3), [4, cbor([PATH_PAIR])]));
B("derivationPath zero components", BODY(...BTC_REQ.slice(0, 3), [4, cbor([PATH_EMPTY])]));
B("addresses empty", BODY(...BTC_REQ, [5, cbor([])]));
B("addresses empty string", BODY(...BTC_REQ, [5, cbor([""])]));
B("addresses bytes", BODY(...BTC_REQ, [5, cbor([cbor(new Uint8Array([1]))])]));
B("addresses text", BODY(...BTC_REQ, [5, cbor("x")]));
B("origin uint", BODY(...BTC_REQ, [6, 0]));

// btc-signature
const BS = (name: string, body: string): void =>
  push(name, btcSignatureCodec, "btc-signature", body);
const SIG65 = new Uint8Array(65).fill(0x1f);
const PUB33 = new Uint8Array(33).fill(0x02);
const BTC_SIG: Array<[number, Cbor | Uint8Array]> = [
  [1, uuid(UUID16)],
  [2, SIG65],
  [3, PUB33],
];
BS("missing requestId", BODY(...BTC_SIG.slice(1)));
BS("missing signature", BODY(...BTC_SIG.slice(0, 1), ...BTC_SIG.slice(2)));
BS("missing publicKey", BODY(...BTC_SIG.slice(0, 2)));
BS(
  "signature 64 bytes",
  BODY(...BTC_SIG.slice(0, 1), [2, new Uint8Array(64)], ...BTC_SIG.slice(2)),
);
BS(
  "signature 66 bytes",
  BODY(...BTC_SIG.slice(0, 1), [2, new Uint8Array(66)], ...BTC_SIG.slice(2)),
);
BS("publicKey 32 bytes", BODY(...BTC_SIG.slice(0, 2), [3, new Uint8Array(32)]));
BS("publicKey 65 bytes", BODY(...BTC_SIG.slice(0, 2), [3, new Uint8Array(65)]));
BS("unknown key", BODY(...BTC_SIG, [4, 0]));
push(
  "vendor 64-byte signature and 32-byte publicKey",
  btcSignatureCodec,
  "btc-signature",
  "a301d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d02584047e7b510784406dfa14d9fd13c3834128b49c56ddfc28edb02c5047219779adeed12017e2f9f116e83762e86f805c7311ea88fb403ff21900e069142b1fb310e0358208e53e7b10656816de70824e3016fc1a277e77825e12825dc4f239f418ab2e04e",
  "asserted literal: keystone-sdk-base@029aeedb2602611cf85ca177320a0c92cf70a13c packages/ur-registry-btc/__test__/BtcSignature.test.ts (vendor signs 64B sig / 32B key; our contract requires 65B / 33B)",
);

// qr-hardware-call
const H = (name: string, body: string): void =>
  push(name, qrHardwareCallCodec, "qr-hardware-call", body);
const call1301 = (inner: Cbor): Cbor => tag(1301, inner);
const schema1302 = (inner: Cbor): Cbor => tag(1302, inner);
const SCHEMA = schema1302(MAP([1, PATH]));
const PARAMS = call1301(MAP([1, cbor([SCHEMA])]));
const schemasBody = (schemas: Cbor[]): Cbor => call1301(MAP([1, cbor(schemas)]));
H("missing callType", BODY([2, PARAMS]));
push(
  "callType derive-context-hash",
  qrHardwareCallCodec,
  "qr-hardware-call",
  "a4010102d90517a40171626162796c6f6e2d6274632d7661756c74026f626974636f696e2d6d61696e6e657403d90130a1018a182cf500f500f500f400f4046864656164626565660367626162796c6f6e0401",
  "asserted literal: keystone-sdk-rust@7f4d2258c9e79770e9c105ee49d5849b6be1c206 libs/ur-registry/src/extend/qr_hardware_call.rs test_derive_context_hash_call_roundtrip (call type 1 is out of scope)",
);
H("callType 2", BODY([1, 2], [2, PARAMS]));
H("params tag 1303", BODY([1, 0], [2, tag(1303, MAP([1, cbor([SCHEMA])]))]));
H("params untagged", BODY([1, 0], [2, MAP([1, cbor([SCHEMA])])]));
H("missing params", BODY([1, 0]));
H("version 2", BODY([1, 0], [2, PARAMS], [4, 2]));
H("unknown key", BODY([1, 0], [2, PARAMS], [5, 0]));
H("origin uint", BODY([1, 0], [2, PARAMS], [3, 0]));
H("call unknown key", BODY([1, 0], [2, call1301(MAP([1, cbor([SCHEMA])], [2, 0]))]));
H("schemas empty", BODY([1, 0], [2, call1301(MAP([1, cbor([])]))]));
H("schemas missing", BODY([1, 0], [2, call1301(MAP())]));
H("schema untagged", BODY([1, 0], [2, schemasBody([MAP([1, PATH])])]));
H("schema tag 1301", BODY([1, 0], [2, schemasBody([call1301(MAP([1, PATH]))])]));
H("schema missing keyPath", BODY([1, 0], [2, schemasBody([schema1302(MAP([2, 0]))])]));
H("curve 2", BODY([1, 0], [2, schemasBody([schema1302(MAP([1, PATH], [2, 2]))])]));
H("algorithm 2", BODY([1, 0], [2, schemasBody([schema1302(MAP([1, PATH], [3, 2]))])]));
H("schema unknown key", BODY([1, 0], [2, schemasBody([schema1302(MAP([1, PATH], [5, 0]))])]));
H("schema wildcard path", BODY([1, 0], [2, schemasBody([schema1302(MAP([1, PATH_WILDCARD]))])]));
H(
  "schema wildcard-component path",
  BODY([1, 0], [2, schemasBody([schema1302(MAP([1, pathWildcardConcrete]))])]),
);
H("chainType uint", BODY([1, 0], [2, schemasBody([schema1302(MAP([1, PATH], [4, 0]))])]));

const doc = {
  schema: "interop-invalid/v1",
  capability: "interop.* (all ten decoders)",
  source: {
    name: "malformed untagged bodies: `codec`.decode(inputCborHex) must throw `tsError` (a CborError code)",
  },
  cases: invalid,
};
writeFileSync(`${ROOT}invalid.json`, `${JSON.stringify(doc, null, 2)}\n`);
console.error(`wrote ${invalid.length} invalid cases`);
