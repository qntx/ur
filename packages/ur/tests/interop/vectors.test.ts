import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
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
import type {
  EthSignRequest,
  EthSignature,
  MultiAccounts,
  SolSignRequest,
  SolSignature,
  TronSignRequest,
  TronSignature,
} from "../../src/interop/index.ts";
import type { Keypath } from "../../src/registry/index.ts";
import {
  codecMap,
  fromTagged,
  fromUr,
  fromUrWith,
  toTagged,
  toUr,
  Ur,
  UrError,
} from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { vectorJson } from "../vectors.ts";

type Case = {
  readonly name: string;
  readonly urType: string;
  readonly cborHex: string;
  readonly inputCborHex?: string;
  readonly codec?: string;
  readonly ur: string;
  readonly value: Record<string, unknown>;
  readonly source: string;
};

const FILES = [
  "interop/multi-accounts.json",
  "interop/eth-sign-request.json",
  "interop/eth-signature.json",
  "interop/sol-sign-request.json",
  "interop/sol-signature.json",
  "interop/tron-sign-request.json",
  "interop/tron-signature.json",
] as const;

const CASES: ReadonlyArray<Case & { file: string; input: string; codecName: string }> =
  FILES.flatMap((file) =>
    vectorJson<{ cases: ReadonlyArray<Case> }>(file).cases.map((c) => ({
      ...c,
      file,
      input: c.inputCborHex ?? c.cborHex,
      codecName: c.codec ?? c.urType,
    })),
  );

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

function mustCase(
  pred: (c: (typeof CASES)[number]) => boolean,
  label: string,
): (typeof CASES)[number] {
  const found = CASES.find(pred);
  if (found === undefined) {
    throw new Error(`no case for ${label}`);
  }
  return found;
}

function mustCodec(name: string): UrCodec<unknown> {
  const codec = CODECS[name];
  if (codec === undefined) {
    throw new Error(`no codec for ${name}`);
  }
  return codec;
}

function pathValue(p: Keypath): Record<string, unknown> {
  return {
    components: `m/${p.components
      .map((c) => (c.kind === "index" ? `${c.index}${c.hardened ? "'" : ""}` : "?"))
      .join("/")}`,
    ...(p.sourceFingerprint === undefined
      ? {}
      : { sourceFingerprint: p.sourceFingerprint.toString(16).padStart(8, "0") }),
    ...(p.depth === undefined ? {} : { depth: p.depth }),
  };
}

function keyValue(k: MultiAccounts["keys"][number]): Record<string, unknown> {
  const inner = k.key;
  return {
    curve: k.curve,
    keyData: bytesToHex(inner.keyData),
    ...(inner.isPrivate === undefined ? {} : { isPrivate: inner.isPrivate }),
    ...(inner.chainCode === undefined ? {} : { chainCode: bytesToHex(inner.chainCode) }),
    ...(inner.useInfo === undefined
      ? {}
      : {
          useInfo: {
            ...(inner.useInfo.type === undefined ? {} : { coinType: inner.useInfo.type }),
            ...(inner.useInfo.network === undefined ? {} : { network: inner.useInfo.network }),
          },
        }),
    ...(inner.origin === undefined ? {} : { origin: pathValue(inner.origin) }),
    ...(inner.children === undefined ? {} : { children: pathValue(inner.children) }),
    ...(inner.parentFingerprint === undefined
      ? {}
      : { parentFingerprint: inner.parentFingerprint }),
    ...(inner.name === undefined ? {} : { name: inner.name }),
    ...(inner.note === undefined ? {} : { note: inner.note }),
  };
}

function valueOf(urType: string, decoded: unknown): Record<string, unknown> {
  switch (urType) {
    case "eth-sign-request": {
      const r = decoded as EthSignRequest;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signData: bytesToHex(r.signData),
        derivationPath: pathValue(r.derivationPath),
        ...(r.address === undefined ? {} : { address: bytesToHex(r.address) }),
        ...(r.origin === undefined ? {} : { origin: r.origin }),
        dataType: r.dataType,
        ...(r.chainId === undefined ? {} : { chainId: r.chainId }),
      };
    }
    case "eth-signature": {
      const r = decoded as EthSignature;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signature: bytesToHex(r.signature),
        ...(r.origin === undefined ? {} : { origin: r.origin }),
      };
    }
    case "sol-sign-request": {
      const r = decoded as SolSignRequest;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signData: bytesToHex(r.signData),
        derivationPath: pathValue(r.derivationPath),
        ...(r.address === undefined ? {} : { address: bytesToHex(r.address) }),
        ...(r.origin === undefined ? {} : { origin: r.origin }),
        signType: r.signType,
      };
    }
    case "sol-signature": {
      const r = decoded as SolSignature;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signature: bytesToHex(r.signature),
      };
    }
    case "tron-sign-request": {
      const r = decoded as TronSignRequest;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signData: bytesToHex(r.signData),
        derivationPath: pathValue(r.derivationPath),
        ...(r.address === undefined ? {} : { address: bytesToHex(r.address) }),
        ...(r.origin === undefined ? {} : { origin: r.origin }),
        dataType: r.dataType,
      };
    }
    case "tron-signature": {
      const r = decoded as TronSignature;
      return {
        ...(r.requestId === undefined ? {} : { requestId: bytesToHex(r.requestId) }),
        signature: bytesToHex(r.signature),
      };
    }
    case "crypto-multi-accounts": {
      const r = decoded as MultiAccounts;
      return {
        masterFingerprint: r.masterFingerprint,
        keys: r.keys.map((k) => keyValue(k)),
        ...(r.device === undefined ? {} : { device: r.device }),
        ...(r.deviceId === undefined ? {} : { deviceId: r.deviceId }),
        ...(r.version === undefined ? {} : { version: r.version }),
      };
    }
    default:
      throw new Error(`unhandled urType ${urType}`);
  }
}

test.each(CASES)("interop vectors $file $name", (c) => {
  const tagged = decodeCbor(hexToBytes(c.input));
  // The named writer's reader decodes its own dialect (both TRON readers
  // also read the other's layout; cross-dialect coverage is below).
  const decodeCodec = mustCodec(c.codecName);
  const decoded = fromTagged(tagged, decodeCodec);
  expect(valueOf(c.urType, decoded)).toStrictEqual(c.value);
  // The named writer (or the single canonical writer) re-encodes byte-identically.
  const writer = decodeCodec;
  expect(bytesToHex(encodeCbor(toTagged(decoded, writer)))).toBe(c.cborHex);
  expect(toUr(decoded, writer).toString()).toBe(c.ur);
  const back = fromUr(Ur.parse(c.ur), decodeCodec);
  expect(valueOf(c.urType, back)).toStrictEqual(c.value);
});

// A TRON body written in one dialect decodes through the other writer too
// (where the data type is representable; messageV1 has no Keystone wire
// value, so the Keystone writer must reject it — asserted separately). URs
// carry untagged bodies, so `fromUr` is the cross-dialect path; `fromTagged`
// requires each codec's own tag.
const TRON = CASES.filter((c) => c.urType === "tron-sign-request");
const tronOther = (c: Case) =>
  c.codec === "onekey-tron-sign-request" ? tronSignRequestCodec : oneKeyTronSignRequestCodec;

test.each(TRON.filter((c) => c.value["dataType"] !== "messageV1"))(
  "tron cross-dialect decode $name",
  (c) => {
    const decoded = fromUr(Ur.parse(c.ur), tronOther(c));
    expect(valueOf("tron-sign-request", decoded)).toStrictEqual(c.value);
  },
);

// messageV1 has no Keystone wire value — the Keystone writer must reject it.
test.each(TRON.filter((c) => c.value["dataType"] === "messageV1"))(
  "tron keystone writer rejects $name",
  (c) => {
    expect(() => fromUr(Ur.parse(c.ur), tronOther(c))).toThrow(UrError);
  },
);

const CANONICAL_CASES: Record<string, (typeof CASES)[number]> = Object.fromEntries(
  FILES.map((file) => [
    file,
    mustCase(
      (k) => k.file === file && k.codecName !== "onekey-tron-sign-request",
      `canonical ${file}`,
    ),
  ]),
);
const ONEKEY_TRON_CASE = mustCase((k) => k.codec === "onekey-tron-sign-request", "onekey tron");

function canonicalCase(file: string): (typeof CASES)[number] {
  const c = CANONICAL_CASES[file];
  if (c === undefined) {
    throw new Error(`no canonical case in ${file}`);
  }
  return c;
}

// Each codec owns exactly one tag, so the canonical seven coexist in one
// codecMap; the OneKey writer's tag name collides with the Keystone one and
// belongs in its own map.
test("interop codecMap builds and dispatches each type", () => {
  const map = codecMap([
    cryptoMultiAccountsCodec,
    ethSignRequestCodec,
    ethSignatureCodec,
    solSignRequestCodec,
    solSignatureCodec,
    tronSignRequestCodec,
    tronSignatureCodec,
  ]);
  expect(map.size).toBe(7);
  for (const file of FILES) {
    const c = canonicalCase(file);
    const decoded = fromUrWith(Ur.parse(c.ur), map);
    expect(decoded.type).toBe(c.urType);
    expect(valueOf(c.urType, decoded.value)).toStrictEqual(c.value);
  }
  const oneKey = codecMap([oneKeyTronSignRequestCodec]);
  const decoded = fromUrWith(Ur.parse(ONEKEY_TRON_CASE.ur), oneKey);
  expect(decoded.type).toBe("tron-sign-request");
  expect(valueOf("tron-sign-request", decoded.value)).toStrictEqual(ONEKEY_TRON_CASE.value);
});
