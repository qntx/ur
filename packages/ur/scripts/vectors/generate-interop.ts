/**
 * Generates `vectors/interop/*.json`: encodes the shared inputs with this repo's interop codecs
 * (authoritative bytes + `ur`), and cross-checks the same inputs against the dev-only Keystone JS
 * oracles (`@keystonehq/bc-ur-registry-eth/sol/tron`, byte equality reported on stderr). Run: `bun
 * packages/ur/scripts/vectors/generate-interop.ts`.
 */

import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";

import {
  CborMap,
  bytesToHex,
  cbor,
  encodeCbor,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { CryptoKeypath, PathComponent } from "@keystonehq/bc-ur-registry";
import {
  DataType as EthDataType,
  ETHSignature,
  EthSignRequest,
} from "@keystonehq/bc-ur-registry-eth";
import { SignType, SolSignRequest, SolSignature } from "@keystonehq/bc-ur-registry-sol";

import {
  INTEROP_TAGS,
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
  EthSignRequest as EthReq,
  MultiAccounts,
  SolSignRequest as SolReq,
  TronSignRequest as TronReq,
} from "../../src/interop/index.ts";
import {
  cryptoCoinInfoCodec,
  cryptoHdKeyCodec,
  cryptoKeypathCodec,
} from "../../src/registry/index.ts";
import type { Keypath, PathComponent as OurPathComponent } from "../../src/registry/index.ts";
import { toUr, toTagged } from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";

// bc-ur-registry-tron 0.5.0's .mjs entry fails under Bun's CJS named-import
// interop (its vendored RegistryType resolves undefined), so the oracle goes
// through the CJS entry via createRequire like a real consumer would.
const require = createRequire(import.meta.url);
// oxlint-disable-next-line no-unsafe-type-assertion -- vendor CJS oracle; the d.mts typings describe the same exports
const tronOracle = require("@keystonehq/bc-ur-registry-tron") as {
  DataType: { transaction: number; personalMessage: number; typedMessage: number };
  TronSignRequest: new (args: Record<string, unknown>) => { toCBOR: () => Buffer };
  TronSignature: new (signature: Buffer, requestId?: Buffer) => { toCBOR: () => Buffer };
};

type BaseRegistry = {
  CryptoKeypath: new (parts: PathComponent[], fp: Buffer, depth: number) => CryptoKeypath;
  PathComponent: new (args: { index: number; hardened: boolean }) => PathComponent;
};

// Each chain package bundles its own nested `@keystonehq/bc-ur-registry`
// (e.g. 0.7.1 under eth), whose cbor-sync encoder only recognizes its own
// Tag/CryptoKeypath classes — construct keypaths with the package's own copy.
function nestedBase(pkg: string): BaseRegistry {
  const req = createRequire(`${require.resolve(pkg)}/../package.json`);
  // oxlint-disable-next-line no-unsafe-type-assertion -- vendor CJS oracle; d.ts describes the same exports
  return req("@keystonehq/bc-ur-registry") as BaseRegistry;
}

const ethBase = nestedBase("@keystonehq/bc-ur-registry-eth");
const solBase = nestedBase("@keystonehq/bc-ur-registry-sol");
const tronBase = nestedBase("@keystonehq/bc-ur-registry-tron");

const ROOT = new URL("../../../../vectors/interop/", import.meta.url).pathname;

const hex = bytesToHex;
const unhex = hexToBytes;

const REQUEST_ID = unhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d");
const XFP_HEX = "73c5da0a";
const XFP = 0x73c5da0a;
const CHAIN_CODE = unhex("47fdacbd0fefe7043c74e0f8d1a4c36a1ac90f2a5f6d0c1b2a3e4d5c6b7a8f9e");
const ADDR20 = unhex("3e88f9a1b2c3d4e5f60718293a4b5c6d7e8f9012");

function path(spec: string, withFpDepth = true): Keypath {
  const components: OurPathComponent[] = spec
    .split("/")
    .filter((s) => s.length > 0 && s !== "m")
    .map((part) => {
      const hardened = part.endsWith("'") || part.endsWith("h");
      const index = Number(part.replace(/['h]$/, ""));
      return { kind: "index", index, hardened };
    });
  return Object.freeze({
    components: Object.freeze(components),
    ...(withFpDepth ? { sourceFingerprint: XFP, depth: components.length } : {}),
  });
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

function cborHexOf<T>(codec: UrCodec<T>, value: T): string {
  return hex(encodeCbor(toTagged(value, codec)));
}

function urOf<T>(codec: UrCodec<T>, value: T): string {
  return toUr(value, codec).toString();
}

type Case = {
  name: string;
  urType: string;
  cborHex: string;
  inputCborHex?: string;
  codec?: string;
  ur: string;
  value: Record<string, unknown>;
  source: string;
};

const KS_JS =
  "Keystone JS (bc-ur-registry-*) and Rust (ur-registry 1.0.9) oracle bytes identical; Rust harness outside the repo";
const ONEKEY =
  "verified against OneKey firmware-pro d9ad133 encoder (harness outside the repo, nothing vendored)";

// ── keystone JS oracles (differential cross-check printed to stderr) ──

function kPath(base: BaseRegistry, spec: string): unknown {
  const parts = spec
    .split("/")
    .filter((s) => s.length > 0 && s !== "m")
    .map((part) => {
      const hardened = part.endsWith("'");
      return new base.PathComponent({ index: Number(part.replace(/['h]$/, "")), hardened });
    });
  return new base.CryptoKeypath(parts, Buffer.from(XFP_HEX, "hex"), parts.length);
}

function keystoneHex(item: { toCBOR: () => Buffer }): string {
  return item.toCBOR().toString("hex");
}

const diffs: string[] = [];
function check(name: string, ours: string, vendor: string): void {
  if (ours !== vendor) {
    diffs.push(`${name}: ours=${ours} vendor=${vendor}`);
  }
}

// ── eth-sign-request ──

const ethReqs: Array<[string, EthReq, string]> = [
  [
    "metamask-eth-tx-full",
    {
      requestId: REQUEST_ID,
      signData: unhex("f8aa80843b9aca00"),
      dataType: "transaction",
      chainId: 1,
      derivationPath: path("m/44'/60'/0'/0/0"),
      address: ADDR20,
      origin: "MetaMask",
    },
    KS_JS,
  ],
  [
    "eth-typed-data",
    {
      requestId: REQUEST_ID,
      signData: unhex("deadbeef"),
      dataType: "typedData",
      chainId: 137,
      derivationPath: path("m/44'/60'/0'/0/0"),
    },
    KS_JS,
  ],
  [
    "eth-personal-message-no-chainid",
    {
      signData: unhex("68656c6c6f20776f726c64"),
      dataType: "personalMessage",
      derivationPath: path("m/44'/60'/0'/0/0"),
      origin: "Rabby",
    },
    "MetaMask keyring omits chainId for personal_sign; Keystone JS oracle bytes identical",
  ],
  [
    "eth-typed-transaction-minimal",
    {
      signData: unhex("02f8aa01"),
      dataType: "typedTransaction",
      derivationPath: path("m/44'/60'/0'/0/0"),
    },
    KS_JS,
  ],
];

// ── eth-signature ──

const ethSig1 = {
  requestId: REQUEST_ID,
  signature: unhex(`${"0f".repeat(32) + "1a".repeat(32)}25`),
  origin: "MetaMask",
};
const ethSig2 = {
  signature: unhex(`${"0f".repeat(32) + "1a".repeat(32)}8501020304050607`),
};

// ── sol ──

const solReqs: Array<[string, SolReq, string]> = [
  [
    "sol-transaction",
    {
      requestId: REQUEST_ID,
      signData: unhex("0102030405060708"),
      derivationPath: path("m/44'/501'/0'/0'"),
      address: unhex("a1b2c3d4e5f6071829304142a3b4c5d6e7f8091a2b3c4d5e6f70819203a4b5"),
      origin: "Backpack",
      signType: "transaction",
    },
    KS_JS,
  ],
  [
    "sol-message",
    {
      signData: unhex("736f6c206d657373616765"),
      derivationPath: path("m/44'/501'/0'/0'"),
      signType: "message",
    },
    KS_JS,
  ],
  [
    "sol-offchain-legacy-onekey",
    {
      requestId: REQUEST_ID,
      signData: unhex("6f6666636861696e"),
      derivationPath: path("m/44'/501'/0'/0'"),
      signType: "offchainMessageLegacy",
    },
    ONEKEY,
  ],
  [
    "sol-offchain-standard-onekey",
    {
      requestId: REQUEST_ID,
      signData: unhex("6f6666636861696e207632"),
      derivationPath: path("m/44'/501'/0'/0'"),
      signType: "offchainMessageStandard",
    },
    ONEKEY,
  ],
];

const solSig = {
  requestId: REQUEST_ID,
  signature: unhex("aa".repeat(64)),
};

// ── tron ──

const tronReqs: Array<[string, TronReq, "keystone" | "onekey", string]> = [
  [
    "tron-transaction-keystone",
    {
      requestId: REQUEST_ID,
      signData: unhex("0a020db22208"),
      dataType: "transaction",
      derivationPath: path("m/44'/195'/0'/0/0"),
      address: unhex("a1b2c3d4e5f6071829304142a3b4c5d6e7f8091a2b"),
      origin: "TronLink",
    },
    "keystone",
    KS_JS,
  ],
  [
    "tron-message-v2-keystone",
    {
      signData: unhex("74726f6e206d657373616765"),
      dataType: "messageV2",
      derivationPath: path("m/44'/195'/0'/0/0"),
    },
    "keystone",
    KS_JS,
  ],
  [
    "tron-transaction-onekey",
    {
      requestId: REQUEST_ID,
      signData: unhex("0a020db22208"),
      dataType: "transaction",
      derivationPath: path("m/44'/195'/0'/0/0"),
      address: unhex("a1b2c3d4e5f6071829304142a3b4c5d6e7f8091a2b"),
      origin: "OneKey",
    },
    "onekey",
    ONEKEY,
  ],
  [
    "tron-message-v1-onekey",
    {
      requestId: REQUEST_ID,
      signData: unhex("6d7367207631"),
      dataType: "messageV1",
      derivationPath: path("m/44'/195'/0'/0/0"),
    },
    "onekey",
    ONEKEY,
  ],
  [
    "tron-message-v2-onekey",
    {
      requestId: REQUEST_ID,
      signData: unhex("6d7367207632"),
      dataType: "messageV2",
      derivationPath: path("m/44'/195'/0'/0/0"),
    },
    "onekey",
    ONEKEY,
  ],
];

const tronSig = {
  requestId: REQUEST_ID,
  signature: unhex("bb".repeat(65)),
};

// ── multi-accounts ──

function keypath(spec: string, fp = XFP): Keypath {
  const components: OurPathComponent[] = spec
    .split("/")
    .filter((s) => s.length > 0 && s !== "m")
    .map((part) => ({
      kind: "index",
      index: Number(part.replace(/['h]$/, "")),
      hardened: part.endsWith("'"),
    }));
  return Object.freeze({
    components: Object.freeze(components),
    sourceFingerprint: fp,
    depth: components.length,
  });
}

const secpKeyData = unhex("02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0");
const secpKey2Data = unhex("03ec9b8f0e1c2a3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4cd");
const ed25519KeyData = unhex("cc".repeat(32));

const multiAccountCases: Array<[string, MultiAccounts, string, string?]> = [
  [
    "keystone-connect-eth-btc",
    {
      masterFingerprint: XFP,
      keys: [
        {
          curve: "secp256k1",
          key: {
            kind: "derived",
            isPrivate: false,
            keyData: secpKeyData,
            chainCode: CHAIN_CODE,
            useInfo: { type: 60, network: 0 },
            origin: keypath("m/44'/60'/0'/0/0"),
            children: keypath("m/0/0"),
            parentFingerprint: XFP,
            name: "Keystone",
            note: "account.standard",
          },
        },
        {
          curve: "secp256k1",
          key: {
            kind: "derived",
            isPrivate: false,
            keyData: secpKey2Data,
            chainCode: CHAIN_CODE,
            useInfo: { type: 0, network: 0 },
            origin: keypath("m/44'/0'/0'"),
            parentFingerprint: XFP,
          },
        },
      ],
      device: "Keystone",
      deviceId: "8e6ff3f7-4a2b-4d1e-9c5f-7b3e2a1d0f9c",
      version: "1.2.3",
    },
    KS_JS,
  ],
  [
    "keystone-minimal",
    {
      masterFingerprint: 0,
      keys: [{ curve: "secp256k1", key: { kind: "derived", keyData: secpKeyData } }],
    },
    KS_JS,
  ],
  [
    "onekey-ed25519-empty-chaincode",
    {
      masterFingerprint: XFP,
      keys: [
        {
          curve: "ed25519",
          key: {
            isPrivate: false,
            keyData: ed25519KeyData,
            useInfo: { type: 501, network: 0 },
            origin: {
              components: [
                { kind: "index", index: 44, hardened: true },
                { kind: "index", index: 501, hardened: true },
                { kind: "index", index: 0, hardened: true },
                { kind: "index", index: 0, hardened: true },
              ],
              depth: 4,
            },
            name: "Keystone",
          },
        },
      ],
      device: "OneKey Pro",
    },
    ONEKEY,
    // OneKey's encoder emits `4: h''` for the empty ed25519 chain code; that
    // reads as absent here, so the canonical re-encode drops key 4.
  ],
];

// ── build files ──

function reqValue(r: EthReq | SolReq | TronReq): Record<string, unknown> {
  return {
    ...(r.requestId === undefined ? {} : { requestId: hex(r.requestId) }),
    signData: hex(r.signData),
    derivationPath: pathValue(r.derivationPath),
    ...(r.address === undefined ? {} : { address: hex(r.address) }),
    ...(r.origin === undefined ? {} : { origin: r.origin }),
    ...("dataType" in r ? { dataType: r.dataType } : {}),
    ...("chainId" in r && r.chainId !== undefined ? { chainId: r.chainId } : {}),
    ...("signType" in r ? { signType: r.signType } : {}),
  };
}

const files: Record<string, { capability: string; cases: Case[] }> = {};

function addFile(type: string, capability: string): void {
  files[type] = { capability, cases: [] };
}

function push(type: string, c: Case): void {
  files[type]?.cases.push(c);
}

addFile("eth-sign-request", "interop.eth-sign-request");
for (const [name, req, source] of ethReqs) {
  const cborHex = cborHexOf(ethSignRequestCodec, req);
  check(
    name,
    cborHex.slice(6),
    (() => {
      const k = new EthSignRequest({
        ...(req.requestId === undefined ? {} : { requestId: Buffer.from(req.requestId) }),
        signData: Buffer.from(req.signData),
        dataType: EthDataType[req.dataType],
        ...(req.chainId === undefined ? {} : { chainId: req.chainId }),
        // oxlint-disable-next-line no-unsafe-type-assertion -- ctor expects the package's nested CryptoKeypath; kPath builds exactly that class
        derivationPath: kPath(ethBase, "m/44'/60'/0'/0/0") as never,
        ...(req.address === undefined ? {} : { address: Buffer.from(req.address) }),
        ...(req.origin === undefined ? {} : { origin: req.origin }),
      });
      return keystoneHex(k);
    })(),
  );
  push("eth-sign-request", {
    name,
    urType: "eth-sign-request",
    cborHex,
    ur: urOf(ethSignRequestCodec, req),
    value: reqValue(req),
    source,
  });
}

addFile("eth-signature", "interop.eth-signature");
type EthSig = {
  requestId?: Uint8Array;
  signature: Uint8Array;
  origin?: string;
};
for (const [name, sig, source] of [
  ["eth-signature-full", ethSig1, KS_JS],
  ["eth-signature-72byte-v", ethSig2, KS_JS],
] as Array<[string, EthSig, string]>) {
  const cborHex = cborHexOf(ethSignatureCodec, sig);
  check(
    name,
    cborHex.slice(6),
    (() => {
      const k = new ETHSignature(
        Buffer.from(sig.signature),
        sig.requestId === undefined ? undefined : Buffer.from(sig.requestId),
        sig.origin,
      );
      return keystoneHex(k);
    })(),
  );
  push("eth-signature", {
    name,
    urType: "eth-signature",
    cborHex,
    ur: urOf(ethSignatureCodec, sig),
    value: {
      ...(sig.requestId === undefined ? {} : { requestId: hex(sig.requestId) }),
      signature: hex(sig.signature),
      ...(sig.origin === undefined ? {} : { origin: sig.origin }),
    },
    source,
  });
}

addFile("sol-sign-request", "interop.sol-sign-request");
for (const [name, req, source] of solReqs) {
  const cborHex = cborHexOf(solSignRequestCodec, req);
  if (req.signType === "transaction" || req.signType === "message") {
    check(
      name,
      cborHex.slice(6),
      (() => {
        const k = new SolSignRequest({
          ...(req.requestId === undefined ? {} : { requestId: Buffer.from(req.requestId) }),
          signData: Buffer.from(req.signData),
          // oxlint-disable-next-line no-unsafe-type-assertion -- ctor expects the package's nested CryptoKeypath; kPath builds exactly that class
          derivationPath: kPath(solBase, "m/44'/501'/0'/0'") as never,
          ...(req.address === undefined ? {} : { address: Buffer.from(req.address) }),
          ...(req.origin === undefined ? {} : { origin: req.origin }),
          signType: req.signType === "transaction" ? SignType.Transaction : SignType.Message,
        });
        return keystoneHex(k);
      })(),
    );
  }
  push("sol-sign-request", {
    name,
    urType: "sol-sign-request",
    cborHex,
    ur: urOf(solSignRequestCodec, req),
    value: reqValue(req),
    source,
  });
}

addFile("sol-signature", "interop.sol-signature");
type SolSig = { requestId?: Uint8Array; signature: Uint8Array };
for (const [name, sig, source] of [
  ["sol-signature", solSig, KS_JS],
  ["sol-signature-no-request-id", { signature: solSig.signature }, KS_JS],
] as Array<[string, SolSig, string]>) {
  const cborHex = cborHexOf(solSignatureCodec, sig);
  check(
    name,
    cborHex.slice(6),
    (() => {
      const k = new SolSignature(
        Buffer.from(sig.signature),
        sig.requestId === undefined ? undefined : Buffer.from(sig.requestId),
      );
      return keystoneHex(k);
    })(),
  );
  push("sol-signature", {
    name,
    urType: "sol-signature",
    cborHex,
    ur: urOf(solSignatureCodec, sig),
    value: {
      ...(sig.requestId === undefined ? {} : { requestId: hex(sig.requestId) }),
      signature: hex(sig.signature),
    },
    source,
  });
}

addFile("tron-sign-request", "interop.tron-sign-request");
for (const [name, req, dialect, source] of tronReqs) {
  const codec = dialect === "keystone" ? tronSignRequestCodec : oneKeyTronSignRequestCodec;
  const cborHex = cborHexOf(codec, req);
  if (dialect === "keystone") {
    check(
      name,
      cborHex.slice(6),
      (() => {
        const k = new tronOracle.TronSignRequest({
          ...(req.requestId === undefined ? {} : { requestId: Buffer.from(req.requestId) }),
          signData: Buffer.from(req.signData),
          dataType:
            req.dataType === "transaction"
              ? tronOracle.DataType.transaction
              : tronOracle.DataType.personalMessage,
          derivationPath: kPath(tronBase, "m/44'/195'/0'/0/0"),
          ...(req.address === undefined ? {} : { address: Buffer.from(req.address) }),
          ...(req.origin === undefined ? {} : { origin: req.origin }),
        });
        return keystoneHex(k);
      })(),
    );
  }
  push("tron-sign-request", {
    name,
    urType: "tron-sign-request",
    cborHex,
    codec: dialect === "keystone" ? "tron-sign-request" : "onekey-tron-sign-request",
    ur: urOf(codec, req),
    value: reqValue(req),
    source,
  });
}

addFile("tron-signature", "interop.tron-signature");
{
  const cborHex = cborHexOf(tronSignatureCodec, tronSig);
  check(
    "tron-signature",
    cborHex.slice(6),
    (() => {
      const k = new tronOracle.TronSignature(
        Buffer.from(tronSig.signature),
        Buffer.from(tronSig.requestId),
      );
      return keystoneHex(k);
    })(),
  );
  push("tron-signature", {
    name: "tron-signature",
    urType: "tron-signature",
    cborHex,
    ur: urOf(tronSignatureCodec, tronSig),
    value: { requestId: hex(tronSig.requestId), signature: hex(tronSig.signature) },
    source: KS_JS,
  });
}

addFile("multi-accounts", "interop.multi-accounts");
for (const [name, accounts, source] of multiAccountCases) {
  const cborHex = cborHexOf(cryptoMultiAccountsCodec, accounts);
  // The OneKey ed25519 dialect writes `4: h''` for the empty chain code; our
  // canonical re-encode drops it, so this case also carries `inputCborHex`.
  let inputCborHex: string | undefined;
  if (name === "onekey-ed25519-empty-chaincode") {
    const [first] = accounts.keys;
    if (first?.curve === "ed25519" && first.key.origin !== undefined) {
      const keyBody = new CborMap();
      keyBody.set(2, false);
      keyBody.set(3, cbor(first.key.keyData));
      keyBody.set(4, cbor(new Uint8Array(0)));
      keyBody.set(
        5,
        taggedValue(
          cryptoCoinInfoCodec.tags[0],
          cryptoCoinInfoCodec.encode({ type: 501, network: 0 }),
        ),
      );
      keyBody.set(
        6,
        taggedValue(cryptoKeypathCodec.tags[0], cryptoKeypathCodec.encode(first.key.origin)),
      );
      if (first.key.name !== undefined) {
        keyBody.set(9, first.key.name);
      }
      const body = new CborMap();
      body.set(1, accounts.masterFingerprint);
      body.set(2, [taggedValue(cryptoHdKeyCodec.tags[0], cbor(keyBody))]);
      if (accounts.device !== undefined) {
        body.set(3, accounts.device);
      }
      inputCborHex = hex(
        encodeCbor(taggedValue(INTEROP_TAGS["crypto-multi-accounts"], cbor(body))),
      );
    }
  }
  push("multi-accounts", {
    name,
    urType: "crypto-multi-accounts",
    cborHex,
    ...(inputCborHex === undefined ? {} : { inputCborHex }),
    ur: urOf(cryptoMultiAccountsCodec, accounts),
    value: {
      masterFingerprint: accounts.masterFingerprint,
      keys: accounts.keys.map((k) => {
        const inner = k.key;
        return {
          curve: k.curve,
          keyData: hex(inner.keyData),
          ...(inner.isPrivate === undefined ? {} : { isPrivate: inner.isPrivate }),
          ...(inner.chainCode === undefined ? {} : { chainCode: hex(inner.chainCode) }),
          ...(inner.useInfo === undefined
            ? {}
            : {
                useInfo: {
                  ...(inner.useInfo.type === undefined ? {} : { coinType: inner.useInfo.type }),
                  ...(inner.useInfo.network === undefined
                    ? {}
                    : { network: inner.useInfo.network }),
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
      }),
      ...(accounts.device === undefined ? {} : { device: accounts.device }),
      ...(accounts.deviceId === undefined ? {} : { deviceId: accounts.deviceId }),
      ...(accounts.version === undefined ? {} : { version: accounts.version }),
    },
    source,
  });
}

for (const [type, file] of Object.entries(files)) {
  const doc = {
    schema: "interop-vector/v1",
    capability: file.capability,
    source: {
      name: `interop ${type} vectors: decode \`inputCborHex\` ?? \`cborHex\`, compare \`value\`, re-encode byte-identically to \`cborHex\`, emit \`ur\``,
      keystoneJs:
        "@keystonehq/bc-ur-registry-eth 0.23.0 / -sol 0.9.5 / -tron 0.5.0 + bc-ur-registry 0.8.1 (ISC/Apache-2.0)",
      keystoneRust: "ur-registry 1.0.9 (MIT) — oracle harness outside the repo",
      onekey: "OneKeyHQ/firmware-pro d9ad133 core/src/apps/ur_registry (read-only reference)",
    },
    cases: file.cases,
  };
  writeFileSync(`${ROOT}${type}.json`, `${JSON.stringify(doc, null, 2)}\n`);
}

if (diffs.length > 0) {
  console.error("KEYSTONE JS DIFFS:");
  for (const d of diffs) {
    console.error(`  ${d}`);
  }
} else {
  console.error("all Keystone JS oracle bytes identical");
}
console.error(`wrote ${Object.keys(files).length} files to ${ROOT}`);
