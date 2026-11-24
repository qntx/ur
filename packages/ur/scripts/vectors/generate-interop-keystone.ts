/**
 * Generates `vectors/interop/{btc-sign-request,btc-signature,qr-hardware-call}.json`: encodes the
 * shared inputs with this repo's interop codecs (authoritative bytes + `ur`), cross-checks byte
 * equality against the dev-only Keystone JS oracles (`@keystonehq/bc-ur-registry-btc`,
 * `@keystonehq/bc-ur-registry`), and replays vendor goldens (asserted literals decode to
 * byte-identical re-encodes). Run: `bun packages/ur/scripts/vectors/generate-interop-keystone.ts`.
 */

import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";

import {
  bytesToHex,
  decodeCbor,
  encodeCbor,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";

import {
  btcSignRequestCodec,
  btcSignatureCodec,
  qrHardwareCallCodec,
  INTEROP_TAGS,
} from "../../src/interop/index.ts";
import type { BtcSignature, BtcSignRequest, QrHardwareCall } from "../../src/interop/index.ts";
import type { Keypath, PathComponent as OurPathComponent } from "../../src/registry/index.ts";
import { fromTagged, fromUr, toUr, toTagged, Ur } from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";

const require = createRequire(import.meta.url);

// oxlint-disable no-unsafe-type-assertion -- vendor CJS oracles
type PathComponent = unknown;
type CryptoKeypath = unknown;

type BtcRegistry = {
  BtcSignRequest: new (args: Record<string, unknown>) => { toCBOR: () => Buffer };
  BtcSignature: new (
    signature: Buffer,
    requestId: Buffer,
    publicKey: Buffer,
  ) => { toCBOR: () => Buffer };
  DataType: { message: number };
};

type BaseRegistry = {
  CryptoKeypath: new (parts: PathComponent[], fp?: Buffer, depth?: number) => CryptoKeypath;
  PathComponent: new (args: { index: number; hardened: boolean }) => PathComponent;
};

type HardwareRegistry = BaseRegistry & {
  QRHardwareCall: new (
    callType: number,
    params: unknown,
    origin?: string,
    version?: number,
  ) => { toCBOR: () => Buffer };
  QRHardwareCallType: { KeyDerivation: number };
  QRHardwareCallVersion: { V0: number; V1: number };
  KeyDerivation: new (schemas: unknown[]) => unknown;
  Curve: { secp256k1: number; ed25519: number };
  DerivationAlgorithm: { slip10: number; bip32ed25519: number };
  KeyDerivationSchema: new (
    keypath: CryptoKeypath,
    curve?: number,
    algo?: number,
    chainType?: string,
  ) => unknown;
};

// `@keystonehq/bc-ur-registry-btc` bundles its own nested `@keystonehq/bc-ur-registry` 0.6.4,
// whose cbor-sync encoder only recognizes its own CryptoKeypath class — build keypaths with the
// package's own copy.
function nestedBase(pkg: string): BaseRegistry {
  const req = createRequire(`${require.resolve(pkg)}/../package.json`);
  return req("@keystonehq/bc-ur-registry") as BaseRegistry;
}

const btcOracle = require("@keystonehq/bc-ur-registry-btc") as BtcRegistry;
const btcBase = nestedBase("@keystonehq/bc-ur-registry-btc");
const hwOracle = require("@keystonehq/bc-ur-registry") as HardwareRegistry;
// oxlint-enable no-unsafe-type-assertion

const ROOT = new URL("../../../../vectors/interop/", import.meta.url).pathname;

const hex = bytesToHex;
const unhex = hexToBytes;

const REQUEST_ID = unhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d");
const XFP_HEX = "73c5da0a";
const XFP = 0x73c5da0a;

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

// Keypath with a fingerprint but no depth field.
function pathFp(spec: string): Keypath {
  const p = path(spec, false);
  return Object.freeze({ ...p, sourceFingerprint: XFP });
}

function pathSpec(p: Keypath): string {
  return `m/${p.components
    .map((c) => (c.kind === "index" ? `${c.index}${c.hardened ? "'" : ""}` : "?"))
    .join("/")}`;
}

function pathValue(p: Keypath): Record<string, unknown> {
  return {
    components: pathSpec(p),
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

const BTC_ORACLE = "@keystonehq/bc-ur-registry-btc 0.1.1 (nested @keystonehq/bc-ur-registry 0.6.4)";
const HW_ORACLE = "@keystonehq/bc-ur-registry 0.8.1";

const files: Record<string, { capability: string; keystoneJs: string; cases: Case[] }> = {};
function addFile(type: string, capability: string, keystoneJs: string): void {
  files[type] = { capability, keystoneJs, cases: [] };
}
function push(type: string, c: Case): void {
  files[type]?.cases.push(c);
}

const KS_BTC_BOTH = `Keystone JS (${BTC_ORACLE}) and Rust (ur-registry 1.0.9) oracle bytes identical; Rust harness outside the repo`;
const KS_HW_JS_ONLY = `Keystone JS (${HW_ORACLE}) oracle bytes identical`;
const KS_HW_BOTH = `Keystone JS (${HW_ORACLE}) and Rust (ur-registry 1.0.9) oracle bytes identical; Rust harness outside the repo`;
const KS_RUST = "Rust (ur-registry 1.0.9) oracle bytes identical; Rust harness outside the repo";
const SDK_BASE = "keystone-sdk-base@029aeedb2602611cf85ca177320a0c92cf70a13c";
const JS_REGISTRY = "keystonehq/bc-ur-registry@ad02fb0995765a0dec8cfbd0d7bf6cdf75d50433 (JS 0.8.1)";
const RUST_REGISTRY =
  "keystone-sdk-rust@7f4d2258c9e79770e9c105ee49d5849b6be1c206 libs/ur-registry/src/extend/qr_hardware_call.rs (ur-registry 1.0.9)";

const diffs: string[] = [];
function check(name: string, ours: string, vendor: string): void {
  if (ours !== vendor) {
    diffs.push(`${name}: ours=${ours} vendor=${vendor}`);
  }
}

function keystoneHex(item: { toCBOR: () => Buffer }): string {
  return item.toCBOR().toString("hex");
}

// A keypath in the oracle's own CryptoKeypath class; `depth` written only when given.
function kPath(base: BaseRegistry, spec: string, fp: boolean, depth?: number): CryptoKeypath {
  const parts = spec
    .split("/")
    .filter((s) => s.length > 0 && s !== "m")
    .map((part) => {
      const hardened = part.endsWith("'");
      return new base.PathComponent({
        index: Number(part.replace(/['h]$/, "")),
        hardened,
      });
    });
  return new base.CryptoKeypath(parts, fp ? Buffer.from(XFP_HEX, "hex") : undefined, depth);
}

function btcReqValue(req: BtcSignRequest): Record<string, unknown> {
  return {
    requestId: hex(req.requestId),
    signData: hex(req.signData),
    dataType: req.dataType,
    derivationPaths: req.derivationPaths.map(pathValue),
    ...(req.addresses === undefined ? {} : { addresses: [...req.addresses] }),
    ...(req.origin === undefined ? {} : { origin: req.origin }),
  };
}

const btcReqs: Array<[string, BtcSignRequest, string]> = [
  [
    "btc-message-single-path",
    {
      requestId: REQUEST_ID,
      signData: unhex("48656c6c6f2063727970746f20776f726c6421"),
      dataType: "message",
      derivationPaths: [path("m/84'/0'/0'/0/0")],
      origin: "QNTX Wallet",
    },
    KS_BTC_BOTH,
  ],
  [
    "btc-message-multi-path-addresses",
    {
      requestId: REQUEST_ID,
      signData: unhex("425443206d756c74692d70617468206d657373616765"),
      dataType: "message",
      derivationPaths: [path("m/44'/0'/0'/0/0"), pathFp("m/86'/0'/0'/0/1")],
      addresses: [
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "1MjiyuupjWK5Ye13f8BAPvgby5WBuQXyJx",
      ],
    },
    KS_BTC_BOTH,
  ],
];

addFile("btc-sign-request", "interop.btc-sign-request", BTC_ORACLE);
for (const [name, req, source] of btcReqs) {
  const cborHex = cborHexOf(btcSignRequestCodec, req);
  check(
    name,
    cborHex.slice(6),
    (() => {
      const k = new btcOracle.BtcSignRequest({
        requestId: Buffer.from(req.requestId),
        signData: Buffer.from(req.signData),
        dataType: btcOracle.DataType.message,
        derivationPaths: req.derivationPaths.map((p) =>
          kPath(btcBase, pathSpec(p), p.sourceFingerprint !== undefined, p.depth),
        ),
        ...(req.addresses === undefined ? {} : { addresses: [...req.addresses] }),
        ...(req.origin === undefined ? {} : { origin: req.origin }),
      });
      return keystoneHex(k);
    })(),
  );
  push("btc-sign-request", {
    name,
    urType: "btc-sign-request",
    cborHex,
    ur: urOf(btcSignRequestCodec, req),
    value: btcReqValue(req),
    source,
  });
}

{
  // Vendor literal: decode the UR, re-encode must reproduce its bytes and `ur` exactly.
  const literal =
    "ur:btc-sign-request/oladtpdagdndcawmgtfrkigrpmndutdnbtkgfssbjnaogufdihjzjzjlcxiajpkkjojyjlcxktjljpjzieclaxadaalytaaddyoeadlecsdwykaeykaeykaewkaewkaocykscnayaaahlykscpehgtiminkkkpkpjoimhggrechkiheheoiyetfwfpgdkoioidkkechgfwkpgyhdkkgeksamimidjyiacxkthsjzjzihjypffpsbdy";
  const decoded = fromUr(Ur.parse(literal), btcSignRequestCodec);
  const cborHex = cborHexOf(btcSignRequestCodec, decoded);
  const ur = urOf(btcSignRequestCodec, decoded);
  check("vendor-btc-wallet-message ur", ur, literal);
  push("btc-sign-request", {
    name: "vendor-btc-wallet-message",
    urType: "btc-sign-request",
    cborHex,
    ur,
    value: btcReqValue(decoded),
    source: `asserted literal: ${SDK_BASE} packages/ur-registry-btc/__test__/BtcSignRequest.test.ts`,
  });
}

function btcSigValue(sig: BtcSignature): Record<string, unknown> {
  return {
    requestId: hex(sig.requestId),
    signature: hex(sig.signature),
    publicKey: hex(sig.publicKey),
  };
}

const btcSigs: Array<[string, BtcSignature, string]> = [
  [
    "btc-signature",
    {
      requestId: REQUEST_ID,
      signature: unhex(`1f${"0f".repeat(32)}${"1a".repeat(32)}`),
      publicKey: unhex(`02${"d2".repeat(32)}`),
    },
    KS_BTC_BOTH,
  ],
  [
    "btc-signature-header-20",
    {
      requestId: REQUEST_ID,
      signature: unhex(`20${"5a".repeat(32)}${"3c".repeat(32)}`),
      publicKey: unhex(`03${"7e".repeat(32)}`),
    },
    KS_BTC_BOTH,
  ],
];

addFile("btc-signature", "interop.btc-signature", BTC_ORACLE);
for (const [name, sig, source] of btcSigs) {
  const cborHex = cborHexOf(btcSignatureCodec, sig);
  check(
    name,
    cborHex.slice(6),
    keystoneHex(
      new btcOracle.BtcSignature(
        Buffer.from(sig.signature),
        Buffer.from(sig.requestId),
        Buffer.from(sig.publicKey),
      ),
    ),
  );
  push("btc-signature", {
    name,
    urType: "btc-signature",
    cborHex,
    ur: urOf(btcSignatureCodec, sig),
    value: btcSigValue(sig),
    source,
  });
}

const WIRE_CURVE: Record<string, number> = { secp256k1: 0, ed25519: 1 };
const WIRE_ALGORITHM: Record<string, number> = { slip10: 0, bip32Ed25519: 1 };

function hwCallValue(call: QrHardwareCall): Record<string, unknown> {
  return {
    params: {
      kind: call.params.kind,
      schemas: call.params.schemas.map((s) => ({
        keyPath: pathValue(s.keyPath),
        ...(s.curve === undefined ? {} : { curve: s.curve }),
        ...(s.algorithm === undefined ? {} : { algorithm: s.algorithm }),
        ...(s.chainType === undefined ? {} : { chainType: s.chainType }),
      })),
    },
    ...(call.origin === undefined ? {} : { origin: call.origin }),
    ...(call.version === undefined ? {} : { version: call.version }),
  };
}

// The JS KeyDerivationSchema always writes curve+algo (0/0 defaults), so the oracle comparison
// only applies to cases with explicit curve AND algorithm on every schema.
function hwOracleHex(call: QrHardwareCall): string {
  const schemas = call.params.schemas.map(
    (s) =>
      new hwOracle.KeyDerivationSchema(
        kPath(
          hwOracle,
          pathSpec(s.keyPath),
          s.keyPath.sourceFingerprint !== undefined,
          s.keyPath.depth,
        ),
        s.curve === undefined ? undefined : WIRE_CURVE[s.curve],
        s.algorithm === undefined ? undefined : WIRE_ALGORITHM[s.algorithm],
        s.chainType,
      ),
  );
  const k = new hwOracle.QRHardwareCall(
    hwOracle.QRHardwareCallType.KeyDerivation,
    new hwOracle.KeyDerivation(schemas),
    call.origin,
    call.version,
  );
  return keystoneHex(k);
}

const hwCalls: Array<[string, QrHardwareCall, string, boolean]> = [
  [
    "keystone-js-default-schemas",
    {
      params: {
        kind: "keyDerivation",
        schemas: [
          {
            keyPath: path("m/44'/0'/0'", false),
            curve: "secp256k1",
            algorithm: "slip10",
          },
          {
            keyPath: path("m/44'/501'/0'/0'/0'", false),
            curve: "ed25519",
            algorithm: "slip10",
          },
        ],
      },
    },
    KS_HW_JS_ONLY,
    true,
  ],
  [
    "wallet-connect-btc-eth-sol",
    {
      params: {
        kind: "keyDerivation",
        schemas: [
          { keyPath: pathFp("m/84'/0'/0'"), curve: "secp256k1", algorithm: "slip10" },
          { keyPath: pathFp("m/44'/60'/0'"), curve: "secp256k1", algorithm: "slip10" },
          { keyPath: pathFp("m/44'/501'/0'"), curve: "ed25519", algorithm: "slip10" },
        ],
      },
      origin: "QNTX Wallet",
    },
    KS_HW_JS_ONLY,
    true,
  ],
  [
    "cardano-bip32-ed25519",
    {
      params: {
        kind: "keyDerivation",
        schemas: [
          {
            keyPath: pathFp("m/1852'/1815'/0'"),
            curve: "ed25519",
            algorithm: "bip32Ed25519",
          },
        ],
      },
    },
    KS_HW_JS_ONLY,
    true,
  ],
  [
    "v1-chain-type-origin",
    {
      params: {
        kind: "keyDerivation",
        schemas: [
          {
            keyPath: pathFp("m/44'/118'/0'/0'/0'"),
            curve: "secp256k1",
            algorithm: "slip10",
            chainType: "ATOM",
          },
        ],
      },
      origin: "leap wallet",
      version: 1,
    },
    KS_HW_BOTH,
    true,
  ],
  [
    "rust-v0-explicit-version",
    {
      params: {
        kind: "keyDerivation",
        schemas: [
          { keyPath: path("m/44'/0'/0'", false) },
          {
            keyPath: path("m/44'/501'/0'/0'/0'", false),
            curve: "ed25519",
          },
        ],
      },
      version: 0,
    },
    KS_RUST,
    false,
  ],
];

addFile("qr-hardware-call", "interop.qr-hardware-call", HW_ORACLE);
for (const [name, call, source, jsOracle] of hwCalls) {
  const cborHex = cborHexOf(qrHardwareCallCodec, call);
  if (jsOracle) {
    check(name, cborHex.slice(6), hwOracleHex(call));
  }
  push("qr-hardware-call", {
    name,
    urType: "qr-hardware-call",
    cborHex,
    ur: urOf(qrHardwareCallCodec, call),
    value: hwCallValue(call),
    source,
  });
}

// Vendor goldens: decode the asserted (untagged) body, re-encode must be byte-identical; when the
// vendor test also pins a UR literal, our emitted `ur` must equal it.
function vendorHwCall(name: string, bodyHex: string, source: string, ur?: string): void {
  const taggedCbor = taggedValue(INTEROP_TAGS["qr-hardware-call"], decodeCbor(unhex(bodyHex)));
  const tagged = hex(encodeCbor(taggedCbor));
  const decoded = fromTagged(taggedCbor, qrHardwareCallCodec);
  const cborHex = cborHexOf(qrHardwareCallCodec, decoded);
  check(`${name} re-encode`, cborHex, tagged);
  const emitted = urOf(qrHardwareCallCodec, decoded);
  if (ur !== undefined) {
    check(`${name} ur`, emitted, ur);
  }
  push("qr-hardware-call", {
    name,
    urType: "qr-hardware-call",
    cborHex,
    ur: emitted,
    value: hwCallValue(decoded),
    source,
  });
}

const JS_HW = `asserted literal: ${JS_REGISTRY} __tests__/extended/QRHardwareCall.test.ts`;
const RUST_HW = `asserted literal: ${RUST_REGISTRY}`;

vendorHwCall(
  "vendor-js-schemas-v0",
  "a2010002d90515a10182d90516a301d90130a10186182cf500f500f502000300d90516a301d90130a1018a182cf51901f5f500f500f500f402010300",
  JS_HW,
  "ur:qr-hardware-call/oeadaeaotaahbzoyadlftaahcmotadtaaddyoyadlncsdwykaeykaeykaoaeaxaetaahcmotadtaaddyoyadlecsdwykcfadykykaeykaeykaewkaoadaxaecnihhtjp",
);
vendorHwCall(
  "vendor-js-v1-sol-schemas",
  "a4010002d90515a10183d90516a401d90130a10186182cf51901f5f501f5020103000463534f4cd90516a401d90130a1018a182cf51901f5f500f500f500f4020103000463534f4cd90516a401d90130a10186182cf51901f5f500f5020103000463534f4c036a5858582057616c6c65740401",
  JS_HW,
  "ur:qr-hardware-call/oxadaeaotaahbzoyadlstaahcmoxadtaaddyoyadlncsdwykcfadykykadykaoadaxaeaaiagugwgstaahcmoxadtaaddyoyadlecsdwykcfadykykaeykaeykaewkaoadaxaeaaiagugwgstaahcmoxadtaaddyoyadlncsdwykcfadykykaeykaoadaxaeaaiagugwgsaximhdhdhdcxhghsjzjzihjyaaadfgdprppm",
);
vendorHwCall(
  "vendor-js-v1-btc-sol",
  "a4010002d90515a10183d90516a401d90130a10186182cf500f500f5020003000463425443d90516a401d90130a1018a182cf51901f5f500f500f500f4020103000463534f4cd90516a401d90130a10186182cf51901f5f501f5020103000463534f4c036a5858582057616c6c65740401",
  JS_HW,
  "ur:qr-hardware-call/oxadaeaotaahbzoyadlstaahcmoxadtaaddyoyadlncsdwykaeykaeykaoaeaxaeaaiafwghfxtaahcmoxadtaaddyoyadlecsdwykcfadykykaeykaeykaewkaoadaxaeaaiagugwgstaahcmoxadtaaddyoyadlncsdwykcfadykykadykaoadaxaeaaiagugwgsaximhdhdhdcxhghsjzjzihjyaaadcfvwihvl",
);
vendorHwCall(
  "vendor-rust-v0-schemas",
  "a3010002d90515a10182d90516a101d90130a10186182cf500f500f5d90516a201d90130a1018a182cf51901f5f500f500f500f502010400",
  `${RUST_HW} test_encode`,
);
vendorHwCall(
  "vendor-rust-cardano",
  "a3010002d90515a10182d90516a301d90130a1018619073cf5190717f500f502010301d90516a301d90130a1018619073cf5190717f501f5020103010400",
  `${RUST_HW} test_encode2`,
);
vendorHwCall(
  "vendor-rust-cosmos-atom",
  "a4010002d90515a10181d90516a301d90130a1018a182cf51876f500f500f500f50200046441544f4d036b6c6561702077616c6c65740401",
  `${RUST_HW} test_encode_decode_cosmos_atom`,
);
vendorHwCall(
  "vendor-rust-leap-atom",
  "a4010002d90515a10184d90516a301d90130a10186182cf5183cf500f502000463455448d90516a301d90130a10186182cf51901f5f500f502010463534f4cd90516a301d90130a10186182cf51876f500f50200046441544f4dd90516a301d90130a1018a182cf51901f5f500f500f400f402010463534f4c036b4c6561702057616c6c65740401",
  `${RUST_HW} test_wrong_hardware_call`,
);
vendorHwCall(
  "vendor-rust-leap-eth-sol",
  "a4010002d90515a10184d90516a301d90130a10186182cf5183cf500f502000463455448d90516a301d90130a10186182cf51901f5f500f502010463534f4cd90516a301d90130a10186182cf51901f5f501f502000463534f4cd90516a301d90130a1018a182cf51901f5f500f500f400f402010463534f4c036b4c6561702057616c6c65740401",
  `${RUST_HW} test_qr_hardware_call`,
);

for (const [type, file] of Object.entries(files)) {
  const doc = {
    schema: "interop-vector/v1",
    capability: file.capability,
    source: {
      name: `interop ${type} vectors: decode \`inputCborHex\` ?? \`cborHex\`, compare \`value\`, re-encode byte-identically to \`cborHex\`, emit \`ur\``,
      keystoneJs: file.keystoneJs,
      keystoneRust: "ur-registry 1.0.9 (MIT) — oracle harness outside the repo",
    },
    cases: file.cases,
  };
  writeFileSync(`${ROOT}${type}.json`, `${JSON.stringify(doc, null, 2)}\n`);
}

if (diffs.length > 0) {
  console.error("ORACLE DIFFS:");
  for (const d of diffs) {
    console.error(`  ${d}`);
  }
  process.exitCode = 1;
} else {
  console.error("all JS oracle bytes identical; vendor literals round-trip");
}
console.error(`wrote ${Object.keys(files).length} files to ${ROOT}`);
