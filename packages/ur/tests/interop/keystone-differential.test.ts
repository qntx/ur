/**
 * Differential coverage against the deployed Keystone JS encoders
 * (`@keystonehq/bc-ur-registry-eth@0.23.0`, `-sol@0.9.5`, `-tron@0.5.0`,
 * `@keystonehq/bc-ur-registry@0.8.1` — dev-only oracles). Vendor `toCBOR()` returns the untagged
 * map; the generator asserts byte equality for every shared vector. Here we cross-decode in both
 * directions and exercise the MetaMask signer flow plus chain-id edge encoding.
 */

import { createRequire } from "node:module";

import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import {
  DataType as EthDataType,
  ETHSignature,
  EthSignRequest,
} from "@keystonehq/bc-ur-registry-eth";
import { expect, test } from "vite-plus/test";

import {
  ethSignRequestCodec,
  ethSignatureCodec,
  tronSignRequestCodec,
} from "../../src/interop/index.ts";
import { fromTagged, toTagged } from "../../src/typed/index.ts";

const require = createRequire(import.meta.url);
// bc-ur-registry-tron 0.5.0's .mjs entry fails under Bun's CJS named-import
// interop (its vendored RegistryType resolves undefined), so the oracle goes
// through the CJS entry via createRequire like a real consumer would.
const tronOracle = require("@keystonehq/bc-ur-registry-tron") as {
  DataType: { transaction: number; personalMessage: number; typedMessage: number };
  TronSignRequest: new (args: Record<string, unknown>) => { toCBOR: () => Buffer };
};

type BaseRegistry = {
  CryptoKeypath: new (parts: unknown[], fp: Buffer, depth: number) => unknown;
  PathComponent: new (args: { index: number; hardened: boolean }) => unknown;
};

// Each chain package bundles its own nested `@keystonehq/bc-ur-registry`
// whose cbor-sync encoder only recognizes its own Tag/CryptoKeypath classes.
function nestedBase(pkg: string): BaseRegistry {
  const req = createRequire(`${require.resolve(pkg)}/../package.json`);
  return req("@keystonehq/bc-ur-registry") as BaseRegistry;
}

const ethReg = nestedBase("@keystonehq/bc-ur-registry-eth");
const tronReg = nestedBase("@keystonehq/bc-ur-registry-tron");

const REQUEST_ID = hexToBytes("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d");
const XFP_HEX = "73c5da0a";

const maybeRequestId = (id: Uint8Array | undefined): { requestId?: Uint8Array } =>
  id === undefined ? {} : { requestId: id };

function kPath(reg: BaseRegistry, spec: string): unknown {
  const parts = spec
    .split("/")
    .filter((s) => s.length > 0 && s !== "m")
    .map(
      (part) =>
        new reg.PathComponent({
          index: Number(part.replace(/['h]$/, "")),
          hardened: part.endsWith("'"),
        }),
    );
  return new reg.CryptoKeypath(parts, Buffer.from(XFP_HEX, "hex"), parts.length);
}

const vendorBody = (item: { toCBOR: () => Buffer }): string => item.toCBOR().toString("hex");

test("keystone JS eth-sign-request bytes equal ours and cross-decode", () => {
  const request = {
    requestId: REQUEST_ID,
    signData: hexToBytes("f8aa80843b9aca00"),
    dataType: "transaction" as const,
    chainId: 1,
    derivationPath: {
      components: [
        { kind: "index" as const, index: 44, hardened: true },
        { kind: "index" as const, index: 60, hardened: true },
        { kind: "index" as const, index: 0, hardened: true },
        { kind: "index" as const, index: 0, hardened: false },
        { kind: "index" as const, index: 0, hardened: false },
      ],
      sourceFingerprint: 0x73c5da0a,
      depth: 5,
    },
    address: hexToBytes("3e88f9a1b2c3d4e5f60718293a4b5c6d7e8f9012"),
    origin: "MetaMask",
  };
  const vendor = new EthSignRequest({
    requestId: Buffer.from(REQUEST_ID),
    signData: Buffer.from(request.signData),
    dataType: EthDataType.transaction,
    chainId: 1,
    derivationPath: kPath(ethReg, "m/44'/60'/0'/0/0") as never,
    address: Buffer.from(request.address),
    origin: "MetaMask",
  });
  const ours = ethSignRequestCodec.encode(request);
  expect(bytesToHex(encodeCbor(ours))).toBe(vendorBody(vendor));
  // The vendor's untagged body decodes through our codec too.
  const vendorDecoded = ethSignRequestCodec.decode(decodeCbor(new Uint8Array(vendor.toCBOR())));
  expect(vendorDecoded.dataType).toBe("transaction");
  expect(vendorDecoded.chainId).toBe(1);
});

test("metamask signer flow: keystone request → our signature → keystone decode", () => {
  // MetaMask emits `EthSignRequest.constructETHRequest(...)`; the signer
  // answers with `eth-signature` carrying the same request id.
  const ksRequest = new EthSignRequest({
    signData: Buffer.from("hello"),
    dataType: EthDataType.personalMessage,
    derivationPath: kPath(ethReg, "m/44'/60'/0'/0/0") as never,
    requestId: Buffer.from(REQUEST_ID),
  });
  const vendorHex = vendorBody(ksRequest);
  // Wrap the vendor body under tag 401 like a real `ur:eth-sign-request` part.
  const vendorTagged = `d90191${vendorHex}`;
  const decoded = fromTagged(decodeCbor(hexToBytes(vendorTagged)), ethSignRequestCodec);
  expect(decoded.signData).toStrictEqual(hexToBytes("68656c6c6f"));
  const signature = {
    ...maybeRequestId(decoded.requestId),
    signature: new Uint8Array(65).fill(0x42),
    origin: "keystone",
  };
  const ourTagged = bytesToHex(encodeCbor(toTagged(signature, ethSignatureCodec)));
  const vendorDecoded = ETHSignature.fromCBOR(Buffer.from(ourTagged.slice(6), "hex"));
  expect(vendorDecoded.getRequestId()).toStrictEqual(Buffer.from(REQUEST_ID));
  expect(vendorDecoded.getSignature()).toStrictEqual(Buffer.alloc(65, 0x42));
});

test("keystone tron-sign-request bytes equal ours", () => {
  const request = {
    requestId: REQUEST_ID,
    signData: hexToBytes("0a020db22208"),
    dataType: "transaction" as const,
    derivationPath: {
      components: [
        { kind: "index" as const, index: 44, hardened: true },
        { kind: "index" as const, index: 195, hardened: true },
        { kind: "index" as const, index: 0, hardened: true },
        { kind: "index" as const, index: 0, hardened: false },
        { kind: "index" as const, index: 0, hardened: false },
      ],
      sourceFingerprint: 0x73c5da0a,
      depth: 5,
    },
    address: hexToBytes("a1b2c3d4e5f6071829304142a3b4c5d6e7f8091a2b"),
    origin: "TronLink",
  };
  const vendor = new tronOracle.TronSignRequest({
    requestId: Buffer.from(REQUEST_ID),
    signData: Buffer.from(request.signData),
    dataType: tronOracle.DataType.transaction,
    derivationPath: kPath(tronReg, "m/44'/195'/0'/0/0"),
    address: Buffer.from(request.address),
    origin: "TronLink",
  });
  expect(bytesToHex(encodeCbor(tronSignRequestCodec.encode(request)))).toBe(vendorBody(vendor));
});

test("keystone JS large chainId encoding probe", () => {
  // Probe: how does the vendor encode chain ids beyond uint32 / f64-int?
  // Recorded for the audit — our codec writes a canonical uint regardless.
  // Vendor results: canonical shortest uint through 2^53-1
  // (`041affffffffff` / `041b…`), but at 2^53 cbor-sync falls back to an
  // IEEE-754 double (`04fb4340000000000000`) — non-dCBOR output our strict
  // decoder rejects as `NonCanonicalNumeric` (pinned in
  // `vectors/interop/invalid.json`).
  const cases: ReadonlyArray<readonly [number, string]> = [
    [0xff_ff_ff_ff, "041affffffff"],
    [0x1_00_00_00_00, "041b0000000100000000"],
    [Number.MAX_SAFE_INTEGER, "041b001fffffffffffff"],
    [Number.MAX_SAFE_INTEGER + 1, "04fb4340000000000000"],
  ];
  for (const [chainId, key4] of cases) {
    const vendor = new EthSignRequest({
      signData: Buffer.from("x"),
      dataType: EthDataType.transaction,
      derivationPath: kPath(ethReg, "m/44'/60'/0'/0/0") as never,
      chainId,
    });
    const hex = vendorBody(vendor);
    // key 4's encoded integer immediately precedes the key-5 keypath.
    expect(hex).toContain(`${key4}05d90130`);
  }
});
