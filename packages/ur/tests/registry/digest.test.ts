import { CborDate, bytesToHex, hexToBytes } from "@blockchaincommons/dcbor";
import { sha256 } from "@noble/hashes/sha2.js";
import { expect, test } from "vite-plus/test";

import { hdKeyDigest, hdKeyDigestSource, seedDigest } from "../../src/registry/index.ts";
import { hdkey2, seedC709, seedYinmnFull } from "./goldens.ts";

test("c709 seedDigest is BCR-2021-002 payload SHA-256", () => {
  const digest = seedDigest({ payload: hexToBytes(seedC709.payloadHex) });
  expect(bytesToHex(digest)).toBe(seedC709.digestHex);
});

test("seedDigest ignores name date note", () => {
  const payload = hexToBytes(seedYinmnFull.payloadHex);
  const expected = bytesToHex(sha256(payload));
  const bare = seedDigest({ payload });
  const full = seedDigest({
    payload,
    creationDate: CborDate.fromEpochSeconds(seedYinmnFull.epochSeconds),
    name: seedYinmnFull.name,
    note: seedYinmnFull.note,
  });
  expect(bytesToHex(bare)).toBe(expected);
  expect(bytesToHex(full)).toBe(expected);
});

test("vector 2 hdKeyDigestSource uses network 1", () => {
  const key = {
    kind: "derived" as const,
    keyData: hexToBytes(hdkey2.keyDataHex),
    chainCode: hexToBytes(hdkey2.chainCodeHex),
    useInfo: { network: 1 },
  };
  expect(bytesToHex(hdKeyDigestSource(key))).toBe(hdkey2.digestSourceHex);
  expect(bytesToHex(hdKeyDigest(key))).toBe(hdkey2.digestHex);
});

test("master hdKeyDigestSource uses coinType 0 network 0", () => {
  const keyData = hexToBytes(hdkey2.keyDataHex);
  const chainCode = hexToBytes(hdkey2.chainCodeHex);
  const master = hdKeyDigestSource({ kind: "master", keyData, chainCode });
  const derived = hdKeyDigestSource({
    kind: "derived",
    keyData,
    chainCode,
    useInfo: { type: 0, network: 0 },
  });
  expect(bytesToHex(master)).toBe(bytesToHex(derived));
  expect(bytesToHex(master).endsWith("0000")).toBe(true);
});
