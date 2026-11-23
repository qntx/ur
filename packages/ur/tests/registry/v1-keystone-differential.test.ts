import {
  CborError,
  bytesToHex,
  decodeCbor,
  encodeCbor,
  hexToBytes,
} from "@blockchaincommons/dcbor";
import {
  CryptoAccount,
  CryptoCoinInfo,
  CryptoECKey,
  CryptoHDKey,
  CryptoKeypath,
  CryptoOutput,
  CryptoPSBT,
  MultiKey,
  PathComponent,
  ScriptExpressions,
} from "@keystonehq/bc-ur-registry";
import type { RegistryItem } from "@keystonehq/bc-ur-registry";
import { expect, test } from "vite-plus/test";

import {
  cryptoAccountCodec,
  cryptoCoinInfoCodec,
  cryptoHdKeyCodec,
  cryptoKeypathCodec,
  cryptoOutputCodec,
  cryptoPsbtCodec,
} from "../../src/registry/index.ts";
import type {
  CoinInfo,
  DerivedHdKey,
  HdKey,
  Keypath,
  OutputDescriptor,
} from "../../src/registry/index.ts";

// Differential oracle: Keystone JS `@keystonehq/bc-ur-registry` 0.8.1.
// `RegistryItem.toCBOR()` emits the untagged body — the same bytes our v1
// codecs carry as a `ur:crypto-*` payload. Callers pass Node `Buffer`
// instances (as Keystone's own tests do); the package's exported `Buffer`
// is the browser polyfill, which its vendored cbor encoder does not detect.
const KS_HEX = (item: RegistryItem) => Buffer.from(item.toCBOR()).toString("hex");

const eckey = (byte: number) => {
  const data = new Uint8Array(33).fill(byte);
  data[0] = 2;
  return { kind: "eckey" as const, key: { data } };
};

const EK1 = eckey(0xaa);
const EK2 = eckey(0xbb);
const EK3 = eckey(0xcc);

const ksECKey = (key: Uint8Array) => new CryptoECKey({ data: Buffer.from(key) });

const ours = <T>(codec: { encode: (v: T) => unknown }, value: T) =>
  bytesToHex(encodeCbor(codec.encode(value) as never));

// Semantic check: what Keystone's fromCBOR sees for each shape.
function keystoneKey(rt: CryptoOutput, c: OutputDescriptor): string {
  const [first] = c.keys;
  if (c.source.includes("multi(")) {
    return `multi:${rt.getMultiKey().getKeys().length}`;
  }
  if (first?.kind === "eckey") {
    return rt.getECKey().getData().toString("hex");
  }
  if (first?.kind === "hdkey") {
    return rt.getHDKey().getKey().toString("hex");
  }
  throw new Error(`unexpected key kind: ${JSON.stringify(first)}`);
}

function expectedKey(c: OutputDescriptor): string {
  const [first] = c.keys;
  if (c.source.includes("multi(")) {
    return `multi:${c.keys.length}`;
  }
  if (first?.kind === "eckey") {
    return Buffer.from(first.key.data).toString("hex");
  }
  if (first?.kind === "hdkey") {
    return Buffer.from(first.key.keyData).toString("hex");
  }
  throw new Error(`unexpected key kind: ${JSON.stringify(first)}`);
}

test("crypto-psbt: bytes identical to CryptoPSBT", () => {
  const psbtBytes = hexToBytes(
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd711bad62001900000000daabaf80d2754b6c177b3a1a3eb01c0e09fbe4d498bd8cbb10f97c26ae84438700000000160014705b90764cd30c5dd4ee1c0d8d6a028269c8f5f7af47b1000022020e77681552fe4b4df5f5c9843b894d4bd94bfd8d5a06a1f5ce2239b3925747cab47a32e38300200300f2052a01000022512ae6011d5748c74695fbf39f64f12f8f03eafef46c2425b7f8779ae19209e205b314044104498e0bc30ef4d1ae7c10d1a245f3cf9e7ffbbf14d566bf4de0dbb8dd8b7b5d505fd0c1b8a81d5ff3c6e2784d536907a352063f5c96b9736fbf8a75d0b496e6b1ac01104104498e0bc30ef4d1ae7c10d1a245f3cf9e7ffbbf14d566bf4de0dbb8dd8b7b5d505fd0c1b8a81d5ff3c6e2784d536907a352063f5c96b9736fbf8a75d0b496e6b1ac01082205755e2c2c8a7426110c8b98eccdea92d3b2757a1f2d20c3755567468f3b1e80e32208045f1a10bd5ce0f4a2e1d3f96cd6b8cd56ab8f15c1b1667fd934e4c7de86e8be6a2220349ac4f6c7d35f8b12d8b3fe21dd82b9f5b46d09a60fb7a5d51e4fa2e14c2f5b6108a3a6d9e56b3f57916cf49f8ce8f1c9c957e7a5f60e1de6151b56f7b21a1cb7e208c0ffbf12e5d06109d70135575b8cf35a3411f25f503b07480f9b79b8ce2a2220e8ddee6f35a2b705e522b6f3c307d9a3fae0e7236d04e1d79e04fcd5aa04db06c8220a9ef44c2d46e93f65a8e987c6d96b6b90fb2eb7c1e050f25e0448eccae8c7f710e04b1e3e8c1e2026b65d56dbe47e7f7e70d41406227b8b750e136b0f54d8205407ec17e2750e56b9de11e3f0c4f1938b4c5ac21b9e19dcee56e75b26a1d1d90bf77d6e5d3b01b92f0102203fce442ce8b6b50f1f86cdedf3f0d95b7d9e5ee53f4e53c27c357cde3b7be00bd1a062b0e2b9e14906e0abee6f3a8e8876a5fe160d6ba1f4bdfe9b2b2d4f43f9f3d76d5cd0e6d7df5ab7b1e523cc7e1ad23e19620d0e4b5e13a4c1f45d4555f4f60e3d19a0570febb770f99a0a6f5f2bde12ca4c6adab5b72bd5cd41be9879b5c5c606b80000",
  );
  const oursValue = { bytes: psbtBytes };
  const oursHex = ours(cryptoPsbtCodec, oursValue);
  const ks = new CryptoPSBT(Buffer.from(psbtBytes));
  expect(oursHex).toBe(KS_HEX(ks));
  // Keystone decodes our bytes; we decode theirs.
  expect(cryptoPsbtCodec.decode(decodeCbor(hexToBytes(KS_HEX(ks))))).toStrictEqual(oursValue);
  expect(CryptoPSBT.fromCBOR(Buffer.from(hexToBytes(oursHex))).getPSBT()).toStrictEqual(
    Buffer.from(psbtBytes),
  );
});

test("crypto-keypath: bytes identical to CryptoKeypath", () => {
  const oursValue: Keypath = {
    components: [
      { kind: "index", index: 44, hardened: true },
      { kind: "index", index: 0, hardened: true },
      { kind: "index", index: 0, hardened: false },
      { kind: "wildcard", hardened: false },
    ],
    sourceFingerprint: 0x78220804,
    depth: 4,
  };
  const ks = new CryptoKeypath(
    [
      new PathComponent({ index: 44, hardened: true }),
      new PathComponent({ index: 0, hardened: true }),
      new PathComponent({ index: 0, hardened: false }),
      new PathComponent({ hardened: false }),
    ],
    Buffer.from("78220804", "hex"),
    4,
  );
  const oursHex = ours(cryptoKeypathCodec, oursValue);
  expect(oursHex).toBe(KS_HEX(ks));
  expect(cryptoKeypathCodec.decode(decodeCbor(hexToBytes(KS_HEX(ks))))).toStrictEqual(oursValue);
  const rt = CryptoKeypath.fromCBOR(Buffer.from(hexToBytes(oursHex)));
  expect(rt.getPath()).toBe("44'/0'/0/*");
});

test("crypto-coin-info: bytes identical where Keystone can express the value", () => {
  // Both absent -> {}.
  expect(ours(cryptoCoinInfoCodec, {})).toBe(KS_HEX(new CryptoCoinInfo()));
  // Non-zero fields are written by both.
  const ethTestnet: CoinInfo = { type: 60, network: 1 };
  const ksEth = new CryptoCoinInfo(60 as never, 1);
  expect(ours(cryptoCoinInfoCodec, ethTestnet)).toBe(KS_HEX(ksEth));
  expect(cryptoCoinInfoCodec.decode(decodeCbor(hexToBytes(KS_HEX(ksEth))))).toStrictEqual(
    ethTestnet,
  );

  // Documented difference: Keystone JS uses truthiness, so it cannot write a
  // present-but-zero field — `new CryptoCoinInfo(0, 0)` emits `a0` while our
  // presence-preserving writer emits `a201000200`.
  const ksZero = new CryptoCoinInfo(0, 0);
  expect(KS_HEX(ksZero)).toBe("a0");
  expect(ours(cryptoCoinInfoCodec, { type: 0, network: 0 })).toBe("a201000200");
  // Keystone's `a0` still decodes on our side (fields absent, not zeros).
  expect(cryptoCoinInfoCodec.decode(decodeCbor(hexToBytes("a0")))).toStrictEqual({});
});

test("crypto-hdkey: master, is-private presence, and full derived key", () => {
  const keyData = hexToBytes(`02${"ab".repeat(32)}`);
  const masterData = hexToBytes(`00${"ef".repeat(32)}`);
  const privData = hexToBytes(`00${"cd".repeat(32)}`);
  const chainCode = hexToBytes("11".repeat(32));

  // Master: key-data is `0x00 || secret` and no is-private field exists.
  const master: HdKey = { kind: "master", keyData: masterData, chainCode };
  const ksMaster = new CryptoHDKey({
    isMaster: true,
    key: Buffer.from(masterData),
    chainCode: Buffer.from(chainCode),
  });
  const masterHex = ours(cryptoHdKeyCodec, master);
  expect(masterHex).toBe(KS_HEX(ksMaster));

  // is-private: false — Keystone writes `2: false` iff the flag is given.
  const pubFlag: DerivedHdKey = { kind: "derived", isPrivate: false, keyData };
  const ksPubFlag = new CryptoHDKey({
    isMaster: false,
    isPrivateKey: false,
    key: Buffer.from(keyData),
  });
  const pubFlagHex = ours(cryptoHdKeyCodec, pubFlag);
  expect(pubFlagHex).toBe(KS_HEX(ksPubFlag));
  expect(CryptoHDKey.fromCBOR(Buffer.from(hexToBytes(pubFlagHex))).isPrivateKey()).toBe(false);

  // is-private absent (undefined) — both omit key 2.
  const pub: DerivedHdKey = { kind: "derived", keyData };
  const ksPub = new CryptoHDKey({ isMaster: false, key: Buffer.from(keyData) });
  expect(ours(cryptoHdKeyCodec, pub)).toBe(KS_HEX(ksPub));

  // is-private: true — `0x00 || secret` key data.
  const priv: DerivedHdKey = { kind: "derived", isPrivate: true, keyData: privData };
  const ksPriv = new CryptoHDKey({
    isMaster: false,
    isPrivateKey: true,
    key: Buffer.from(privData),
  });
  const privHex = ours(cryptoHdKeyCodec, priv);
  expect(privHex).toBe(KS_HEX(ksPriv));
  expect(CryptoHDKey.fromCBOR(Buffer.from(hexToBytes(privHex))).isPrivateKey()).toBe(true);

  // Full derived key: nested v1 tags 305/304 for use-info and keypaths.
  const full: DerivedHdKey = {
    kind: "derived",
    isPrivate: false,
    keyData,
    chainCode,
    useInfo: { type: 60 },
    origin: {
      components: [
        { kind: "index", index: 44, hardened: true },
        { kind: "index", index: 60, hardened: true },
        { kind: "index", index: 0, hardened: true },
      ],
      sourceFingerprint: 0x757e6fc9,
      depth: 3,
    },
    children: {
      components: [
        { kind: "index", index: 0, hardened: false },
        { kind: "wildcard", hardened: false },
      ],
      depth: 0,
    },
    parentFingerprint: 0x42324f74,
    name: "Keystone",
    note: "account.standard",
  };
  const ksFull = new CryptoHDKey({
    isMaster: false,
    isPrivateKey: false,
    key: Buffer.from(keyData),
    chainCode: Buffer.from(chainCode),
    useInfo: new CryptoCoinInfo(60 as never, 0),
    origin: new CryptoKeypath(
      [
        new PathComponent({ index: 44, hardened: true }),
        new PathComponent({ index: 60, hardened: true }),
        new PathComponent({ index: 0, hardened: true }),
      ],
      Buffer.from("757e6fc9", "hex"),
      3,
    ),
    children: new CryptoKeypath(
      [new PathComponent({ index: 0, hardened: false }), new PathComponent({ hardened: false })],
      undefined,
      0,
    ),
    parentFingerprint: Buffer.from("42324f74", "hex"),
    name: "Keystone",
    note: "account.standard",
  });
  const fullHex = ours(cryptoHdKeyCodec, full);
  expect(fullHex).toBe(KS_HEX(ksFull));
  expect(cryptoHdKeyCodec.decode(decodeCbor(hexToBytes(KS_HEX(ksFull))))).toStrictEqual(full);
  const ksRt = CryptoHDKey.fromCBOR(Buffer.from(hexToBytes(fullHex)));
  expect(ksRt.getName()).toBe("Keystone");
  expect(ksRt.getNote()).toBe("account.standard");
  expect(ksRt.isPrivateKey()).toBe(false);

  // Documented difference: `useInfo: {type: 60, network: 0}` writes an
  // explicit `2: 0` that Keystone's truthiness encoder drops.
  const withZero = ours(cryptoHdKeyCodec, { ...full, useInfo: { type: 60, network: 0 } });
  expect(withZero).not.toBe(KS_HEX(ksFull));
  expect(withZero).toContain("d90131a201183c0200");
  expect(KS_HEX(ksFull)).toContain("d90131a101183c");
});

test("crypto-output: script trees identical to CryptoOutput", () => {
  const hdkey: DerivedHdKey = {
    kind: "derived",
    isPrivate: false,
    keyData: hexToBytes(`03${"de".repeat(32)}`),
  };
  const ksHd = new CryptoHDKey({
    isMaster: false,
    isPrivateKey: false,
    key: Buffer.from(hdkey.keyData),
  });
  const oursHd = { kind: "hdkey" as const, key: hdkey };

  const CASES: ReadonlyArray<{
    name: string;
    value: OutputDescriptor;
    make: () => RegistryItem;
  }> = [
    {
      name: "pkh eckey",
      value: { source: "pkh(@0)", keys: [EK1] },
      make: () => new CryptoOutput([ScriptExpressions.PUBLIC_KEY_HASH], ksECKey(EK1.key.data)),
    },
    {
      name: "wpkh eckey",
      value: { source: "wpkh(@0)", keys: [EK1] },
      make: () =>
        new CryptoOutput([ScriptExpressions.WITNESS_PUBLIC_KEY_HASH], ksECKey(EK1.key.data)),
    },
    {
      name: "sh(wpkh) eckey",
      value: { source: "sh(wpkh(@0))", keys: [EK1] },
      make: () =>
        new CryptoOutput(
          [ScriptExpressions.SCRIPT_HASH, ScriptExpressions.WITNESS_PUBLIC_KEY_HASH],
          ksECKey(EK1.key.data),
        ),
    },
    {
      name: "sh multi 2-of-3 eckey",
      value: { source: "sh(multi(2,@0,@1,@2))", keys: [EK1, EK2, EK3] },
      make: () =>
        new CryptoOutput(
          [ScriptExpressions.SCRIPT_HASH, ScriptExpressions.MULTISIG],
          new MultiKey(2, [ksECKey(EK1.key.data), ksECKey(EK2.key.data), ksECKey(EK3.key.data)]),
        ),
    },
    {
      name: "sh sortedmulti 2-of-3 eckey",
      value: { source: "sh(sortedmulti(2,@0,@1,@2))", keys: [EK1, EK2, EK3] },
      make: () =>
        new CryptoOutput(
          [ScriptExpressions.SCRIPT_HASH, ScriptExpressions.SORTED_MULTISIG],
          new MultiKey(2, [ksECKey(EK1.key.data), ksECKey(EK2.key.data), ksECKey(EK3.key.data)]),
        ),
    },
    {
      name: "wpkh hdkey",
      value: { source: "wpkh(@0)", keys: [oursHd] },
      make: () => new CryptoOutput([ScriptExpressions.WITNESS_PUBLIC_KEY_HASH], ksHd),
    },
    {
      // Keystone's bare-key `sh(...)` spelling: no 410 cosigner tag exists in
      // Keystone JS; `sh(key)` is exactly what our `sh(cosigner(@0))` writes.
      name: "sh bare-key cosigner spelling",
      value: { source: "sh(cosigner(@0))", keys: [EK1] },
      make: () => new CryptoOutput([ScriptExpressions.SCRIPT_HASH], ksECKey(EK1.key.data)),
    },
    {
      name: "wsh bare-key cosigner spelling",
      value: { source: "wsh(cosigner(@0))", keys: [EK1] },
      make: () => new CryptoOutput([ScriptExpressions.WITNESS_SCRIPT_HASH], ksECKey(EK1.key.data)),
    },
  ];

  for (const c of CASES) {
    const hex = ours(cryptoOutputCodec, c.value);
    const ks = c.make();
    expect(hex).toBe(KS_HEX(ks));
    // We decode Keystone's bytes back to the same descriptor.
    expect(cryptoOutputCodec.decode(decodeCbor(hexToBytes(KS_HEX(ks))))).toStrictEqual(c.value);
    // Keystone reads our bytes semantically.
    const rt = CryptoOutput.fromCBOR(Buffer.from(hexToBytes(hex)));
    expect(keystoneKey(rt, c.value)).toBe(expectedKey(c.value));
  }
});

test("crypto-account: multi-entry account identical to CryptoAccount", () => {
  const value = {
    masterFingerprint: 0x73c5da0a,
    outputDescriptors: [
      { source: "wpkh(@0)", keys: [EK1] },
      { source: "sh(wpkh(@0))", keys: [EK2] },
      { source: "sh(sortedmulti(2,@0,@1))", keys: [EK1, EK3] },
    ] as ReadonlyArray<OutputDescriptor>,
  };
  const ks = new CryptoAccount(Buffer.from("73c5da0a", "hex"), [
    new CryptoOutput([ScriptExpressions.WITNESS_PUBLIC_KEY_HASH], ksECKey(EK1.key.data)),
    new CryptoOutput(
      [ScriptExpressions.SCRIPT_HASH, ScriptExpressions.WITNESS_PUBLIC_KEY_HASH],
      ksECKey(EK2.key.data),
    ),
    new CryptoOutput(
      [ScriptExpressions.SCRIPT_HASH, ScriptExpressions.SORTED_MULTISIG],
      new MultiKey(2, [ksECKey(EK1.key.data), ksECKey(EK3.key.data)]),
    ),
  ]);
  const hex = ours(cryptoAccountCodec, value);
  expect(hex).toBe(KS_HEX(ks));

  // Entries are bare script trees — no 308 tag anywhere in the payload.
  expect(hex).not.toContain("d90134");

  expect(cryptoAccountCodec.decode(decodeCbor(hexToBytes(KS_HEX(ks))))).toStrictEqual(value);
  const rt = CryptoAccount.fromCBOR(Buffer.from(hexToBytes(hex)));
  expect(rt.getMasterFingerprint()).toStrictEqual(Buffer.from("73c5da0a", "hex"));
  expect(rt.getOutputDescriptors()).toHaveLength(3);
});

test("crypto-output: name/note unsupported by both writers", () => {
  // Keystone's CryptoOutput has no name/note fields; ours rejects them.
  const value: OutputDescriptor = {
    source: "wpkh(@0)",
    keys: [EK1],
    name: "a name",
  };
  expect(() => ours(cryptoOutputCodec, value)).toThrow(CborError);
});
