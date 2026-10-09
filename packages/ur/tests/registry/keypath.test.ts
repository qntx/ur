import { CborError, CborMap, bytesToHex, encodeCbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Ur,
  UrError,
  fromUr,
  fromUrString,
  keypathCodec,
  toUr,
  toUrString,
} from "../../src/registry/index.ts";
import type { Keypath, PathComponent } from "../../src/registry/index.ts";

function errorOf(fn: () => void): UrError {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected UrError");
}

function cborHex(keypath: Keypath): string {
  return bytesToHex(encodeCbor(keypathCodec.untaggedCbor(keypath)));
}

test("keypath codec tag", () => {
  expect(keypathCodec.tags[0]?.name).toBe("keypath");
  expect(keypathCodec.tags[0]?.value).toBe(40_304);
});

test("index component encode hex", () => {
  const keypath: Keypath = {
    components: [{ kind: "index", index: 44, hardened: true }],
  };
  expect(cborHex(keypath)).toBe("a10182182cf5");
  const decoded = fromUrString(toUrString(keypath, keypathCodec), keypathCodec);
  expect(decoded.components).toStrictEqual(keypath.components);
});

test("wildcard component encode hex", () => {
  const hardened: Keypath = { components: [{ kind: "wildcard", hardened: true }] };
  const unhardened: Keypath = { components: [{ kind: "wildcard", hardened: false }] };
  expect(cborHex(hardened)).toBe("a1018280f5");
  expect(cborHex(unhardened)).toBe("a1018280f4");
  expect(fromUrString(toUrString(hardened, keypathCodec), keypathCodec).components).toStrictEqual(
    hardened.components,
  );
});

test("range component encode hex", () => {
  const keypath: Keypath = {
    components: [{ kind: "range", low: 0, high: 1, hardened: false }],
  };
  expect(cborHex(keypath)).toBe("a10182820001f4");
  expect(fromUrString(toUrString(keypath, keypathCodec), keypathCodec).components).toStrictEqual(
    keypath.components,
  );
});

test("pair component encode hex", () => {
  const keypath: Keypath = {
    components: [
      {
        kind: "pair",
        external: { index: 0, hardened: false },
        internal: { index: 1, hardened: true },
      },
    ],
  };
  expect(cborHex(keypath)).toBe("a101818400f401f5");
  expect(fromUrString(toUrString(keypath, keypathCodec), keypathCodec).components).toStrictEqual(
    keypath.components,
  );
});

test("mixed index wildcard range pair walker", () => {
  const components: ReadonlyArray<PathComponent> = [
    { kind: "index", index: 44, hardened: true },
    { kind: "wildcard", hardened: false },
    { kind: "range", low: 0, high: 1, hardened: true },
    {
      kind: "pair",
      external: { index: 0, hardened: false },
      internal: { index: 1, hardened: false },
    },
  ];
  const keypath: Keypath = { components };
  expect(cborHex(keypath)).toBe("a10187182cf580f4820001f58400f401f4");
  expect(fromUrString(toUrString(keypath, keypathCodec), keypathCodec).components).toStrictEqual(
    components,
  );
});

test("empty components with source fingerprint", () => {
  const keypath: Keypath = { components: [], sourceFingerprint: 0xe9181cf3, depth: 0 };
  expect(cborHex(keypath)).toBe("a30180021ae9181cf30300");
  const decoded = fromUrString(toUrString(keypath, keypathCodec), keypathCodec);
  expect(decoded.components).toStrictEqual([]);
  expect(decoded.sourceFingerprint).toBe(0xe9181cf3);
  expect(decoded.depth).toBe(0);
});

test("empty components without fingerprint is CborType", () => {
  const encodeErr = errorOf(() => toUrString({ components: [] }, keypathCodec));
  expect(encodeErr.code).toBe("CborType");
  expect(encodeErr.cause).toBeInstanceOf(CborError);
  expect(encodeErr.cause).toMatchObject({ code: "WrongType" });

  const map = new CborMap();
  map.set(1, []);
  const decodeErr = errorOf(() => fromUr(Ur.fromCbor("keypath", map), keypathCodec));
  expect(decodeErr.code).toBe("CborType");
});

test("missing components is CborType MissingMapKey", () => {
  const err = errorOf(() => fromUr(Ur.fromCbor("keypath", new CborMap()), keypathCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "MissingMapKey" });
});

test("extra map key is CborType", () => {
  const map = new CborMap();
  map.set(1, [0, false]);
  map.set(4, 0);
  const err = errorOf(() => fromUr(Ur.fromCbor("keypath", map), keypathCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("range low >= high is CborType OutOfRange", () => {
  const err = errorOf(() =>
    toUrString({ components: [{ kind: "range", low: 1, high: 1, hardened: false }] }, keypathCodec),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("index 0x80000000 is CborType OutOfRange", () => {
  const err = errorOf(() =>
    toUrString(
      { components: [{ kind: "index", index: 0x80_00_00_00, hardened: false }] },
      keypathCodec,
    ),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("source fingerprint 0 is CborType OutOfRange", () => {
  const err = errorOf(() => toUrString({ components: [], sourceFingerprint: 0 }, keypathCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("index missing trailing bool is CborType", () => {
  const map = new CborMap();
  map.set(1, [44]);
  const err = errorOf(() => fromUr(Ur.fromCbor("keypath", map), keypathCodec));
  expect(err.code).toBe("CborType");
});

test("pair does not consume a trailing bool", () => {
  const map = new CborMap();
  map.set(1, [[0, false, 1, false], true]);
  const err = errorOf(() => fromUr(Ur.fromCbor("keypath", map), keypathCodec));
  expect(err.code).toBe("CborType");
});

test("v1 crypto-keypath decodes and re-encodes as v2", () => {
  // No official standalone v1 keypath UR exists; v1/v2 bodies share the CDDL (BCR-2020-006).
  const keypath: Keypath = { components: [{ kind: "index", index: 44, hardened: true }] };
  const v1Uri = Ur.fromCbor("crypto-keypath", keypathCodec.untaggedCbor(keypath)).toString();
  const v2 = fromUrString(toUrString(keypath, keypathCodec), keypathCodec);
  expect(fromUrString(v1Uri, keypathCodec)).toStrictEqual(v2);
  expect(fromUrString(v1Uri.toUpperCase(), keypathCodec)).toStrictEqual(v2);
  expect(toUrString(v2, keypathCodec).startsWith("ur:keypath/")).toBe(true);
});

test("toUr copies caller path object by encoding immediately", () => {
  const components: PathComponent[] = [{ kind: "index", index: 44, hardened: true }];
  const ur = toUr({ components }, keypathCodec);
  components[0] = { kind: "index", index: 0, hardened: false };
  expect(ur.toString()).toBe(
    toUrString({ components: [{ kind: "index", index: 44, hardened: true }] }, keypathCodec),
  );
});
