import {
  CborError,
  CborMap,
  cbor,
  expectArray,
  expectMap,
  extractTaggedContent,
  taggedValue,
  validateTag,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import { copyBuf, copyBytes } from "../registry/bytes.ts";
import type { CoinInfo } from "../registry/coin-info.ts";
import { decodeDerivedHdKeyBody, readDerivedMeta, writeDerivedMeta } from "../registry/hdkey.ts";
import type { DerivedHdKey } from "../registry/hdkey.ts";
import type { Keypath } from "../registry/keypath.ts";
import { expectClosedIntMap, expectUint } from "../registry/map.ts";
import { TAGS } from "../registry/tags.ts";
import type { UrCodec } from "../typed/codec.ts";
import { optionalText, setOptionalText } from "./common.ts";
import { INTEROP_TAGS } from "./tags.ts";

const ACCOUNT_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4, 5]);
const KEY_BODY_KEYS: ReadonlySet<number> = new Set([2, 3, 4, 5, 6, 7, 8, 9, 10]);
const KEY_DATA_LEN = 33;
const ED25519_KEY_DATA_LEN = 32;
const CHAIN_CODE_LEN = 32;

export type Ed25519HdKey = {
  readonly isPrivate?: false;
  readonly keyData: Uint8Array; // 32 bytes
  readonly chainCode?: Uint8Array; // 32 bytes when present; wire h'' reads as absent
  readonly useInfo?: CoinInfo;
  readonly origin?: Keypath;
  readonly children?: Keypath;
  readonly parentFingerprint?: number;
  readonly name?: string;
  readonly note?: string;
};

export type MultiAccountsKey =
  | { readonly curve: "secp256k1"; readonly key: DerivedHdKey }
  | { readonly curve: "ed25519"; readonly key: Ed25519HdKey };

export type MultiAccounts = {
  readonly masterFingerprint: number;
  readonly keys: ReadonlyArray<MultiAccountsKey>; // non-empty
  readonly device?: string; // "" encodes as absent
  readonly deviceId?: string;
  readonly version?: string;
};

// Keys are `#6.303` tagged crypto-hdkey bodies with derived keys only:
// 33-byte keyData ⇒ secp256k1 (public key-data is opaque),
// 32-byte ⇒ Ed25519 (a field the registry hdkey cannot express).
function encodeKey(key: MultiAccountsKey): Cbor {
  if (key.curve === "secp256k1") {
    const derived = key.key;
    if (derived.isPrivate === true || derived.keyData.length !== KEY_DATA_LEN) {
      throw CborError.outOfRange();
    }
    const map = new CborMap();
    map.set(3, cbor(copyBuf(derived.keyData)));
    writeDerivedMeta(map, derived, true);
    return taggedValue(TAGS["crypto-hdkey"], cbor(map));
  }
  const ed = key.key;
  if (ed.isPrivate !== undefined && ed.isPrivate) {
    throw CborError.outOfRange();
  }
  if (ed.keyData.length !== ED25519_KEY_DATA_LEN) {
    throw CborError.outOfRange();
  }
  const map = new CborMap();
  map.set(3, cbor(copyBuf(ed.keyData)));
  writeDerivedMeta(map, ed, true);
  return taggedValue(TAGS["crypto-hdkey"], cbor(map));
}

function decodeKey(cbor: Cbor): MultiAccountsKey {
  validateTag(cbor, [TAGS["crypto-hdkey"], TAGS.hdkey]);
  const body = extractTaggedContent(cbor);
  const peek = expectMap(body);
  const keyData = peek.get(3);
  if (keyData === undefined) {
    throw CborError.wrongType();
  }
  const bytes = copyBytes(keyData);
  if (bytes.length === KEY_DATA_LEN) {
    const derived = decodeDerivedHdKeyBody(body);
    if (derived.isPrivate === true) {
      throw CborError.outOfRange();
    }
    return Object.freeze({ curve: "secp256k1", key: derived });
  }
  if (bytes.length !== ED25519_KEY_DATA_LEN) {
    throw CborError.outOfRange();
  }
  const map = expectClosedIntMap(body, KEY_BODY_KEYS);
  const meta = readDerivedMeta(map, true);
  if (meta.isPrivate === true) {
    throw CborError.outOfRange();
  }
  if (meta.chainCode !== undefined && meta.chainCode.length !== CHAIN_CODE_LEN) {
    throw CborError.outOfRange();
  }
  const { isPrivate: _isPrivate, ...rest } = meta;
  return Object.freeze({
    curve: "ed25519",
    key: Object.freeze({
      ...rest,
      keyData: bytes,
      ...(meta.isPrivate === undefined ? {} : { isPrivate: false as const }),
    }),
  });
}

function assertFingerprint(n: number): void {
  if (!Number.isInteger(n) || n < 0 || n > 0xff_ff_ff_ff) {
    throw CborError.outOfRange();
  }
}

export const cryptoMultiAccountsCodec: UrCodec<MultiAccounts> = {
  tags: [INTEROP_TAGS["crypto-multi-accounts"]],
  encode(accounts) {
    if (accounts.keys.length === 0) {
      throw CborError.outOfRange();
    }
    assertFingerprint(accounts.masterFingerprint);
    const map = new CborMap();
    map.set(1, accounts.masterFingerprint);
    const keys = accounts.keys.map(encodeKey);
    map.set(2, keys);
    setOptionalText(map, 3, accounts.device);
    setOptionalText(map, 4, accounts.deviceId);
    setOptionalText(map, 5, accounts.version);
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, ACCOUNT_KEYS);
    const keys = expectArray(map.getOrThrow(2));
    if (keys.length === 0) {
      throw CborError.outOfRange();
    }
    const device = optionalText(map, 3);
    const deviceId = optionalText(map, 4);
    const version = optionalText(map, 5);
    return Object.freeze({
      masterFingerprint: expectUint(map.getOrThrow(1), 0xff_ff_ff_ff),
      keys: keys.map(decodeKey),
      ...(device === undefined ? {} : { device }),
      ...(deviceId === undefined ? {} : { deviceId }),
      ...(version === undefined ? {} : { version }),
    });
  },
};
