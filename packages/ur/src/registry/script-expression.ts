import {
  CborError,
  CborMap,
  MajorType,
  bytesToHex,
  cbor,
  expectArray,
  extractTaggedContent,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { toTagged } from "../typed/index.ts";
import { addressCodec, encodeAddressBody } from "./address.ts";
import type { Address } from "./address.ts";
import { cryptoCoinInfoCodec } from "./coin-info.ts";
import { ecKeyCodec } from "./eckey.ts";
import type { EcKey } from "./eckey.ts";
import { cryptoHdKeyCodec, hdKeyCodec } from "./hdkey.ts";
import type { HdKey } from "./hdkey.ts";
import { expectUint31 } from "./map.ts";
import {
  SCRIPT_TAGS,
  TAGS,
  TAG_ADDRESS,
  TAG_ADDRESS_V1,
  TAG_COSIGNER,
  TAG_COMBO,
  TAG_ECKEY,
  TAG_ECKEY_V1,
  TAG_HDKEY,
  TAG_HDKEY_V1,
  TAG_MULTISIG,
  TAG_PUBLIC_KEY,
  TAG_PUBLIC_KEY_HASH,
  TAG_RAW_SCRIPT,
  TAG_SCRIPT_HASH,
  TAG_SORTED_MULTISIG,
  TAG_TAPROOT,
  TAG_WITNESS_PUBLIC_KEY_HASH,
  TAG_WITNESS_SCRIPT_HASH,
} from "./tags.ts";

export type DescriptorKey =
  | { readonly kind: "hdkey"; readonly key: HdKey }
  | { readonly kind: "eckey"; readonly key: EcKey }
  | { readonly kind: "address"; readonly address: Address };

type ScriptResult = { readonly text: string; readonly keys: DescriptorKey[] };

const MULTIKEY_KEYS: ReadonlySet<number> = new Set([1, 2]);

function tagNumber(cbor: Cbor): number {
  if (cbor.type !== MajorType.Tagged) {
    throw CborError.wrongType();
  }
  return Number(cbor.tag);
}

function bytesOf(cbor: Cbor): Uint8Array {
  if (cbor.type !== MajorType.ByteString || !(cbor.value instanceof Uint8Array)) {
    throw CborError.wrongType();
  }
  return cbor.value;
}

function closedMultikeyMap(cbor: Cbor): CborMap {
  if (cbor.type !== MajorType.Map) {
    throw CborError.wrongType();
  }
  const map = cbor.value;
  for (const [k] of map) {
    if (k.type !== MajorType.Unsigned || !MULTIKEY_KEYS.has(Number(k.value))) {
      throw CborError.wrongType();
    }
  }
  return map;
}

/** Key_exp = #6.306 / #6.303 / #6.307 (v2 tag equivalents accepted). */
function keyExp(cbor: Cbor): DescriptorKey {
  const tag = tagNumber(cbor);
  const content = extractTaggedContent(cbor);
  if (tag === TAG_ECKEY || tag === TAG_ECKEY_V1) {
    return { kind: "eckey", key: ecKeyCodec.decode(content) };
  }
  if (tag === TAG_HDKEY || tag === TAG_HDKEY_V1) {
    return { kind: "hdkey", key: hdKeyCodec.decode(content) };
  }
  if (tag === TAG_ADDRESS || tag === TAG_ADDRESS_V1) {
    return { kind: "address", address: addressCodec.decode(content) };
  }
  throw CborError.wrongType();
}

function isKeyExpTag(tag: number): boolean {
  return (
    tag === TAG_ECKEY ||
    tag === TAG_ECKEY_V1 ||
    tag === TAG_HDKEY ||
    tag === TAG_HDKEY_V1 ||
    tag === TAG_ADDRESS ||
    tag === TAG_ADDRESS_V1
  );
}

const KEY_FN: Readonly<Record<number, string>> = {
  [TAG_PUBLIC_KEY]: "pk",
  [TAG_PUBLIC_KEY_HASH]: "pkh",
  [TAG_WITNESS_PUBLIC_KEY_HASH]: "wpkh",
  [TAG_COMBO]: "combo",
  [TAG_COSIGNER]: "cosigner",
};

const WRAPPER_FN: Readonly<Record<number, string>> = {
  [TAG_SCRIPT_HASH]: "sh",
  [TAG_WITNESS_SCRIPT_HASH]: "wsh",
};

/**
 * BIP-380 text rendering of a v1 script-expression tree (BCR-2020-010 tags 400–410). Keys become
 * `@0`, `@1`, … in order of appearance and are collected as v2 `DescriptorKey` values. The grammar
 * gives every script function at most one child subtree (multikey's list is handled inline), so
 * each node's local `@n` numbering is already the global order. `parent` is the enclosing wrapper
 * tag, which bounds nesting to `sh(wsh(...))`. Unsupported combinations (e.g. a taproot script
 * tree) throw `CborError` — surfaced as `CborType` by the codec layer.
 */
function scriptExp(cbor: Cbor, parent?: number): ScriptResult {
  const tag = tagNumber(cbor);
  const content = extractTaggedContent(cbor);

  const keyFn = KEY_FN[tag];
  if (keyFn !== undefined) {
    return { text: `${keyFn}(@0)`, keys: [keyExp(content)] };
  }

  const wrapper = WRAPPER_FN[tag];
  if (wrapper !== undefined) {
    // BIP-380/381/382: sh() is top-level only; wsh() is top-level or directly inside sh().
    const allowed =
      parent === undefined || (parent === TAG_SCRIPT_HASH && tag === TAG_WITNESS_SCRIPT_HASH);
    if (!allowed) {
      throw CborError.wrongType();
    }
    // Lenient read: KeystoneHQ writes `sh(key_exp)` where BCR-2020-010 uses
    // `sh(410(key_exp))` (cosigner). Restore the cosigner marker; only sh/wsh
    // accept it, so the fallback lives here, not on the top level.
    if (content.type === MajorType.Tagged && isKeyExpTag(Number(content.tag))) {
      const key = keyExp(content);
      return { text: `${wrapper}(cosigner(@0))`, keys: [key] };
    }
    const inner = scriptExp(content, tag);
    return { text: `${wrapper}(${inner.text})`, keys: inner.keys };
  }

  if (tag === TAG_MULTISIG || tag === TAG_SORTED_MULTISIG) {
    const map = closedMultikeyMap(content);
    const thresholdV = map.get(1);
    const keysV = map.get(2);
    if (thresholdV === undefined || keysV === undefined) {
      throw CborError.wrongType();
    }
    const threshold = expectUint31(thresholdV);
    const keys = expectArray(keysV);
    if (threshold < 1 || threshold > keys.length || keys.length === 0) {
      throw CborError.outOfRange();
    }
    const parts: string[] = [];
    const collected: DescriptorKey[] = [];
    for (const k of keys) {
      collected.push(keyExp(k));
      parts.push(`@${collected.length - 1}`);
    }
    const name = tag === TAG_MULTISIG ? "multi" : "sortedmulti";
    return { text: `${name}(${threshold},${parts.join(",")})`, keys: collected };
  }

  if (tag === TAG_RAW_SCRIPT) {
    return { text: `raw(${bytesToHex(bytesOf(content))})`, keys: [] };
  }

  if (tag === TAG_TAPROOT) {
    // BIP-386 tr(KEY) only; a tr script tree is unsupported (registry design).
    const key = keyExp(content);
    return { text: "tr(@0)", keys: [key] };
  }

  throw CborError.wrongType();
}

/**
 * Convert a v1 `crypto-output` body (a script-expression tagged value) into the v2
 * `OutputDescriptor` shape `{ source, keys }`.
 */
export function scriptExpressionToDescriptor(cbor: Cbor): {
  readonly source: string;
  readonly keys: ReadonlyArray<DescriptorKey>;
} {
  const out = scriptExp(cbor);
  return Object.freeze({ source: out.text, keys: Object.freeze(out.keys) });
}

// v1 keyExp write side: descriptor keys tagged 303/306/307 with v1 bodies —
// the embedded hdkey carries presence-preserving `is-private` plus nested
// 305/304 tags, the embedded address a v1 (305) coin-info.
const ecKeyV1Codec: UrCodec<EcKey> = {
  tags: [TAGS["crypto-eckey"], TAGS.eckey],
  encode: ecKeyCodec.encode,
  decode: ecKeyCodec.decode,
};

const addressV1Codec: UrCodec<Address> = {
  tags: [TAGS["crypto-address"], TAGS.address],
  encode(address) {
    return encodeAddressBody(address, cryptoCoinInfoCodec);
  },
  decode: addressCodec.decode,
};

function keyExpV1(key: DescriptorKey): Cbor {
  if (key.kind === "hdkey") {
    return toTagged(key.key, cryptoHdKeyCodec);
  }
  if (key.kind === "eckey") {
    return toTagged(key.key, ecKeyV1Codec);
  }
  return toTagged(key.address, addressV1Codec);
}

type Cursor = { pos: number };

function takeName(source: string, cur: Cursor): string {
  const start = cur.pos;
  while (cur.pos < source.length) {
    const code = source.codePointAt(cur.pos) ?? -1;
    if (code < 0x61 || code > 0x7a) {
      break;
    }
    cur.pos += 1;
  }
  if (cur.pos === start) {
    throw CborError.wrongType();
  }
  return source.slice(start, cur.pos);
}

function takeChar(source: string, cur: Cursor, ch: string): void {
  if (source[cur.pos] !== ch) {
    throw CborError.wrongType();
  }
  cur.pos += 1;
}

function takeUint(source: string, cur: Cursor): number {
  const start = cur.pos;
  while (cur.pos < source.length) {
    const code = source.codePointAt(cur.pos) ?? -1;
    if (code < 0x30 || code > 0x39) {
      break;
    }
    cur.pos += 1;
  }
  if (cur.pos === start) {
    throw CborError.wrongType();
  }
  const n = Number(source.slice(start, cur.pos));
  if (!Number.isSafeInteger(n)) {
    throw CborError.outOfRange();
  }
  return n;
}

function takeKey(source: string, cur: Cursor, keys: ReadonlyArray<DescriptorKey>): Cbor {
  takeChar(source, cur, "@");
  const n = takeUint(source, cur);
  const key = keys[n];
  if (key === undefined) {
    throw CborError.outOfRange();
  }
  return keyExpV1(key);
}

const KEY_FN_TAGS: Readonly<Record<string, (typeof SCRIPT_TAGS)[keyof typeof SCRIPT_TAGS]>> = {
  pk: SCRIPT_TAGS.pk,
  pkh: SCRIPT_TAGS.pkh,
  wpkh: SCRIPT_TAGS.wpkh,
  combo: SCRIPT_TAGS.combo,
  tr: SCRIPT_TAGS.tr,
};

type Parent = "top" | "sh" | "wsh";

// The write grammar is exactly the reader's output language: single-key
// functions `pk|pkh|wpkh|combo|cosigner|tr(@n)`, `sh` top-level only, `wsh`
// top-level or directly inside `sh`, `multi|sortedmulti(k,@a,…)`,
// `raw(<lowercase even-length hex>)`. No whitespace.
function parseExp(
  source: string,
  cur: Cursor,
  parent: Parent,
  keys: ReadonlyArray<DescriptorKey>,
): Cbor {
  const name = takeName(source, cur);
  takeChar(source, cur, "(");
  if (name === "cosigner") {
    const key = takeKey(source, cur, keys);
    takeChar(source, cur, ")");
    // Keystone's multisig-cosigner spelling: bare key_exp inside sh/wsh
    // (Keystone JS cannot read tag 410 there); top level keeps 410.
    return parent === "top" ? taggedValue(SCRIPT_TAGS.cosigner, key) : key;
  }
  const keyTag = KEY_FN_TAGS[name];
  if (keyTag !== undefined) {
    const key = takeKey(source, cur, keys);
    takeChar(source, cur, ")");
    return taggedValue(keyTag, key);
  }
  if (name === "sh" || name === "wsh") {
    // sh() is top-level only; wsh() is top-level or directly inside sh().
    if (name === "sh" ? parent !== "top" : parent === "wsh") {
      throw CborError.wrongType();
    }
    const inner = parseExp(source, cur, name, keys);
    takeChar(source, cur, ")");
    return taggedValue(name === "sh" ? SCRIPT_TAGS.sh : SCRIPT_TAGS.wsh, inner);
  }
  if (name === "multi" || name === "sortedmulti") {
    const threshold = takeUint(source, cur);
    const list: Cbor[] = [];
    do {
      takeChar(source, cur, ",");
      list.push(takeKey(source, cur, keys));
    } while (source[cur.pos] === ",");
    takeChar(source, cur, ")");
    if (threshold < 1 || threshold > list.length) {
      throw CborError.outOfRange();
    }
    const map = new CborMap();
    map.set(1, threshold);
    map.set(2, list);
    return taggedValue(name === "multi" ? SCRIPT_TAGS.multi : SCRIPT_TAGS.sortedmulti, cbor(map));
  }
  if (name === "raw") {
    const start = cur.pos;
    while (cur.pos < source.length) {
      const code = source.codePointAt(cur.pos) ?? -1;
      const hexDigit = (code >= 0x30 && code <= 0x39) || (code >= 0x61 && code <= 0x66);
      if (!hexDigit) {
        break;
      }
      cur.pos += 1;
    }
    const hex = source.slice(start, cur.pos);
    takeChar(source, cur, ")");
    return taggedValue(SCRIPT_TAGS.raw, cbor(hexToBytes(hex)));
  }
  throw CborError.wrongType();
}

/**
 * Inverse of {@link scriptExpressionToDescriptor}: render `source` (restricted to the reader's
 * output grammar) back into a BCR-2020-010 script-expression tree, embedding `keys` with the v1
 * tags. Anything outside the grammar throws `CborError` — surfaced as `CborType` by the codec
 * layer.
 */
export function descriptorToScriptExpression(
  source: string,
  keys: ReadonlyArray<DescriptorKey>,
): Cbor {
  const cur = { pos: 0 };
  const tree = parseExp(source, cur, "top", keys);
  if (cur.pos !== source.length) {
    throw CborError.wrongType();
  }
  return tree;
}
