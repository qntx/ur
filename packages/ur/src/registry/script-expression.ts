import {
  CborError,
  MajorType,
  bytesToHex,
  expectArray,
  extractTaggedContent,
} from "@blockchaincommons/dcbor";
import type { Cbor, CborMap } from "@blockchaincommons/dcbor";

import { addressCodec } from "./address.ts";
import type { Address } from "./address.ts";
import { ecKeyCodec } from "./eckey.ts";
import type { EcKey } from "./eckey.ts";
import { hdKeyCodec } from "./hdkey.ts";
import type { HdKey } from "./hdkey.ts";
import { expectUint31 } from "./map.ts";
import {
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
