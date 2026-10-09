import {
  CborError,
  CborMap,
  MajorType,
  cbor,
  expectArray,
  expectText,
  isMap,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { fromTagged, toTagged } from "../typed/index.ts";
import { addressCodec } from "./address.ts";
import { ecKeyCodec } from "./eckey.ts";
import { hdKeyCodec } from "./hdkey.ts";
import { assertText, expectClosedIntMap } from "./map.ts";
import { scriptExpressionToDescriptor } from "./script-expression.ts";
import type { DescriptorKey } from "./script-expression.ts";
import { TAGS } from "./tags.ts";

export type { DescriptorKey } from "./script-expression.ts";

const DESCRIPTOR_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4]);

export type OutputDescriptor = {
  readonly source: string; // text descriptor with @n placeholders
  readonly keys: ReadonlyArray<DescriptorKey>;
  readonly name?: string; // omitted on write if empty
  readonly note?: string;
};

/** The `@n` placeholders in `source` must be exactly the set `0..keys.length-1`. */
function assertPlaceholders(source: string, keyCount: number): void {
  const found = new Set<number>();
  for (const m of source.matchAll(/@(\d+)/g)) {
    const n = Number(m[1]);
    if (!Number.isSafeInteger(n) || n < 0 || n >= keyCount) {
      throw CborError.outOfRange();
    }
    found.add(n);
  }
  if (found.size !== keyCount) {
    throw CborError.outOfRange();
  }
}

function encodeKey(key: DescriptorKey): Cbor {
  if (key.kind === "hdkey") {
    return toTagged(key.key, hdKeyCodec);
  }
  if (key.kind === "eckey") {
    return toTagged(key.key, ecKeyCodec);
  }
  return toTagged(key.address, addressCodec);
}

function decodeKey(cbor: Cbor): DescriptorKey {
  const tag = cbor.type === MajorType.Tagged ? Number(cbor.tag) : undefined;
  if (tag === TAGS.hdkey.value || tag === TAGS["crypto-hdkey"].value) {
    return { kind: "hdkey", key: fromTagged(cbor, hdKeyCodec) };
  }
  if (tag === TAGS.eckey.value || tag === TAGS["crypto-eckey"].value) {
    return { kind: "eckey", key: fromTagged(cbor, ecKeyCodec) };
  }
  if (tag === TAGS.address.value || tag === TAGS["crypto-address"].value) {
    return { kind: "address", address: fromTagged(cbor, addressCodec) };
  }
  throw CborError.wrongType();
}

function encodeDescriptor(desc: OutputDescriptor): Cbor {
  assertPlaceholders(desc.source, desc.keys.length);
  const map = new CborMap();
  map.set(1, assertText(desc.source));
  if (desc.keys.length > 0) {
    map.set(2, desc.keys.map(encodeKey));
  }
  if (desc.name !== undefined && desc.name !== "") {
    map.set(3, assertText(desc.name));
  }
  if (desc.note !== undefined && desc.note !== "") {
    map.set(4, assertText(desc.note));
  }
  return cbor(map);
}

function decodeDescriptorMap(value: Cbor): OutputDescriptor {
  const map = expectClosedIntMap(value, DESCRIPTOR_KEYS);
  const source = expectText(map.getOrThrow(1));
  const keysV = map.get(2);
  const nameV = map.get(3);
  const noteV = map.get(4);
  const keys = keysV === undefined ? [] : expectArray(keysV).map(decodeKey);
  assertPlaceholders(source, keys.length);
  return Object.freeze({
    source,
    keys: Object.freeze(keys),
    ...(nameV === undefined ? {} : { name: expectText(nameV) }),
    ...(noteV === undefined ? {} : { note: expectText(noteV) }),
  });
}

export const outputDescriptorCodec: UrCodec<OutputDescriptor> = {
  tags: [TAGS["output-descriptor"], TAGS["crypto-output"]],
  encode(desc) {
    return encodeDescriptor(desc);
  },
  decode(value) {
    if (isMap(value)) {
      return decodeDescriptorMap(value);
    }
    // v1 crypto-output: a tagged script-expression tree -> v2 descriptor value.
    const { source, keys } = scriptExpressionToDescriptor(value);
    return Object.freeze({ source, keys });
  },
};
