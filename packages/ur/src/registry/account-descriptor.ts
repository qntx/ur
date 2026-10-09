import { CborError, CborMap, MajorType, cbor, expectArray } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { fromTagged, toTagged } from "../typed/index.ts";
import { expectClosedIntMap, expectUint } from "./map.ts";
import { outputDescriptorCodec } from "./output-descriptor.ts";
import type { OutputDescriptor } from "./output-descriptor.ts";
import { scriptExpressionToDescriptor } from "./script-expression.ts";
import { TAGS, TAG_COSIGNER, TAG_SCRIPT_HASH } from "./tags.ts";

const ACCOUNT_KEYS: ReadonlySet<number> = new Set([1, 2]);

export type AccountDescriptor = {
  readonly masterFingerprint: number; // uint32
  readonly outputDescriptors: ReadonlyArray<OutputDescriptor>; // >= 1
};

function assertFingerprint(n: number): number {
  if (!Number.isInteger(n) || n < 0 || n > 0xff_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertDescriptors(descriptors: ReadonlyArray<OutputDescriptor>): void {
  if (descriptors.length === 0) {
    throw CborError.outOfRange();
  }
}

/**
 * One `output-descriptors` entry: a tagged `40308` map (v2), a tagged `308` crypto-output script
 * expression (v1, per BCR-2020-015), or — leniently, as KeystoneHQ writes it — a bare `400…410`
 * script expression.
 */
function decodeEntry(item: Cbor): OutputDescriptor {
  const tag = item.type === MajorType.Tagged ? Number(item.tag) : undefined;
  if (tag !== undefined && tag >= TAG_SCRIPT_HASH && tag <= TAG_COSIGNER) {
    const { source, keys } = scriptExpressionToDescriptor(item);
    return Object.freeze({ source, keys });
  }
  return fromTagged(item, outputDescriptorCodec);
}

export const accountDescriptorCodec: UrCodec<AccountDescriptor> = {
  tags: [TAGS["account-descriptor"], TAGS["crypto-account"]],
  encode(account) {
    assertFingerprint(account.masterFingerprint);
    assertDescriptors(account.outputDescriptors);
    const map = new CborMap();
    map.set(1, account.masterFingerprint);
    map.set(
      2,
      account.outputDescriptors.map((d) => toTagged(d, outputDescriptorCodec)),
    );
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, ACCOUNT_KEYS);
    const descriptors = expectArray(map.getOrThrow(2)).map(decodeEntry);
    assertDescriptors(descriptors);
    return Object.freeze({
      masterFingerprint: expectUint(map.getOrThrow(1), 0xff_ff_ff_ff),
      outputDescriptors: Object.freeze(descriptors),
    });
  },
};
