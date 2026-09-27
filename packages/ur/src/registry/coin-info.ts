import { CborError, CborMap, cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { expectClosedIntMap, expectInt32, expectUint31 } from "./map.ts";
import { TAGS } from "./tags.ts";

const COIN_INFO_KEYS: ReadonlySet<number> = new Set([1, 2]);

export const CoinType = { btc: 0, eth: 0x3c } as const;
export const Network = { mainnet: 0, btcTestnet: 1 } as const;

export type CoinInfo = {
  readonly type?: number; // uint31, default 0, omit on write if 0 or undefined
  readonly network?: number; // int, default 0, omit on write if 0 or undefined
};

function assertUint31(n: number): number {
  if (!Number.isInteger(n) || n < 0 || n > 0x7f_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertInt32(n: number): number {
  if (!Number.isInteger(n) || n < -0x80_00_00_00 || n > 0x7f_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

export const coinInfoCodec: UrCodec<CoinInfo> = {
  tags: [TAGS["coin-info"]],
  untaggedCbor(info) {
    const map = new CborMap();
    if (info.type !== undefined && info.type !== 0) {
      map.set(1, assertUint31(info.type));
    }
    if (info.network !== undefined && info.network !== 0) {
      map.set(2, assertInt32(info.network));
    }
    return cbor(map);
  },
  fromUntaggedCbor(value) {
    const map = expectClosedIntMap(value, COIN_INFO_KEYS);
    const type = map.get(1);
    const network = map.get(2);
    return Object.freeze({
      ...(type === undefined ? {} : { type: expectUint31(type) }),
      ...(network === undefined ? {} : { network: expectInt32(network) }),
    });
  },
};
