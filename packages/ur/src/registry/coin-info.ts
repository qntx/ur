import { CborError, CborMap, cbor } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

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

// v2 omits defaults; v1 (BCR-2020-006) writes each field iff it is present —
// vendors disagree on defaulted fields, so the deprecated writer preserves
// presence (`0` included) to stay byte-identical on every vendor's own input.
function encodeBody(info: CoinInfo, v1: boolean): Cbor {
  const map = new CborMap();
  if (info.type !== undefined && (v1 || info.type !== 0)) {
    map.set(1, assertUint31(info.type));
  }
  if (info.network !== undefined && (v1 || info.network !== 0)) {
    map.set(2, assertInt32(info.network));
  }
  return cbor(map);
}

export const coinInfoCodec: UrCodec<CoinInfo> = {
  tags: [TAGS["coin-info"], TAGS["crypto-coin-info"]],
  encode(info) {
    return encodeBody(info, false);
  },
  decode(value) {
    const map = expectClosedIntMap(value, COIN_INFO_KEYS);
    const type = map.get(1);
    const network = map.get(2);
    return Object.freeze({
      ...(type === undefined ? {} : { type: expectUint31(type) }),
      ...(network === undefined ? {} : { network: expectInt32(network) }),
    });
  },
};

/**
 * Deprecated v1 writer (`ur:crypto-coin-info`, tag 305). Presence-preserving: `type` and `network`
 * are written iff present, `0` included — unlike the v2 writer, which omits defaults.
 */
export const cryptoCoinInfoCodec: UrCodec<CoinInfo> = {
  tags: [TAGS["crypto-coin-info"], TAGS["coin-info"]],
  encode(info) {
    return encodeBody(info, true);
  },
  decode: coinInfoCodec.decode,
};
