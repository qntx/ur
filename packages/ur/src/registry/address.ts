import { CborError, CborMap, cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { fromTagged, toTagged } from "../typed/index.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { coinInfoCodec } from "./coin-info.ts";
import type { CoinInfo } from "./coin-info.ts";
import { expectClosedIntMap, expectUint } from "./map.ts";
import { TAGS } from "./tags.ts";

const ADDRESS_KEYS: ReadonlySet<number> = new Set([1, 2, 3]);
const TYPED_DATA_LEN = 20;

const ADDRESS_TYPES = ["p2pkh", "p2sh", "p2wpkh"] as const;
export type AddressType = (typeof ADDRESS_TYPES)[number];

export type Address = {
  readonly info?: CoinInfo; // tagged coin-info; v1/v2 tag read, v2 written
  readonly type?: AddressType; // with `type`, data is exactly 20 bytes (S-13)
  readonly data: Uint8Array;
};

function assertDataLen(type: AddressType | undefined, data: Uint8Array): void {
  if (type !== undefined) {
    if (data.length !== TYPED_DATA_LEN) {
      throw CborError.outOfRange();
    }
    return;
  }
  if (data.length === 0) {
    throw CborError.outOfRange();
  }
}

export const addressCodec: UrCodec<Address> = {
  tags: [TAGS.address, TAGS["crypto-address"]],
  encode(address) {
    assertDataLen(address.type, address.data);
    const map = new CborMap();
    if (address.info !== undefined) {
      map.set(1, toTagged(address.info, coinInfoCodec));
    }
    if (address.type !== undefined) {
      const index = ADDRESS_TYPES.indexOf(address.type);
      if (index === -1) {
        throw CborError.wrongType();
      }
      map.set(2, index);
    }
    map.set(3, cbor(copyBuf(address.data)));
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, ADDRESS_KEYS);
    const info = map.get(1);
    const typeV = map.get(2);
    const data = copyBytes(map.getOrThrow(3));
    const type = typeV === undefined ? undefined : ADDRESS_TYPES[expectUint(typeV, 2)];
    assertDataLen(type, data);
    return Object.freeze({
      ...(info === undefined ? {} : { info: fromTagged(info, coinInfoCodec) }),
      ...(type === undefined ? {} : { type }),
      data,
    });
  },
};
