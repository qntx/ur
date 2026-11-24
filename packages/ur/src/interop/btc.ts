import {
  CborError,
  CborMap,
  cbor,
  expectArray,
  expectText,
  expectUnsigned,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import { copyBuf } from "../registry/bytes.ts";
import type { Keypath } from "../registry/keypath.ts";
import { assertText, expectClosedIntMap } from "../registry/map.ts";
import type { UrCodec } from "../typed/codec.ts";
import {
  derivationPathTagged,
  optionalText,
  readBytesLen,
  readDerivationPath,
  readNonEmptyBytes,
  readRequestId,
  requestIdTagged,
  setOptionalText,
} from "./common.ts";
import { INTEROP_TAGS } from "./tags.ts";

const SIGN_REQUEST_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4, 5, 6]);
const SIGNATURE_KEYS: ReadonlySet<number> = new Set([1, 2, 3]);
const SIGNATURE_LEN = 65;
const PUBLIC_KEY_LEN = 33;

export type BtcDataType = "message";

export type BtcSignRequest = {
  readonly requestId: Uint8Array; // 16 bytes, #6.37 — required (both vendor encoders always write it)
  readonly signData: Uint8Array; // non-empty
  readonly dataType: BtcDataType;
  readonly derivationPaths: ReadonlyArray<Keypath>; // non-empty, concrete, written #6.304
  readonly addresses?: ReadonlyArray<string>; // non-empty, every entry non-empty
  readonly origin?: string; // "" encodes as absent
};

export type BtcSignature = {
  readonly requestId: Uint8Array; // 16 bytes, #6.37
  readonly signature: Uint8Array; // 65 bytes: compact header ‖ r ‖ s
  readonly publicKey: Uint8Array; // 33 bytes, compressed
};

const DATA_TYPE_WIRE: Readonly<Record<BtcDataType, number>> = {
  message: 1,
};

function decodeDataType(cbor: Cbor): BtcDataType {
  switch (expectUnsigned(cbor)) {
    case 1:
      return "message";
    default:
      throw CborError.outOfRange();
  }
}

function dataTypeWire(dataType: BtcDataType): number {
  const wire = DATA_TYPE_WIRE[dataType];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

function encodeAddresses(addresses: ReadonlyArray<string>): string[] {
  if (addresses.length === 0) {
    throw CborError.outOfRange();
  }
  return addresses.map((address) => {
    const text = assertText(address);
    if (text === "") {
      throw CborError.outOfRange();
    }
    return text;
  });
}

function decodeAddresses(cbor: Cbor): string[] {
  const addresses = expectArray(cbor);
  if (addresses.length === 0) {
    throw CborError.outOfRange();
  }
  return addresses.map((item) => {
    const text = expectText(item);
    if (text === "") {
      throw CborError.outOfRange();
    }
    return text;
  });
}

export const btcSignRequestCodec: UrCodec<BtcSignRequest> = {
  tags: [INTEROP_TAGS["btc-sign-request"]],
  encode(request) {
    if (request.derivationPaths.length === 0) {
      throw CborError.outOfRange();
    }
    const map = new CborMap();
    map.set(1, requestIdTagged(request.requestId));
    const signData = copyBuf(request.signData);
    if (signData.length === 0) {
      throw CborError.outOfRange();
    }
    map.set(2, cbor(signData));
    map.set(3, dataTypeWire(request.dataType));
    map.set(4, request.derivationPaths.map(derivationPathTagged));
    if (request.addresses !== undefined) {
      map.set(5, encodeAddresses(request.addresses));
    }
    setOptionalText(map, 6, request.origin);
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGN_REQUEST_KEYS);
    const derivationPaths = expectArray(map.getOrThrow(4));
    if (derivationPaths.length === 0) {
      throw CborError.outOfRange();
    }
    const addresses = map.get(5);
    const origin = optionalText(map, 6);
    return Object.freeze({
      requestId: readRequestId(map.getOrThrow(1)),
      signData: readNonEmptyBytes(map.getOrThrow(2)),
      dataType: decodeDataType(map.getOrThrow(3)),
      derivationPaths: Object.freeze(derivationPaths.map(readDerivationPath)),
      ...(addresses === undefined ? {} : { addresses: Object.freeze(decodeAddresses(addresses)) }),
      ...(origin === undefined ? {} : { origin }),
    });
  },
};

export const btcSignatureCodec: UrCodec<BtcSignature> = {
  tags: [INTEROP_TAGS["btc-signature"]],
  encode(signature) {
    const map = new CborMap();
    map.set(1, requestIdTagged(signature.requestId));
    const bytes = copyBuf(signature.signature);
    if (bytes.length !== SIGNATURE_LEN) {
      throw CborError.outOfRange();
    }
    map.set(2, cbor(bytes));
    const publicKey = copyBuf(signature.publicKey);
    if (publicKey.length !== PUBLIC_KEY_LEN) {
      throw CborError.outOfRange();
    }
    map.set(3, cbor(publicKey));
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGNATURE_KEYS);
    return Object.freeze({
      requestId: readRequestId(map.getOrThrow(1)),
      signature: readBytesLen(map.getOrThrow(2), SIGNATURE_LEN),
      publicKey: readBytesLen(map.getOrThrow(3), PUBLIC_KEY_LEN),
    });
  },
};
