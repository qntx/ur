import { CborError, CborMap, MajorType, cbor, expectUnsigned } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import { copyBuf } from "../registry/bytes.ts";
import type { Keypath } from "../registry/keypath.ts";
import { expectClosedIntMap } from "../registry/map.ts";
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
import { INTEROP_TAGS, ONEKEY_TRON_SIGN_REQUEST_TAG } from "./tags.ts";

const SIGN_REQUEST_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4, 5, 6]);
const SIGNATURE_KEYS: ReadonlySet<number> = new Set([1, 2]);
const SIGNATURE_LEN = 65;

export type TronDataType = "transaction" | "messageV1" | "messageV2";

export type TronSignRequest = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signData: Uint8Array; // non-empty
  readonly dataType: TronDataType;
  readonly derivationPath: Keypath; // concrete, written #6.304
  readonly address?: Uint8Array; // non-empty opaque
  readonly origin?: string; // "" encodes as absent
};

export type TronSignature = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signature: Uint8Array; // 65 bytes
};

// Keystone layout: 3 = dataType (1 transaction, 2 messageV2); 4 = path;
// 5 = address?; 6 = origin?. OneKey's BaseSignRequest layout: 3 = path;
// 4 = address?; 5 = origin?; 6 = requestType (1, 2 = messageV1, 3 = messageV2).
// The two are told apart by key 3's CBOR major type (unsigned vs tagged).
function decodeBody(value: Cbor): TronSignRequest {
  const map = expectClosedIntMap(value, SIGN_REQUEST_KEYS);
  const requestId = map.get(1);
  const discriminator = map.getOrThrow(3);
  let request: TronSignRequest;
  if (discriminator.type === MajorType.Unsigned) {
    const dataType = keystoneDataType(expectUnsigned(discriminator));
    request = {
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signData: readNonEmptyBytes(map.getOrThrow(2)),
      dataType,
      derivationPath: readDerivationPath(map.getOrThrow(4)),
      ...optionalAddressOrigin(map, 5, 6),
    };
  } else if (discriminator.type === MajorType.Tagged) {
    request = {
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signData: readNonEmptyBytes(map.getOrThrow(2)),
      dataType: oneKeyRequestType(map.getOrThrow(6)),
      derivationPath: readDerivationPath(discriminator),
      ...optionalAddressOrigin(map, 4, 5),
    };
  } else {
    throw CborError.wrongType();
  }
  return Object.freeze(request);
}

function keystoneDataType(n: number | bigint): TronDataType {
  switch (n) {
    case 1:
      return "transaction";
    case 2:
      return "messageV2";
    default:
      throw CborError.outOfRange();
  }
}

function oneKeyRequestType(cbor: Cbor): TronDataType {
  switch (expectUnsigned(cbor)) {
    case 1:
      return "transaction";
    case 2:
      return "messageV1";
    case 3:
      return "messageV2";
    default:
      throw CborError.outOfRange();
  }
}

function optionalAddressOrigin(
  map: CborMap,
  addressKey: number,
  originKey: number,
): { address?: Uint8Array; origin?: string } {
  const address = map.get(addressKey);
  const origin = optionalText(map, originKey);
  return {
    ...(address === undefined ? {} : { address: readNonEmptyBytes(address) }),
    ...(origin === undefined ? {} : { origin }),
  };
}

function keystoneDataTypeWire(dataType: TronDataType): number {
  switch (dataType) {
    case "transaction":
      return 1;
    case "messageV2":
      return 2;
    default:
      throw CborError.outOfRange();
  }
}

const ONEKEY_REQUEST_TYPE_WIRE: Readonly<Record<TronDataType, number>> = {
  transaction: 1,
  messageV1: 2,
  messageV2: 3,
};

function oneKeyRequestTypeWire(dataType: TronDataType): number {
  const wire = ONEKEY_REQUEST_TYPE_WIRE[dataType];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

function sharedFields(map: CborMap, request: TronSignRequest): void {
  if (request.requestId !== undefined) {
    map.set(1, requestIdTagged(request.requestId));
  }
  const signData = copyBuf(request.signData);
  if (signData.length === 0) {
    throw CborError.outOfRange();
  }
  map.set(2, cbor(signData));
}

function optionalTail(
  map: CborMap,
  request: TronSignRequest,
  addressKey: number,
  originKey: number,
): void {
  if (request.address !== undefined) {
    if (request.address.length === 0) {
      throw CborError.outOfRange();
    }
    map.set(addressKey, cbor(copyBuf(request.address)));
  }
  setOptionalText(map, originKey, request.origin);
}

/**
 * Keystone's `tron-sign-request` writer (tag 5101): `{1 uuid?, 2 signData, 3 dataType, 4 path, 5
 * address?, 6 origin?}` where `dataType` is 1 transaction / 2 messageV2 — `messageV1` has no
 * Keystone wire value, so both encode and decode reject it (decode would not round-trip). Reads the
 * OneKey dialect too at the body level: key 3's CBOR type picks the layout, and `transaction`/
 * `messageV2` OneKey bodies decode because they re-encode under this writer. `fromTagged` requires
 * this codec's own tag (5101).
 */
export const tronSignRequestCodec: UrCodec<TronSignRequest> = {
  tags: [INTEROP_TAGS["tron-sign-request"]],
  encode(request) {
    const map = new CborMap();
    sharedFields(map, request);
    map.set(3, keystoneDataTypeWire(request.dataType));
    map.set(4, derivationPathTagged(request.derivationPath));
    optionalTail(map, request, 5, 6);
    return cbor(map);
  },
  decode(value) {
    const request = decodeBody(value);
    if (request.dataType === "messageV1") {
      throw CborError.outOfRange();
    }
    return request;
  },
};

/**
 * OneKey's `tron-sign-request` writer (tag 5201, same UR type name): the `BaseSignRequest` layout
 * `{1 uuid?, 2 signData, 3 path, 4 address?, 5 origin?, 6 requestType}` where `requestType` is 1
 * transaction / 2 messageV1 / 3 messageV2. Accepts every data type and reads the Keystone dialect
 * too at the body level. `fromTagged` requires this codec's own tag (5201).
 */
export const oneKeyTronSignRequestCodec: UrCodec<TronSignRequest> = {
  tags: [ONEKEY_TRON_SIGN_REQUEST_TAG],
  encode(request) {
    const map = new CborMap();
    sharedFields(map, request);
    map.set(3, derivationPathTagged(request.derivationPath));
    optionalTail(map, request, 4, 5);
    map.set(6, oneKeyRequestTypeWire(request.dataType));
    return cbor(map);
  },
  decode: decodeBody,
};

export const tronSignatureCodec: UrCodec<TronSignature> = {
  tags: [INTEROP_TAGS["tron-signature"]],
  encode(signature) {
    const map = new CborMap();
    if (signature.requestId !== undefined) {
      map.set(1, requestIdTagged(signature.requestId));
    }
    const bytes = copyBuf(signature.signature);
    if (bytes.length !== SIGNATURE_LEN) {
      throw CborError.outOfRange();
    }
    map.set(2, cbor(bytes));
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGNATURE_KEYS);
    const requestId = map.get(1);
    return Object.freeze({
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signature: readBytesLen(map.getOrThrow(2), SIGNATURE_LEN),
    });
  },
};
