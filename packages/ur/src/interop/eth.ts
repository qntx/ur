import { CborError, CborMap, cbor, expectInteger, expectUnsigned } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import { copyBuf, copyBytes } from "../registry/bytes.ts";
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
import { INTEROP_TAGS } from "./tags.ts";

const SIGN_REQUEST_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4, 5, 6, 7]);
const SIGNATURE_KEYS: ReadonlySet<number> = new Set([1, 2, 3]);
const ADDRESS_LEN = 20;
const SIGNATURE_MIN = 65;
const SIGNATURE_MAX = 72;
const CHAIN_ID_MAX = 0x1f_ff_ff_ff_ff_ff; // 2^53 - 1

export type EthDataType = "transaction" | "typedData" | "personalMessage" | "typedTransaction";

export type EthSignRequest = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signData: Uint8Array; // non-empty
  readonly dataType: EthDataType;
  readonly chainId?: number; // integer 1..=2^53-1
  readonly derivationPath: Keypath; // concrete, written #6.304
  readonly address?: Uint8Array; // 20 bytes
  readonly origin?: string; // "" encodes as absent
};

export type EthSignature = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signature: Uint8Array; // 65..=72 bytes (r‖s‖v, v big-endian ≥ 1 byte)
  readonly origin?: string;
};

const DATA_TYPE_WIRE: Readonly<Record<EthDataType, number>> = {
  transaction: 1,
  typedData: 2,
  personalMessage: 3,
  typedTransaction: 4,
};

function decodeDataType(cbor: Cbor): EthDataType {
  const n = expectUnsigned(cbor);
  switch (n) {
    case 1:
      return "transaction";
    case 2:
      return "typedData";
    case 3:
      return "personalMessage";
    case 4:
      return "typedTransaction";
    default:
      throw CborError.outOfRange();
  }
}

function dataTypeWire(dataType: EthDataType): number {
  const wire = DATA_TYPE_WIRE[dataType];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

function assertChainId(chainId: number): number {
  if (!Number.isInteger(chainId) || chainId < 1 || chainId > CHAIN_ID_MAX) {
    throw CborError.outOfRange();
  }
  return chainId;
}

function readChainId(value: Cbor): number {
  const n = expectInteger(value);
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > CHAIN_ID_MAX) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertAddress(address: Uint8Array): Uint8Array {
  if (address.length !== ADDRESS_LEN) {
    throw CborError.outOfRange();
  }
  return copyBuf(address);
}

export const ethSignRequestCodec: UrCodec<EthSignRequest> = {
  tags: [INTEROP_TAGS["eth-sign-request"]],
  encode(request) {
    const map = new CborMap();
    if (request.requestId !== undefined) {
      map.set(1, requestIdTagged(request.requestId));
    }
    const signData = copyBuf(request.signData);
    if (signData.length === 0) {
      throw CborError.outOfRange();
    }
    map.set(2, cbor(signData));
    map.set(3, dataTypeWire(request.dataType));
    if (request.chainId !== undefined) {
      map.set(4, assertChainId(request.chainId));
    }
    map.set(5, derivationPathTagged(request.derivationPath));
    if (request.address !== undefined) {
      map.set(6, cbor(assertAddress(request.address)));
    }
    setOptionalText(map, 7, request.origin);
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGN_REQUEST_KEYS);
    const requestId = map.get(1);
    const chainId = map.get(4);
    const address = map.get(6);
    const origin = optionalText(map, 7);
    return Object.freeze({
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signData: readNonEmptyBytes(map.getOrThrow(2)),
      dataType: decodeDataType(map.getOrThrow(3)),
      ...(chainId === undefined ? {} : { chainId: readChainId(chainId) }),
      derivationPath: readDerivationPath(map.getOrThrow(5)),
      ...(address === undefined ? {} : { address: readBytesLen(address, ADDRESS_LEN) }),
      ...(origin === undefined ? {} : { origin }),
    });
  },
};

export const ethSignatureCodec: UrCodec<EthSignature> = {
  tags: [INTEROP_TAGS["eth-signature"]],
  encode(signature) {
    const map = new CborMap();
    if (signature.requestId !== undefined) {
      map.set(1, requestIdTagged(signature.requestId));
    }
    const bytes = copyBuf(signature.signature);
    if (bytes.length < SIGNATURE_MIN || bytes.length > SIGNATURE_MAX) {
      throw CborError.outOfRange();
    }
    map.set(2, cbor(bytes));
    setOptionalText(map, 3, signature.origin);
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGNATURE_KEYS);
    const requestId = map.get(1);
    const signature = copyBytes(map.getOrThrow(2));
    if (signature.length < SIGNATURE_MIN || signature.length > SIGNATURE_MAX) {
      throw CborError.outOfRange();
    }
    const origin = optionalText(map, 3);
    return Object.freeze({
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signature,
      ...(origin === undefined ? {} : { origin }),
    });
  },
};
