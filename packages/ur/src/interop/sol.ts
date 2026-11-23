import { CborError, CborMap, cbor, expectUnsigned } from "@blockchaincommons/dcbor";
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
import { INTEROP_TAGS } from "./tags.ts";

const SIGN_REQUEST_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4, 5, 6]);
const SIGNATURE_KEYS: ReadonlySet<number> = new Set([1, 2]);
const SIGNATURE_LEN = 64;

export type SolSignType =
  | "transaction"
  | "message"
  | "offchainMessageLegacy"
  | "offchainMessageStandard";

export type SolSignRequest = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signData: Uint8Array; // non-empty
  readonly derivationPath: Keypath; // concrete, written #6.304
  readonly address?: Uint8Array; // non-empty opaque
  readonly origin?: string; // "" encodes as absent
  readonly signType: SolSignType; // 3/4 are OneKey-only extensions
};

export type SolSignature = {
  readonly requestId?: Uint8Array; // 16 bytes, #6.37
  readonly signature: Uint8Array; // 64 bytes
};

const SIGN_TYPE_WIRE: Readonly<Record<SolSignType, number>> = {
  transaction: 1,
  message: 2,
  offchainMessageLegacy: 3,
  offchainMessageStandard: 4,
};

function decodeSignType(cbor: Cbor): SolSignType {
  const n = expectUnsigned(cbor);
  switch (n) {
    case 1:
      return "transaction";
    case 2:
      return "message";
    case 3:
      return "offchainMessageLegacy";
    case 4:
      return "offchainMessageStandard";
    default:
      throw CborError.outOfRange();
  }
}

function signTypeWire(signType: SolSignType): number {
  const wire = SIGN_TYPE_WIRE[signType];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

export const solSignRequestCodec: UrCodec<SolSignRequest> = {
  tags: [INTEROP_TAGS["sol-sign-request"]],
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
    map.set(3, derivationPathTagged(request.derivationPath));
    if (request.address !== undefined) {
      if (request.address.length === 0) {
        throw CborError.outOfRange();
      }
      map.set(4, cbor(copyBuf(request.address)));
    }
    setOptionalText(map, 5, request.origin);
    map.set(6, signTypeWire(request.signType));
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, SIGN_REQUEST_KEYS);
    const requestId = map.get(1);
    const address = map.get(4);
    const origin = optionalText(map, 5);
    return Object.freeze({
      ...(requestId === undefined ? {} : { requestId: readRequestId(requestId) }),
      signData: readNonEmptyBytes(map.getOrThrow(2)),
      derivationPath: readDerivationPath(map.getOrThrow(3)),
      ...(address === undefined ? {} : { address: readNonEmptyBytes(address) }),
      ...(origin === undefined ? {} : { origin }),
      signType: decodeSignType(map.getOrThrow(6)),
    });
  },
};

export const solSignatureCodec: UrCodec<SolSignature> = {
  tags: [INTEROP_TAGS["sol-signature"]],
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
