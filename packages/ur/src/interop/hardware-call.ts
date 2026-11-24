import {
  CborError,
  CborMap,
  cbor,
  expectArray,
  expectUnsigned,
  extractTaggedContent,
  taggedValue,
  validateTag,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { Keypath } from "../registry/keypath.ts";
import { expectClosedIntMap } from "../registry/map.ts";
import type { UrCodec } from "../typed/codec.ts";
import {
  derivationPathTagged,
  optionalText,
  readDerivationPath,
  setOptionalText,
} from "./common.ts";
import { INTEROP_TAGS } from "./tags.ts";

const CALL_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4]);
const PARAMS_KEYS: ReadonlySet<number> = new Set([1]);
const SCHEMA_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4]);

export type KeyDerivationCurve = "secp256k1" | "ed25519";
export type KeyDerivationAlgorithm = "slip10" | "bip32Ed25519";

export type KeyDerivationSchema = {
  readonly keyPath: Keypath; // concrete, written #6.304
  readonly curve?: KeyDerivationCurve; // presence-preserving
  readonly algorithm?: KeyDerivationAlgorithm; // presence-preserving
  readonly chainType?: string; // "" encodes as absent
};

export type KeyDerivationCall = {
  readonly kind: "keyDerivation"; // call type 0, params #6.1301
  readonly schemas: ReadonlyArray<KeyDerivationSchema>; // non-empty
};

export type QrHardwareCallParams = KeyDerivationCall;
export type QrHardwareCallVersion = 0 | 1;

export type QrHardwareCall = {
  readonly params: QrHardwareCallParams;
  readonly origin?: string; // "" encodes as absent
  readonly version?: QrHardwareCallVersion; // presence-preserving: absent ≠ 0
};

const CURVE_WIRE: Readonly<Record<KeyDerivationCurve, number>> = {
  secp256k1: 0,
  ed25519: 1,
};

const ALGORITHM_WIRE: Readonly<Record<KeyDerivationAlgorithm, number>> = {
  slip10: 0,
  bip32Ed25519: 1,
};

function decodeCurve(cbor: Cbor): KeyDerivationCurve {
  switch (expectUnsigned(cbor)) {
    case 0:
      return "secp256k1";
    case 1:
      return "ed25519";
    default:
      throw CborError.outOfRange();
  }
}

function decodeAlgorithm(cbor: Cbor): KeyDerivationAlgorithm {
  switch (expectUnsigned(cbor)) {
    case 0:
      return "slip10";
    case 1:
      return "bip32Ed25519";
    default:
      throw CborError.outOfRange();
  }
}

function curveWire(curve: KeyDerivationCurve): number {
  const wire = CURVE_WIRE[curve];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

function algorithmWire(algorithm: KeyDerivationAlgorithm): number {
  const wire = ALGORITHM_WIRE[algorithm];
  if (wire === undefined) {
    throw CborError.wrongType();
  }
  return wire;
}

function decodeVersion(cbor: Cbor): QrHardwareCallVersion {
  switch (expectUnsigned(cbor)) {
    case 0:
      return 0;
    case 1:
      return 1;
    default:
      throw CborError.outOfRange();
  }
}

function encodeSchema(schema: KeyDerivationSchema): Cbor {
  const map = new CborMap();
  map.set(1, derivationPathTagged(schema.keyPath));
  if (schema.curve !== undefined) {
    map.set(2, curveWire(schema.curve));
  }
  if (schema.algorithm !== undefined) {
    map.set(3, algorithmWire(schema.algorithm));
  }
  setOptionalText(map, 4, schema.chainType);
  return taggedValue(INTEROP_TAGS["key-derivation-schema"], cbor(map));
}

function decodeSchema(cbor: Cbor): KeyDerivationSchema {
  validateTag(cbor, [INTEROP_TAGS["key-derivation-schema"]]);
  const map = expectClosedIntMap(extractTaggedContent(cbor), SCHEMA_KEYS);
  const curve = map.get(2);
  const algorithm = map.get(3);
  const chainType = optionalText(map, 4);
  return Object.freeze({
    keyPath: readDerivationPath(map.getOrThrow(1)),
    ...(curve === undefined ? {} : { curve: decodeCurve(curve) }),
    ...(algorithm === undefined ? {} : { algorithm: decodeAlgorithm(algorithm) }),
    ...(chainType === undefined ? {} : { chainType }),
  });
}

function encodeParams(params: KeyDerivationCall): Cbor {
  if (params.schemas.length === 0) {
    throw CborError.outOfRange();
  }
  const map = new CborMap();
  map.set(1, params.schemas.map(encodeSchema));
  return cbor(map);
}

function decodeParams(cbor: Cbor): KeyDerivationCall {
  validateTag(cbor, [INTEROP_TAGS["key-derivation-call"]]);
  const map = expectClosedIntMap(extractTaggedContent(cbor), PARAMS_KEYS);
  const schemas = expectArray(map.getOrThrow(1));
  if (schemas.length === 0) {
    throw CborError.outOfRange();
  }
  return Object.freeze({
    kind: "keyDerivation",
    schemas: Object.freeze(schemas.map(decodeSchema)),
  });
}

export const qrHardwareCallCodec: UrCodec<QrHardwareCall> = {
  tags: [INTEROP_TAGS["qr-hardware-call"]],
  encode(call) {
    if (call.params.kind !== "keyDerivation") {
      throw CborError.wrongType();
    }
    const map = new CborMap();
    map.set(1, 0);
    map.set(2, taggedValue(INTEROP_TAGS["key-derivation-call"], encodeParams(call.params)));
    setOptionalText(map, 3, call.origin);
    if (call.version !== undefined) {
      if (call.version !== 0 && call.version !== 1) {
        throw CborError.outOfRange();
      }
      map.set(4, call.version);
    }
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, CALL_KEYS);
    // call type is checked before params.
    if (expectUnsigned(map.getOrThrow(1)) !== 0) {
      throw CborError.outOfRange();
    }
    const origin = optionalText(map, 3);
    const version = map.get(4);
    return Object.freeze({
      params: decodeParams(map.getOrThrow(2)),
      ...(origin === undefined ? {} : { origin }),
      ...(version === undefined ? {} : { version: decodeVersion(version) }),
    });
  },
};
