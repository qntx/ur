import { expectBytes } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

export function copyBuf(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export function copyBytes(cbor: Cbor): Uint8Array {
  return copyBuf(expectBytes(cbor));
}
