import { CborError, cbor } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { TAGS } from "./tags.ts";

const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff] as const;

export type Psbt = {
  readonly bytes: Uint8Array; // includes magic 0x70736274ff
};

function copyPsbt(bytes: Uint8Array): Uint8Array {
  if (bytes.length < PSBT_MAGIC.length) {
    throw CborError.outOfRange();
  }
  for (let i = 0; i < PSBT_MAGIC.length; i++) {
    if (bytes[i] !== PSBT_MAGIC[i]) {
      throw CborError.wrongType();
    }
  }
  return copyBuf(bytes);
}

export const psbtCodec: UrCodec<Psbt> = {
  tags: [TAGS.psbt, TAGS["crypto-psbt"]],
  encode(psbt) {
    return cbor(copyPsbt(psbt.bytes));
  },
  decode(value: Cbor) {
    return Object.freeze({ bytes: copyPsbt(copyBytes(value)) });
  },
};
