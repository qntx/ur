import { cbor, encodeCbor } from "@blockchaincommons/dcbor";
import { sha256 } from "@noble/hashes/sha2.js";

import { copyBuf } from "./bytes.ts";
import type { HdKey } from "./hdkey.ts";
import type { Seed } from "./seed.ts";

/** BCR-2021-002: SHA-256 of the raw seed payload, not the CBOR map. */
export function seedDigest(seed: Seed): Uint8Array {
  return sha256(seed.payload);
}

/** BCR-2021-002: dCBOR of [keyData, chainCode | null, coinType, network]. */
export function hdKeyDigestSource(key: HdKey): Uint8Array {
  const chainCode = key.chainCode === undefined ? null : copyBuf(key.chainCode);
  const coinType = key.kind === "master" ? 0 : (key.useInfo?.type ?? 0);
  const network = key.kind === "master" ? 0 : (key.useInfo?.network ?? 0);
  return encodeCbor(cbor([copyBuf(key.keyData), chainCode, coinType, network]));
}

export function hdKeyDigest(key: HdKey): Uint8Array {
  return sha256(hdKeyDigestSource(key));
}
