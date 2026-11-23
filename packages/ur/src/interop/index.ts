// Interop (vendor-extension) codecs: Keystone / OneKey / ERC-4527 `eth-*`, `sol-*`, `tron-*`
// sign requests/signatures and `crypto-multi-accounts`. Same typed-layer contract as
// `registry`: `UrCodec`s plug into `toUr`/`fromUr`/`codecMap` and the `Ur` helpers.

export { INTEROP_TAGS } from "./tags.ts";
export {
  ethSignRequestCodec,
  ethSignatureCodec,
  type EthDataType,
  type EthSignRequest,
  type EthSignature,
} from "./eth.ts";
export {
  solSignRequestCodec,
  solSignatureCodec,
  type SolSignRequest,
  type SolSignType,
  type SolSignature,
} from "./sol.ts";
export {
  oneKeyTronSignRequestCodec,
  tronSignRequestCodec,
  tronSignatureCodec,
  type TronDataType,
  type TronSignRequest,
  type TronSignature,
} from "./tron.ts";
export {
  cryptoMultiAccountsCodec,
  type Ed25519HdKey,
  type MultiAccounts,
  type MultiAccountsKey,
} from "./multi-accounts.ts";

export type { CoinInfo, DerivedHdKey, Keypath, PathComponent } from "../registry/index.ts";
export { cryptoKeypathCodec } from "../registry/index.ts";
export {
  type CodecMap,
  type CodecValue,
  type UrCodec,
  codecUrTypes,
  toUr,
  fromUr,
  toTagged,
  fromTagged,
  codecMap,
  fromUrWith,
  Ur,
  isUrType,
  parseUrType,
  type UrType,
} from "../typed/index.ts";
export { UrError, type UrErrorCode, type UrErrorInfo, type UrLimit } from "../error.ts";
