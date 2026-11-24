# bcur-registry

BCR-2020-006 registry types — `Seed`, `HdKey` (`MasterKey`/`DerivedKey`), `Keypath`, `CoinInfo`, `EcKey`, `Address`, `OutputDescriptor`, `SskrShare`, `Psbt`, `AccountDescriptor` — on the `bcur` typed dCBOR layer, with domain types (`Fingerprint`, `Index`, `ChildNumber`, `ChildRange`, `PathComponent`, `CoinType`, `Network`, `Curve`, `AddressType`) that carry invariants, checked `new` constructors, consuming `with_*` builders, zeroized secrets, and v1 `crypto-output`/`crypto-account` conversion to descriptor parts.

The `v1` module holds opt-in writer newtypes for the deprecated `crypto-*` wire forms — `CryptoPsbt`, `CryptoHdKey`, `CryptoKeypath`, `CryptoCoinInfo`, `CryptoOutput`, `CryptoAccount` — that emit exactly what deployed v1 readers expect: presence-preserving field writes (`Some(0)`/`Some(false)` included), v1 tags on nested use-info/keypaths, bare script trees inside `crypto-account`, and validation that rejects what v1 cannot express (`name`/`note`, sources outside the BCR-2020-010 grammar).

The `interop` cargo feature (default off) exposes `bcur_registry::interop`:
the deployed wallet-extension codecs `eth-*`, `sol-*`, `tron-*`, `btc-*`,
`crypto-multi-accounts`, and `qr-hardware-call` (Keystone, `OneKey`,
ERC-4527), including both TRON dialects (`TronSignRequest` tag 5101
Keystone layout, `OneKeyTronSignRequest` tag 5201 `OneKey` layout).

Docs: <https://github.com/qntx/ur/tree/main/docs/rust/registry.mdx>

Licensed under MIT OR Apache-2.0.
