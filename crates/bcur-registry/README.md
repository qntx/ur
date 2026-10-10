# bcur-registry

BCR-2020-006 registry types — `Seed`, `HdKey` (`MasterKey`/`DerivedKey`), `Keypath`, `CoinInfo`, `EcKey`, `Address`, `OutputDescriptor`, `SskrShare`, `Psbt`, `AccountDescriptor` — on the `bcur` typed dCBOR layer, with domain types (`Fingerprint`, `Index`, `ChildNumber`, `ChildRange`, `PathComponent`, `CoinType`, `Network`, `Curve`, `AddressType`) that carry invariants, checked `new` constructors, consuming `with_*` builders, zeroized secrets, and v1 `crypto-output`/`crypto-account` conversion to descriptor parts.

Docs: <https://github.com/qntx/ur/tree/main/docs/rust/registry.mdx>

Licensed under MIT OR Apache-2.0.
