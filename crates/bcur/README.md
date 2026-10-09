# bcur

A Rust implementation of [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) (URs).

URs encode binary payloads as URI-friendly strings for QR codes and unreliable channels, using [bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) and fountain codes for multi-part transfer.

## Layering

**L0–L3 (always built).** A UR type token is a validated label (`[a-z0-9-]+` after ASCII lowercasing). The body is raw bytes plus the bytewords CRC. `ur::encode` / `ur::Encoder` do **not** parse or require CBOR, so generic hosts and tests can move opaque payloads; this split matches ur-rs.

**BCR-2020-005** says a UR _message_ MUST be dCBOR and that type `bytes` MUST NOT be used except for testing. That MUST is enforced on **L4** (`feature = "dcbor"`): `FromStr for typed::Ur` and `TryFrom<ur::Decoded> for typed::Ur` reject non-dCBOR (`ErrorKind::CborDecode`). L4 uses the first registered `dcbor` tag **name** as the type token and strips the tag from the UR body (005 "top-level UR is untagged").

Registry types (seed, hdkey, PSBT, …) are not part of this crate; application types implement `UrEncodable` / `UrDecodable`.

## Features

| Feature | Default | Description                         |
| ------- | ------- | ----------------------------------- |
| `std`   | yes     | Host / std builds                   |
| `dcbor` | no      | Typed `Ur` / traits (implies `std`) |

`no_std` + `alloc`: `--no-default-features`.

## Quick start

L3 transport — opaque bytes plus a type token. The encoder is an iterator; the decoder reports one outcome per frame.

```rust
use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoder, Encoder};
use bcur::{State, ur_type};

let data = b"Ten chars!".repeat(10);
let mut encoder = Encoder::new(ur_type!("alpha"), data.clone(), EncoderOptions::new(10)).unwrap();
let mut decoder = Decoder::default();
for frame in encoder.by_ref() {
    decoder.receive(&frame).unwrap();
    if matches!(decoder.state(), State::Complete(_)) {
        break;
    }
}
assert_eq!(decoder.into_decoded().unwrap().message(), data.as_slice());
```

L4 typed dCBOR (`feature = "dcbor"`). The first registered tag **name** is the UR type; the body is untagged.

```rust
use bcur::{Ur, ur_type};

let ur = Ur::new(ur_type!("test"), vec![1, 2, 3]);
assert_eq!(ur.to_string(), "ur:test/lsadaoaxjygonesw");
```

## License

MIT OR Apache-2.0
