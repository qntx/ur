# bcur

A Rust implementation of [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) (URs): bytewords, fountain codes, and single- or multi-part UR strings. `no_std` + `alloc` capable; the typed dCBOR layer is behind the `dcbor` feature.

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

See the [documentation](https://github.com/qntx/ur/tree/main/docs).

## License

MIT OR Apache-2.0
