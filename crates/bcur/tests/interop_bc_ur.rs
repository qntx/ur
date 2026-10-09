#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::excessive_nesting,
    reason = "integration targets link full dev-deps and host unwraps by design"
)]

//! Integration checks aligned with bc-ur public examples (wire bytes only).
//!
//! Does not copy bc-ur source; only well-known published UR strings / CBOR.

use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoder, Encoder, ParsedUr, encode, parse, to_qr_string};
use bcur::{DecoderLimits, State, UrType, ur_type};

#[test]
fn bc_ur_array_123_single_part() {
    let cbor = hex::decode("83010203").unwrap();
    let ur = encode(&UrType::new("test").unwrap(), &cbor);
    assert_eq!(ur, "ur:test/lsadaoaxjygonesw");
    let parsed = parse(&ur, &DecoderLimits::default()).unwrap();
    let ParsedUr::Single { message, .. } = parsed else {
        unreachable!("expected single");
    };
    assert_eq!(message, cbor);
}

#[test]
fn uppercase_qr_roundtrip_single_and_multi() {
    let cbor = hex::decode("83010203").unwrap();
    let lower = encode(&UrType::new("test").unwrap(), &cbor);
    let upper = to_qr_string(&lower);
    assert_eq!(
        parse(&upper, &DecoderLimits::default()).unwrap(),
        parse(&lower, &DecoderLimits::default()).unwrap()
    );

    let data = b"bc-ur multipath".repeat(8);
    let mut encoder =
        Encoder::new(ur_type!("bytes"), data.clone(), EncoderOptions::new(10)).unwrap();
    let mut decoder = Decoder::default();
    while !matches!(decoder.state(), State::Complete(_)) {
        let part = encoder.next().unwrap();
        decoder.receive(&to_qr_string(&part)).unwrap();
    }
    assert_eq!(decoder.into_decoded().unwrap().message(), data.as_slice());
}
