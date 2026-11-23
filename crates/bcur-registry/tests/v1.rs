#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "integration targets link full dev-deps; vector JSON is trusted"
)]

//! v1 `crypto-*` writer vectors: `vectors/registry/v1-writers.json` and
//! `vectors/registry/v1-encode-invalid.json`.

use std::str::FromStr;

use bcur::fountain::EncoderOptions;
use bcur::typed::{Ur, UrDecodable, UrEncodable};
use bcur::ur::{self, UrType};
use bcur_registry::v1::{
    CryptoAccount, CryptoCoinInfo, CryptoHdKey, CryptoKeypath, CryptoOutput, CryptoPsbt,
};
use bcur_registry::{
    AccountDescriptor, CoinInfo, Curve, DescriptorKey, EcKey, Fingerprint, HdKey, OutputDescriptor,
};
use dcbor::{CBOR, CBORTaggedDecodable, CBORTaggedEncodable};
use serde_json::Value;

fn vector(path: &str) -> Value {
    let root = env!("CARGO_MANIFEST_DIR");
    serde_json::from_str(&std::fs::read_to_string(format!("{root}/../../vectors/{path}")).unwrap())
        .unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn cases(path: &str) -> Vec<Value> {
    vector(path)["cases"].as_array().unwrap().clone()
}

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().unwrap()
}

fn body(case: &Value, key: &str) -> CBOR {
    CBOR::try_from_data(unhex(text(case, key))).unwrap()
}

/// Untagged decode + v1 re-encode dispatch for the vector's `codec` names.
fn untagged(codec: &str, cbor: CBOR) -> dcbor::Result<CBOR> {
    match codec {
        "crypto-psbt" => CryptoPsbt::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "crypto-hdkey" => CryptoHdKey::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "crypto-keypath" => CryptoKeypath::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "crypto-coin-info" => CryptoCoinInfo::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "crypto-output" => CryptoOutput::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "crypto-account" => CryptoAccount::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        other => panic!("no codec for {other}"),
    }
}

fn to_ur_string(codec: &str, cbor: &CBOR) -> String {
    macro_rules! go {
        ($t:ty) => {
            <$t>::from_untagged_cbor(cbor.clone())
                .unwrap()
                .to_ur()
                .unwrap()
                .to_string()
        };
    }
    match codec {
        "crypto-psbt" => go!(CryptoPsbt),
        "crypto-hdkey" => go!(CryptoHdKey),
        "crypto-keypath" => go!(CryptoKeypath),
        "crypto-coin-info" => go!(CryptoCoinInfo),
        "crypto-output" => go!(CryptoOutput),
        "crypto-account" => go!(CryptoAccount),
        other => panic!("no codec for {other}"),
    }
}

fn from_ur(codec: &str, ur: &Ur) -> CBOR {
    macro_rules! go {
        ($t:ty) => {
            <$t>::from_ur(ur).unwrap().untagged_cbor()
        };
    }
    match codec {
        "crypto-psbt" => go!(CryptoPsbt),
        "crypto-hdkey" => go!(CryptoHdKey),
        "crypto-keypath" => go!(CryptoKeypath),
        "crypto-coin-info" => go!(CryptoCoinInfo),
        "crypto-output" => go!(CryptoOutput),
        "crypto-account" => go!(CryptoAccount),
        other => panic!("no codec for {other}"),
    }
}

#[test]
fn v1_writer_vectors() {
    let cases = cases("registry/v1-writers.json");
    assert_ne!(cases.len(), 0);
    for case in &cases {
        let name = text(case, "name");
        let codec = text(case, "codec");
        let expected = text(case, "v1CborHex");
        let input = body(case, "inputCborHex");

        let out =
            untagged(codec, input.clone()).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
        assert_eq!(
            hex(&out.to_cbor_data()),
            expected,
            "{name}: v1 re-encode mismatch"
        );
        assert_eq!(to_ur_string(codec, &input), text(case, "ur"), "{name}: ur");

        // The emitted UR decodes back to the same v1 body.
        let ur = Ur::from_str(text(case, "ur")).unwrap();
        assert_eq!(
            hex(&from_ur(codec, &ur).to_cbor_data()),
            expected,
            "{name}: from_ur"
        );
    }
}

#[test]
fn v1_encode_invalid_vectors() {
    let cases = cases("registry/v1-encode-invalid.json");
    assert_ne!(cases.len(), 0);
    for case in &cases {
        let name = text(case, "name");
        let codec = text(case, "codec");
        // The shared contract is rejection; `tsError` is read only by the
        // TypeScript runner.
        assert!(
            untagged(codec, body(case, "inputCborHex")).is_err(),
            "{name}: expected rejection"
        );
    }
}

#[test]
fn v1_psbt_multipart_ur_roundtrip() {
    let cases = cases("registry/v1-writers.json");
    let case = cases
        .iter()
        .find(|c| text(c, "name").starts_with("BIP-174"))
        .expect("BIP-174 psbt case");
    let input = unhex(text(case, "inputCborHex"));
    let psbt = CryptoPsbt::from_untagged_cbor(body(case, "inputCborHex")).unwrap();
    let message = psbt.untagged_cbor().to_cbor_data();
    assert_eq!(hex(&message), text(case, "v1CborHex"));

    let ur_type = UrType::new("crypto-psbt").unwrap();
    let encoder =
        ur::Encoder::new(ur_type.clone(), message.clone(), EncoderOptions::new(100)).unwrap();
    assert!(encoder.fragment_count() > 1, "expected a multi-part UR");

    let mut decoder = ur::Decoder::default().accept([ur_type]);
    for part in encoder.take(64) {
        decoder.receive(&part).unwrap();
    }
    let decoded = decoder.into_decoded().expect("decoder must complete");
    assert_eq!(decoded.message(), message.as_slice());

    // The reassembled body is still a valid crypto-psbt byte-identically.
    let cbor = CBOR::try_from_data(decoded.message()).unwrap();
    let rt = CryptoPsbt::from_untagged_cbor(cbor).unwrap();
    assert_eq!(hex(&rt.untagged_cbor().to_cbor_data()), hex(&input));
}

#[test]
fn v1_coin_info_presence_and_tags() {
    // v1 writes each field iff present, zero included.
    let both_zero =
        CoinInfo::from_untagged_cbor(CBOR::try_from_data(unhex("a201000200")).unwrap()).unwrap();
    let out = CryptoCoinInfo::from(both_zero)
        .untagged_cbor()
        .to_cbor_data();
    assert_eq!(hex(&out), "a201000200");

    // The v2 writer drops explicit defaults; v1 keeps them.
    assert_eq!(hex(&both_zero.untagged_cbor().to_cbor_data()), "a0");

    // Tagged body carries tag 305.
    let tagged = CBOR::from(CryptoCoinInfo::from(both_zero));
    let cbor = CBOR::try_from_data(unhex("d90131a201000200")).unwrap();
    assert_eq!(
        CryptoCoinInfo::try_from(cbor).unwrap().into_inner(),
        both_zero
    );
    let _ = tagged;
}

#[test]
fn v1_hdkey_presence() {
    // `is-private: false` survives a v1 round trip; nested tags are v1.
    let input =
        unhex("a202f403582102abababababababababababababababababababababababababababababababab");
    let hdkey =
        CryptoHdKey::from_untagged_cbor(CBOR::try_from_data(input.clone()).unwrap()).unwrap();
    let out = hdkey.untagged_cbor().to_cbor_data();
    assert_eq!(out, input);
    let derived = match hdkey.into_inner() {
        HdKey::Derived(d) => d,
        other @ HdKey::Master(_) => panic!("expected derived key, got {other:?}"),
    };
    assert_eq!(derived.is_private_flag(), Some(false));
}

#[test]
fn v1_output_and_account_reject_unwritable() {
    let eckey = || {
        DescriptorKey::EcKey(
            EcKey::public(
                Curve::Secp256k1,
                unhex("02abababababababababababababababababababababababababababababababab"),
            )
            .unwrap(),
        )
    };
    // name/note rejection paths.
    let named = OutputDescriptor::new("wpkh(@0)", vec![eckey()])
        .unwrap()
        .with_name("a name");
    assert!(CryptoOutput::try_from(named.clone()).is_err());
    let nested = OutputDescriptor::new("sh(sh(@0))", vec![eckey()]).unwrap();
    assert!(CryptoOutput::try_from(nested).is_err());
    let first = OutputDescriptor::new("wpkh(@0)", vec![eckey()]).unwrap();
    let account = AccountDescriptor::new(Fingerprint::from([0x73, 0xc5, 0xda, 0x0a]), first)
        .with_output_descriptor(named);
    assert!(CryptoAccount::try_from(account).is_err());
}
