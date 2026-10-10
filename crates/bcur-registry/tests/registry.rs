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

//! Shared-vector compliance: `vectors/official/registry/{seed,hdkey,psbt,sskr}`
//! and `vectors/registry/invalid.json`, mirroring
//! `packages/ur/tests/vectors/registry.test.ts`.

use std::str::FromStr;

use bcur::bytewords::{self, Style};
use bcur::typed::{Ur, UrDecodable, UrEncodable};
use bcur_registry::{CoinInfo, HdKey, Keypath, Psbt, Seed, SskrShare};
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

fn body(case: &Value) -> CBOR {
    CBOR::try_from_data(unhex(text(case, "cborHex"))).unwrap()
}

/// Untagged decode + re-encode dispatch, mirroring the TS `CODECS` table.
fn untagged(codec: &str, cbor: CBOR) -> dcbor::Result<CBOR> {
    match codec {
        "seed" => Seed::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "hdkey" => HdKey::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "keypath" => Keypath::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "coin-info" => CoinInfo::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "psbt" => Psbt::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "sskr" => SskrShare::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        other => panic!("no codec for {other}"),
    }
}

fn to_ur_string(codec: &str, cbor: &CBOR) -> String {
    match codec {
        "seed" => Seed::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "hdkey" => HdKey::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "keypath" => Keypath::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "coin-info" => CoinInfo::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "psbt" => Psbt::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "sskr" => SskrShare::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        other => panic!("no codec for {other}"),
    }
}

fn from_ur_untagged(codec: &str, ur: &Ur) -> CBOR {
    match codec {
        "seed" => Seed::from_ur(ur).unwrap().untagged_cbor(),
        "hdkey" => HdKey::from_ur(ur).unwrap().untagged_cbor(),
        "keypath" => Keypath::from_ur(ur).unwrap().untagged_cbor(),
        "coin-info" => CoinInfo::from_ur(ur).unwrap().untagged_cbor(),
        "psbt" => Psbt::from_ur(ur).unwrap().untagged_cbor(),
        "sskr" => SskrShare::from_ur(ur).unwrap().untagged_cbor(),
        other => panic!("no codec for {other}"),
    }
}

// UR-ADR-019: the tag-100 creation date reads as the tag-1 date and re-encodes
// as tag 1 — the official vector's input is the tag-100 form.
const SEED_TAG100_NAME: &str = "v2 seed, tag-100 creation date";
const SEED_TAG1_CBOR_HEX: &str = "a20150c7098580125e2ab0981253468b2dbc5202c11a5eb9e700";
const SEED_TAG1_UR: &str = "ur:seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaosecyhyrhvdaednlbbywe";

#[test]
fn official_seed_hdkey_psbt_roundtrip() {
    for path in [
        "official/registry/seed.json",
        "official/registry/hdkey.json",
        "official/registry/psbt.json",
    ] {
        for case in cases(path) {
            let name = text(&case, "name");
            let codec = text(&case, "urType");
            let cbor_hex = text(&case, "cborHex");
            let file = path.rsplit('/').next().unwrap();
            let tag100 = name == SEED_TAG100_NAME;
            let expected_hex = if tag100 { SEED_TAG1_CBOR_HEX } else { cbor_hex };
            let expected_ur = if tag100 {
                SEED_TAG1_UR
            } else {
                text(&case, "ur")
            };

            let reencoded = untagged(codec, body(&case))
                .unwrap_or_else(|e| panic!("{file}/{name}: decode failed: {e:?}"));
            assert_eq!(
                hex(&reencoded.to_cbor_data()),
                expected_hex,
                "{file}/{name}: re-encode"
            );

            assert_eq!(
                to_ur_string(codec, &body(&case)),
                expected_ur,
                "{file}/{name}: to_ur"
            );

            let ur = Ur::from_str(expected_ur)
                .unwrap_or_else(|e| panic!("{file}/{name}: Ur::from_str: {e:?}"));
            assert_eq!(
                hex(&from_ur_untagged(codec, &ur).to_cbor_data()),
                expected_hex,
                "{file}/{name}: from_ur"
            );
        }
    }
}

#[test]
fn official_hdkey_digests() {
    for case in cases("official/registry/hdkey.json") {
        let (Some(source_hex), Some(digest_hex)) =
            (case["digestSourceHex"].as_str(), case["digestHex"].as_str())
        else {
            continue;
        };
        let name = text(&case, "name");
        let key = HdKey::from_untagged_cbor(body(&case)).unwrap();
        assert_eq!(
            hex(&key.digest_source()),
            source_hex,
            "{name}: digest_source"
        );
        assert_eq!(hex(&key.digest()), digest_hex, "{name}: digest");
    }
}

#[test]
fn official_sskr_shares() {
    for case in cases("official/registry/sskr.json") {
        let name = text(&case, "name");
        for share in case["shares"].as_array().unwrap() {
            let index = share["index"].as_u64().unwrap();
            let cbor_hex = text(share, "cborHex");
            let label = format!("{name} share {index}");

            let cbor = CBOR::try_from_data(unhex(cbor_hex)).unwrap();
            let value = SskrShare::from_untagged_cbor(cbor).unwrap();
            assert_eq!(
                hex(&value.untagged_cbor().to_cbor_data()),
                cbor_hex,
                "{label}: re-encode"
            );

            // Tagged share as standard bytewords (the doc's display form).
            let tagged = value.tagged_cbor().to_cbor_data();
            assert_eq!(
                hex(&tagged),
                text(share, "taggedCborHex"),
                "{label}: tagged"
            );
            assert_eq!(
                bytewords::decode(text(share, "bytewords"), Style::Standard).unwrap(),
                tagged,
                "{label}: bytewords"
            );

            assert_eq!(
                value.to_ur().unwrap().to_string(),
                text(share, "ur"),
                "{label}: to_ur"
            );
            let ur = Ur::from_str(text(share, "ur")).unwrap();
            assert_eq!(
                hex(&SskrShare::from_ur(&ur)
                    .unwrap()
                    .untagged_cbor()
                    .to_cbor_data()),
                cbor_hex,
                "{label}: from_ur"
            );
        }
    }
}

const fn dcbor_name(error: &dcbor::Error) -> &'static str {
    match error {
        dcbor::Error::Underrun => "Underrun",
        dcbor::Error::UnsupportedHeaderValue(_) => "UnsupportedHeaderValue",
        dcbor::Error::NonCanonicalNumeric => "NonCanonicalNumeric",
        dcbor::Error::InvalidSimpleValue => "InvalidSimpleValue",
        dcbor::Error::InvalidString(_) => "InvalidString",
        dcbor::Error::NonCanonicalString => "NonCanonicalString",
        dcbor::Error::UnusedData(_) => "UnusedData",
        dcbor::Error::MisorderedMapKey => "MisorderedMapKey",
        dcbor::Error::DuplicateMapKey => "DuplicateMapKey",
        dcbor::Error::MissingMapKey => "MissingMapKey",
        dcbor::Error::OutOfRange => "OutOfRange",
        dcbor::Error::WrongType => "WrongType",
        dcbor::Error::WrongTag(..) => "WrongTag",
        dcbor::Error::InvalidUtf8(_) => "InvalidUtf8",
        dcbor::Error::InvalidDate(_) => "InvalidDate",
        dcbor::Error::Custom(_) => "Custom",
    }
}

#[test]
fn invalid_vectors() {
    let ours = ["seed", "hdkey", "keypath", "coin-info", "psbt", "sskr"];
    let mut ran = 0;
    for case in cases("registry/invalid.json") {
        let codec = text(&case, "codec");
        if !ours.contains(&codec) {
            continue;
        }
        ran += 1;
        let name = text(&case, "name");
        let cbor = body(&case);
        let error = untagged(codec, cbor).unwrap_err();
        assert_eq!(dcbor_name(&error), text(&case, "dcbor"), "{name}");
    }
    assert!(ran > 0, "no in-scope invalid cases ran");
}
