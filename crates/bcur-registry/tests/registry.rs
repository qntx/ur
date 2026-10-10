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

//! Shared-vector compliance: `vectors/official/registry/*`,
//! `vectors/keystone/*`, and `vectors/registry/*`.

use std::str::FromStr;

use bcur::bytewords::{self, Style};
use bcur::typed::{Ur, UrDecodable, UrEncodable};
use bcur_registry::{
    AccountDescriptor, Address, CoinInfo, DescriptorKey, EcKey, HdKey, Keypath, OutputDescriptor,
    Psbt, Seed, SskrShare,
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

fn body(case: &Value) -> CBOR {
    CBOR::try_from_data(unhex(text(case, "cborHex"))).unwrap()
}

/// Untagged decode + re-encode dispatch for the vector's `codec` names.
fn untagged(codec: &str, cbor: CBOR) -> dcbor::Result<CBOR> {
    match codec {
        "seed" => Seed::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "hdkey" => HdKey::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "keypath" => Keypath::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "coin-info" => CoinInfo::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "psbt" => Psbt::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "sskr" => SskrShare::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "eckey" => EcKey::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "address" => Address::from_untagged_cbor(cbor).map(|v| v.untagged_cbor()),
        "output-descriptor" | "crypto-output" => {
            OutputDescriptor::from_untagged_cbor(cbor).map(|v| v.untagged_cbor())
        }
        "account-descriptor" | "crypto-account" => {
            AccountDescriptor::from_untagged_cbor(cbor).map(|v| v.untagged_cbor())
        }
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
        "eckey" => EcKey::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "address" => Address::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "output-descriptor" | "crypto-output" => OutputDescriptor::from_untagged_cbor(cbor.clone())
            .unwrap()
            .to_ur()
            .unwrap()
            .to_string(),
        "account-descriptor" | "crypto-account" => {
            AccountDescriptor::from_untagged_cbor(cbor.clone())
                .unwrap()
                .to_ur()
                .unwrap()
                .to_string()
        }
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
        "eckey" => EcKey::from_ur(ur).unwrap().untagged_cbor(),
        "address" => Address::from_ur(ur).unwrap().untagged_cbor(),
        "output-descriptor" | "crypto-output" => {
            OutputDescriptor::from_ur(ur).unwrap().untagged_cbor()
        }
        "account-descriptor" | "crypto-account" => {
            AccountDescriptor::from_ur(ur).unwrap().untagged_cbor()
        }
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

#[test]
fn invalid_vectors() {
    let mut ran = 0;
    for case in cases("registry/invalid.json") {
        ran += 1;
        let name = text(&case, "name");
        let codec = text(&case, "codec");
        // The shared contract is rejection; the vector's `tsError` field is
        // read only by the TypeScript runner.
        assert!(
            untagged(codec, body(&case)).is_err(),
            "{name}: expected rejection"
        );
    }
    assert!(ran > 0, "no in-scope invalid cases ran");
}

fn tagged_key_hexes(descriptor: &OutputDescriptor) -> Vec<String> {
    descriptor
        .keys()
        .iter()
        .map(|key| hex(&CBOR::from(key.clone()).to_cbor_data()))
        .collect()
}

fn expected_key_hexes(case: &Value) -> Vec<String> {
    case["keys"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .map(|k| text(k, "taggedCborHex").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `source` contains an `@<digits>` placeholder or starts with `raw(`.
fn has_descriptor_text(source: &str) -> bool {
    source.starts_with("raw(")
        || source
            .as_bytes()
            .windows(2)
            .any(|w| w[0] == b'@' && w[1].is_ascii_digit())
}

/// `substituteEcKeys`: every `@n` becomes the lowercase hex of that key's
/// eckey data.
fn substitute_eckeys(descriptor: &OutputDescriptor) -> String {
    let mut text = descriptor.source().to_owned();
    for index in (0..descriptor.keys().len()).rev() {
        if let DescriptorKey::EcKey(key) = &descriptor.keys()[index] {
            text = text.replace(&format!("@{index}"), &hex(key.data()));
        }
    }
    text
}

#[test]
fn official_v2_registry_roundtrip() {
    for path in [
        "official/registry/eckey.json",
        "official/registry/address.json",
        "official/registry/output-descriptor.json",
        "official/registry/account-descriptor.json",
    ] {
        for case in cases(path) {
            let name = text(&case, "name");
            let codec = text(&case, "urType");
            let file = path.rsplit('/').next().unwrap();

            let reencoded = untagged(codec, body(&case))
                .unwrap_or_else(|e| panic!("{file}/{name}: decode failed: {e:?}"));
            assert_eq!(
                hex(&reencoded.to_cbor_data()),
                text(&case, "cborHex"),
                "{file}/{name}: re-encode"
            );

            if let Some(source) = case["source"].as_str() {
                assert_eq!(
                    OutputDescriptor::from_untagged_cbor(body(&case))
                        .unwrap()
                        .source(),
                    source,
                    "{file}/{name}: source"
                );
            }

            if let Some(ur_text) = case["ur"].as_str() {
                assert_eq!(
                    to_ur_string(codec, &body(&case)),
                    ur_text,
                    "{file}/{name}: to_ur"
                );
                let ur = Ur::from_str(ur_text)
                    .unwrap_or_else(|e| panic!("{file}/{name}: Ur::from_str: {e:?}"));
                assert_eq!(
                    hex(&from_ur_untagged(codec, &ur).to_cbor_data()),
                    text(&case, "cborHex"),
                    "{file}/{name}: from_ur"
                );
            }
        }
    }
}

/// v1 crypto-output: decode the tagged script-expression body, then
/// re-encode as v2 and compare against the conversion vector (paired by
/// index).
#[test]
fn v1_crypto_output_conversion() {
    let conversions = cases("registry/crypto-output-conversion.json");
    for (index, case) in cases("official/registry/crypto-output.json")
        .iter()
        .enumerate()
    {
        let name = text(case, "name");
        let descriptor = OutputDescriptor::from_untagged_cbor(body(case))
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));
        let expected = &conversions[index];

        assert_eq!(
            descriptor.source(),
            text(expected, "source"),
            "{name}: source"
        );
        assert_eq!(
            tagged_key_hexes(&descriptor),
            expected_key_hexes(expected),
            "{name}: keys"
        );
        assert_eq!(
            hex(&descriptor.untagged_cbor().to_cbor_data()),
            text(&expected["v2"], "cborHex"),
            "{name}: v2 cbor"
        );
        assert_eq!(
            descriptor.to_ur().unwrap().to_string(),
            text(&expected["v2"], "ur"),
            "{name}: v2 ur"
        );

        // The official v1 UR also decodes through `crypto-output`.
        let ur = Ur::from_str(text(case, "ur")).unwrap();
        assert_eq!(
            OutputDescriptor::from_ur(&ur).unwrap().source(),
            text(expected, "source"),
            "{name}: v1 ur"
        );
    }
}

/// v1 crypto-account (official): decode as untagged body and re-encode as
/// v2, matched against the conversion vector's account case.
#[test]
fn v1_crypto_account_conversion() {
    let conversions = cases("registry/crypto-output-conversion.json");
    let expected = conversions.last().unwrap();
    for case in cases("official/registry/crypto-account.json") {
        let name = text(&case, "name");
        let account = AccountDescriptor::from_untagged_cbor(body(&case))
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

        assert_eq!(
            u64::from(account.master_fingerprint()),
            expected["masterFingerprint"].as_u64().unwrap(),
            "{name}: fingerprint"
        );
        let entries = expected["entries"].as_array().unwrap();
        assert_eq!(account.output_descriptors().len(), entries.len());
        for (descriptor, entry) in account.output_descriptors().iter().zip(entries) {
            assert_eq!(descriptor.source(), text(entry, "source"));
            assert_eq!(tagged_key_hexes(descriptor), expected_key_hexes(entry));
        }
        assert_eq!(
            hex(&account.untagged_cbor().to_cbor_data()),
            text(&expected["v2"], "cborHex"),
            "{name}: v2 cbor"
        );
        assert_eq!(
            account.to_ur().unwrap().to_string(),
            text(&expected["v2"], "ur"),
            "{name}: v2 ur"
        );

        // The official v1 UR also decodes through `crypto-account`.
        let ur = Ur::from_str(text(&case, "ur")).unwrap();
        assert_eq!(
            AccountDescriptor::from_ur(&ur)
                .unwrap()
                .master_fingerprint(),
            account.master_fingerprint(),
            "{name}: v1 ur"
        );
    }
}

/// `KeystoneHQ` ur-registry (second source): the 5 crypto-output URs decode
/// to the same sources as the official conversion cases.
#[test]
fn keystone_crypto_output() {
    let conversions = cases("registry/crypto-output-conversion.json");
    for (index, case) in cases("keystone/crypto-output.json").iter().enumerate() {
        let name = text(case, "name");
        let ur = Ur::from_str(text(case, "ur")).unwrap();
        let descriptor = OutputDescriptor::from_ur(&ur)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));
        assert_eq!(
            descriptor.source(),
            text(&conversions[index], "source"),
            "{name}: source"
        );

        match case["textDescriptor"].as_str() {
            // eckey cases: substituting @n with the key data reproduces the
            // text descriptor.
            Some(text_descriptor) if !text_descriptor.contains("xpub") => {
                assert_eq!(
                    substitute_eckeys(&descriptor),
                    text_descriptor,
                    "{name}: textDescriptor"
                );
            }
            // xpub rendering needs BIP32 base58; assert only the key kind.
            Some(text_descriptor) if text_descriptor.contains("xpub") => {
                assert!(
                    descriptor
                        .keys()
                        .iter()
                        .all(|k| matches!(k, DescriptorKey::HdKey(_))),
                    "{name}: expected hdkey keys"
                );
            }
            _ => {}
        }
    }
}

/// `KeystoneHQ` crypto-account URs: the first shares the official account's
/// fingerprint and all but its last descriptor source.
#[test]
fn keystone_crypto_account() {
    let officials = cases("official/registry/crypto-account.json");
    let official = AccountDescriptor::from_untagged_cbor(body(&officials[0])).unwrap();
    for (index, case) in cases("keystone/crypto-account.json").iter().enumerate() {
        let name = text(case, "name");
        let ur = Ur::from_str(text(case, "ur")).unwrap();
        let account = AccountDescriptor::from_ur(&ur)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));
        assert!(!account.output_descriptors().is_empty(), "{name}");
        for descriptor in account.output_descriptors() {
            assert!(
                has_descriptor_text(descriptor.source()),
                "{name}: {}",
                descriptor.source()
            );
        }
        if index == 0 {
            assert_eq!(
                account.master_fingerprint(),
                official.master_fingerprint(),
                "{name}: fingerprint"
            );
            let tail = official.output_descriptors().len() - 1;
            let sources: Vec<&str> = account
                .output_descriptors()
                .iter()
                .map(OutputDescriptor::source)
                .collect();
            let expected: Vec<&str> = official.output_descriptors()[..tail]
                .iter()
                .map(OutputDescriptor::source)
                .collect();
            assert_eq!(sources, expected, "{name}: sources");
        }
    }
}

/// `crossCheck` metadata: placeholder-substitution cases are internally
/// consistent.
#[test]
fn conversion_crosscheck() {
    for case in cases("registry/crypto-output-conversion.json") {
        let cross_check = &case["crossCheck"];
        if cross_check["matches"].as_bool() == Some(true) {
            assert_eq!(
                cross_check["method"].as_str().unwrap(),
                "placeholder-substitution"
            );
            assert_eq!(
                cross_check["substituted"].as_str().unwrap(),
                cross_check["textDescriptor"].as_str().unwrap()
            );
        }
    }
}
