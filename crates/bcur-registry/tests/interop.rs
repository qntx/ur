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

//! Interop vectors: `vectors/interop/*.json` (+ `invalid.json`). Each case
//! decodes `inputCborHex` (or `cborHex`), is compared against the
//! language-neutral `value`, and re-encodes byte-identically.
#![cfg(feature = "interop")]

use bcur::typed::{UrDecodable, UrEncodable};
use std::str::FromStr;

use bcur::typed::Ur;
use bcur_registry::interop::{
    ChainId, EthDataType, EthSignRequest, EthSignature, MultiAccounts, MultiAccountsKey,
    OneKeyTronSignRequest, RequestId, SolSignRequest, SolSignType, SolSignature, TronDataType,
    TronSignRequest, TronSignature,
};
use bcur_registry::{CoinInfo, CoinType, Keypath, PathComponent};
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

fn tagged(case: &Value) -> CBOR {
    let hex = case["inputCborHex"]
        .as_str()
        .or_else(|| case["cborHex"].as_str())
        .unwrap();
    CBOR::try_from_data(unhex(hex)).unwrap()
}

fn opt_hex(value: &Value, key: &str) -> Option<Vec<u8>> {
    value.get(key).map(|v| unhex(v.as_str().unwrap()))
}

fn opt_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).map(|v| v.as_u64().unwrap())
}

fn opt_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `m/44'/60'/0'` style string for a concrete keypath.
fn path_string(path: &Keypath) -> String {
    let mut out = String::from("m");
    for component in path.components() {
        match component {
            PathComponent::Child(n) => {
                out.push('/');
                out.push_str(&n.index().get().to_string());
                if n.is_hardened() {
                    out.push('\'');
                }
            }
            _ => out.push_str("/?"),
        }
    }
    out
}

fn check_path(actual: &Keypath, expected: &Value) {
    assert_eq!(
        path_string(actual),
        expected["components"].as_str().unwrap(),
        "path components"
    );
    match expected.get("sourceFingerprint") {
        Some(fp) => {
            let fp_bytes: [u8; 4] = unhex(fp.as_str().unwrap()).try_into().unwrap();
            assert_eq!(
                actual.source_fingerprint().unwrap().to_bytes(),
                fp_bytes,
                "source fingerprint"
            );
        }
        None => assert!(
            actual.source_fingerprint().is_none(),
            "source fingerprint must be absent"
        ),
    }
    match expected.get("depth") {
        Some(d) => assert_eq!(
            actual.depth(),
            Some(u8::try_from(d.as_u64().unwrap()).unwrap()),
            "depth"
        ),
        None => assert!(actual.depth().is_none(), "depth must be absent"),
    }
}

fn check_coin_info(actual: Option<CoinInfo>, expected: Option<&Value>) {
    match (actual, expected) {
        (Some(info), Some(v)) => {
            assert_eq!(
                info.coin_type().map(CoinType::get),
                v.get("coinType")
                    .and_then(Value::as_u64)
                    .map(|n| u32::try_from(n).unwrap()),
                "coin type"
            );
            assert_eq!(
                info.network().map(|n| i64::from(n.get())),
                v.get("network").and_then(Value::as_i64),
                "network"
            );
        }
        (None, None) => {}
        _ => panic!("use_info presence mismatch"),
    }
}

fn check_eth_request(actual: &EthSignRequest, value: &Value) {
    assert_eq!(
        opt_hex(value, "requestId").as_deref(),
        actual
            .request_id()
            .map(|r| r.as_bytes().to_vec())
            .as_deref(),
        "request id"
    );
    assert_eq!(
        unhex(value["signData"].as_str().unwrap()),
        actual.sign_data(),
        "sign data"
    );
    let data_type = match value["dataType"].as_str().unwrap() {
        "transaction" => EthDataType::Transaction,
        "typedData" => EthDataType::TypedData,
        "personalMessage" => EthDataType::PersonalMessage,
        "typedTransaction" => EthDataType::TypedTransaction,
        other => panic!("bad dataType {other}"),
    };
    assert_eq!(actual.data_type(), data_type, "data type");
    assert_eq!(
        opt_u64(value, "chainId"),
        actual.chain_id().map(ChainId::get),
        "chain id"
    );
    check_path(actual.derivation_path(), &value["derivationPath"]);
    assert_eq!(
        opt_hex(value, "address").as_deref(),
        actual.address().map(<[u8; 20]>::as_slice),
        "address"
    );
    assert_eq!(opt_text(value, "origin"), actual.origin(), "origin");
}

fn check_eth_signature(actual: &EthSignature, value: &Value) {
    assert_eq!(
        opt_hex(value, "requestId").as_deref(),
        actual
            .request_id()
            .map(|r| r.as_bytes().to_vec())
            .as_deref(),
        "request id"
    );
    assert_eq!(
        unhex(value["signature"].as_str().unwrap()),
        actual.signature(),
        "signature"
    );
    assert_eq!(opt_text(value, "origin"), actual.origin(), "origin");
}

fn check_sol_request(actual: &SolSignRequest, value: &Value) {
    assert_eq!(
        opt_hex(value, "requestId").as_deref(),
        actual
            .request_id()
            .map(|r| r.as_bytes().to_vec())
            .as_deref(),
        "request id"
    );
    assert_eq!(
        unhex(value["signData"].as_str().unwrap()),
        actual.sign_data(),
        "sign data"
    );
    let sign_type = match value["signType"].as_str().unwrap() {
        "transaction" => SolSignType::Transaction,
        "message" => SolSignType::Message,
        "offchainMessageLegacy" => SolSignType::OffchainMessageLegacy,
        "offchainMessageStandard" => SolSignType::OffchainMessageStandard,
        other => panic!("bad signType {other}"),
    };
    assert_eq!(actual.sign_type(), sign_type, "sign type");
    check_path(actual.derivation_path(), &value["derivationPath"]);
    assert_eq!(
        opt_hex(value, "address").as_deref(),
        actual.address(),
        "address"
    );
    assert_eq!(opt_text(value, "origin"), actual.origin(), "origin");
}

fn check_sol_signature(actual: &SolSignature, value: &Value) {
    assert_eq!(
        opt_hex(value, "requestId").as_deref(),
        actual
            .request_id()
            .map(|r| r.as_bytes().to_vec())
            .as_deref(),
        "request id"
    );
    assert_eq!(
        &unhex(value["signature"].as_str().unwrap())[..],
        actual.signature(),
        "signature"
    );
}

fn tron_data_type(value: &Value) -> TronDataType {
    match value["dataType"].as_str().unwrap() {
        "transaction" => TronDataType::Transaction,
        "messageV1" => TronDataType::MessageV1,
        "messageV2" => TronDataType::MessageV2,
        other => panic!("bad dataType {other}"),
    }
}

fn check_tron_request_fields(
    value: &Value,
    data_type: TronDataType,
    request_id: Option<RequestId>,
    sign_data: &[u8],
    derivation_path: &Keypath,
    address: Option<&[u8]>,
    origin: Option<&str>,
) {
    assert_eq!(tron_data_type(value), data_type, "data type");
    assert_eq!(
        opt_hex(value, "requestId").as_deref(),
        request_id.map(|r| r.as_bytes().to_vec()).as_deref(),
        "request id"
    );
    assert_eq!(
        unhex(value["signData"].as_str().unwrap()),
        sign_data,
        "sign data"
    );
    check_path(derivation_path, &value["derivationPath"]);
    assert_eq!(opt_hex(value, "address").as_deref(), address, "address");
    assert_eq!(opt_text(value, "origin"), origin, "origin");
}

/// Decode a `tron-sign-request` case through the writer named by `codec` and
/// compare all fields against the language-neutral `value`.
fn check_tron_request(value: &Value, codec: Option<&str>, input: &CBOR) {
    if codec == Some("onekey-tron-sign-request") {
        let v = OneKeyTronSignRequest::try_from(input.clone()).unwrap();
        check_tron_request_fields(
            value,
            v.data_type(),
            v.request_id(),
            v.sign_data(),
            v.derivation_path(),
            v.address(),
            v.origin(),
        );
    } else {
        let v = TronSignRequest::try_from(input.clone()).unwrap();
        check_tron_request_fields(
            value,
            v.data_type(),
            v.request_id(),
            v.sign_data(),
            v.derivation_path(),
            v.address(),
            v.origin(),
        );
    }
}

fn check_multi_accounts(actual: &MultiAccounts, value: &Value) {
    assert_eq!(
        actual.master_fingerprint().to_bytes(),
        u32::try_from(value["masterFingerprint"].as_u64().unwrap())
            .unwrap()
            .to_be_bytes(),
        "master fingerprint"
    );
    let keys = value["keys"].as_array().unwrap();
    assert_eq!(actual.keys().len(), keys.len(), "key count");
    for (actual_key, expected) in actual.keys().iter().zip(keys.iter()) {
        let curve = expected["curve"].as_str().unwrap();
        let key_data = unhex(expected["keyData"].as_str().unwrap());
        let (
            info_origin,
            info_children,
            info_name,
            info_note,
            info_fp,
            info_use,
            info_chain,
            info_priv,
        );
        match actual_key {
            MultiAccountsKey::Secp256k1(key) => {
                assert_eq!(curve, "secp256k1", "curve");
                assert_eq!(&key_data[..], key.key_data(), "key data");
                info_priv = key.is_private_flag();
                info_chain = key.chain_code().map(<[u8; 32]>::as_slice);
                info_use = key.use_info();
                info_origin = key.origin();
                info_children = key.children();
                info_fp = key.parent_fingerprint();
                info_name = key.name();
                info_note = key.note();
            }
            MultiAccountsKey::Ed25519(key) => {
                assert_eq!(curve, "ed25519", "curve");
                assert_eq!(&key_data[..], key.key_data(), "key data");
                info_priv = key.is_private_flag();
                info_chain = key.chain_code().map(<[u8; 32]>::as_slice);
                info_use = key.use_info();
                info_origin = key.origin();
                info_children = key.children();
                info_fp = key.parent_fingerprint();
                info_name = key.name();
                info_note = key.note();
            }
        }
        assert_eq!(
            expected.get("isPrivate").and_then(Value::as_bool),
            info_priv,
            "is-private flag"
        );
        assert_eq!(
            opt_hex(expected, "chainCode").as_deref(),
            info_chain,
            "chain code"
        );
        check_coin_info(info_use, expected.get("useInfo"));
        match (info_origin, expected.get("origin")) {
            (Some(p), Some(v)) => check_path(p, v),
            (None, None) => {}
            _ => panic!("origin presence mismatch"),
        }
        match (info_children, expected.get("children")) {
            (Some(p), Some(v)) => check_path(p, v),
            (None, None) => {}
            _ => panic!("children presence mismatch"),
        }
        assert_eq!(
            opt_u64(expected, "parentFingerprint"),
            info_fp.map(|f| u64::from(u32::from_be_bytes(f.to_bytes()))),
            "parent fingerprint"
        );
        assert_eq!(opt_text(expected, "name"), info_name, "name");
        assert_eq!(opt_text(expected, "note"), info_note, "note");
    }
    assert_eq!(opt_text(value, "device"), actual.device(), "device");
    assert_eq!(opt_text(value, "deviceId"), actual.device_id(), "device id");
    assert_eq!(opt_text(value, "version"), actual.version(), "version");
}

fn cbor_hex(case: &Value) -> &str {
    case["cborHex"].as_str().unwrap()
}

fn reencoded(cbor: CBOR, ur_type: &str, codec: Option<&str>) -> (CBOR, String) {
    match (ur_type, codec) {
        ("eth-sign-request", _) => {
            let v = EthSignRequest::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("eth-signature", _) => {
            let v = EthSignature::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("sol-sign-request", _) => {
            let v = SolSignRequest::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("sol-signature", _) => {
            let v = SolSignature::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("tron-sign-request", Some("onekey-tron-sign-request")) => {
            let v = OneKeyTronSignRequest::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("tron-sign-request", _) => {
            let v = TronSignRequest::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("tron-signature", _) => {
            let v = TronSignature::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        ("crypto-multi-accounts", _) => {
            let v = MultiAccounts::try_from(cbor).unwrap();
            (v.tagged_cbor(), v.to_ur().unwrap().to_string())
        }
        (t, _) => panic!("unhandled {t}"),
    }
}

const FILES: &[(&str, &str)] = &[
    ("multi-accounts", "crypto-multi-accounts"),
    ("eth-sign-request", "eth-sign-request"),
    ("eth-signature", "eth-signature"),
    ("sol-sign-request", "sol-sign-request"),
    ("sol-signature", "sol-signature"),
    ("tron-sign-request", "tron-sign-request"),
    ("tron-signature", "tron-signature"),
];

#[test]
fn interop_vectors() {
    for (file, ur_type) in FILES {
        for case in vector(&format!("interop/{file}.json"))["cases"]
            .as_array()
            .unwrap()
        {
            let input = tagged(case);
            let value = &case["value"];
            let codec = case["codec"].as_str();
            // Semantic check against the language-neutral value.
            match *ur_type {
                "eth-sign-request" => {
                    check_eth_request(&EthSignRequest::try_from(input.clone()).unwrap(), value);
                }
                "eth-signature" => {
                    check_eth_signature(&EthSignature::try_from(input.clone()).unwrap(), value);
                }
                "sol-sign-request" => {
                    check_sol_request(&SolSignRequest::try_from(input.clone()).unwrap(), value);
                }
                "sol-signature" => {
                    check_sol_signature(&SolSignature::try_from(input.clone()).unwrap(), value);
                }
                "tron-sign-request" => check_tron_request(value, codec, &input),
                "tron-signature" => {
                    let v = TronSignature::try_from(input.clone()).unwrap();
                    assert_eq!(
                        opt_hex(value, "requestId").as_deref(),
                        v.request_id().map(|r| r.as_bytes().to_vec()).as_deref()
                    );
                    assert_eq!(
                        &unhex(value["signature"].as_str().unwrap())[..],
                        v.signature()
                    );
                }
                "crypto-multi-accounts" => {
                    check_multi_accounts(&MultiAccounts::try_from(input.clone()).unwrap(), value);
                }
                _ => unreachable!(),
            }
            // Byte-identical re-encode with the named writer + UR round trip.
            let (reencoded_cbor, ur) = reencoded(input.clone(), ur_type, codec);
            assert_eq!(
                hex::encode(reencoded_cbor.to_cbor_data()),
                cbor_hex(case),
                "{}",
                case["name"]
            );
            assert_eq!(ur, case["ur"].as_str().unwrap(), "{}", case["name"]);
            let parsed = Ur::from_str(case["ur"].as_str().unwrap()).unwrap();
            let back = reencoded_cbor_back(&parsed, ur_type, codec);
            assert_eq!(hex::encode(back.to_cbor_data()), cbor_hex(case));
        }
    }
}

fn reencoded_cbor_back(ur: &Ur, ur_type: &str, codec: Option<&str>) -> CBOR {
    match (ur_type, codec) {
        ("eth-sign-request", _) => EthSignRequest::from_ur(ur).unwrap().tagged_cbor(),
        ("eth-signature", _) => EthSignature::from_ur(ur).unwrap().tagged_cbor(),
        ("sol-sign-request", _) => SolSignRequest::from_ur(ur).unwrap().tagged_cbor(),
        ("sol-signature", _) => SolSignature::from_ur(ur).unwrap().tagged_cbor(),
        ("tron-sign-request", Some("onekey-tron-sign-request")) => {
            OneKeyTronSignRequest::from_ur(ur).unwrap().tagged_cbor()
        }
        ("tron-sign-request", _) => TronSignRequest::from_ur(ur).unwrap().tagged_cbor(),
        ("tron-signature", _) => TronSignature::from_ur(ur).unwrap().tagged_cbor(),
        ("crypto-multi-accounts", _) => MultiAccounts::from_ur(ur).unwrap().tagged_cbor(),
        (t, _) => panic!("unhandled {t}"),
    }
}

#[test]
fn tron_cross_dialect() {
    for case in vector("interop/tron-sign-request.json")["cases"]
        .as_array()
        .unwrap()
    {
        let input = tagged(case);
        let is_onekey = case["codec"].as_str() == Some("onekey-tron-sign-request");
        // The untagged body (as carried by the UR) decodes through both
        // readers; tagged conversion accepts only each writer's own tag.
        let body = Ur::from_str(case["ur"].as_str().unwrap())
            .unwrap()
            .cbor()
            .clone();
        if is_onekey {
            // The Keystone writer reads the OneKey layout but must reject
            // messageV1 (not representable in its writer).
            match TronSignRequest::from_untagged_cbor(body.clone()) {
                Ok(v) => assert_ne!(v.data_type(), TronDataType::MessageV1),
                Err(_) => {
                    assert_eq!(case["value"]["dataType"].as_str().unwrap(), "messageV1");
                }
            }
            assert!(OneKeyTronSignRequest::from_untagged_cbor(body).is_ok());
            assert!(TronSignRequest::try_from(input).is_err());
        } else {
            // The OneKey writer reads the Keystone layout for every type.
            assert!(OneKeyTronSignRequest::from_untagged_cbor(body.clone()).is_ok());
            assert!(TronSignRequest::from_untagged_cbor(body).is_ok());
            assert!(OneKeyTronSignRequest::try_from(input).is_err());
        }
    }
}

#[test]
fn interop_invalid() {
    let decode = |codec: &str, body: &[u8]| {
        // A body that fails dCBOR parsing (e.g. non-canonical numerics)
        // counts as rejected before the codec even runs.
        let Ok(cbor) = CBOR::try_from_data(body) else {
            return true;
        };
        match codec {
            "eth-sign-request" => EthSignRequest::from_untagged_cbor(cbor).is_err(),
            "eth-signature" => EthSignature::from_untagged_cbor(cbor).is_err(),
            "sol-sign-request" => SolSignRequest::from_untagged_cbor(cbor).is_err(),
            "sol-signature" => SolSignature::from_untagged_cbor(cbor).is_err(),
            "tron-sign-request" => TronSignRequest::from_untagged_cbor(cbor).is_err(),
            "onekey-tron-sign-request" => OneKeyTronSignRequest::from_untagged_cbor(cbor).is_err(),
            "tron-signature" => TronSignature::from_untagged_cbor(cbor).is_err(),
            "crypto-multi-accounts" => MultiAccounts::from_untagged_cbor(cbor).is_err(),
            other => panic!("no codec {other}"),
        }
    };
    for case in vector("interop/invalid.json")["cases"].as_array().unwrap() {
        let body = unhex(case["inputCborHex"].as_str().unwrap());
        assert!(
            decode(case["codec"].as_str().unwrap(), &body),
            "{} must reject",
            case["name"]
        );
    }
}
