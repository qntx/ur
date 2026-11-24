#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration targets link full dev-deps and host unwraps/panics by design"
)]

//! Cross-language interop differential replay: the TypeScript harness
//! (`scripts/parity/interop-differential.ts`, driven by `bun run test:parity`)
//! writes a seeded file of untagged bodies (random valid values, most with a
//! single structural mutation); this test replays every case and asserts an
//! identical accept/reject error category and, for accepted cases, a
//! byte-identical tagged re-encoding and UR string.
#![cfg(feature = "interop")]

use serde_json::Value;

use bcur::typed::UrEncodable;
use bcur_registry::Error;
use bcur_registry::interop::{BtcSignRequest, BtcSignature, QrHardwareCall, tags};
use dcbor::{CBOR, CBORTaggedEncodable, Tag};

fn load_file() -> Value {
    let path = std::env::var("BCUR_INTEROP_DIFFERENTIAL").expect(
        "BCUR_INTEROP_DIFFERENTIAL is not set — generate cases first via `bun run test:parity` \
         (or `bun scripts/parity/interop-differential.ts --out <path>`)",
    );
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read differential file {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"))
}

/// TS `CborError` code each Rust error category corresponds to.
const fn category(error: &Error) -> &'static str {
    match error {
        Error::Cbor(_) | Error::UnknownKey { .. } => "WrongType",
        Error::MissingKey { .. } => "MissingMapKey",
        Error::UnexpectedTag { .. } => "WrongTag",
        Error::OutOfRange { .. } | Error::InvalidLength { .. } => "OutOfRange",
        _ => "other",
    }
}

enum Replayed {
    Accepted { cbor_hex: String, ur: String },
    Rejected(&'static str),
}

fn replay<T>(tag: Tag, body: CBOR) -> Replayed
where
    T: TryFrom<CBOR, Error = Error> + CBORTaggedEncodable + UrEncodable,
{
    match T::try_from(CBOR::to_tagged_value(tag, body)) {
        Ok(v) => Replayed::Accepted {
            cbor_hex: hex::encode(v.tagged_cbor().to_cbor_data()),
            ur: v.to_ur().unwrap().to_string(),
        },
        Err(e) => Replayed::Rejected(category(&e)),
    }
}

fn replay_body(codec: &str, body: CBOR) -> Replayed {
    match codec {
        "btc-sign-request" => replay::<BtcSignRequest>(tags::BTC_SIGN_REQUEST, body),
        "btc-signature" => replay::<BtcSignature>(tags::BTC_SIGNATURE, body),
        "qr-hardware-call" => replay::<QrHardwareCall>(tags::QR_HARDWARE_CALL, body),
        other => panic!("no codec {other}"),
    }
}

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap()
}

fn check_case(seed: u64, ci: usize, case: &Value) {
    let codec = json_str(case, "codec");
    let label = format!("seed {seed} case {ci} ({codec})");
    let outcome = CBOR::try_from_data(hex::decode(json_str(case, "inputCborHex")).unwrap())
        .map_or(Replayed::Rejected("CborDecode"), |body| {
            replay_body(codec, body)
        });
    let expected = case.get("outcome").unwrap();
    if expected.get("accepted").and_then(Value::as_bool).unwrap() {
        match outcome {
            Replayed::Accepted { cbor_hex, ur } => {
                assert_eq!(
                    json_str(expected, "cborHex"),
                    cbor_hex,
                    "interop divergence: {label}: tagged re-encode",
                );
                assert_eq!(
                    json_str(expected, "ur"),
                    ur,
                    "interop divergence: {label}: ur",
                );
            }
            Replayed::Rejected(cat) => {
                panic!("interop divergence: {label}: expected accepted, rejected with {cat}");
            }
        }
    } else {
        let want = json_str(expected, "code");
        match outcome {
            Replayed::Rejected(cat) => {
                assert_eq!(want, cat, "interop divergence: {label}: error category");
            }
            Replayed::Accepted { .. } => {
                panic!("interop divergence: {label}: expected rejected ({want}), accepted");
            }
        }
    }
}

#[test]
#[ignore = "run via bun run test:parity"]
fn interop_differential() {
    let file = load_file();
    assert_eq!(
        file.get("schema").and_then(Value::as_u64),
        Some(1),
        "unsupported interop differential schema version"
    );
    let seed = file.get("seed").and_then(Value::as_u64).unwrap();
    let cases = file.get("cases").and_then(Value::as_array).unwrap();
    for (ci, case) in cases.iter().enumerate() {
        check_case(seed, ci, case);
    }
    eprintln!(
        "interop differential: {} cases replayed (seed {seed})",
        cases.len()
    );
}
