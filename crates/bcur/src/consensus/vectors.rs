//! Generated consensus vectors, read from the repository-root `vectors/` tree.
//! Complements `crate::official_vectors`, which covers extracted official
//! vectors.

#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::panic,
    reason = "test-only module: vector JSON is trusted; assertions panic loudly on any mismatch"
)]

use serde_json::Value;

use crate::consensus::xoshiro::{scaled_int, unit_interval};

#[test]
fn generated_next_double() {
    let doc: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/consensus/next-double.json"
    )))
    .unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let raw = u64::from_str_radix(case["rawHex"].as_str().unwrap(), 16).unwrap();
        let bits = unit_interval(raw).to_bits();
        let want = u64::from_str_radix(case["nextDoubleBitsHex"].as_str().unwrap(), 16).unwrap();
        assert_eq!(bits, want, "rawHex {}", case["rawHex"]);
        let range = case["nextIntRange"].as_array().unwrap();
        let low = range[0].as_u64().unwrap();
        let high = range[1].as_u64().unwrap();
        let got = scaled_int(f64::from_bits(bits), low, high);
        assert_eq!(
            got,
            case["nextInt"].as_u64().unwrap(),
            "rawHex {}",
            case["rawHex"]
        );
    }
}
