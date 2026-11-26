#![cfg(feature = "dcbor")]
#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::excessive_nesting,
    reason = "integration targets link full dev-deps and host unwraps/panics by design"
)]

//! CBOR nesting-limit vectors (`vectors/typed/cbor-depth.json`), decoded on a
//! deliberately small stack so a depth-scan regression fails cleanly instead
//! of silently recursing: `dcbor` decodes and drops nested values one stack
//! frame per level, so every accepted payload must also drop within the
//! budget.
//!
//! The vector suite runs in a child process (see
//! [`vector_cases_on_a_512_kib_stack`]) so a stack overflow is an observable
//! crash rather than an abort that takes the whole test binary down.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::process::Command;
use std::thread;

use serde_json::Value;

use bcur::typed::Ur;
use bcur::ur::{self, Decoder};
use bcur::{ErrorKind, Limit, UrType};

macro_rules! vector {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/",
            $path
        ))
    };
}

/// Decode stack for vector cases: small enough that over-limit recursion in
/// `dcbor`'s decoder/drop overflows it, large enough for depth 64.
const STACK_BYTES: usize = 512 * 1024;

/// Re-runs this test in a child process so its death is observable.
const CHILD_ENV: &str = "BCUR_CBOR_DEPTH_CHILD";

/// `UrType` shared by every case: the depth scan runs before decode, so the
/// type token is inert.
fn depth_type() -> UrType {
    UrType::new("x-depth").unwrap()
}

fn json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap()
}

fn spec() -> Value {
    json(vector!("typed/cbor-depth.json"))
}

fn cases(spec: &Value) -> &[Value] {
    spec.get("cases").and_then(Value::as_array).unwrap()
}

fn find_case<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| json_str(case, "name") == name)
        .unwrap_or_else(|| panic!("no case named {name}"))
}

/// `concat(segments[i].hex * (segments[i].repeat ?? 1))`.
fn case_bytes(case: &Value) -> Vec<u8> {
    let name = json_str(case, "name");
    let mut bytes = Vec::new();
    for segment in case.get("segments").and_then(Value::as_array).unwrap() {
        let chunk = hex::decode(json_str(segment, "hex")).unwrap();
        let repeat = segment.get("repeat").and_then(Value::as_u64).unwrap_or(1);
        for _ in 0..repeat {
            bytes.extend_from_slice(&chunk);
        }
    }
    assert!(!bytes.is_empty(), "{name}: empty case bytes");
    bytes
}

/// Runs `f` on a 512 KiB stack and re-raises a panic in the caller.
fn on_small_stack<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    let handle = thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(f)
        .expect("spawn the small-stack thread");
    if let Err(panic) = handle.join() {
        resume_unwind(panic);
    }
}

/// Decodes one vector case entirely inside one small-stack thread; a passing
/// `Ur` is also dropped there so its recursive `Drop` is covered by the same
/// budget.
fn check_case(case: &Value) {
    let name = json_str(case, "name").to_owned();
    let bytes = case_bytes(case);
    let error = case.get("error").cloned();
    on_small_stack(move || {
        let result = Ur::from_cbor_data(depth_type(), &bytes);
        match error {
            None => {
                let ur = result.unwrap_or_else(|e| panic!("{name}: must decode: {e:?}"));
                assert_eq!(
                    ur.to_cbor_data(),
                    bytes,
                    "{name}: byte-identical round-trip"
                );
                drop(ur);
            }
            Some(want) => {
                let code = json_str(&want, "code").to_owned();
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{name}: must fail with {code}"));
                match code.as_str() {
                    "ResourceLimit" => {
                        assert_eq!(err.kind(), ErrorKind::ResourceLimit, "{name}");
                        assert_eq!(err.limit(), Some(Limit::CborDepth), "{name}");
                    }
                    "CborDecode" => {
                        assert_eq!(err.kind(), ErrorKind::CborDecode, "{name}");
                        assert!(
                            std::error::Error::source(&err).is_some(),
                            "{name}: must carry the dcbor source error"
                        );
                    }
                    other => panic!("{name}: unhandled vector error code {other}"),
                }
            }
        }
    });
}

#[test]
fn vector_cases_on_a_512_kib_stack() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let mut failed = Vec::new();
        for case in cases(&spec()) {
            if catch_unwind(AssertUnwindSafe(|| check_case(case))).is_err() {
                failed.push(json_str(case, "name").to_owned());
            }
        }
        assert!(failed.is_empty(), "failing cases: {failed:?}");
        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "vector_cases_on_a_512_kib_stack",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn the child test process");
    if !output.status.success() {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            output
                .status
                .signal()
                .map_or_else(|| output.status.to_string(), |sig| format!("signal {sig}"))
        };
        #[cfg(not(unix))]
        let status = output.status.to_string();
        panic!(
            "child run exited with {status}\nchild stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn depth_boundary_per_container_kind() {
    let spec = spec();
    assert_eq!(
        spec.get("maxDepth").and_then(Value::as_u64),
        Some(64),
        "vector maxDepth"
    );
    assert_eq!(bcur::typed::CBOR_MAX_DEPTH, 64);
    for head in [&[0x81][..], &[0xa1, 0x00], &[0xc6]] {
        let mut within = head.repeat(bcur::typed::CBOR_MAX_DEPTH);
        within.push(0x00);
        let mut over = head.repeat(bcur::typed::CBOR_MAX_DEPTH + 1);
        over.push(0x00);
        on_small_stack(move || {
            let ur = Ur::from_cbor_data(depth_type(), &within)
                .unwrap_or_else(|e| panic!("{head:02x?} at depth 64 must decode: {e:?}"));
            assert_eq!(ur.to_cbor_data(), within, "{head:02x?}");
            drop(ur);
            let err = Ur::from_cbor_data(depth_type(), &over)
                .err()
                .unwrap_or_else(|| panic!("{head:02x?} at depth 65 must be ResourceLimit"));
            assert_eq!(err.kind(), ErrorKind::ResourceLimit, "{head:02x?}");
            assert_eq!(err.limit(), Some(Limit::CborDepth), "{head:02x?}");
        });
    }
}

#[test]
fn every_typed_entry_point_enforces_the_limit() {
    let spec = spec();
    let cases = cases(&spec);
    let deep = case_bytes(find_case(cases, "array-depth-65"));
    let shallow = case_bytes(find_case(cases, "array-depth-64"));

    for (label, bytes, within_limit) in [
        ("array-depth-65", &deep, false),
        ("array-depth-64", &shallow, true),
    ] {
        let uri = ur::encode(&depth_type(), bytes);
        let parsed: bcur::Result<Ur> = uri.parse();
        let mut decoder = Decoder::default();
        decoder
            .receive(&uri)
            .unwrap_or_else(|e| panic!("{label}: receive: {e:?}"));
        let decoded = decoder
            .into_decoded()
            .unwrap_or_else(|e| panic!("{label}: into_decoded: {e:?}"));
        let converted = Ur::try_from(decoded);
        if within_limit {
            parsed.unwrap_or_else(|e| panic!("{label}: Ur::from_str: {e:?}"));
            converted.unwrap_or_else(|e| panic!("{label}: Ur::try_from: {e:?}"));
        } else {
            for (path, result) in [("Ur::from_str", &parsed), ("Ur::try_from", &converted)] {
                let err = result
                    .as_ref()
                    .err()
                    .unwrap_or_else(|| panic!("{label}: {path} must reject the deep payload"));
                assert_eq!(err.kind(), ErrorKind::ResourceLimit, "{label}: {path}");
                assert_eq!(err.limit(), Some(Limit::CborDepth), "{label}: {path}");
            }
        }
    }
}

#[test]
fn official_case_matches_its_source() {
    let spec = spec();
    let official = find_case(cases(&spec), "official-crypto-account");
    let registry = json(vector!("official/registry/crypto-account.json"));
    let named = registry
        .get("cases")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|case| json_str(case, "name") == "BIP39 'shield group…' account, 7 v1 descriptors")
        .unwrap();
    assert_eq!(
        hex::encode(case_bytes(official)),
        json_str(named, "cborHex"),
        "official-crypto-account must copy the named registry case verbatim"
    );
}
