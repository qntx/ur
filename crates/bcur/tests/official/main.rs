#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::panic,
    reason = "integration targets link full dev-deps; official vector JSON is trusted"
)]

//! Official compliance vectors (BCR-2024-001, `URKit`, bc-ur), read from the
//! repository-root `vectors/` tree. Public-API coverage; consensus internals and
//! cases needing the shared message generator are covered in
//! `src/official_vectors.rs`.

use serde_json::Value;

mod bytewords;
mod mur;
mod ur;

pub(crate) fn vector(path: &str) -> Value {
    let root = env!("CARGO_MANIFEST_DIR");
    serde_json::from_str(&std::fs::read_to_string(format!("{root}/../../vectors/{path}")).unwrap())
        .unwrap()
}

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

pub(crate) fn hex(b: &[u8]) -> String {
    hex::encode(b)
}
