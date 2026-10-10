//! Integration tests for the `bcur` binary (text I/O only).

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "integration binary tests host unwraps and link all crate deps"
)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

fn bcur() -> Command {
    Command::cargo_bin("bcur").expect("bcur bin")
}

#[test]
fn encode_hex_cbor_array_matches_golden() {
    bcur()
        .args(["encode", "--type", "test", "--hex"])
        .write_stdin("83010203")
        .assert()
        .success()
        .stdout("ur:test/lsadaoaxjygonesw\n");
}

#[test]
fn encode_decode_roundtrip_raw_bytes() {
    let payload = b"cli-roundtrip-payload-0123456789";
    let encoded = bcur()
        .args(["encode", "--type", "bytes"])
        .write_stdin(payload.as_slice())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    bcur()
        .args(["decode"])
        .write_stdin(encoded)
        .assert()
        .success()
        .stdout(predicate::eq(payload.as_slice()));
}

#[test]
fn fountain_encode_decode_roundtrip() {
    let payload = vec![0x5a_u8; 256];
    let encoded = bcur()
        .args([
            "encode",
            "--type",
            "bytes",
            "--max-chars",
            "100",
            "--count",
            "80",
        ])
        .write_stdin(payload.as_slice())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(encoded).expect("utf8");
    assert!(
        text.lines().count() > 1,
        "expected multiple fountain parts, got: {text}"
    );
    assert!(
        text.lines().next().is_some_and(|l| l.contains("/1-")),
        "expected multi-part path, got: {text}"
    );

    bcur()
        .args(["decode"])
        .write_stdin(text)
        .assert()
        .success()
        .stdout(predicate::eq(payload.as_slice()));
}

#[test]
fn decode_skips_rejected_lines() {
    let payload = vec![0x5a_u8; 256];
    let encoded = bcur()
        .args([
            "encode",
            "--type",
            "bytes",
            "--max-chars",
            "100",
            "--count",
            "80",
        ])
        .write_stdin(payload.as_slice())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(encoded).expect("utf8");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    // A garbage line and a foreign-type frame between valid frames.
    lines.insert(1, "not-a-ur".to_owned());
    lines.insert(3, "ur:psbt/hsidiaecdkfpsa".to_owned());
    let input = lines.join("\n");

    bcur()
        .args(["decode"])
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::eq(payload.as_slice()))
        .stderr(predicate::str::contains("skipped line 2"))
        .stderr(predicate::str::contains("skipped line 4"));
}

#[test]
fn decode_fails_on_fatal_line() {
    // An admitted `ur:bytes` frame over the URI-length budget is fatal.
    let oversized = format!("ur:bytes/{}\n", "ae".repeat(4200));
    bcur()
        .args(["decode"])
        .write_stdin(oversized)
        .assert()
        .failure()
        .stderr(predicate::str::contains("resource limit"));
}

#[test]
fn decode_first_complete_single_part_wins() {
    bcur()
        .args(["decode", "--hex"])
        .write_stdin("ur:test/lsadaoaxjygonesw\nur:test/lsadaoaxjygonesw\n")
        .assert()
        .success()
        .stdout("83010203\n");
}

#[test]
fn decode_expected_type_mismatch() {
    bcur()
        .args(["decode", "--type", "bytes"])
        .write_stdin("ur:test/lsadaoaxjygonesw\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected UR type"));
}

#[test]
fn encode_rejects_empty_type() {
    bcur()
        .args(["encode", "--type", ""])
        .write_stdin("x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid UR type"));
}

#[test]
fn decode_hex_output_file() {
    let out = NamedTempFile::new().expect("tmp");
    bcur()
        .args([
            "decode",
            "--hex",
            "--out",
            out.path().to_str().expect("utf8 path"),
        ])
        .write_stdin("ur:test/lsadaoaxjygonesw\n")
        .assert()
        .success()
        .stdout("");
    let got = std::fs::read_to_string(out.path()).expect("read");
    assert_eq!(got, "83010203\n");
}

#[test]
fn qr_static_prints_unicode_blocks() {
    bcur()
        .args(["qr"])
        .write_stdin("ur:test/lsadaoaxjygonesw\n")
        .assert()
        .success()
        .stdout(predicate::str::contains('\u{2588}'));
}

#[test]
fn qr_animate_without_tty_fails() {
    let payload = vec![0x5a_u8; 256];
    bcur()
        .args([
            "encode",
            "--qr",
            "--animate",
            "--type",
            "bytes",
            "--max-chars",
            "100",
        ])
        .write_stdin(payload)
        .assert()
        .failure()
        .stderr(predicate::str::contains("terminal"));
}
