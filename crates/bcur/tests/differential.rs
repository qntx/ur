#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::excessive_nesting,
    reason = "integration targets link full dev-deps and host unwraps/panics by design"
)]

//! Cross-language differential replay: the TypeScript harness
//! (`scripts/parity/differential.ts`, driven by `bun run test:parity`)
//! writes a seeded case file; this test replays every case and asserts
//! byte-identical encoder output and identical per-frame decoder outcomes,
//! completion index, final phase, and decoded message.

use serde_json::Value;
use sha2::Digest;

use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoded, Decoder, Encoder};
use bcur::{Error, Limit, Received, State, UrType};

fn load_file() -> Value {
    let path = std::env::var("BCUR_DIFFERENTIAL").expect(
        "BCUR_DIFFERENTIAL is not set — generate cases first via `bun run test:parity` \
         (or `bun scripts/parity/differential.ts --out <path>`)",
    );
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read differential file {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"))
}

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap()
}

fn json_usize(v: &Value, key: &str) -> usize {
    usize::try_from(v.get(key).and_then(Value::as_u64).unwrap()).unwrap()
}

/// Frame error categories recorded by the shared vectors (camelCase names
/// are the vector format, not a library API).
const fn limit_name(limit: Limit) -> &'static str {
    match limit {
        Limit::MessageLength => "messageLength",
        Limit::FragmentCount => "fragmentCount",
        Limit::FragmentLength => "fragmentLength",
        Limit::UriLength => "uriLength",
        _ => "unknown",
    }
}

fn cases(file: &Value) -> &[Value] {
    file.get("cases").and_then(Value::as_array).unwrap()
}

/// Replays the recorded encoder options through the public `ur::Encoder`.
fn encode_all(case: &Value, message: &[u8]) -> Vec<String> {
    let ur_type = UrType::new(json_str(case, "urType")).unwrap();
    let options = case.get("options").unwrap();
    let opts = EncoderOptions {
        max_fragment_len: json_usize(options, "maxFragmentLength"),
        min_fragment_len: options
            .get("minFragmentLength")
            .and_then(Value::as_u64)
            .map_or(10, |v| usize::try_from(v).unwrap()),
        first_sequence: u32::try_from(
            options
                .get("firstSequence")
                .and_then(Value::as_u64)
                .unwrap(),
        )
        .unwrap(),
    };
    let m = case.get("encoded").and_then(Value::as_array).unwrap().len();
    Encoder::new(ur_type, message.to_vec(), opts)
        .unwrap()
        .take(m)
        .collect()
}

fn describe_got(got: &Result<Received, Error>) -> String {
    match got {
        Ok(Received::Accepted) => "accepted".to_owned(),
        Ok(Received::Duplicate) => "duplicate".to_owned(),
        Err(e) => format!(
            "{}({:?}, limit {:?})",
            if e.is_fatal() { "fatal" } else { "rejected" },
            e.kind(),
            e.limit().map(limit_name)
        ),
    }
}

fn check_outcome(seed: u64, ci: usize, fi: usize, expected: &Value, got: &Result<Received, Error>) {
    let status = json_str(expected, "status");
    let ok = match (status, got) {
        ("accepted", Ok(Received::Accepted)) | ("duplicate", Ok(Received::Duplicate)) => true,
        ("rejected", Err(e)) => !e.is_fatal(),
        ("fatal", Err(e)) => e.is_fatal(),
        _ => false,
    };
    let error_ok = match (expected.get("error"), got) {
        (None, _) => true,
        (Some(want), Err(e)) => {
            format!("{:?}", e.kind()) == json_str(want, "code")
                && want
                    .get("limit")
                    .is_none_or(|l| e.limit().map(limit_name) == l.as_str())
        }
        (Some(_), Ok(_)) => false,
    };
    assert!(
        ok && error_ok,
        "differential mismatch: seed {seed} case {ci} frame {fi}: \
         expected {status} ({}), got {}",
        expected
            .get("error")
            .map_or_else(|| "-".to_owned(), ToString::to_string),
        describe_got(got),
    );
}

const fn phase_of(state: &State<'_, Decoded>) -> &'static str {
    match state {
        State::Empty => "empty",
        State::Collecting(_) => "collecting",
        State::Complete(_) => "complete",
        State::Failed(_) => "failed",
    }
}

fn replay_case(seed: u64, ci: usize, case: &Value) {
    let message = hex::decode(json_str(case, "messageHex")).unwrap();

    // Encoder parity: the first M UR strings must be byte-identical.
    let encoded = encode_all(case, &message);
    let want = case.get("encoded").and_then(Value::as_array).unwrap();
    for (i, (got, want_str)) in encoded.iter().zip(want.iter()).enumerate() {
        assert_eq!(
            want_str.as_str().unwrap(),
            got,
            "encoder divergence: seed {seed} case {ci} part {i}",
        );
    }

    // Decoder parity: feed every recorded frame and compare outcomes.
    let frames = case.get("frames").and_then(Value::as_array).unwrap();
    let outcomes = case.get("outcomes").and_then(Value::as_array).unwrap();
    assert_eq!(
        frames.len(),
        outcomes.len(),
        "frames/outcomes length mismatch: seed {seed} case {ci}"
    );
    let mut decoder = Decoder::default();
    let mut complete_at = None;
    for (fi, (frame, expected)) in frames.iter().zip(outcomes.iter()).enumerate() {
        let got = decoder.receive(frame.as_str().unwrap());
        check_outcome(seed, ci, fi, expected, &got);
        if complete_at.is_none()
            && matches!(got, Ok(Received::Accepted))
            && matches!(decoder.state(), State::Complete(_))
        {
            complete_at = Some(fi + 1);
        }
    }

    let want_complete_at = case.get("completeAt").and_then(Value::as_u64);
    assert_eq!(
        want_complete_at.map(|v| usize::try_from(v).unwrap()),
        complete_at,
        "completion index divergence: seed {seed} case {ci}",
    );
    let state = decoder.state();
    let phase = phase_of(&state);
    assert_eq!(
        json_str(case, "phase"),
        phase,
        "final phase divergence: seed {seed} case {ci}",
    );
    if let State::Complete(decoded) = state {
        // A foreign single-part frame can legitimately complete an empty
        // session, so compare against the recorded decoded type and the
        // SHA-256 of the decoded message, not the case's urType/messageHex.
        assert_eq!(
            Some(decoded.ur_type().as_str()),
            case.get("decodedType").and_then(Value::as_str),
            "decoded type divergence: seed {seed} case {ci}",
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(decoded.message())),
            json_str(case, "messageSha256"),
            "decoded message divergence: seed {seed} case {ci}",
        );
    }
}

#[test]
#[ignore = "run via bun run test:parity"]
fn differential() {
    let file = load_file();
    assert_eq!(
        file.get("schema").and_then(Value::as_u64),
        Some(1),
        "unsupported differential schema version"
    );
    let seed = file.get("seed").and_then(Value::as_u64).unwrap();
    for (ci, case) in cases(&file).iter().enumerate() {
        replay_case(seed, ci, case);
    }
    eprintln!(
        "differential: {} cases replayed (seed {seed})",
        cases(&file).len()
    );
}
