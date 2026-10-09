//! Official bytewords vectors (`URKit` `BytewordsTests` + BCR-2020-012 examples).

use bcur::bytewords::{Style, decode, encode, identifier};
use serde_json::Value;

use crate::{unhex, vector};

fn style(name: &str) -> Style {
    match name {
        "standard" => Style::Standard,
        "uri" => Style::Uri,
        "minimal" => Style::Minimal,
        other => panic!("unknown style {other}"),
    }
}

#[test]
fn official_bytewords() {
    let doc = vector("official/bytewords.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if let Some(expected) = case["error"].as_str() {
            let input = case["input"].as_str().unwrap();
            // Empty input is covered by `official_bytewords_empty_input` below
            // (a known error-classification divergence).
            if input.is_empty() {
                continue;
            }
            let err = decode(input, style(case["style"].as_str().unwrap())).unwrap_err();
            assert_eq!(format!("{:?}", err.kind()), expected, "{name}");
            continue;
        }
        let input = unhex(case["inputHex"].as_str().unwrap());
        for (field, st) in [
            ("standard", Style::Standard),
            ("uri", Style::Uri),
            ("minimal", Style::Minimal),
        ] {
            if let Some(want) = case[field].as_str() {
                let encoded = encode(&input, st);
                assert_eq!(encoded, want, "{name} {field}");
                let decoded = decode(&encoded, st).unwrap();
                assert_eq!(decoded, input, "{name} {field} round-trip");
            }
        }
    }
}

#[test]
fn official_bytewords_empty_input() {
    let err = decode("", Style::Standard).unwrap_err();
    assert_eq!(
        err.kind(),
        bcur::ErrorKind::InvalidBytewordsChecksum,
        "{err:?}"
    );
}

#[test]
fn official_bytewords_identifier() {
    let doc = vector("official/bytewords-identifier.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if let Some(words) = case["words"].as_array() {
            let expected: Vec<&str> = words.iter().filter_map(Value::as_str).collect();
            assert_eq!(
                bcur::bytewords::WORDS.as_slice(),
                expected.as_slice(),
                "{name}"
            );
            continue;
        }
        let digest: [u8; 4] = unhex(case["digestHex"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            identifier(digest),
            case["identifier"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn official_bytemoji_identifier() {
    let doc = vector("official/bytemoji.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // The 256-entry table itself is crate-private; it is checked against
        // the same vector in `src/official_vectors.rs`.
        let Some(digest_hex) = case["digestHex"].as_str() else {
            continue;
        };
        let digest: [u8; 4] = unhex(digest_hex).try_into().unwrap();
        assert_eq!(
            bcur::bytemoji::identifier(digest),
            case["bytemojis"].as_str().unwrap(),
            "{name}"
        );
        if let Some(bw) = case["bytewords"].as_str() {
            assert_eq!(identifier(digest), bw, "{name} bytewords twin");
        }
    }
}
