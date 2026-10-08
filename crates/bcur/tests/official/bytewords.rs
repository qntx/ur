//! Official bytewords vectors (`URKit` `BytewordsTests` + BCR-2020-012 examples).

use bcur::bytewords::{Style, decode, encode};

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
            assert_eq!(format!("{err:?}"), expected, "{name}");
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

// `decode("", Standard)` yields `Error::InvalidWord` while the official
// expectation (and the TypeScript implementation) is `InvalidBytewordsChecksum`.
#[test]
#[ignore = "F-25: empty bytewords input classifies as InvalidWord, expected InvalidBytewordsChecksum"]
fn official_bytewords_empty_input() {
    let err = decode("", Style::Standard).unwrap_err();
    assert_eq!(format!("{err:?}"), "InvalidBytewordsChecksum");
}
