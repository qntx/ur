#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::excessive_nesting,
    reason = "integration targets link full dev-deps and host unwraps by design"
)]

//! TypeScript/Rust parity contract vectors, read from the repository-root
//! `vectors/` tree.

use serde_json::Value;

use bcur::bytewords::{self, Style};
use bcur::fountain::EncoderOptions;
use bcur::fountain::{self, Part};
use bcur::ur::{Decoder, Encoder, ParsedUr};
use bcur::ur_type;
use bcur::{DecoderLimits, ErrorKind, Limit, Received, State, UrType};

macro_rules! vector {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/",
            $path
        ))
    };
}

fn json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
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

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap()
}

fn json_u32(v: &Value, key: &str) -> u32 {
    u32::try_from(v.get(key).and_then(Value::as_u64).unwrap()).unwrap()
}

fn json_usize(v: &Value, key: &str) -> usize {
    usize::try_from(v.get(key).and_then(Value::as_u64).unwrap()).unwrap()
}

fn data_lines(raw: &str) -> Vec<&str> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn assert_line_file(raw: &str) {
    assert!(raw.ends_with('\n'), "line files need a trailing newline");
    assert!(!raw.contains('\r'), "line files are LF-only");
    assert!(
        !raw.lines().any(|line| line.starts_with('#')),
        "line files have no header comments"
    );
}

fn assert_session_fails(limit: Limit, mut decoder: Decoder, part: &str) {
    let is_limit = |r: &bcur::Result<Received>| matches!(r, Err(e) if e.kind() == ErrorKind::ResourceLimit && e.limit() == Some(limit) && e.is_fatal());
    assert!(
        is_limit(&decoder.receive(part)),
        "first receive must be {limit:?}"
    );
    assert!(
        matches!(decoder.state(), State::Failed(_)),
        "resource limit fails the session"
    );
    assert_eq!(
        decoder.receive(part).unwrap(),
        Received::Duplicate,
        "later frames are duplicates in a terminal state"
    );
    assert!(
        matches!(decoder.into_decoded().unwrap_err(), e if e.kind() == ErrorKind::ResourceLimit
            && e.limit() == Some(limit)),
        "into_decoded must repeat {limit:?}"
    );
}

#[test]
fn vectors_readme_is_canonical() {
    let readme = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/README.md"
    ));
    assert!(readme.contains("packages/ur/tests/"));
    assert!(readme.contains("crates/bcur"));
    assert!(readme.contains("implementation bug"));
    assert!(readme.contains("THIRD_PARTY.md"));
    assert!(readme.contains("parity.json"));
    assert!(readme.contains("data-only"));
}

#[test]
fn bytewords_contract() {
    let spec = json(vector!("bytewords/contract.json"));
    let input = hex::decode(json_str(&spec, "inputHex")).unwrap();
    assert_eq!(
        bytewords::encode(&input, Style::Standard),
        json_str(&spec, "standard")
    );
    assert_eq!(
        bytewords::encode(&input, Style::Uri),
        json_str(&spec, "uri")
    );
    assert_eq!(
        bytewords::encode(&input, Style::Minimal),
        json_str(&spec, "minimal")
    );
    assert_eq!(
        bytewords::decode(json_str(&spec, "standard"), Style::Standard).unwrap(),
        input
    );
    assert_eq!(
        bytewords::decode(json_str(&spec, "uri"), Style::Uri).unwrap(),
        input
    );
    assert_eq!(
        bytewords::decode(json_str(&spec, "minimal"), Style::Minimal).unwrap(),
        input
    );
}

#[test]
fn part_cbor_contract() {
    let spec = json(vector!("fountain/part-cbor.json"));
    let cbor = hex::decode(json_str(&spec, "cborHex")).unwrap();
    let part = Part::from_cbor(&cbor, &DecoderLimits::default()).unwrap();
    assert_eq!(part.sequence(), json_u32(&spec, "sequence"));
    assert_eq!(part.sequence_count(), json_u32(&spec, "sequenceCount"));
    assert_eq!(part.message_len(), json_u32(&spec, "messageLength"));
    assert_eq!(part.checksum(), json_u32(&spec, "checksum"));
    assert_eq!(hex::encode(part.data()), json_str(&spec, "dataHex"));
    assert_eq!(hex::encode(part.to_cbor()), json_str(&spec, "cborHex"));

    // Non-shortest integer encodings decode to the same part (UR-ADR-017).
    let non_shortest = hex::decode(json_str(&spec, "nonShortestSequenceCborHex")).unwrap();
    let decoded = Part::from_cbor(&non_shortest, &DecoderLimits::default()).unwrap();
    assert_eq!(decoded, part);
    assert_eq!(decoded.to_cbor(), cbor);
}

#[test]
fn part_cbor_decode_contract() {
    let doc = json(vector!("fountain/part-cbor-decode.json"));
    let cases = doc.get("cases").and_then(Value::as_array).unwrap();
    for case in cases {
        let name = json_str(case, "name");
        let cbor = hex::decode(json_str(case, "cborHex")).unwrap();
        let limits = case
            .get("limits")
            .map(|l| {
                let d = DecoderLimits::default();
                let get = |k: &str, dflt: usize| {
                    l.get(k)
                        .and_then(Value::as_u64)
                        .map_or(dflt, |v| usize::try_from(v).unwrap())
                };
                DecoderLimits {
                    max_message_length: get("maxMessageLength", d.max_message_length),
                    max_fragment_count: get("maxFragmentCount", d.max_fragment_count),
                    max_fragment_length: get("maxFragmentLength", d.max_fragment_length),
                    ..d
                }
            })
            .unwrap_or_default();
        let result = Part::from_cbor(&cbor, &limits);
        if let Some(err) = case.get("error") {
            let want_kind = json_str(err, "code");
            let got = result.unwrap_err();
            assert_eq!(format!("{:?}", got.kind()), want_kind, "{name}");
            if let Some(limit) = err.get("limit") {
                assert_eq!(got.limit().map(limit_name), limit.as_str(), "{name}");
            }
        } else {
            // Independent structural cross-check: minicbor parses every
            // accepted case to the same fields (recorded as `source.crossCheck`).
            let mut d = minicbor::Decoder::new(&cbor);
            assert_eq!(d.array().unwrap(), Some(5), "{name}");
            let (f_seq, f_count, f_mlen, f_ck) = (
                d.u64().unwrap(),
                d.u64().unwrap(),
                d.u64().unwrap(),
                d.u64().unwrap(),
            );
            let data = d.bytes().unwrap().to_vec();
            assert_eq!(d.position(), cbor.len(), "{name}");
            let want = case.get("part").unwrap();
            assert_eq!(f_seq, u64::from(json_u32(want, "sequence")), "{name}");
            assert_eq!(
                f_count,
                u64::from(json_u32(want, "sequenceCount")),
                "{name}"
            );
            assert_eq!(f_mlen, u64::from(json_u32(want, "messageLength")), "{name}");
            assert_eq!(f_ck, u64::from(json_u32(want, "checksum")), "{name}");
            assert_eq!(hex::encode(&data), json_str(want, "dataHex"), "{name}");

            let part = result.unwrap();
            assert_eq!(part.sequence(), json_u32(want, "sequence"), "{name}");
            assert_eq!(
                part.sequence_count(),
                json_u32(want, "sequenceCount"),
                "{name}"
            );
            assert_eq!(
                part.message_len(),
                json_u32(want, "messageLength"),
                "{name}"
            );
            assert_eq!(part.checksum(), json_u32(want, "checksum"), "{name}");
            assert_eq!(
                hex::encode(part.data()),
                json_str(want, "dataHex"),
                "{name}"
            );
            // Re-encode shortest.
            assert_eq!(
                hex::encode(part.to_cbor()),
                json_str(case, "reencodedHex"),
                "{name}"
            );
        }
    }
}

#[test]
fn k1_contract() {
    let spec = json(vector!("ur/k1.json"));
    let payload = json_str(&spec, "payloadUtf8").as_bytes();
    let ur_type = UrType::new(json_str(&spec, "type")).unwrap();
    let mut encoder =
        Encoder::new(ur_type.clone(), payload.to_vec(), EncoderOptions::new(64)).unwrap();
    assert!(encoder.is_single_part());
    let outbound = encoder.next().unwrap();
    assert!(!outbound.contains(json_str(&spec, "outboundMustNotContain")));
    assert_eq!(
        spec.get("outboundEqualsSinglePartEncode")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(outbound, bcur::ur::encode(&ur_type, payload));
    assert_eq!(
        spec.get("inboundFountain11Accepted")
            .and_then(Value::as_bool),
        Some(true)
    );
    let mut fountain = fountain::Encoder::new(payload.to_vec(), EncoderOptions::new(64)).unwrap();
    let part = fountain.next().unwrap();
    let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
    let uri = format!("ur:{}/1-1/{body}", ur_type.as_str());
    let mut decoder = Decoder::default();
    assert_eq!(decoder.receive(&uri).unwrap(), Received::Accepted);
    assert!(matches!(decoder.state(), State::Complete(_)));
    assert_eq!(decoder.into_decoded().unwrap().message(), payload);
}

#[test]
fn l4_test_array_contract() {
    let spec = json(vector!("typed/test-array.json"));
    let cbor = hex::decode(json_str(&spec, "cborHex")).unwrap();
    let ur_type = UrType::new(json_str(&spec, "type")).unwrap();
    let uri = json_str(&spec, "uri");
    assert_eq!(bcur::ur::encode(&ur_type, &cbor), uri);

    #[cfg(feature = "dcbor")]
    {
        let ur = bcur::Ur::new(ur_type!("test"), vec![1, 2, 3]);
        assert_eq!(ur.to_string(), uri);
    }

    let parsed = bcur::ur::parse(json_str(&spec, "uriUpper"), &DecoderLimits::default()).unwrap();
    let ParsedUr::Single { message, .. } = parsed else {
        unreachable!("expected single");
    };
    assert_eq!(message, cbor);
}

#[test]
fn decoder_limits_contract() {
    let spec = json(vector!("limits/defaults.json"));
    let limits = DecoderLimits::default();
    assert_eq!(
        limits.max_message_length,
        json_usize(&spec, "maxMessageLength")
    );
    assert_eq!(
        limits.max_fragment_count,
        json_usize(&spec, "maxFragmentCount")
    );
    assert_eq!(
        limits.max_fragment_length,
        json_usize(&spec, "maxFragmentLength")
    );
    assert_eq!(limits.max_uri_length, json_usize(&spec, "maxUriLength"));
}

#[test]
fn resource_limits_fail_session() {
    let uri_payload = b"Ten chars!".repeat(8);
    let mut uri_enc =
        Encoder::new(ur_type!("bytes"), uri_payload, EncoderOptions::new(10)).unwrap();
    let uri_part = uri_enc.next().unwrap();
    assert_session_fails(
        Limit::UriLength,
        Decoder::new(DecoderLimits {
            max_uri_length: 16,
            ..DecoderLimits::default()
        }),
        &uri_part,
    );

    let fragment_payload = b"Ten chars!".repeat(16);
    let mut fragment_enc =
        Encoder::new(ur_type!("bytes"), fragment_payload, EncoderOptions::new(10)).unwrap();
    assert!(fragment_enc.fragment_count() > 1);
    let fragment_part = fragment_enc.next().unwrap();
    assert_session_fails(
        Limit::FragmentCount,
        Decoder::new(DecoderLimits {
            max_fragment_count: 1,
            ..DecoderLimits::default()
        }),
        &fragment_part,
    );
}

#[test]
fn nonfatal_errors_leave_state() {
    let data = b"Ten chars!".repeat(6);
    let mut a = Encoder::new(ur_type!("alpha"), data.clone(), EncoderOptions::new(10)).unwrap();
    let mut b = Encoder::new(ur_type!("beta"), data, EncoderOptions::new(10)).unwrap();
    let mut decoder = Decoder::default();
    decoder.receive(&a.next().unwrap()).unwrap();
    assert!(matches!(
        decoder.receive(&b.next().unwrap()),
        Err(ref e) if e.kind() == ErrorKind::UnexpectedType && !e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Collecting(_)));
    assert!(decoder.receive(&a.next().unwrap()).is_ok());

    // A completed session whose bytes are not well-formed dCBOR fails the
    // typed conversion, not the decode itself.
    #[cfg(feature = "dcbor")]
    {
        let uri = bcur::ur::encode(&ur_type!("bytes"), b"\xff");
        let mut d = Decoder::default();
        d.receive(&uri).unwrap();
        let decoded = d.into_decoded().unwrap();
        assert!(matches!(
            bcur::Ur::try_from(decoded),
            Err(ref e) if e.kind() == ErrorKind::CborDecode
        ));
    }
}

#[test]
fn multipart_20_contract() {
    let mixed = vector!("ur-rs/multipart-20.txt");
    assert_line_file(mixed);
    let uris = data_lines(mixed);
    assert_eq!(uris.len(), 20, "ur-rs/multipart-20.txt");

    let mut decoder = Decoder::default();
    for uri in &uris {
        decoder.receive(uri).unwrap();
    }
    assert!(matches!(decoder.state(), State::Complete(_)));
    let payload = decoder.into_decoded().unwrap().into_parts().1;
    let mut encoder = Encoder::new(ur_type!("bytes"), payload, EncoderOptions::new(30)).unwrap();
    assert_eq!(encoder.fragment_count(), 9);
    assert_eq!(
        encoder.next().unwrap(),
        *uris.first().expect("20-URI table")
    );
}

#[test]
fn published_singles_contract() {
    let raw = vector!("ur/published-singles.txt");
    assert_line_file(raw);
    let uris = data_lines(raw);
    assert_eq!(uris.len(), 3, "ur/published-singles.txt");
    for uri in uris {
        let parsed = bcur::ur::parse(uri, &DecoderLimits::default()).unwrap();
        assert!(matches!(parsed, ParsedUr::Single { .. }));
    }
}

#[cfg(feature = "dcbor")]
mod multi_tag {
    use dcbor::prelude::*;
    use dcbor::{CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};

    use super::{json, json_str, json_u32};
    use bcur::typed::{Ur, UrDecodable, UrEncodable};
    use bcur::ur_type;
    use bcur::{ErrorKind, UrType};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MultiTagNote {
        id: u64,
        note: String,
    }

    impl CBORTagged for MultiTagNote {
        fn cbor_tags() -> Vec<Tag> {
            vec![
                Tag::with_static_name(9999, "x-test"),
                Tag::with_static_name(9998, "x-test-legacy"),
            ]
        }
    }

    impl CBORTaggedEncodable for MultiTagNote {
        fn untagged_cbor(&self) -> CBOR {
            let mut map = Map::new();
            map.insert(1_u64, self.id);
            map.insert(2_u64, self.note.clone());
            map.into()
        }
    }

    impl CBORTaggedDecodable for MultiTagNote {
        fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
            let CBORCase::Map(map) = cbor.into_case() else {
                return Err(dcbor::Error::WrongType);
            };
            Ok(Self {
                id: map.extract(1_u64)?,
                note: map.extract(2_u64)?,
            })
        }
    }

    impl TryFrom<CBOR> for MultiTagNote {
        type Error = dcbor::Error;

        fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
            Self::from_tagged_cbor(cbor)
        }
    }

    #[test]
    fn l4_multi_tag_contract() {
        let spec = json(vector!("typed/multi-tag.json"));
        let value = MultiTagNote {
            id: u64::from(json_u32(&spec, "id")),
            note: json_str(&spec, "note").to_owned(),
        };

        // Write: first tag name, untagged body.
        let ur = value.to_ur().unwrap();
        assert_eq!(ur.to_string(), json_str(&spec, "uri"));
        assert_eq!(hex::encode(ur.to_cbor_data()), json_str(&spec, "bodyHex"));

        // Tagged CBOR under both tags round-trips.
        let tagged = CBOR::try_from_hex(json_str(&spec, "taggedHex")).unwrap();
        assert_eq!(MultiTagNote::try_from(tagged).unwrap(), value);
        let legacy_tagged = CBOR::try_from_hex(json_str(&spec, "legacyTaggedHex")).unwrap();
        assert_eq!(MultiTagNote::try_from(legacy_tagged).unwrap(), value);
        assert_eq!(
            hex::encode(value.tagged_cbor().to_cbor_data()),
            json_str(&spec, "taggedHex")
        );

        // Read: either tag name accepted.
        for key in ["uri", "legacyUri"] {
            let parsed: Ur = json_str(&spec, key).parse().unwrap();
            assert_eq!(MultiTagNote::from_ur(&parsed).unwrap(), value);
        }

        // Foreign type lists every accepted name.
        let foreign: Ur = json_str(&spec, "foreignUri").parse().unwrap();
        let err = MultiTagNote::from_ur(&foreign).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedType);
        let expected: Vec<String> = err.expected_types().iter().map(UrType::to_string).collect();
        assert_eq!(expected, vec!["x-test", "x-test-legacy"]);
    }

    #[test]
    fn l4_multi_tag_write_type_is_first_name() {
        let value = MultiTagNote {
            id: 7,
            note: "hi".to_owned(),
        };
        assert_eq!(value.to_ur().unwrap().ur_type(), &ur_type!("x-test"));
    }
}
