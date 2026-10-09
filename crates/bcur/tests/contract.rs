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
use bcur::fountain::{self, Part};
use bcur::{Decoder, DecoderLimits, Encoder, ErrorKind, Kind, Limit, UrType, decode, encode};

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

fn assert_session_poison(limit: Limit, decoder: &mut Decoder, part: &str) {
    let is_limit = |r: &bcur::Result<()>| matches!(r, Err(e) if e.kind() == ErrorKind::ResourceLimit && e.limit() == Some(limit));
    assert!(
        is_limit(&decoder.receive(part)),
        "first receive must be {limit:?}"
    );
    assert!(decoder.is_poisoned(), "resource limit poisons the session");
    assert!(
        is_limit(&decoder.receive(part)),
        "later receive must repeat {limit:?}"
    );
    assert!(
        matches!(decoder.message(), Err(e) if e.kind() == ErrorKind::ResourceLimit
            && e.limit() == Some(limit)),
        "message must repeat {limit:?}"
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
                    max_fragment_data_length: get(
                        "maxFragmentDataLength",
                        d.max_fragment_data_length,
                    ),
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
                assert_eq!(got.limit().map(Limit::as_str), limit.as_str(), "{name}");
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
    let mut encoder = Encoder::new(payload, 64, &ur_type).unwrap();
    assert!(encoder.is_single_part());
    let outbound = encoder.next_part().unwrap();
    assert!(!outbound.contains(json_str(&spec, "outboundMustNotContain")));
    assert_eq!(
        spec.get("outboundEqualsSinglePartEncode")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(outbound, encode(payload, &ur_type));
    assert_eq!(
        spec.get("inboundFountain11Accepted")
            .and_then(Value::as_bool),
        Some(true)
    );
    let mut fountain =
        fountain::Encoder::new(payload.to_vec(), fountain::EncoderOptions::new(64)).unwrap();
    let part = fountain.next().unwrap();
    let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
    let uri = format!("ur:{}/1-1/{body}", ur_type.as_str());
    let mut decoder = Decoder::default();
    decoder.receive(&uri).unwrap();
    assert!(decoder.complete());
    assert_eq!(decoder.message().unwrap().as_deref(), Some(payload));
}

#[test]
fn l4_test_array_contract() {
    let spec = json(vector!("typed/test-array.json"));
    let cbor = hex::decode(json_str(&spec, "cborHex")).unwrap();
    let ur_type = UrType::new(json_str(&spec, "type")).unwrap();
    let uri = json_str(&spec, "uri");
    assert_eq!(encode(&cbor, &ur_type), uri);

    #[cfg(feature = "dcbor")]
    {
        let ur = bcur::Ur::new("test", vec![1, 2, 3]).unwrap();
        assert_eq!(ur.string(), uri);
    }

    let (kind, data) = decode(json_str(&spec, "uriUpper")).unwrap();
    assert_eq!(kind, Kind::SinglePart);
    assert_eq!(data, cbor);
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
        limits.max_fragment_data_length,
        json_usize(&spec, "maxFragmentDataLength")
    );
    assert_eq!(limits.max_buffer_parts, json_usize(&spec, "maxBufferParts"));
    assert_eq!(
        limits.max_received_parts,
        json_usize(&spec, "maxReceivedParts")
    );
    assert_eq!(limits.max_uri_len, json_usize(&spec, "maxUriLen"));
}

#[test]
fn poison_maps_via_rust_ident() {
    let spec = json(vector!("limits/poison.json"));
    let raw = vector!("limits/poison.json");
    assert!(!raw.contains("DecoderState"));
    let rows = spec.get("limits").and_then(Value::as_array).unwrap();
    let kinds = [
        Limit::UriLength,
        Limit::FragmentCount,
        Limit::FragmentLength,
        Limit::MessageLength,
        Limit::ReceivedParts,
        Limit::BufferParts,
    ];
    assert_eq!(rows.len(), kinds.len());
    for (row, kind) in rows.iter().zip(kinds) {
        assert_eq!(json_str(row, "rust"), format!("{kind:?}"));
        assert_eq!(json_str(row, "limit"), kind.as_str());
        let session = row.get("sessionPoison").and_then(Value::as_bool).unwrap();
        assert!(session);
    }
}

#[test]
fn poison_receive_and_message_same_code() {
    let spec = json(vector!("limits/poison.json"));
    let names: Vec<&str> = spec
        .get("receiveAndMessageSameCode")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(names, ["uriLength", "fragmentCount"]);

    let uri_payload = b"Ten chars!".repeat(8);
    let mut uri_enc = Encoder::bytes(&uri_payload, 10).unwrap();
    let uri_part = uri_enc.next_part().unwrap();
    let mut uri_decoder = Decoder::with_limits(DecoderLimits {
        max_uri_len: 16,
        ..DecoderLimits::default()
    });
    assert_session_poison(Limit::UriLength, &mut uri_decoder, &uri_part);

    let fragment_payload = b"Ten chars!".repeat(16);
    let mut fragment_enc = Encoder::bytes(&fragment_payload, 10).unwrap();
    assert!(fragment_enc.fragment_count() > 1);
    let mut fragment_decoder = Decoder::with_limits(DecoderLimits {
        max_fragment_count: 1,
        ..DecoderLimits::default()
    });
    let fragment_part = fragment_enc.next_part().unwrap();
    assert_session_poison(Limit::FragmentCount, &mut fragment_decoder, &fragment_part);
}

#[test]
fn poison_not_poison_errors() {
    let spec = json(vector!("limits/poison.json"));
    let names = spec
        .get("notPoison")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(names.contains(&"UnexpectedType"));
    assert!(names.contains(&"CborDecode"));

    let data = b"Ten chars!".repeat(6);
    let mut a = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
    let mut b = Encoder::new(&data, 10, &UrType::new("beta").unwrap()).unwrap();
    let mut decoder = Decoder::default();
    decoder.receive(&a.next_part().unwrap()).unwrap();
    assert!(matches!(
        decoder.receive(&b.next_part().unwrap()),
        Err(ref e) if e.kind() == ErrorKind::UnexpectedType
    ));
    assert!(!decoder.is_poisoned());
    decoder.receive(&a.next_part().unwrap()).unwrap();

    #[cfg(feature = "dcbor")]
    {
        use bcur::MultipartDecoder;

        let mut typed = MultipartDecoder::new();
        typed.receive("ur:bytes/iehsjyhspmwfwfia").unwrap();
        assert!(typed.complete());
        assert!(matches!(
            typed.message(),
            Err(ref e) if e.kind() == ErrorKind::CborDecode
        ));
        assert!(!typed.is_poisoned());
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
    assert!(decoder.complete());
    let payload = decoder.message().unwrap().unwrap();
    let mut encoder = Encoder::bytes(&payload, 30).unwrap();
    assert_eq!(encoder.fragment_count(), 9);
    assert_eq!(
        encoder.next_part().unwrap(),
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
        let (kind, _) = decode(uri).unwrap();
        assert_eq!(kind, Kind::SinglePart);
    }
}
