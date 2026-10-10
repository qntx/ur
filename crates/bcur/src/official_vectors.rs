//! Official compliance vectors (BCR-2024-001, `URKit`, bc-ur), read from the
//! repository-root `vectors/` tree. These cover crate-private consensus internals
//! (`crc32`, `Xoshiro256`, `Sampler`, `shuffled`, `choose_fragments`, `partition`,
//! `fragment_length`), plus public-API cases that need the crate-internal message
//! generator. `crates/bcur/tests/official/` covers the rest of the public API.

#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::panic,
    clippy::excessive_nesting,
    reason = "test-only module: official vector JSON is trusted; assertions panic loudly on any mismatch"
)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde_json::Value;

use crate::consensus::xoshiro::test_utils::make_message;
use crate::consensus::{Sampler, Xoshiro256, choose_fragments, crc32};
use crate::fountain::{fragment_length, partition};

// vectors/ sits at the repository root — same include scheme as crates/bcur/tests.
macro_rules! vector {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/",
            $path
        ))
    };
}
macro_rules! vdoc {
    ($path:literal) => {{
        let doc: Value = serde_json::from_str(vector!($path)).unwrap();
        doc
    }};
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn u64s(v: &Value) -> Vec<u64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect()
}

fn rows(v: &Value) -> Vec<Vec<u64>> {
    v.as_array().unwrap().iter().map(u64s).collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| String::from(x.as_str().unwrap()))
        .collect()
}

fn message_of(case: &Value) -> Vec<u8> {
    let m = &case["message"];
    make_message(
        m["seed"].as_str().unwrap(),
        m["length"].as_u64().unwrap() as usize,
    )
}

#[test]
fn official_crc32() {
    let doc = vdoc!("official/mur/crc32.json");
    for case in doc["cases"].as_array().unwrap() {
        let input = case["inputUtf8"].as_str().map_or_else(
            || unhex(case["inputHex"].as_str().unwrap()),
            |s| s.as_bytes().to_vec(),
        );
        let expected = u32::from_str_radix(case["checksum"].as_str().unwrap(), 16).unwrap();
        assert_eq!(crc32::checksum(&input), expected, "{}", case["name"]);
    }
}

fn rng_for(seed: &Value) -> Xoshiro256 {
    if let Some(s) = seed["string"].as_str() {
        return Xoshiro256::from(s);
    }
    if let Some(s) = seed["crc32OfUtf8"].as_str() {
        return Xoshiro256::from_crc(s.as_bytes());
    }
    if let Some(s) = seed["bytesHex"].as_str() {
        return Xoshiro256::from(unhex(s).as_slice());
    }
    panic!("unknown seed: {seed}");
}

#[test]
fn official_xoshiro() {
    let doc = vdoc!("official/mur/rng.json");
    for case in doc["cases"].as_array().unwrap() {
        let mut rng = rng_for(&case["seed"]);
        let count = case["count"].as_u64().unwrap() as usize;
        let op = case["op"].as_str().unwrap();
        match op {
            "nextMod" => {
                let modulus = case["args"]["modulus"].as_u64().unwrap();
                let out: Vec<u64> = (0..count).map(|_| rng.next_u64() % modulus).collect();
                assert_eq!(out, u64s(&case["expected"]), "{}", case["name"]);
            }
            "nextInt" => {
                let low = case["args"]["low"].as_u64().unwrap();
                let high = case["args"]["high"].as_u64().unwrap();
                let out: Vec<u64> = (0..count).map(|_| rng.next_int(low, high)).collect();
                assert_eq!(out, u64s(&case["expected"]), "{}", case["name"]);
            }
            "nextData" => {
                let len = case["args"]["length"].as_u64().unwrap() as usize;
                let out: Vec<String> = (0..count)
                    .map(|_| hex::encode(rng.next_bytes(len)))
                    .collect();
                assert_eq!(out, strings(&case["expected"]), "{}", case["name"]);
            }
            other => panic!("unknown op {other}"),
        }
    }
}

#[test]
fn official_fragment_length() {
    let doc = vdoc!("official/mur/fragment-length.json");
    for case in doc["cases"].as_array().unwrap() {
        let len = fragment_length(
            case["messageLength"].as_u64().unwrap() as usize,
            case["maxFragmentLength"].as_u64().unwrap() as usize,
            case["minFragmentLength"].as_u64().unwrap() as usize,
        );
        assert_eq!(len, case["expected"].as_u64().unwrap() as usize);
    }
}

#[test]
fn official_partition() {
    let doc = vdoc!("official/mur/partition.json");
    for case in doc["cases"].as_array().unwrap() {
        let len = case["message"]["length"].as_u64().unwrap() as usize;
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let min = case["minFragmentLength"].as_u64().unwrap_or(10) as usize;
        let frag_len = fragment_length(len, max, min);
        let fragments: Vec<String> = partition(message_of(case), frag_len)
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(fragments, strings(&case["fragmentsHex"]));
    }
}

fn counts_by_key(values: &[u64]) -> Vec<u64> {
    let mut counts = alloc::collections::BTreeMap::new();
    for v in values {
        *counts.entry(*v).or_insert(0_u64) += 1;
    }
    counts.into_values().collect()
}

#[test]
fn official_sampler() {
    let doc = vdoc!("official/mur/degree.json");
    for case in doc["cases"].as_array().unwrap() {
        let kind = case["kind"].as_str().unwrap();
        let count = case["count"].as_u64().unwrap() as usize;
        match kind {
            "degree-chooser" | "degree-chooser-per-nonce" => {
                let len = case["message"]["length"].as_u64().unwrap() as usize;
                let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
                let min = case["minFragmentLength"].as_u64().unwrap_or(10) as usize;
                let frag_len = fragment_length(len, max, min);
                let fragment_count = partition(message_of(case), frag_len).len() as u32;
                let degrees: Vec<u64> = if kind == "degree-chooser-per-nonce" {
                    (0..count)
                        .map(|i| {
                            let s = case["rngSeed"]
                                .as_str()
                                .unwrap()
                                .replace("{n}", &(i + 1).to_string());
                            u64::from(
                                Xoshiro256::from(s.as_str()).choose_degree(fragment_count as usize),
                            )
                        })
                        .collect()
                } else {
                    let mut rng = Xoshiro256::from(case["rngSeed"].as_str().unwrap());
                    (0..count)
                        .map(|_| u64::from(rng.choose_degree(fragment_count as usize)))
                        .collect()
                };
                assert_eq!(degrees, u64s(&case["degrees"]), "{}", case["name"]);
                if let Some(totals) = case.get("totals") {
                    assert_eq!(counts_by_key(&degrees), u64s(totals));
                }
            }
            "random-sampler" => {
                let probs: Vec<f64> = case["probabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_f64().unwrap())
                    .collect();
                let sampler = Sampler::new(probs);
                let mut rng = Xoshiro256::from(case["rngSeed"].as_str().unwrap());
                let samples: Vec<u64> = (0..count)
                    .map(|_| u64::from(sampler.next(&mut rng)))
                    .collect();
                assert_eq!(samples, u64s(&case["samples"]), "{}", case["name"]);
                assert_eq!(counts_by_key(&samples), u64s(&case["totals"]));
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn official_shuffle() {
    let doc = vdoc!("official/mur/shuffle.json");
    for case in doc["cases"].as_array().unwrap() {
        let values: Vec<u64> = u64s(&case["values"]);
        let mut rng = Xoshiro256::from(case["rngSeed"].as_str().unwrap());
        if case["kind"].as_str().unwrap() == "continued" {
            let rounds: Vec<Vec<u64>> = (0..case["rounds"].as_u64().unwrap())
                .map(|_| rng.shuffled(values.clone(), values.len()))
                .collect();
            assert_eq!(rounds, rows(&case["expected"]), "{}", case["name"]);
        } else {
            let count = case["count"].as_u64().unwrap() as usize;
            let shuffled = rng.shuffled(values.clone(), count);
            assert_eq!(shuffled, u64s(&case["expected"]), "{}", case["name"]);
        }
    }
}

#[test]
fn official_chooser() {
    let doc = vdoc!("official/mur/chooser.json");
    for case in doc["cases"].as_array().unwrap() {
        let len = case["message"]["length"].as_u64().unwrap() as usize;
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let min = case["minFragmentLength"].as_u64().unwrap_or(10) as usize;
        let message = message_of(case);
        let frag_len = fragment_length(len, max, min);
        let fragment_count = partition(message.clone(), frag_len).len();
        let checksum = crc32::checksum(&message);
        let indexes: Vec<Vec<u64>> = case["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seq| {
                choose_fragments(
                    NonZeroU32::new(seq.as_u64().unwrap() as u32).unwrap(),
                    NonZeroU32::new(fragment_count as u32).unwrap(),
                    checksum,
                )
                .iter()
                .map(|x| *x as u64)
                .collect()
            })
            .collect();
        assert_eq!(indexes, rows(&case["indexes"]));
    }
}

// Encoder/decoder cases exercise the public `fountain`/`ur` API but live here
// because the message generator is crate-internal.

#[test]
fn official_encoder() {
    let doc = vdoc!("official/mur/encoder.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let mut enc = crate::fountain::Encoder::new(
            message_of(case),
            crate::fountain::EncoderOptions::new(max),
        )
        .unwrap();
        match case["kind"].as_str().unwrap() {
            "parts" => {
                for want in case["parts"].as_array().unwrap() {
                    let part = enc.next().unwrap();
                    assert_eq!(
                        u64::from(part.sequence()),
                        want["seqNum"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        u64::from(part.sequence_count()),
                        want["seqLen"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        u64::from(part.message_len()),
                        want["messageLen"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        alloc::format!("{:08x}", part.checksum()),
                        want["checksum"].as_str().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        hex::encode(part.data()),
                        want["dataHex"].as_str().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        hex::encode(part.to_cbor()),
                        want["cborHex"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "complete" => {
                let mut generated = 0_u64;
                while !enc.is_complete() {
                    enc.next().unwrap();
                    generated += 1;
                }
                assert_eq!(
                    generated,
                    case["expectCompleteAfterParts"].as_u64().unwrap(),
                    "{name}"
                );
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

/// `vectors/fountain/encoder-options.json` (generated): encoder option
/// behavior — `min_fragment_len` binding, `first_sequence`, iterator end at
/// `u32::MAX`, `K == 1` repetition, `is_complete` transitions,
/// `last_fragment_indexes`.
#[test]
fn fountain_encoder_options() {
    let doc = vdoc!("fountain/encoder-options.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let len = case["message"]["length"].as_u64().unwrap() as usize;
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let min = case["minFragmentLength"].as_u64().unwrap_or(10) as usize;
        match case["kind"].as_str().unwrap() {
            "fragment-length" => {
                let frag_len = fragment_length(len, max, min);
                assert_eq!(
                    frag_len,
                    case["fragmentLength"].as_u64().unwrap() as usize,
                    "{name}"
                );
                assert_eq!(
                    len.div_ceil(frag_len),
                    case["fragmentCount"].as_u64().unwrap() as usize,
                    "{name}"
                );
            }
            "sequences" => {
                let options = crate::fountain::EncoderOptions {
                    max_fragment_len: max,
                    min_fragment_len: min,
                    first_sequence: case["firstSequence"].as_u64().unwrap_or(0) as u32,
                };
                let mut enc = crate::fountain::Encoder::new(message_of(case), options)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let want_seqs = u64s(&case["sequences"]);
                let mut data_hex = Vec::new();
                for (i, want) in want_seqs.iter().enumerate() {
                    let part = enc.next().unwrap_or_else(|| panic!("{name}: done early"));
                    assert_eq!(u64::from(part.sequence()), *want, "{name}");
                    data_hex.push(hex::encode(part.data()));
                    if let Some(flags) = case["isCompleteAfter"].as_array() {
                        assert_eq!(enc.is_complete(), flags[i].as_bool().unwrap(), "{name}");
                    }
                    if let Some(rows) = case["lastFragmentIndexes"].as_array() {
                        let want_idx: Vec<u32> = u64s(&rows[i])
                            .iter()
                            .map(|&v| u32::try_from(v).unwrap())
                            .collect();
                        assert_eq!(enc.last_fragment_indexes(), want_idx.as_slice(), "{name}");
                    }
                }
                if let Some(want_hex) = case["dataHex"].as_array() {
                    let got: Vec<String> = data_hex;
                    let want: Vec<String> = want_hex
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    assert_eq!(got, want, "{name}");
                }
                if case["doneAfter"].as_bool().unwrap_or(false) {
                    assert!(enc.next().is_none(), "{name}");
                }
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn official_decoder() {
    let doc = vdoc!("official/mur/decoder.json");
    for case in doc["cases"].as_array().unwrap() {
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let message = message_of(case);
        let options = crate::fountain::EncoderOptions {
            first_sequence: case["firstSeqNum"].as_u64().unwrap_or(0) as u32,
            ..crate::fountain::EncoderOptions::new(max)
        };
        let mut enc = crate::fountain::Encoder::new(message.clone(), options).unwrap();
        let mut dec = crate::fountain::Decoder::default();
        loop {
            let part = enc.next().unwrap();
            dec.receive(&part).unwrap();
            if matches!(dec.state(), crate::fountain::State::Complete(_)) {
                break;
            }
        }
        assert_eq!(dec.into_message().unwrap(), message);
    }
}

fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut out = if len < 24 {
        alloc::vec![0x40 | len as u8]
    } else if len < 256 {
        alloc::vec![0x58, len as u8]
    } else {
        alloc::vec![0x59, (len >> 8) as u8, len as u8]
    };
    out.extend_from_slice(bytes);
    out
}

fn payload_of(case: &Value) -> Vec<u8> {
    let message = message_of(case);
    match case["wrap"].as_str() {
        Some("cbor-bstr") => cbor_bstr(&message),
        _ => message,
    }
}

#[test]
fn official_bytemoji_table() {
    let doc = vdoc!("official/bytemoji.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if let Some(table) = case["table"].as_str() {
            assert_eq!(
                crate::constants::BYTEMOJIS.concat(),
                table,
                "{name}: BYTEMOJIS table vs BCR-2024-008 reference string"
            );
            continue;
        }
        let digest: [u8; 4] = hex::decode(case["digestHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            crate::bytemoji::identifier(digest),
            case["bytemojis"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn official_ur_single() {
    let doc = vdoc!("official/ur/single.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ur = case["ur"].as_str().unwrap();
        let ur_type = crate::ur::UrType::new(case["urType"].as_str().unwrap()).unwrap();
        let parsed = crate::ur::parse(ur, &crate::fountain::DecoderLimits::default()).unwrap();
        if case["kind"].as_str() == Some("multi") {
            let crate::ur::ParsedUr::Multi {
                ur_type: parsed_type,
                part,
            } = parsed
            else {
                panic!("{name}: expected multi");
            };
            assert_eq!(parsed_type, ur_type, "{name}");
            let seq = case["seqNum"].as_u64().unwrap() as u32;
            let count = case["seqLen"].as_u64().unwrap() as u32;
            assert_eq!(part.sequence(), seq, "{name}");
            assert_eq!(part.sequence_count(), count, "{name}");
        } else {
            let crate::ur::ParsedUr::Single {
                ur_type: parsed_type,
                message,
            } = parsed
            else {
                panic!("{name}: expected single");
            };
            assert_eq!(parsed_type, ur_type, "{name}");
            if let Some(expected) = case["cborHex"].as_str() {
                assert_eq!(hex::encode(&message), expected, "{name}");
            }
            if case["payload"].is_object() {
                let bstr = &case["payload"]["cborBstr"];
                let expected = cbor_bstr(&make_message(
                    bstr["seed"].as_str().unwrap(),
                    bstr["length"].as_u64().unwrap() as usize,
                ));
                assert_eq!(message, expected, "{name}");
            }
            assert_eq!(crate::ur::encode(&ur_type, &message), ur, "{name}");
        }
    }
}

#[test]
fn official_ur_multipart() {
    let doc = vdoc!("official/ur/multipart.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ur_type = crate::ur::UrType::new(case["urType"].as_str().unwrap()).unwrap();
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let payload = payload_of(case);
        let first_seq = case["firstSeqNum"].as_u64().unwrap_or(0) as u32;
        let mut enc = crate::ur::Encoder::new(
            ur_type,
            payload.clone(),
            crate::fountain::EncoderOptions {
                first_sequence: first_seq,
                ..crate::fountain::EncoderOptions::new(max)
            },
        )
        .unwrap();
        if let Some(parts_file) = case["partsFile"].as_str() {
            assert_eq!(parts_file, "ur-rs/multipart-20.txt");
            let expected: Vec<String> = vector!("ur-rs/multipart-20.txt")
                .split('\n')
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            let got: Vec<String> = (0..case["partCount"].as_u64().unwrap())
                .map(|_| enc.next().unwrap())
                .collect();
            assert_eq!(got, expected, "{name}");
        } else {
            let mut dec = crate::ur::Decoder::default();
            while !matches!(dec.state(), crate::fountain::State::Complete(_)) {
                dec.receive(&enc.next().unwrap()).unwrap();
            }
            assert_eq!(
                dec.into_decoded().unwrap().message(),
                payload.as_slice(),
                "{name}"
            );
        }
    }
}

fn limits_of(case: &Value) -> crate::fountain::DecoderLimits {
    let limits = &case["limits"];
    let mut out = crate::fountain::DecoderLimits::default();
    if let Some(v) = limits["maxMessageLength"].as_u64() {
        out.max_message_length = v as usize;
    }
    if let Some(v) = limits["maxFragmentCount"].as_u64() {
        out.max_fragment_count = v as usize;
    }
    if let Some(v) = limits["maxFragmentLength"].as_u64() {
        out.max_fragment_length = v as usize;
    }
    if let Some(v) = limits["maxUriLength"].as_u64() {
        out.max_uri_length = v as usize;
    }
    out
}

/// Frame error categories recorded by the shared decoder-frame vectors
/// (camelCase names are the vector format, not a library API).
const fn limit_name(limit: crate::Limit) -> &'static str {
    match limit {
        crate::Limit::MessageLength => "messageLength",
        crate::Limit::FragmentCount => "fragmentCount",
        crate::Limit::FragmentLength => "fragmentLength",
        crate::Limit::UriLength => "uriLength",
    }
}

fn assert_error(frame: &Value, error: &crate::Error, name: &str, i: usize) {
    let want = &frame["error"];
    assert_eq!(
        alloc::format!("{:?}", error.kind()),
        want["code"].as_str().unwrap(),
        "{name} frame {i}"
    );
    if let Some(limit) = want["limit"].as_str() {
        assert_eq!(
            error.limit().map(limit_name),
            Some(limit),
            "{name} frame {i}"
        );
    }
}

fn json_u32(value: &Value, key: &str) -> u32 {
    u32::try_from(value[key].as_u64().unwrap()).unwrap()
}

fn json_u32_or(value: &Value, key: &str, default: u32) -> u32 {
    value[key]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(default)
}

/// Builds the frame's part: either the encoder's part for `sequence`, possibly
/// patched, or nothing when no sequence is given.
fn cached_or_patched(
    frame: &Value,
    enc: &mut crate::fountain::Encoder,
    cache: &mut alloc::collections::BTreeMap<u32, crate::fountain::Part>,
) -> Result<crate::fountain::Part, crate::Error> {
    let seq = u32::try_from(frame["sequence"].as_u64().unwrap_or(0)).unwrap_or(0);
    while !cache.contains_key(&seq) {
        let part = enc.next().unwrap();
        cache.insert(part.sequence(), part);
    }
    let base = cache.get(&seq).unwrap().clone();
    let Some(patch) = frame.get("patch") else {
        return Ok(base);
    };
    crate::fountain::Part::new(
        json_u32_or(patch, "sequence", base.sequence()),
        json_u32_or(patch, "sequenceCount", base.sequence_count()),
        json_u32_or(patch, "messageLength", base.message_len()),
        json_u32_or(patch, "checksum", base.checksum()),
        patch["dataHex"]
            .as_str()
            .map_or_else(|| base.data().to_vec(), unhex),
    )
}

/// `vectors/fountain/decoder-frames.json` (generated): per-frame GF(2) decoder
/// outcomes. The generator cross-checked accepted/duplicate and the completion
/// check against an independent naive `BigInt` rank tracker.
#[test]
fn fountain_decoder_frames() {
    let doc = vdoc!("fountain/decoder-frames.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let options = crate::fountain::EncoderOptions {
            max_fragment_len: max,
            min_fragment_len: case["minFragmentLength"].as_u64().unwrap_or(10) as usize,
            first_sequence: case["firstSequence"].as_u64().unwrap_or(0) as u32,
        };
        let mut enc = crate::fountain::Encoder::new(message_of(case), options).unwrap();
        let mut cache: alloc::collections::BTreeMap<u32, crate::fountain::Part> =
            alloc::collections::BTreeMap::new();
        let mut dec = crate::fountain::Decoder::new(limits_of(case));
        let mut completed_at = None;
        for (i, frame) in case["frames"].as_array().unwrap().iter().enumerate() {
            let want = frame["status"].as_str().unwrap();
            let built = frame.get("part").map_or_else(
                || cached_or_patched(frame, &mut enc, &mut cache),
                |raw| {
                    crate::fountain::Part::new(
                        json_u32(raw, "sequence"),
                        json_u32(raw, "sequenceCount"),
                        json_u32(raw, "messageLength"),
                        json_u32(raw, "checksum"),
                        unhex(raw["dataHex"].as_str().unwrap()),
                    )
                },
            );
            let part = match built {
                Ok(part) => part,
                Err(error) => {
                    assert_eq!(want, "rejected", "{name} frame {i}");
                    assert_error(frame, &error, name, i);
                    continue;
                }
            };
            let got = match dec.receive(&part) {
                Ok(crate::fountain::Received::Accepted) => "accepted",
                Ok(crate::fountain::Received::Duplicate) => "duplicate",
                Err(error) => {
                    assert_error(frame, &error, name, i);
                    if error.is_fatal() {
                        "fatal"
                    } else {
                        "rejected"
                    }
                }
            };
            assert_eq!(got, want, "{name} frame {i}");
            if completed_at.is_none() && matches!(dec.state(), crate::fountain::State::Complete(_))
            {
                completed_at = Some(i + 1);
            }
        }
        assert_eq!(
            completed_at,
            case["completeAt"].as_u64().map(|v| v as usize),
            "{name}"
        );
        if let Some(want) = case["messageHex"].as_str() {
            assert_eq!(hex::encode(dec.into_message().unwrap()), want, "{name}");
        }
    }
}

/// `vectors/ur/decoder-frames.json` (generated): per-frame UR decoder outcomes.
#[test]
fn ur_decoder_frames() {
    let doc = vdoc!("ur/decoder-frames.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut dec = crate::ur::Decoder::new(limits_of(case));
        if let Some(accept) = case["accept"].as_array() {
            dec = dec.accept(
                accept
                    .iter()
                    .map(|t| crate::ur::UrType::new(t.as_str().unwrap()).unwrap()),
            );
        }
        let mut completed_at = None;
        for (i, frame) in case["frames"].as_array().unwrap().iter().enumerate() {
            let want = frame["status"].as_str().unwrap();
            let got = match dec.receive(frame["text"].as_str().unwrap()) {
                Ok(crate::fountain::Received::Accepted) => "accepted",
                Ok(crate::fountain::Received::Duplicate) => "duplicate",
                Err(error) => {
                    assert_error(frame, &error, name, i);
                    if error.is_fatal() {
                        "fatal"
                    } else {
                        "rejected"
                    }
                }
            };
            assert_eq!(got, want, "{name} frame {i}");
            if completed_at.is_none() && matches!(dec.state(), crate::fountain::State::Complete(_))
            {
                completed_at = Some(i + 1);
            }
        }
        assert_eq!(
            completed_at,
            case["completeAt"].as_u64().map(|v| v as usize),
            "{name}"
        );
        if let Some(want) = case["messageHex"].as_str() {
            assert_eq!(
                hex::encode(dec.into_decoded().unwrap().message()),
                want,
                "{name}"
            );
        }
    }
}
