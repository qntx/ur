//! Official compliance vectors (BCR-2024-001, `URKit`, bc-ur), read from the
//! repository-root `vectors/` tree. These cover crate-private consensus internals
//! (`crc32`, `Xoshiro256`, `Weighted`, `shuffled`, `choose_fragments`, `partition`,
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

use serde_json::Value;

use crate::crc32;
use crate::fountain::{choose_fragments, fragment_length, partition};
use crate::rng::test_utils::make_message;
use crate::rng::{Weighted, Xoshiro256};

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
        // `minFragmentLength` is not supported yet (F-11); both official cases pass
        // because the minimum bound does not bind.
        let len = fragment_length(
            case["messageLength"].as_u64().unwrap() as usize,
            case["maxFragmentLength"].as_u64().unwrap() as usize,
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
        let frag_len = fragment_length(len, max);
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
                let frag_len = fragment_length(len, max);
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
                let sampler = Weighted::new(probs);
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
                .map(|_| rng.shuffled(values.clone()))
                .collect();
            assert_eq!(rounds, rows(&case["expected"]), "{}", case["name"]);
        } else {
            let count = case["count"].as_u64().unwrap() as usize;
            // A prefix of the full remove-shuffle equals the reference partial shuffle.
            let mut shuffled = rng.shuffled(values.clone());
            shuffled.truncate(count);
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
        let message = message_of(case);
        let frag_len = fragment_length(len, max);
        let fragment_count = partition(message.clone(), frag_len).len();
        let checksum = crc32::checksum(&message);
        let indexes: Vec<Vec<u64>> = case["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seq| {
                let mut idx =
                    choose_fragments(seq.as_u64().unwrap() as usize, fragment_count, checksum);
                idx.sort_unstable();
                idx.iter().map(|x| *x as u64).collect()
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
        let mut enc = crate::fountain::Encoder::new(&message_of(case), max).unwrap();
        match case["kind"].as_str().unwrap() {
            "parts" => {
                for want in case["parts"].as_array().unwrap() {
                    let part = enc.next_part().unwrap();
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
                        u64::from(part.message_length()),
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
                while !enc.complete() {
                    enc.next_part().unwrap();
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

#[test]
fn official_decoder() {
    let doc = vdoc!("official/mur/decoder.json");
    for case in doc["cases"].as_array().unwrap() {
        let max = case["maxFragmentLength"].as_u64().unwrap() as usize;
        let message = message_of(case);
        let mut enc = crate::fountain::Encoder::new(&message, max).unwrap();
        // `firstSeqNum` is not a supported API yet (F-11); discarding the first N
        // emitted parts is equivalent wire behavior.
        for _ in 0..case["firstSeqNum"].as_u64().unwrap_or(0) {
            let _ = enc.next_part().unwrap();
        }
        let mut dec = crate::fountain::Decoder::new();
        while !dec.complete() {
            dec.receive(enc.next_part().unwrap()).unwrap();
        }
        assert_eq!(dec.message().unwrap().as_deref(), Some(message.as_slice()));
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
fn official_ur_single() {
    let doc = vdoc!("official/ur/single.json");
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ur = case["ur"].as_str().unwrap();
        let ur_type = crate::ur::UrType::new(case["urType"].as_str().unwrap()).unwrap();
        let parsed = crate::ur::parse(ur).unwrap();
        assert_eq!(parsed.ur_type, ur_type, "{name}");
        if case["kind"].as_str() == Some("multi") {
            assert_eq!(parsed.kind, crate::ur::Kind::MultiPart, "{name}");
            let seq = case["seqNum"].as_u64().unwrap() as u32;
            let count = case["seqLen"].as_u64().unwrap() as u32;
            assert_eq!(parsed.indices, Some((seq, count)), "{name}");
            let (kind, payload) = crate::ur::decode(ur).unwrap();
            assert_eq!(kind, crate::ur::Kind::MultiPart, "{name}");
            assert!(!payload.is_empty(), "{name}");
        } else {
            assert_eq!(parsed.kind, crate::ur::Kind::SinglePart, "{name}");
            let payload = crate::ur::decode_message(ur).unwrap();
            if let Some(expected) = case["cborHex"].as_str() {
                assert_eq!(hex::encode(&payload), expected, "{name}");
            }
            if case["payload"].is_object() {
                let bstr = &case["payload"]["cborBstr"];
                let expected = cbor_bstr(&make_message(
                    bstr["seed"].as_str().unwrap(),
                    bstr["length"].as_u64().unwrap() as usize,
                ));
                assert_eq!(payload, expected, "{name}");
            }
            assert_eq!(crate::ur::encode(&payload, &ur_type), ur, "{name}");
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
        let mut enc = crate::ur::Encoder::new(&payload, max, &ur_type).unwrap();
        // See official_decoder: discarding the first N parts emulates `firstSeqNum`.
        for _ in 0..case["firstSeqNum"].as_u64().unwrap_or(0) {
            let _ = enc.next_part().unwrap();
        }
        if let Some(parts_file) = case["partsFile"].as_str() {
            assert_eq!(parts_file, "ur-rs/multipart-20.txt");
            let expected: Vec<String> = vector!("ur-rs/multipart-20.txt")
                .split('\n')
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            let got: Vec<String> = (0..case["partCount"].as_u64().unwrap())
                .map(|_| enc.next_part().unwrap())
                .collect();
            assert_eq!(got, expected, "{name}");
        } else {
            let mut dec = crate::ur::Decoder::new();
            while !dec.complete() {
                dec.receive(&enc.next_part().unwrap()).unwrap();
            }
            assert_eq!(
                dec.message().unwrap().as_deref(),
                Some(payload.as_slice()),
                "{name}"
            );
        }
    }
}
