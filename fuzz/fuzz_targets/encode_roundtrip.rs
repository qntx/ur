#![no_main]

use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoder, Encoder};
use bcur::{State, UrType};
use libfuzzer_sys::fuzz_target;

/// True when the UR path contains `/<digits>-<digits>/` (fountain form).
fn has_fountain_path(ur: &str) -> bool {
    let mut rest = ur;
    while let Some(i) = rest.find('/') {
        rest = &rest[i + 1..];
        let Some(dash) = rest.find('-') else {
            continue;
        };
        let Some(end) = rest[dash + 1..].find('/') else {
            continue;
        };
        let seq = &rest[..dash];
        let count = &rest[dash + 1..dash + 1 + end];
        if !seq.is_empty()
            && !count.is_empty()
            && seq.bytes().all(|b| b.is_ascii_digit())
            && count.bytes().all(|b| b.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Layout: `[max_frag:u16le][type_len:u8][type][payload]`.
fn parse_input(data: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    let max_frag = u16::from_le_bytes([*data.first()?, *data.get(1)?]) as usize;
    let type_len = usize::from(*data.get(2)?);
    let rest = data.get(3..)?;
    if rest.len() < type_len {
        return None;
    }
    let (ty, payload) = rest.split_at(type_len);
    Some((ty, payload, max_frag))
}

fn encode_roundtrip(type_bytes: &[u8], payload: &[u8], max_frag: usize) {
    let Ok(type_str) = str::from_utf8(type_bytes) else {
        return;
    };
    let Ok(ur_type) = UrType::new(type_str) else {
        return;
    };
    let max_frag = max_frag.clamp(1, payload.len().max(1));
    let Ok(mut encoder) =
        Encoder::new(ur_type, payload.to_vec(), EncoderOptions::new(max_frag))
    else {
        return;
    };
    let mut decoder = Decoder::default();

    if encoder.is_single_part() {
        let part = encoder.next().expect("K==1 next");
        assert!(
            !has_fountain_path(&part),
            "K==1 must emit ur:<type>/<body>, got {part}"
        );
        match decoder.receive(&part) {
            Err(e) if e.is_fatal() => {}
            Err(other) => panic!("decoder receive: {other:?}"),
            Ok(_) => {
                assert_eq!(decoder.into_decoded().unwrap().message(), payload);
            }
        }
        return;
    }

    let k = usize::try_from(encoder.fragment_count()).unwrap_or(usize::MAX);
    let cap = k.saturating_mul(6).max(40);
    for _ in 0..cap {
        let Some(part) = encoder.next() else {
            return;
        };
        match decoder.receive(&part) {
            Err(e) if e.is_fatal() => return,
            Err(other) => panic!("decoder receive: {other:?}"),
            Ok(_) if matches!(decoder.state(), State::Complete(_)) => {
                assert_eq!(decoder.into_decoded().unwrap().message(), payload);
                return;
            }
            Ok(_) => {}
        }
    }
    panic!("did not complete after {cap} parts");
}

fuzz_target!(|data: &[u8]| {
    let Some((ty, payload, max_frag)) = parse_input(data) else {
        return;
    };
    encode_roundtrip(ty, payload, max_frag);
});
