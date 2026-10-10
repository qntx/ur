#![no_main]

//! Arbitrary sequences of arbitrary parts into one `fountain::Decoder`:
//! never panic, and the phase may only move forward
//! (`Empty -> Collecting -> Complete | Failed`).

use bcur::DecoderLimits;
use bcur::fountain::{Decoder, Part, State};
use libfuzzer_sys::fuzz_target;

fn phase_rank(decoder: &Decoder) -> u8 {
    match decoder.state() {
        State::Empty => 0,
        State::Collecting(_) => 1,
        State::Complete(_) | State::Failed(_) => 2,
    }
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([
        data.get(at).copied().unwrap_or(0),
        data.get(at.wrapping_add(1)).copied().unwrap_or(0),
        data.get(at.wrapping_add(2)).copied().unwrap_or(0),
        data.get(at.wrapping_add(3)).copied().unwrap_or(0),
    ])
}

/// Synthesizes parts from raw fields; `Part::new` enforces the padding
/// invariant itself, so the layout just has to stay plausible.
fn synthesize(data: &[u8], at: usize) -> Option<Part> {
    let sequence = read_u32(data, at) % 64 + 1;
    let count = read_u32(data, at + 4) % 16 + 1;
    let frag_len = usize::from(data.get(at + 8).copied().unwrap_or(0)) % 32 + 1;
    let count_sz = usize::try_from(count).ok()?;
    let message_len = count_sz.saturating_mul(frag_len).saturating_sub(
        usize::from(data.get(at + 9).copied().unwrap_or(0)) % frag_len,
    );
    let message_len = u32::try_from(message_len.max(1)).ok()?;
    let checksum = read_u32(data, at + 10);
    let frag: Vec<u8> = (0..frag_len)
        .map(|i| data.get(at + 14 + i).copied().unwrap_or(0))
        .collect();
    Part::new(sequence, count, message_len, checksum, frag).ok()
}

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(
        DecoderLimits::default()
            .with_max_fragment_count(64)
            .with_max_fragment_length(64)
            .with_max_message_length(4096),
    );
    let mut phase = 0_u8;

    // Stream A: raw CBOR chunks decoded as parts.
    for chunk in data.chunks(40) {
        if let Ok(part) = Part::from_cbor(chunk, &DecoderLimits::default()) {
            feed(&mut decoder, &part, &mut phase);
        }
    }

    // Stream B: synthesized parts from raw fields, including out-of-order
    // and duplicated sequence numbers.
    let mut at = 0_usize;
    while at < data.len() {
        if let Some(part) = synthesize(data, at) {
            feed(&mut decoder, &part, &mut phase);
        }
        at = at.wrapping_add(7);
    }
});

fn feed(decoder: &mut Decoder, part: &Part, phase: &mut u8) {
    match decoder.receive(part) {
        Ok(_) => {}
        Err(e) if e.is_fatal() => {
            assert!(
                matches!(decoder.state(), State::Failed(_)),
                "fatal receive must fail the session"
            );
        }
        Err(_) => {
            assert!(
                *phase < 2,
                "nonfatal error in a terminal phase must be impossible"
            );
        }
    }
    let now = phase_rank(decoder);
    assert!(now >= *phase, "decoder phase regressed");
    *phase = now;
    if let State::Collecting(progress) = decoder.state() {
        assert!(progress.rank() <= progress.fragment_count());
        assert!(progress.recovered() <= progress.rank());
    }
}
