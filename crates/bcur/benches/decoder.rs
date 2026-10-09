#![allow(
    unused_crate_dependencies,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::excessive_nesting,
    reason = "criterion benches: fixed payloads and intentional unwraps"
)]

//! GF(2) fountain decoder throughput: `K = 2000` rows, 20% deterministic
//! loss from sequence 1 until completion. With `fragLen = 8192` the
//! `maxMessageLength`-sized message is capped at 1 MiB (`K = 128`).

use bcur::fountain::{Decoder, Encoder, EncoderOptions, State};
use criterion::{Criterion, criterion_group, criterion_main};

const MAX_MESSAGE: usize = 1024 * 1024;

fn message_for(target_k: usize, frag_len: usize) -> Vec<u8> {
    let len = target_k.saturating_mul(frag_len).min(MAX_MESSAGE);
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// One decode run: 20% loss (every 5th part dropped) until `Complete`.
/// Returns the number of parts actually fed.
fn decode_run(message: &[u8], frag_len: usize) -> usize {
    let mut enc = Encoder::new(message.to_vec(), EncoderOptions::new(frag_len)).unwrap();
    let mut dec = Decoder::default();
    let mut seq = 0_u32;
    let mut fed = 0_usize;
    loop {
        let part = enc.next().unwrap();
        seq = seq.wrapping_add(1);
        if seq.is_multiple_of(5) {
            continue;
        }
        dec.receive(&part).unwrap();
        fed += 1;
        if matches!(dec.state(), State::Complete(_)) {
            return fed;
        }
    }
}

fn bench_decoder(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf2_decoder_20pct_loss");
    for (target_k, frag_len) in [(2000_usize, 200_usize), (2000, 8192)] {
        let message = message_for(target_k, frag_len);
        let k = message.len().div_ceil(frag_len);
        group.bench_function(format!("k{k}_frag{frag_len}"), |b| {
            b.iter(|| decode_run(&message, frag_len));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decoder);
criterion_main!(benches);
