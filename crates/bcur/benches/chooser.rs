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

//! Per-stream fragment chooser throughput: parts `K + 1 ..= K + 1000` for
//! `K` in {50, 500, 2000} — the mixed sequences that exercise the degree
//! sampler and remove-shuffle.

use std::time::Duration;

use bcur::fountain::Encoder;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn bench_chooser(c: &mut Criterion) {
    let mut group = c.benchmark_group("chooser");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    for k in [50_usize, 500, 2000] {
        // Message sized so K fragments are all 1 byte — the mix XOR is cheap
        // and the measurement tracks the chooser, not the payload copy.
        let message = vec![0xAB_u8; k + 1];
        group.bench_function(format!("k{k}_seq_mixed_1000"), |b| {
            b.iter_batched(
                || {
                    let mut enc = Encoder::new(&message, 1).unwrap();
                    for _ in 0..k {
                        enc.next_part().unwrap();
                    }
                    enc
                },
                |mut enc| {
                    for _ in 0..1000 {
                        enc.next_part().unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_chooser);
criterion_main!(benches);
