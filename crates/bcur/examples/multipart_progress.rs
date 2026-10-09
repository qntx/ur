#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::missing_assert_message,
    reason = "demo example prints progress and uses expect for brevity"
)]

//! Print fountain progress while emitting multi-part UR strings.

use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoder, Encoder};
use bcur::{State, ur_type};

fn main() {
    let data = b"Progress demo payload - multi-part UR scan simulation.".repeat(4);
    let mut encoder =
        Encoder::new(ur_type!("bytes"), data.clone(), EncoderOptions::new(16)).expect("encoder");
    let mut decoder = Decoder::default();
    let mut emitted = 0_u32;

    loop {
        let part = encoder.next().expect("part");
        emitted = emitted.saturating_add(1);
        decoder.receive(&part).expect("receive");
        let p = decoder.progress();
        println!(
            "emitted={} rank={}/{} recovered={} processed={}",
            emitted,
            p.rank(),
            p.fragment_count(),
            p.recovered(),
            p.processed(),
        );
        if matches!(decoder.state(), State::Complete(_)) {
            break;
        }
    }

    let msg = decoder.into_decoded().expect("decoded").into_parts().1;
    println!("done: {} bytes recovered", msg.len());
    assert_eq!(msg, data);
}
