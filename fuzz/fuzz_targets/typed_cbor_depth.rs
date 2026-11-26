#![no_main]

use bcur::typed::Ur;
use bcur::{ErrorKind, Limit, UrType};
use dcbor::{CBOR, CBORCase};
use libfuzzer_sys::fuzz_target;

bcur_fuzz::dcbor_asan_options!();

/// Decode/drop stack per input. `dcbor` recurses one frame per nesting level
/// on decode and on drop, so the typed layer's pre-decode depth scan is what
/// stands between libFuzzer and a stack overflow: this stack must fit
/// `CBOR_MAX_DEPTH` levels comfortably yet overflow on any deeper input that
/// a scan regression would let through.
///
/// Calibrated on the ASan release build (aarch64-apple-darwin,
/// `cargo +nightly fuzz build typed_cbor_depth`): deepest `81`-nested input
/// that still decodes and drops on each candidate stack. Maps (`a100`) and
/// tags (`c6`) match within the 8-level measurement granularity.
///
/// | stack   | deepest `81`×N that fits | first overflow |
/// |---------|--------------------------|----------------|
/// | 64 KiB  | —                        | 64             |
/// | 128 KiB | 96                       | 104            |
/// | 256 KiB | 200                      | 208            |
/// | 512 KiB | 400                      | 408            |
/// | 1 MiB   | 800                      | 832            |
///
/// Chosen: 512 KiB — the smallest power of two that fits ≥ 4·64 = 256 levels
/// of every kind (~1.3 KiB of ASan stack per level). Overflow starts ~6× the
/// limit, far below the ~4k levels a `-max_len` 4096 input can nest, so any
/// scan hole that admits over-limit input crashes here.
const DECODE_STACK: usize = 512 * 1024;

/// Containers on the deepest path (arrays, maps, tags; empty containers
/// count one level — the `CBOR_MAX_DEPTH` contract).
fn depth(cbor: &CBOR) -> usize {
    let mut deepest = 0_usize;
    let mut stack: Vec<(&CBOR, usize)> = vec![(cbor, 1)];
    while let Some((node, level)) = stack.pop() {
        match node.as_case() {
            CBORCase::Array(items) => {
                deepest = deepest.max(level);
                stack.extend(items.iter().map(|item| (item, level + 1)));
            }
            CBORCase::Map(map) => {
                deepest = deepest.max(level);
                stack.extend(
                    map.iter()
                        .flat_map(|(k, v)| [(k, level + 1), (v, level + 1)]),
                );
            }
            CBORCase::Tagged(_tag, inner) => {
                deepest = deepest.max(level);
                stack.push((inner, level + 1));
            }
            _ => {}
        }
    }
    deepest
}

fuzz_target!(|data: &[u8]| {
    let input = data.to_vec();
    // Decode, compare, and drop on one bounded stack: an overflow in the
    // thread is a hard crash, which is the signal that the scan failed.
    let joined = std::thread::Builder::new()
        .stack_size(DECODE_STACK)
        .spawn(move || {
            let ur_type = UrType::new("x").expect("static type literal");
            match Ur::from_cbor_data(ur_type, &input) {
                Err(e) if e.kind() == ErrorKind::ResourceLimit => {
                    assert_eq!(
                        e.limit(),
                        Some(Limit::CborDepth),
                        "ResourceLimit from the depth scan must be cborDepth"
                    );
                }
                typed => {
                    // The scan accepted these bytes, so `dcbor` saw them too;
                    // the two decoders must reach the same verdict.
                    match (typed, CBOR::try_from_data(&input)) {
                        (Ok(ur), Ok(cbor)) => {
                            assert_eq!(ur.cbor(), &cbor, "typed decode must equal dcbor");
                            assert!(
                                depth(&cbor) <= bcur::typed::CBOR_MAX_DEPTH,
                                "accepted input must nest within CBOR_MAX_DEPTH"
                            );
                        }
                        (Err(e), Err(_)) => {
                            assert_eq!(
                                e.kind(),
                                ErrorKind::CborDecode,
                                "non-limit typed failure must be CborDecode"
                            );
                        }
                        (Ok(_), Err(_)) => {
                            panic!("typed accepted bytes that dcbor rejected")
                        }
                        (Err(_), Ok(_)) => {
                            panic!("typed rejected bytes that dcbor accepted")
                        }
                    }
                }
            }
        })
        .expect("spawn the decode thread")
        .join();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
});
