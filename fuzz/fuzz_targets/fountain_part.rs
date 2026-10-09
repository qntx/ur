#![no_main]

use bcur::DecoderLimits;
use bcur::fountain::Part;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = DecoderLimits::default();
    if let Ok(part) = Part::from_cbor(data, &limits) {
        let again = Part::from_cbor(&part.to_cbor(), &limits)
            .expect("shortest-form part must re-decode");
        assert_eq!(part, again, "from_cbor(to_cbor(p)) must equal p");
    }
});
