#![no_main]

use bcur_registry::interop::BtcSignature;
use dcbor::{CBOR, CBORTaggedEncodable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(cbor) = CBOR::try_from_data(data.to_vec()) else {
        return;
    };
    if let Ok(v) = BtcSignature::try_from(cbor) {
        let tagged = v.tagged_cbor();
        let back = BtcSignature::try_from(tagged.clone()).expect("re-decode of own output must succeed");
        assert_eq!(
            tagged.to_cbor_data(),
            back.tagged_cbor().to_cbor_data(),
            "re-encode must be byte-stable"
        );
    }
});
