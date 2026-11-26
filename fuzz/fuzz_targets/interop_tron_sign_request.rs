#![no_main]

use bcur_registry::interop::{OneKeyTronSignRequest, TronSignRequest};
use dcbor::{CBOR, CBORCase, CBORTaggedDecodable, CBORTaggedEncodable};
use libfuzzer_sys::fuzz_target;

bcur_fuzz::dcbor_asan_options!();

fn check<T>(cbor: &CBOR)
where
    T: TryFrom<CBOR> + CBORTaggedEncodable,
    T::Error: core::fmt::Debug,
{
    if let Ok(v) = T::try_from(cbor.clone()) {
        let tagged = v.tagged_cbor();
        let back = T::try_from(tagged.clone()).expect("re-decode of own output must succeed");
        assert_eq!(
            tagged.to_cbor_data(),
            back.tagged_cbor().to_cbor_data(),
            "re-encode must be byte-stable"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(cbor) = CBOR::try_from_data(data.to_vec()) else {
        return;
    };
    // Both dialect readers: Keystone layout and OneKey layout.
    check::<TronSignRequest>(&cbor);
    check::<OneKeyTronSignRequest>(&cbor);
    // Untagged bodies decode through both readers regardless of the outer
    // tag, so exercise that path too when the input is tagged.
    if let CBORCase::Tagged(_, inner) = cbor.as_case() {
        let _ = TronSignRequest::from_untagged_cbor(inner.clone());
        let _ = OneKeyTronSignRequest::from_untagged_cbor(inner.clone());
    }
});
