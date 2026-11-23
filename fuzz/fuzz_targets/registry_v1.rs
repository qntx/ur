#![no_main]

use bcur_registry::v1::{
    CryptoAccount, CryptoCoinInfo, CryptoHdKey, CryptoKeypath, CryptoOutput, CryptoPsbt,
};
use dcbor::{CBOR, CBORTaggedEncodable};
use libfuzzer_sys::fuzz_target;

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
    check::<CryptoPsbt>(&cbor);
    check::<CryptoHdKey>(&cbor);
    check::<CryptoKeypath>(&cbor);
    check::<CryptoCoinInfo>(&cbor);
    check::<CryptoOutput>(&cbor);
    check::<CryptoAccount>(&cbor);
});
