#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration targets link full dev-deps; failures abort the test"
)]

//! Constructor validation, Debug redaction, digests frozen from the TypeScript
//! implementation, tag registration, and wire-shape checks.

use std::num::NonZeroU32;

use bcur_registry::{
    ChildIndex, CoinInfo, DerivedKey, Error, ErrorKind, HdKey, Keypath, MasterKey, PathComponent,
    Psbt, Seed, SskrHeader, SskrShare, coin_type, network, register_tags, register_tags_in, tags,
};
use dcbor::{
    CBOR, CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, TagsStore, TagsStoreTrait,
};

fn err(result: Result<impl Sized, Error>) -> Error {
    result.err().unwrap()
}

// ---- error.rs ----

#[test]
fn error_display_kind_field_and_dcbor_mapping() {
    let e = Error::new(ErrorKind::InvalidLength, "payload");
    assert_eq!(e.kind(), ErrorKind::InvalidLength);
    assert_eq!(e.field(), "payload");
    assert_eq!(e.to_string(), "payload: invalid length");
    assert!(matches!(dcbor::Error::from(e), dcbor::Error::OutOfRange));

    assert!(matches!(
        dcbor::Error::from(Error::new(ErrorKind::InvalidValue, "bytes")),
        dcbor::Error::WrongType
    ));
    assert!(matches!(
        dcbor::Error::from(Error::new(ErrorKind::OutOfRange, "index")),
        dcbor::Error::OutOfRange
    ));
    assert!(matches!(
        dcbor::Error::from(Error::new(ErrorKind::InvalidPlaceholder, "key")),
        dcbor::Error::OutOfRange
    ));
}

// ---- tags.rs ----

#[test]
fn tag_constants_values_and_names() {
    assert_eq!(tags::SEED.value(), 40_300);
    assert_eq!(tags::SEED.name().unwrap(), "seed");
    assert_eq!(tags::COIN_INFO.name().unwrap(), "coin-info");
    assert_eq!(tags::ACCOUNT_DESCRIPTOR.value(), 40_311);
    assert_eq!(tags::CRYPTO_ADDRESS.value(), 307);
    assert_eq!(tags::CRYPTO_ADDRESS.name().unwrap(), "crypto-address");
    assert_eq!(tags::CRYPTO_PSBT.value(), 310);
    assert_eq!(tags::SH.value(), 400);
    assert_eq!(tags::TR.value(), 409);
    assert_eq!(tags::COSIGNER.value(), 410);
}

#[test]
fn register_tags_inserts_all_names() {
    let mut store = TagsStore::new([]);
    register_tags_in(&mut store);
    assert_eq!(store.name_for_value(40_300), "seed");
    assert_eq!(store.name_for_value(307), "crypto-address");
    assert_eq!(store.tag_for_name("cosigner").unwrap().value(), 410);

    register_tags();
    let diag = Seed::new(vec![0xC7; 16])
        .unwrap()
        .tagged_cbor()
        .diagnostic_annotated();
    assert!(diag.contains("seed"), "{diag}");
}

// ---- coin-info ----

#[test]
fn coin_info_ranges_and_defaults() {
    let e = err(CoinInfo::new(0x8000_0000, 0));
    assert_eq!((e.kind(), e.field()), (ErrorKind::OutOfRange, "coin_type"));

    let info = CoinInfo::default();
    assert_eq!(info.coin_type(), coin_type::BTC);
    assert_eq!(info.network(), network::MAINNET);
    // Defaults omitted on write: an all-default CoinInfo encodes as `{}`.
    assert_eq!(info.untagged_cbor().to_cbor_data(), vec![0xa0]);

    let tagged_tags = CoinInfo::cbor_tags();
    assert_eq!(tagged_tags[0].value(), 40_305);
    assert_eq!(tagged_tags[1].value(), 305);
}

// ---- keypath ----

#[test]
fn keypath_rejections() {
    assert_eq!(
        err(Keypath::new(vec![], None, None)).kind(),
        ErrorKind::InvalidValue
    );
    assert_eq!(
        err(Keypath::new(
            vec![PathComponent::Index {
                index: 0x8000_0000,
                hardened: false
            }],
            None,
            None,
        ))
        .field(),
        "index"
    );
    assert_eq!(
        err(Keypath::new(
            vec![PathComponent::Range {
                low: 5,
                high: 5,
                hardened: false
            }],
            None,
            None,
        ))
        .field(),
        "range"
    );
}

#[test]
fn keypath_components_wire_roundtrip() {
    let path = Keypath::new(
        vec![
            PathComponent::Index {
                index: 44,
                hardened: true,
            },
            PathComponent::Wildcard { hardened: false },
            PathComponent::Range {
                low: 0,
                high: 100,
                hardened: true,
            },
            PathComponent::Pair {
                external: ChildIndex {
                    index: 0,
                    hardened: false,
                },
                internal: ChildIndex {
                    index: 1,
                    hardened: false,
                },
            },
        ],
        NonZeroU32::new(0x73c5_da0a),
        Some(4),
    )
    .unwrap();

    let cbor = path.untagged_cbor();
    let CBORCase::Map(map) = cbor.as_case() else {
        panic!("keypath must be a map")
    };
    // Pair is a single 4-tuple item (no trailing hardened flag).
    let items = map.get::<i32, CBOR>(1).unwrap().try_into_array().unwrap();
    let CBORCase::Array(pair) = items.last().unwrap().as_case() else {
        panic!("last component must be the pair array")
    };
    assert_eq!(pair.len(), 4);
    assert_eq!(items.len(), 7); // 2 + 2 + 2 + 1

    let decoded = Keypath::from_untagged_cbor(cbor.clone()).unwrap();
    assert_eq!(decoded, path);
    // Tagged round trip accepts the v2 tag.
    let retagged = Keypath::from_tagged_cbor(path.tagged_cbor()).unwrap();
    assert_eq!(retagged, path);
}

#[test]
fn keypath_v1_tag_reads() {
    // crypto-keypath (304) tagged body: {1: [44, true]}
    let body = CBOR::try_from_data(hex::decode("a10182182cf5").unwrap()).unwrap();
    let tagged = CBOR::from(CBORCase::Tagged(
        dcbor::Tag::with_static_name(304, "crypto-keypath"),
        body,
    ));
    let path = Keypath::from_tagged_cbor(tagged).unwrap();
    assert_eq!(
        path.components(),
        &[PathComponent::Index {
            index: 44,
            hardened: true
        }]
    );
}

// ---- seed ----

#[test]
fn seed_payload_range_and_digest() {
    assert_eq!(err(Seed::new(Vec::new())).field(), "payload");
    assert_eq!(err(Seed::new(vec![0; 65])).field(), "payload");
    assert_eq!(err(Seed::new(vec![0; 65])).kind(), ErrorKind::InvalidLength);

    let seed = Seed::new(vec![0xC7; 16]).unwrap();
    // Frozen from TypeScript seedDigest (SHA-256 of the raw payload).
    assert_eq!(
        hex::encode(seed.digest()),
        "780962710c098d5d9d12cad1c04310aa50e55db30b8f77189230c82302e9a951"
    );
}

#[test]
fn seed_date_writes_tag1() {
    let seed = Seed::new(vec![0xC7; 16])
        .unwrap()
        .with_creation_date(dcbor::Date::from_timestamp(1_605_566_400.0));
    let data = seed.untagged_cbor().to_cbor_data();
    assert!(
        data.windows(3).any(|w| w == [0xc1, 0x1a, 0x5f]),
        "{}",
        hex::encode(&data)
    );
}

// ---- psbt ----

#[test]
fn psbt_magic_and_length() {
    assert_eq!(
        err(Psbt::new(vec![0x70; 4])).kind(),
        ErrorKind::InvalidLength
    );
    let e = err(Psbt::new(b"xxxxxx".to_vec()));
    assert_eq!((e.kind(), e.field()), (ErrorKind::InvalidValue, "bytes"));

    let psbt = Psbt::new(b"psbt\xffrest".to_vec()).unwrap();
    assert_eq!(psbt.as_bytes(), b"psbt\xffrest");
    assert_eq!(psbt.into_bytes(), b"psbt\xffrest");
}

// ---- sskr ----

const fn header() -> SskrHeader {
    SskrHeader {
        identifier: 0x1234,
        group_threshold: 2,
        group_count: 3,
        group_index: 0,
        member_threshold: 2,
        member_index: 4,
    }
}

#[test]
fn sskr_header_ranges() {
    let mut h = header();
    h.group_threshold = 17;
    assert_eq!(err(SskrShare::new(h, vec![1])).field(), "group_threshold");
    h = header();
    h.group_index = 3;
    assert_eq!(err(SskrShare::new(h, vec![1])).field(), "group_index");
    h = header();
    h.member_index = 16;
    assert_eq!(err(SskrShare::new(h, vec![1])).field(), "member_index");

    let share = SskrShare::new(header(), vec![0xAA; 8]).unwrap();
    assert_eq!(share.header(), header());
    assert_eq!(share.share_value(), &[0xAA; 8]);

    // Packed wire form: identifier big-endian, nibbles store N-1.
    let body = share.untagged_cbor().to_cbor_data();
    assert_eq!(hex::encode(&body), "4d1234120104aaaaaaaaaaaaaaaa");
}

// ---- hdkey ----

fn pub_key_data() -> [u8; 33] {
    let mut data = [0u8; 33];
    data[0] = 3;
    for (i, b) in data.iter_mut().enumerate().skip(1) {
        *b = u8::try_from(i).unwrap();
    }
    data
}

fn priv_key_data() -> [u8; 33] {
    let mut data = pub_key_data();
    data[0] = 0;
    data
}

fn chain_code() -> [u8; 32] {
    let mut code = [0u8; 32];
    for (i, b) in code.iter_mut().enumerate() {
        *b = 0xa0 + u8::try_from(i).unwrap();
    }
    code
}

#[test]
fn hdkey_private_prefix() {
    let e = err(DerivedKey::new_private(pub_key_data()));
    assert_eq!((e.kind(), e.field()), (ErrorKind::OutOfRange, "key_data"));
    assert!(DerivedKey::new_private(priv_key_data()).is_ok());
}

#[test]
fn hdkey_master_wire_shape() {
    let key = HdKey::Master(MasterKey::new(priv_key_data(), chain_code()));
    let cbor = key.untagged_cbor();
    let CBORCase::Map(map) = cbor.as_case() else {
        panic!("master must be a map")
    };
    assert_eq!(map.len(), 3);
    assert!(map.get::<i32, CBOR>(1).unwrap().try_into_bool().unwrap());
    assert_eq!(
        map.get::<i32, CBOR>(3)
            .unwrap()
            .as_byte_string()
            .unwrap()
            .len(),
        33
    );
    assert_eq!(
        map.get::<i32, CBOR>(4)
            .unwrap()
            .as_byte_string()
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn hdkey_derived_write_rules() {
    // Public: key 2 omitted entirely; empty name/note omitted.
    let key = DerivedKey::new_public(pub_key_data()).with_name("");
    let cbor = HdKey::from(key).untagged_cbor();
    let CBORCase::Map(map) = cbor.as_case() else {
        panic!("derived must be a map")
    };
    assert!(map.get::<i32, CBOR>(2).is_none());
    assert!(map.get::<i32, CBOR>(9).is_none());

    // Private: key 2 = true.
    let private = DerivedKey::new_private(priv_key_data())
        .unwrap()
        .with_chain_code(chain_code())
        .with_parent_fingerprint(NonZeroU32::new(0x73c5_da0a).unwrap())
        .with_name("account")
        .with_note("note");
    let private_cbor = HdKey::from(private).untagged_cbor();
    let CBORCase::Map(private_map) = private_cbor.as_case() else {
        panic!("derived must be a map")
    };
    assert!(
        private_map
            .get::<i32, CBOR>(2)
            .unwrap()
            .try_into_bool()
            .unwrap()
    );
    assert_eq!(private_map.len(), 6);
}

#[test]
fn hdkey_digests_frozen_from_ts() {
    // Frozen values computed via packages/ur/src/registry/digest.ts.
    let pub_only = HdKey::Derived(DerivedKey::new_public(pub_key_data()));
    assert_eq!(
        hex::encode(pub_only.digest_source()),
        "845821030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20f60000"
    );
    assert_eq!(
        hex::encode(pub_only.digest()),
        "537cf8827a16fd960bf8b58898cc87d622f9985432d228988a69c4f337b90312"
    );

    let full = HdKey::Derived(
        DerivedKey::new_private(priv_key_data())
            .unwrap()
            .with_chain_code(chain_code())
            .with_use_info(CoinInfo::new(coin_type::ETH, network::BTC_TESTNET).unwrap()),
    );
    assert_eq!(
        hex::encode(full.digest_source()),
        "845821000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f205820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf183c01"
    );
    assert_eq!(
        hex::encode(full.digest()),
        "36e61629fabf20a34c31ff3645e46a9235d4f5c99799cb0067ffd8b899984b10"
    );

    let master = HdKey::Master(MasterKey::new(priv_key_data(), chain_code()));
    assert_eq!(
        hex::encode(master.digest_source()),
        "845821000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f205820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000"
    );
}

// ---- Debug redaction ----

#[test]
fn debug_redacts_secrets() {
    let seed_debug = format!("{:?}", Seed::new(vec![0xC7; 16]).unwrap());
    assert!(
        seed_debug.contains("[REDACTED]") && !seed_debug.contains("199"),
        "{seed_debug}"
    );

    let master_debug = format!("{:?}", MasterKey::new(priv_key_data(), chain_code()));
    assert!(
        master_debug.matches("[REDACTED]").count() == 2,
        "{master_debug}"
    );

    let private_debug = format!("{:?}", DerivedKey::new_private(priv_key_data()).unwrap());
    assert!(private_debug.contains("[REDACTED]"), "{private_debug}");

    let public_debug = format!("{:?}", DerivedKey::new_public(pub_key_data()));
    assert!(!public_debug.contains("[REDACTED]"), "{public_debug}");

    let share_debug = format!("{:?}", SskrShare::new(header(), vec![0xAA; 8]).unwrap());
    assert!(
        share_debug.contains("[REDACTED]") && share_debug.contains("identifier: 4660"),
        "{share_debug}"
    );
}
