#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    reason = "integration targets link full dev-deps; failures abort the test"
)]

//! Constructor validation, domain-type invariants, `Display`/`FromStr`,
//! Debug redaction, digest literals, tag registration, wire shapes, and
//! `Send + Sync`.

use bcur_registry::{
    AccountDescriptor, Address, AddressType, ChildNumber, ChildRange, CoinInfo, CoinType, Curve,
    DerivedKey, DescriptorKey, EcKey, Error, Fingerprint, HdKey, Index, Keypath, MasterKey,
    Network, OutputDescriptor, PathComponent, Psbt, Seed, SskrHeader, SskrShare, register_tags,
    register_tags_in, tags,
};
use dcbor::{
    CBOR, CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, TagsStore, TagsStoreTrait,
};

fn err(result: Result<impl Sized, Error>) -> Error {
    result.err().unwrap()
}

// ---- error.rs ----

#[test]
fn error_display_source_and_dcbor_mapping() {
    use core::error::Error as _;

    let e = Error::InvalidLength {
        field: "payload",
        len: 65,
    };
    assert_eq!(
        e.to_string(),
        "payload length 65 is outside the allowed range"
    );
    assert!(e.source().is_none());

    let cbor = Error::Cbor(dcbor::Error::WrongType);
    assert!(cbor.source().is_some());

    // Error -> dcbor: Cbor unwraps; every other variant becomes Custom.
    assert!(matches!(
        dcbor::Error::from(Error::Cbor(dcbor::Error::MissingMapKey)),
        dcbor::Error::MissingMapKey
    ));
    assert!(matches!(
        dcbor::Error::from(e),
        dcbor::Error::Custom(m) if m == "payload length 65 is outside the allowed range"
    ));
    // dcbor -> Error is always Cbor.
    assert!(matches!(
        Error::from(dcbor::Error::OutOfRange),
        Error::Cbor(dcbor::Error::OutOfRange)
    ));

    for error in [
        Error::UnknownKey { key: 42 },
        Error::MissingKey { key: 7 },
        Error::UnexpectedTag { tag: 999 },
        Error::OutOfRange { field: "index" },
        Error::Invalid {
            field: "fingerprint",
            reason: "expected 8 hexadecimal digits",
        },
        Error::Placeholders,
        Error::UnsupportedScript { tag: 401 },
    ] {
        let text = error.to_string();
        assert_eq!(text, text.to_lowercase(), "{text}");
        assert!(!text.ends_with('.'), "{text}");
    }
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

// ---- domain types ----

#[test]
fn fingerprint_display_fromstr_and_bytes() {
    let f = Fingerprint::from([0xd9, 0x73, 0xbe, 0xe1]);
    assert_eq!(f.to_string(), "d973bee1");
    assert_eq!(f.to_bytes(), [0xd9, 0x73, 0xbe, 0xe1]);
    assert_eq!("d973bee1".parse::<Fingerprint>().unwrap(), f);
    assert_eq!("D973BEE1".parse::<Fingerprint>().unwrap(), f);
    for bad in ["", "d973bee", "d973bee11", "zz73bee1"] {
        assert!(matches!(
            bad.parse::<Fingerprint>(),
            Err(Error::Invalid {
                field: "fingerprint",
                ..
            })
        ));
    }
}

#[test]
fn index_bounds_and_display() {
    assert_eq!(Index::new(0x7fff_ffff).unwrap().get(), 0x7fff_ffff);
    assert_eq!(Index::new(0x7fff_ffff).unwrap().to_string(), "2147483647");
    assert!(matches!(
        Index::new(0x8000_0000),
        Err(Error::OutOfRange { field: "index" })
    ));
    assert!(Index::try_from(44_u32).is_ok());
    assert!(Index::try_from(0x8000_0000_u32).is_err());
}

#[test]
fn child_number_display() {
    assert_eq!(ChildNumber::Normal(Index::new(0).unwrap()).to_string(), "0");
    assert_eq!(
        ChildNumber::Hardened(Index::new(84).unwrap()).to_string(),
        "84'"
    );
    assert!(ChildNumber::Hardened(Index::new(1).unwrap()).is_hardened());
    assert!(!ChildNumber::Normal(Index::new(1).unwrap()).is_hardened());
}

#[test]
fn child_range_bounds() {
    let range = ChildRange::new(Index::new(0).unwrap(), Index::new(100).unwrap(), true).unwrap();
    assert_eq!(range.start().get(), 0);
    assert_eq!(range.end().get(), 100);
    assert!(range.is_hardened());
    assert!(matches!(
        ChildRange::new(Index::new(5).unwrap(), Index::new(5).unwrap(), false),
        Err(Error::Invalid { field: "range", .. })
    ));
}

#[test]
fn coin_type_and_network() {
    assert_eq!(CoinType::BTC.get(), 0);
    assert_eq!(CoinType::ETH.get(), 0x3c);
    assert!(matches!(
        CoinType::new(0x8000_0000),
        Err(Error::OutOfRange { field: "coin_type" })
    ));
    assert_eq!(CoinType::default(), CoinType::BTC);
    assert_eq!(Network::MAINNET.get(), 0);
    assert_eq!(Network::TESTNET.get(), 1);
    assert_eq!(Network::from(-1).get(), -1);
    assert_eq!(Network::default(), Network::MAINNET);
}

#[test]
fn curve_mapping() {
    assert_eq!(Curve::from(0), Curve::Secp256k1);
    assert_eq!(Curve::from(u64::MAX), Curve::Other(u64::MAX));
    assert_eq!(u64::from(Curve::Secp256k1), 0);
    assert_eq!(u64::from(Curve::Other(7)), 7);
    assert_eq!(Curve::default(), Curve::Secp256k1);
}

// ---- coin-info ----

#[test]
fn coin_info_defaults() {
    let info = CoinInfo::default();
    assert_eq!(info.coin_type(), CoinType::BTC);
    assert_eq!(info.network(), Network::MAINNET);
    assert_eq!(info, CoinInfo::BTC_MAINNET);
    // Defaults omitted on write: an all-default CoinInfo encodes as `{}`.
    assert_eq!(info.untagged_cbor().to_cbor_data(), vec![0xa0]);

    let tagged_tags = CoinInfo::cbor_tags();
    assert_eq!(tagged_tags[0].value(), 40_305);
    assert_eq!(tagged_tags[1].value(), 305);

    let eth_test = CoinInfo::new(CoinType::ETH, Network::TESTNET);
    let cbor = hex::encode(eth_test.untagged_cbor().to_cbor_data());
    assert_eq!(cbor, "a201183c0201");
}

// ---- keypath ----

#[test]
fn keypath_rejections() {
    // Fully vacuous keypath is rejected.
    assert!(matches!(
        Keypath::new(Vec::new(), None, None),
        Err(Error::Invalid {
            field: "keypath",
            ..
        })
    ));
    // A zero source fingerprint is rejected.
    assert!(matches!(
        Keypath::new(Vec::new(), Some(Fingerprint::from([0; 4])), None),
        Err(Error::OutOfRange {
            field: "source_fingerprint"
        })
    ));
    // A non-empty depth-only keypath is fine.
    assert!(Keypath::new(Vec::new(), None, Some(4)).is_ok());
}

#[test]
fn keypath_components_wire_roundtrip() {
    let index = |v: u32| Index::new(v).unwrap();
    let path = Keypath::new(
        vec![
            PathComponent::Child(ChildNumber::Hardened(index(44))),
            PathComponent::Wildcard { hardened: false },
            PathComponent::Range(ChildRange::new(index(0), index(100), true).unwrap()),
            PathComponent::Pair {
                external: ChildNumber::Normal(index(0)),
                internal: ChildNumber::Normal(index(1)),
            },
        ],
        Some(Fingerprint::from(0x73c5_da0a_u32.to_be_bytes())),
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
        &[PathComponent::Child(ChildNumber::Hardened(
            Index::new(44).unwrap()
        ))]
    );

    // Untagged values and foreign tags are rejected by TryFrom.
    assert!(matches!(
        Keypath::try_from(CBOR::from(1_u8)),
        Err(Error::Cbor(dcbor::Error::WrongType))
    ));
    assert!(matches!(
        Keypath::try_from(CBOR::to_tagged_value(40_309, CBOR::from(1_u8))),
        Err(Error::UnexpectedTag { tag: 40_309 })
    ));
}

// ---- seed ----

#[test]
fn seed_payload_range_and_digest() {
    assert!(matches!(
        Seed::new(Vec::new()),
        Err(Error::InvalidLength {
            field: "payload",
            len: 0
        })
    ));
    assert!(matches!(
        Seed::new(vec![0; 65]),
        Err(Error::InvalidLength {
            field: "payload",
            len: 65
        })
    ));

    let seed = Seed::new(vec![0xC7; 16]).unwrap();
    assert_eq!(<Seed as AsRef<[u8]>>::as_ref(&seed), &[0xC7; 16]);
    // Frozen literal: SHA-256 of the raw payload.
    assert_eq!(
        hex::encode(seed.digest()),
        "780962710c098d5d9d12cad1c04310aa50e55db30b8f77189230c82302e9a951"
    );
}

#[test]
fn seed_date_writes_tag1_and_empty_text_normalizes() {
    let seed = Seed::new(vec![0xC7; 16])
        .unwrap()
        .with_creation_date(dcbor::Date::from_timestamp(1_605_566_400.0))
        .with_name("")
        .with_note("");
    assert!(seed.name().is_none() && seed.note().is_none());
    let data = seed.untagged_cbor().to_cbor_data();
    assert!(
        data.windows(3).any(|w| w == [0xc1, 0x1a, 0x5f]),
        "{}",
        hex::encode(&data)
    );
    // An empty name/note on the wire decodes to None.
    let with_empty = Seed::try_from(CBOR::to_tagged_value(
        40_300,
        Seed::new(vec![0xC7; 16])
            .unwrap()
            .with_name("")
            .untagged_cbor(),
    ))
    .unwrap();
    assert!(with_empty.name().is_none());
}

// ---- psbt ----

#[test]
fn psbt_magic_and_length() {
    assert!(matches!(
        Psbt::new(vec![0x70; 4]),
        Err(Error::InvalidLength {
            field: "bytes",
            len: 4
        })
    ));
    assert!(matches!(
        Psbt::new(b"xxxxxx".to_vec()),
        Err(Error::Invalid { field: "bytes", .. })
    ));

    let psbt = Psbt::new(b"psbt\xffrest".to_vec()).unwrap();
    assert_eq!(psbt.as_ref(), b"psbt\xffrest");
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
    assert!(matches!(
        SskrShare::new(h, vec![1]),
        Err(Error::OutOfRange {
            field: "group_threshold"
        })
    ));
    h = header();
    h.group_index = 3;
    assert!(matches!(
        SskrShare::new(h, vec![1]),
        Err(Error::OutOfRange {
            field: "group_index"
        })
    ));
    h = header();
    h.member_index = 16;
    assert!(matches!(
        SskrShare::new(h, vec![1]),
        Err(Error::OutOfRange {
            field: "member_index"
        })
    ));
    h = header();
    h.group_threshold = 4;
    assert!(matches!(
        SskrShare::new(h, vec![1]),
        Err(Error::OutOfRange {
            field: "group_threshold"
        })
    ));

    let share = SskrShare::new(header(), vec![0xAA; 8]).unwrap();
    assert_eq!(share.header(), header());
    assert_eq!(share.value(), &[0xAA; 8]);

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
    assert!(matches!(
        DerivedKey::private(pub_key_data()),
        Err(Error::OutOfRange { field: "key_data" })
    ));
    assert!(DerivedKey::private(priv_key_data()).is_ok());

    // A master key is always private (BCR-2020-007): the 0x00 prefix is
    // required.
    assert!(matches!(
        MasterKey::new(pub_key_data(), chain_code()),
        Err(Error::OutOfRange { field: "key_data" })
    ));
}

#[test]
fn hdkey_master_wire_shape() {
    let key = HdKey::Master(MasterKey::new(priv_key_data(), chain_code()).unwrap());
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
    assert!(key.is_master() && key.is_private());
    assert!(key.name().is_none() && key.origin().is_none());
}

#[test]
fn hdkey_derived_write_rules() {
    // Public: key 2 omitted entirely; empty name/note normalize to absent.
    let key = DerivedKey::public(pub_key_data()).with_name("");
    assert!(key.name().is_none());
    let cbor = HdKey::from(key).untagged_cbor();
    let CBORCase::Map(map) = cbor.as_case() else {
        panic!("derived must be a map")
    };
    assert!(map.get::<i32, CBOR>(2).is_none());
    assert!(map.get::<i32, CBOR>(9).is_none());

    // Private: key 2 = true.
    let private = DerivedKey::private(priv_key_data())
        .unwrap()
        .with_chain_code(chain_code())
        .with_parent_fingerprint(Fingerprint::from(0x73c5_da0a_u32.to_be_bytes()))
        .unwrap()
        .with_name("account")
        .with_note("note");
    assert_eq!(private.name(), Some("account"));
    assert_eq!(
        private.parent_fingerprint().unwrap().to_string(),
        "73c5da0a"
    );
    // A zero parent fingerprint is rejected.
    assert!(matches!(
        DerivedKey::public(pub_key_data()).with_parent_fingerprint(Fingerprint::from([0; 4])),
        Err(Error::OutOfRange {
            field: "parent_fingerprint"
        })
    ));
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
fn hdkey_digests_frozen() {
    // Frozen literals for the canonical digest bytes.
    let pub_only = HdKey::Derived(DerivedKey::public(pub_key_data()));
    assert_eq!(
        hex::encode(pub_only.digest_source()),
        "845821030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20f60000"
    );
    assert_eq!(
        hex::encode(pub_only.digest()),
        "537cf8827a16fd960bf8b58898cc87d622f9985432d228988a69c4f337b90312"
    );

    let full = HdKey::Derived(
        DerivedKey::private(priv_key_data())
            .unwrap()
            .with_chain_code(chain_code())
            .with_use_info(CoinInfo::new(CoinType::ETH, Network::TESTNET)),
    );
    assert_eq!(
        hex::encode(full.digest_source()),
        "845821000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f205820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf183c01"
    );
    assert_eq!(
        hex::encode(full.digest()),
        "36e61629fabf20a34c31ff3645e46a9235d4f5c99799cb0067ffd8b899984b10"
    );

    let master = HdKey::Master(MasterKey::new(priv_key_data(), chain_code()).unwrap());
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

    let master_debug = format!(
        "{:?}",
        MasterKey::new(priv_key_data(), chain_code()).unwrap()
    );
    assert!(
        master_debug.matches("[REDACTED]").count() == 2,
        "{master_debug}"
    );

    let private_debug = format!("{:?}", DerivedKey::private(priv_key_data()).unwrap());
    assert!(private_debug.contains("[REDACTED]"), "{private_debug}");

    let public_debug = format!("{:?}", DerivedKey::public(pub_key_data()));
    assert!(!public_debug.contains("[REDACTED]"), "{public_debug}");

    let share_debug = format!("{:?}", SskrShare::new(header(), vec![0xAA; 8]).unwrap());
    assert!(
        share_debug.contains("[REDACTED]") && share_debug.contains("identifier: 4660"),
        "{share_debug}"
    );
}

// ---- eckey ----

fn pub_eckey() -> EcKey {
    let mut data = vec![0x02];
    data.extend_from_slice(&[0xAB; 32]);
    EcKey::public(Curve::Secp256k1, data).unwrap()
}

#[test]
fn eckey_validation() {
    // secp256k1 private must be exactly 32 bytes.
    assert!(matches!(
        EcKey::private(Curve::Secp256k1, vec![0; 31]),
        Err(Error::InvalidLength {
            field: "data",
            len: 31
        })
    ));
    // secp256k1 public must be 33 or 65 bytes.
    assert!(matches!(
        EcKey::public(Curve::Secp256k1, vec![0; 34]),
        Err(Error::InvalidLength {
            field: "data",
            len: 34
        })
    ));
    // Other curves only require non-empty data, and any u64 curve value is
    // accepted.
    assert!(matches!(
        EcKey::public(Curve::Other(1), Vec::new()),
        Err(Error::InvalidLength { field: "data", .. })
    ));
    assert!(EcKey::public(Curve::Other(1), vec![0; 4]).is_ok());
    assert!(EcKey::public(Curve::Other(u64::MAX), vec![0; 33]).is_ok());
}

#[test]
fn eckey_wire_rules() {
    // Defaults omitted: curve 0 and public write only key 3.
    let cbor = pub_eckey().untagged_cbor().to_cbor_data();
    assert_eq!(hex::encode(&cbor), format!("a103582102{}", "ab".repeat(32)));

    let private = EcKey::private(Curve::Secp256k1, vec![0x01; 32]).unwrap();
    let encoded = hex::encode(private.untagged_cbor().to_cbor_data());
    assert_eq!(encoded, format!("a202f5035820{}", "01".repeat(32)));

    // Non-default curve is written under key 1.
    let other = EcKey::public(Curve::Other(1), vec![0; 4]).unwrap();
    assert_eq!(
        hex::encode(other.untagged_cbor().to_cbor_data()),
        "a20101034400000000"
    );
    assert_eq!(other.curve(), Curve::Other(1));
    assert!(!other.is_private());
    assert_eq!(other.data(), &[0; 4]);

    // v1 tag reads, v2 tag writes.
    assert_eq!(EcKey::cbor_tags()[0].value(), 40_306);
    assert_eq!(EcKey::cbor_tags()[1].value(), 306);
}

#[test]
fn eckey_debug_redacts_private_only() {
    let private = EcKey::private(Curve::Secp256k1, vec![0x01; 32]).unwrap();
    let debug = format!("{private:?}");
    assert!(
        debug.contains("[REDACTED]") && !debug.contains("data: [1"),
        "{debug}"
    );
    let public = format!("{:?}", pub_eckey());
    assert!(!public.contains("[REDACTED]"), "{public}");
}

// ---- address ----

#[test]
fn address_validation_and_wire() {
    let hash = [0x77; 20];

    // Typed constructors are infallible.
    assert_eq!(
        Address::p2pkh(hash).address_type(),
        Some(AddressType::P2pkh)
    );
    assert_eq!(Address::p2sh(hash).address_type(), Some(AddressType::P2sh));
    assert_eq!(
        Address::p2wpkh(hash).address_type(),
        Some(AddressType::P2wpkh)
    );

    // Untyped payloads must be non-empty.
    assert!(matches!(
        Address::untyped(Vec::new()),
        Err(Error::InvalidLength {
            field: "data",
            len: 0
        })
    ));

    let bare = Address::untyped(vec![0x77; 20]).unwrap();
    assert!(bare.address_type().is_none() && bare.info().is_none());
    assert_eq!(bare.data(), &[0x77; 20]);
    assert_eq!(
        hex::encode(bare.untagged_cbor().to_cbor_data()),
        format!("a10354{}", "77".repeat(20))
    );

    let typed = Address::p2sh(hash);
    assert_eq!(
        hex::encode(typed.untagged_cbor().to_cbor_data()),
        format!("a202010354{}", "77".repeat(20))
    );

    // `with_info` writes a v2-tagged coin-info under key 1.
    let with_info = bare.with_info(CoinInfo::new(CoinType::ETH, Network::MAINNET));
    let cbor = hex::encode(with_info.untagged_cbor().to_cbor_data());
    assert!(cbor.starts_with("a201d99d71a101183c03"), "{cbor}");
    assert_eq!(with_info.info().unwrap().coin_type(), CoinType::ETH);

    // Wire index mapping 0/1/2.
    for (address, index) in [
        (Address::p2pkh(hash), "00"),
        (Address::p2sh(hash), "01"),
        (Address::p2wpkh(hash), "02"),
    ] {
        let hexed = hex::encode(address.untagged_cbor().to_cbor_data());
        assert!(hexed.contains(&format!("02{index}03")), "{hexed}");
    }

    // Decoding a typed payload of the wrong length is rejected.
    let bad = CBOR::to_tagged_value(
        40_307,
        CBOR::try_from_data(hex::decode(format!("a202010353{}", "00".repeat(19))).unwrap())
            .unwrap(),
    );
    assert!(matches!(
        Address::try_from(bad),
        Err(Error::InvalidLength { field: "data", .. })
    ));
}

// ---- output-descriptor ----

fn descriptor_key() -> DescriptorKey {
    DescriptorKey::from(pub_eckey())
}

fn placeholder_err(source: &str, keys: Vec<DescriptorKey>) -> Error {
    err(OutputDescriptor::new(source, keys))
}

#[test]
fn output_descriptor_placeholders() {
    let valid = OutputDescriptor::new("pk(@0)", vec![descriptor_key()]);
    assert!(valid.is_ok());

    // Every placeholder violation is Error::Placeholders.
    for source in [
        "pk(@1)",
        "pkh(x)",
        "pk(@01)",
        "pk(@99999999999999999999999999)",
    ] {
        assert!(
            matches!(
                placeholder_err(source, vec![descriptor_key()]),
                Error::Placeholders
            ),
            "{source}"
        );
    }
    // Duplicates and gaps leave the set smaller than the key count.
    for (source, n) in [("sh(@0,@0)", 2_usize), ("sh(@0,@2)", 3)] {
        assert!(matches!(
            placeholder_err(source, vec![descriptor_key(); n]),
            Error::Placeholders
        ));
    }
    // `@01` parses as the number 1.
    assert!(
        OutputDescriptor::new("multi(2,@1,@0)", vec![descriptor_key(), descriptor_key()]).is_ok()
    );

    // Placeholders maps to dcbor Custom through the error boundary.
    assert!(matches!(
        dcbor::Error::from(placeholder_err("pk(@1)", vec![descriptor_key()])),
        dcbor::Error::Custom(_)
    ));
}

#[test]
fn output_descriptor_wire_rules() {
    // No placeholders and no keys: key 2 omitted.
    let raw = OutputDescriptor::new("raw(deadbeef)", Vec::new()).unwrap();
    assert_eq!(
        hex::encode(raw.untagged_cbor().to_cbor_data()),
        "a1016d72617728646561646265656629"
    );

    // Empty name/note normalize to None and are omitted.
    let empty_named = raw.clone().with_name("").with_note("");
    assert!(empty_named.name().is_none() && empty_named.note().is_none());
    assert_eq!(empty_named.untagged_cbor(), raw.untagged_cbor());
    let named = raw.with_name("vault").with_note("cold");
    assert_eq!(named.name(), Some("vault"));
    assert_eq!(named.note(), Some("cold"));
    let hexed = hex::encode(named.untagged_cbor().to_cbor_data());
    assert!(hexed.contains("03657661756c74"), "{hexed}");

    assert_eq!(OutputDescriptor::cbor_tags()[0].value(), 40_308);
    assert_eq!(OutputDescriptor::cbor_tags()[1].value(), 308);
}

#[test]
fn output_descriptor_v1_nesting_rejection() {
    let key = EcKey::try_from(CBOR::to_tagged_value(40_306, pub_eckey().untagged_cbor()));
    assert!(key.is_ok());
    let pk = CBOR::to_tagged_value(
        402,
        CBOR::to_tagged_value(40_306, pub_eckey().untagged_cbor()),
    );
    let sh = CBOR::to_tagged_value(400, pk.clone());
    // sh() at top level converts.
    assert!(OutputDescriptor::from_untagged_cbor(sh.clone()).is_ok());
    // sh(sh(...)) and wsh(sh(...)) are rejected as unsupported scripts; the
    // decoder boundary turns that into dcbor::Error::Custom.
    assert!(matches!(
        OutputDescriptor::from_untagged_cbor(CBOR::to_tagged_value(400, sh.clone())).unwrap_err(),
        dcbor::Error::Custom(_)
    ));
    assert!(matches!(
        OutputDescriptor::from_untagged_cbor(CBOR::to_tagged_value(401, sh)).unwrap_err(),
        dcbor::Error::Custom(_)
    ));
    // TryFrom surfaces the registry error directly: sh(sh(...)) has a
    // nested sh(), which BIP-380 forbids.
    let nested = CBOR::to_tagged_value(400, CBOR::to_tagged_value(400, pk.clone()));
    assert!(matches!(
        OutputDescriptor::try_from(CBOR::to_tagged_value(40_308, nested)),
        Err(Error::UnsupportedScript { tag: 400 })
    ));
    // sh(wsh(pk(key))) is the one allowed nesting.
    let wsh = CBOR::to_tagged_value(401, pk);
    assert_eq!(
        OutputDescriptor::from_untagged_cbor(CBOR::to_tagged_value(400, wsh))
            .unwrap()
            .source(),
        "sh(wsh(pk(@0)))"
    );
    // A KeystoneHQ bare `sh(key)` restores `cosigner`.
    let bare_key =
        CBOR::to_tagged_value(400, CBOR::to_tagged_value(306, pub_eckey().untagged_cbor()));
    assert_eq!(
        OutputDescriptor::from_untagged_cbor(bare_key)
            .unwrap()
            .source(),
        "sh(cosigner(@0))"
    );
}

#[test]
fn descriptor_key_dispatch() {
    // From impls and the v2 tagged wire form.
    let key = DescriptorKey::from(pub_eckey());
    let cbor = CBOR::from(key.clone());
    let (tag, _) = cbor.as_tagged_value().unwrap();
    assert_eq!(tag.value(), 40_306);
    assert!(matches!(key, DescriptorKey::EcKey(_)));

    // Untagged values are Cbor(WrongType); foreign tags are UnexpectedTag.
    assert!(matches!(
        DescriptorKey::try_from(CBOR::from(1_u8)),
        Err(Error::Cbor(dcbor::Error::WrongType))
    ));
    assert!(matches!(
        DescriptorKey::try_from(CBOR::to_tagged_value(40_309, CBOR::from(1_u8))),
        Err(Error::UnexpectedTag { tag: 40_309 })
    ));
}

// ---- account-descriptor ----

#[test]
fn account_descriptor_wire() {
    let fingerprint = Fingerprint::from(0x37b5_eed4_u32.to_be_bytes());
    let descriptor = OutputDescriptor::new("pkh(@0)", vec![descriptor_key()]).unwrap();
    let account =
        AccountDescriptor::new(fingerprint, descriptor.clone()).with_output_descriptor(descriptor);
    assert_eq!(account.master_fingerprint(), fingerprint);
    assert_eq!(account.output_descriptors().len(), 2);
    assert_eq!(account.output_descriptors()[0].source(), "pkh(@0)");

    // A zero master fingerprint is allowed (BCR-2023-019).
    let zero = AccountDescriptor::new(
        Fingerprint::from([0; 4]),
        OutputDescriptor::new("pkh(@0)", vec![descriptor_key()]).unwrap(),
    );
    assert_eq!(zero.master_fingerprint(), Fingerprint::from([0; 4]));

    let hexed = hex::encode(account.untagged_cbor().to_cbor_data());
    // Entries are v2-tagged (40308 = 0x9d74) output-descriptors.
    assert!(hexed.contains("d99d74"), "{hexed}");
    assert_eq!(AccountDescriptor::cbor_tags()[0].value(), 40_311);
    assert_eq!(AccountDescriptor::cbor_tags()[1].value(), 311);
}

// ---- Send + Sync ----

#[test]
fn public_types_are_send_and_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<Error>();
    assert::<Fingerprint>();
    assert::<Index>();
    assert::<ChildNumber>();
    assert::<ChildRange>();
    assert::<PathComponent>();
    assert::<CoinType>();
    assert::<Network>();
    assert::<Curve>();
    assert::<AddressType>();
    assert::<CoinInfo>();
    assert::<Keypath>();
    assert::<HdKey>();
    assert::<MasterKey>();
    assert::<DerivedKey>();
    assert::<Seed>();
    assert::<EcKey>();
    assert::<Address>();
    assert::<DescriptorKey>();
    assert::<OutputDescriptor>();
    assert::<AccountDescriptor>();
    assert::<Psbt>();
    assert::<SskrHeader>();
    assert::<SskrShare>();
}
