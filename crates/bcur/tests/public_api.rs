#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::similar_names,
    clippy::unwrap_used,
    dead_code,
    reason = "compile-time existence checks for the documented public API"
)]

//! Compile-time existence checks for every public item `docs/internal/api.mdx`
//! lists for L1–L3 (`#![warn(missing_docs)]` already guards doc coverage).
//! Items appear as function-pointer coercions — the check is that the paths,
//! signatures, and impls the API document promises actually exist.

use bcur::bytewords::{self, Style};
use bcur::fountain::{self, DecoderLimits, EncoderOptions};
use bcur::ur::{self, Decoded, ParsedUr};
use bcur::{Error, ErrorKind, Limit, Part, Progress, Received, State, UrType, ur_type};

// ---- L1 -----------------------------------------------------------------

const _: fn(&[u8], Style) -> String = bytewords::encode;
const _: fn(&str, Style) -> bcur::Result<Vec<u8>> = bytewords::decode;
const _: fn(&[u8], Style) -> String = bytewords::checksum;
const _: fn(usize, Style) -> usize = bytewords::encoded_len;
const _: fn([u8; 4]) -> String = bytewords::identifier;
const _: fn(&str) -> Option<&'static str> = bytewords::canonicalize;
const _: [&str; 256] = bytewords::WORDS;
const _: [&str; 256] = bytewords::MINIMALS;
const _: fn([u8; 4]) -> String = bcur::bytemoji::identifier;
const _: Style = Style::Standard;
const _: Style = Style::Uri;
const _: Style = Style::Minimal;

// ---- UrType --------------------------------------------------------------

const _: fn(&str) -> bcur::Result<UrType> = UrType::new;
const _: fn(&'static str) -> Option<UrType> = UrType::new_static;
const _: fn(&UrType) -> &str = UrType::as_str;
const _: fn(&UrType) -> &str = <UrType as AsRef<str>>::as_ref;
const _: fn(&UrType) -> String = <UrType as ToString>::to_string;
const _: fn(&UrType) -> UrType = <UrType as Clone>::clone;
const _: fn(&UrType, &UrType) -> bool = <UrType as PartialEq>::eq;
const _: fn(&UrType, &UrType) -> core::cmp::Ordering = <UrType as Ord>::cmp;
const _: fn(&str) -> bcur::Result<UrType> = <UrType as core::str::FromStr>::from_str;
const _: fn(&str) -> bcur::Result<UrType> = ur_type_try_str;
const _: fn(String) -> bcur::Result<UrType> = <UrType as TryFrom<String>>::try_from;

fn ur_type_try_str(s: &str) -> bcur::Result<UrType> {
    UrType::try_from(s)
}
const _: fn() = assert_traits::<UrType>;
const UR_TYPE: UrType = ur_type!("seed");

const fn assert_traits<T: Eq + Ord + core::hash::Hash + core::fmt::Display>() {}

// ---- ur::parse / encode / to_qr_string ------------------------------------

const _: fn(&str, &DecoderLimits) -> bcur::Result<ParsedUr> = ur::parse;
const _: fn(&UrType, &[u8]) -> String = ur::encode;
const _: fn(&str) -> String = ur::to_qr_string;

const fn parsed_ur_type(parsed: &ParsedUr) -> &UrType {
    match parsed {
        ParsedUr::Single { ur_type, .. } | ParsedUr::Multi { ur_type, .. } => ur_type,
    }
}

// ---- ur::Encoder -----------------------------------------------------------

const _: fn(UrType, Vec<u8>, EncoderOptions) -> bcur::Result<ur::Encoder> =
    ur_encoder_new::<Vec<u8>>;

fn ur_encoder_new<M: Into<Vec<u8>>>(
    ur_type: UrType,
    message: M,
    options: EncoderOptions,
) -> bcur::Result<ur::Encoder> {
    ur::Encoder::new(ur_type, message, options)
}
const _: fn(&ur::Encoder) -> &UrType = ur::Encoder::ur_type;
const _: fn(&ur::Encoder) -> u32 = ur::Encoder::fragment_count;
const _: fn(&ur::Encoder) -> bool = ur::Encoder::is_single_part;
const _: fn(&ur::Encoder) -> bool = ur::Encoder::is_complete;
const _: fn(&ur::Encoder) -> &[u32] = ur::Encoder::last_fragment_indexes;
const _: fn(&mut ur::Encoder) -> Option<String> = <ur::Encoder as Iterator>::next;
const _: fn() = assert_fused::<ur::Encoder>;

const fn assert_fused<T: Iterator + core::iter::FusedIterator>() {}

// ---- ur::Decoder / Decoded --------------------------------------------------

const _: fn(DecoderLimits) -> ur::Decoder = ur::Decoder::new;
const _: fn() -> ur::Decoder = <ur::Decoder as Default>::default;
const _: fn(ur::Decoder, [UrType; 1]) -> ur::Decoder = ur_decoder_accept::<[UrType; 1]>;

fn ur_decoder_accept<I: IntoIterator<Item = UrType>>(
    decoder: ur::Decoder,
    types: I,
) -> ur::Decoder {
    decoder.accept(types)
}
const _: fn(&mut ur::Decoder, &str) -> bcur::Result<Received> = ur::Decoder::receive;
const _: fn(&ur::Decoder) -> State<'_, Decoded> = ur::Decoder::state;
const _: fn(&ur::Decoder) -> Progress = ur::Decoder::progress;
const _: fn(&ur::Decoder) -> &[u32] = ur::Decoder::last_indexes;
const _: fn(ur::Decoder) -> bcur::Result<Decoded> = ur::Decoder::into_decoded;
const _: fn(&mut ur::Decoder) = ur::Decoder::reset;
const _: fn(&Decoded) -> &UrType = Decoded::ur_type;
const _: fn(&Decoded) -> &[u8] = Decoded::message;
const _: fn(Decoded) -> (UrType, Vec<u8>) = Decoded::into_parts;

// ---- fountain (L2, touched by R2 signatures) ---------------------------------

const _: fn(Vec<u8>, EncoderOptions) -> bcur::Result<fountain::Encoder> =
    fountain_encoder_new::<Vec<u8>>;

fn fountain_encoder_new<M: Into<Vec<u8>>>(
    message: M,
    options: EncoderOptions,
) -> bcur::Result<fountain::Encoder> {
    fountain::Encoder::new(message, options)
}
const _: fn(&fountain::Encoder) -> u32 = fountain::Encoder::fragment_count;
const _: fn(&fountain::Encoder) -> &[u32] = fountain::Encoder::last_fragment_indexes;
const _: fn(&mut fountain::Encoder) -> Option<Part> = <fountain::Encoder as Iterator>::next;
const _: fn(&[u8], &DecoderLimits) -> bcur::Result<Part> = Part::from_cbor;
const _: fn(&Part) -> Vec<u8> = Part::to_cbor;
const _: fn(DecoderLimits) -> fountain::Decoder = fountain::Decoder::new;
const _: fn() -> fountain::Decoder = <fountain::Decoder as Default>::default;
const _: fn(&mut fountain::Decoder, &Part) -> bcur::Result<Received> = fountain::Decoder::receive;
const _: fn(&fountain::Decoder) -> State<'_, [u8]> = fountain::Decoder::state;
const _: fn(&fountain::Decoder) -> Progress = fountain::Decoder::progress;
const _: fn(&fountain::Decoder) -> &[u32] = fountain::Decoder::last_indexes;
const _: fn(fountain::Decoder) -> bcur::Result<Vec<u8>> = fountain::Decoder::into_message;
const _: fn(&mut fountain::Decoder) = fountain::Decoder::reset;

// ---- crate root re-exports ---------------------------------------------------

const _: fn(&Error) -> ErrorKind = Error::kind;
const _: fn(&Error) -> Option<Limit> = Error::limit;
const _: fn(&Error) -> bool = Error::is_fatal;
const _: fn(&Progress) -> u32 = Progress::fragment_count;
const _: fn(&Progress) -> f64 = Progress::ratio;

// ---- typed (L4, feature `dcbor`) --------------------------------------------

#[cfg(feature = "dcbor")]
mod l4 {
    use std::fmt::Display;
    use std::str::FromStr;

    use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};

    use bcur::fountain::EncoderOptions;
    use bcur::ur::{self, Encoder};
    use bcur::{Result, Ur, UrDecodable, UrEncodable, UrType};

    const _: fn(UrType, CBOR) -> Ur = ur_new::<CBOR>;

    fn ur_new<C: Into<CBOR>>(ur_type: UrType, cbor: C) -> Ur {
        Ur::new(ur_type, cbor)
    }
    const _: fn(UrType, &[u8]) -> Result<Ur> = Ur::from_cbor_data;
    const _: fn(&Ur) -> &UrType = Ur::ur_type;
    const _: fn(&Ur) -> &CBOR = Ur::cbor;
    const _: fn(Ur) -> CBOR = Ur::into_cbor;
    const _: fn(&Ur) -> Vec<u8> = Ur::to_cbor_data;
    const _: fn(&Ur) -> String = Ur::to_qr_string;
    const _: fn(&Ur, EncoderOptions) -> Result<Encoder> = Ur::encoder;
    const _: fn(ur::Decoded) -> Result<Ur> = decoded_into_ur;

    fn decoded_into_ur(decoded: ur::Decoded) -> Result<Ur> {
        Ur::try_from(decoded)
    }
    const _: fn(&Ur, &mut std::fmt::Formatter<'_>) -> std::fmt::Result = <Ur as Display>::fmt;
    const _: fn(&str) -> Result<Ur> = ur_from_str;

    fn ur_from_str(s: &str) -> Result<Ur> {
        Ur::from_str(s)
    }

    fn encodable<T: UrEncodable>(value: &T) -> Result<Ur> {
        value.to_ur()
    }

    fn decodable<T: UrDecodable>(ur: &Ur) -> Result<T> {
        T::from_ur(ur)
    }

    /// Minimal named-tag type for the trait-bound checks.
    struct ApiNote(u8);

    impl CBORTagged for ApiNote {
        fn cbor_tags() -> Vec<Tag> {
            vec![Tag::with_static_name(40_002, "api-note")]
        }
    }

    impl CBORTaggedEncodable for ApiNote {
        fn untagged_cbor(&self) -> CBOR {
            self.0.into()
        }
    }

    impl CBORTaggedDecodable for ApiNote {
        fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
            Ok(Self(cbor.try_into()?))
        }
    }

    impl TryFrom<CBOR> for ApiNote {
        type Error = dcbor::Error;

        fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
            Self::from_tagged_cbor(cbor)
        }
    }

    #[test]
    fn l4_api_items_exist() {
        let ur = encodable(&ApiNote(7)).unwrap();
        let _note = decodable::<ApiNote>(&ur).unwrap();
    }
}

#[test]
fn public_api_items_exist() {
    // Referencing the items above is the check; keep a trivial runtime anchor.
    let ur = ur::encode(&UR_TYPE, b"data");
    let parsed = ur::parse(&ur, &DecoderLimits::default()).unwrap();
    assert_eq!(parsed_ur_type(&parsed), &UR_TYPE);
}
