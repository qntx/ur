#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::excessive_nesting,
    reason = "integration targets link full dev-deps and host unwraps by design"
)]

//! Adversarial multi-part decoder session behavior (public API).

use bcur::fountain::EncoderOptions;
use bcur::ur::{Decoder, Encoder};
use bcur::ur_type;
use bcur::{DecoderLimits, ErrorKind, Limit, Received, State, UrType};

#[test]
fn uri_len_limit_fails_session() {
    let data = b"Ten chars!".repeat(8);
    let mut enc = Encoder::new(ur_type!("bytes"), data, EncoderOptions::new(10)).unwrap();
    let part = enc.next().unwrap();

    let mut decoder = Decoder::new(DecoderLimits {
        max_uri_length: 16,
        ..DecoderLimits::default()
    });
    assert!(matches!(
        decoder.receive(&part),
        Err(ref e) if e.kind() == ErrorKind::ResourceLimit
            && e.limit() == Some(Limit::UriLength)
            && e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Failed(_)));
    // Terminal: further frames are duplicates without parsing.
    assert_eq!(decoder.receive(&part).unwrap(), Received::Duplicate);
    assert!(matches!(
        decoder.into_decoded(),
        Err(ref e) if e.kind() == ErrorKind::ResourceLimit && e.limit() == Some(Limit::UriLength)
    ));
}

#[test]
fn fragment_count_limit_fails() {
    let data = b"Ten chars!".repeat(16);
    let mut enc = Encoder::new(ur_type!("bytes"), data, EncoderOptions::new(10)).unwrap();
    assert!(enc.fragment_count() > 1);

    let mut decoder = Decoder::new(DecoderLimits {
        max_fragment_count: 1,
        ..DecoderLimits::default()
    });
    let part = enc.next().unwrap();
    assert!(matches!(
        decoder.receive(&part),
        Err(ref e) if e.kind() == ErrorKind::ResourceLimit
            && e.limit() == Some(Limit::FragmentCount)
            && e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Failed(_)));
}

#[test]
fn message_length_limit_fails() {
    let data = b"Ten chars!".repeat(16);
    let mut enc = Encoder::new(ur_type!("bytes"), data, EncoderOptions::new(10)).unwrap();
    let mut decoder = Decoder::new(DecoderLimits {
        max_message_length: 8,
        ..DecoderLimits::default()
    });
    assert!(matches!(
        decoder.receive(&enc.next().unwrap()),
        Err(ref e) if e.kind() == ErrorKind::ResourceLimit
            && e.limit() == Some(Limit::MessageLength)
            && e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Failed(_)));
}

#[test]
fn type_stickiness_is_rejected_not_fatal() {
    let data = b"Ten chars!".repeat(6);
    let mut a = Encoder::new(ur_type!("alpha"), data.clone(), EncoderOptions::new(10)).unwrap();
    let mut b = Encoder::new(ur_type!("beta"), data, EncoderOptions::new(10)).unwrap();
    let mut decoder = Decoder::default();
    decoder.receive(&a.next().unwrap()).unwrap();
    assert!(matches!(
        decoder.receive(&b.next().unwrap()),
        Err(ref e) if e.kind() == ErrorKind::UnexpectedType && !e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Collecting(_)));
    // Same type is still received without error.
    assert!(decoder.receive(&a.next().unwrap()).is_ok());
    assert!(decoder.progress().rank() >= 1);
}

#[test]
fn single_part_receive_completes() {
    let mut decoder = Decoder::default();
    assert_eq!(
        decoder.receive("ur:bytes/iehsjyhspmwfwfia").unwrap(),
        Received::Accepted
    );
    assert!(matches!(decoder.state(), State::Complete(_)));
    assert_eq!(decoder.into_decoded().unwrap().message(), b"data");
}

#[test]
fn accept_type_mismatch_is_rejected_not_fatal() {
    let data = b"Ten chars!".repeat(4);
    let mut enc = Encoder::new(ur_type!("alpha"), data, EncoderOptions::new(10)).unwrap();
    let mut decoder = Decoder::default().accept([UrType::new("beta").unwrap()]);
    assert!(matches!(
        decoder.receive(&enc.next().unwrap()),
        Err(ref e) if e.kind() == ErrorKind::UnexpectedType && !e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Empty));
}

#[test]
fn index_path_mismatch_is_rejected_not_fatal() {
    let data = b"Ten chars!".repeat(4);
    let mut enc = Encoder::new(ur_type!("bytes"), data, EncoderOptions::new(10)).unwrap();
    let part = enc.next().unwrap();
    let corrupted = part.replacen("/1-", "/2-", 1);
    let mut decoder = Decoder::default();
    assert!(matches!(
        decoder.receive(&corrupted),
        Err(ref e) if e.kind() == ErrorKind::InvalidIndices && !e.is_fatal()
    ));
    assert!(matches!(decoder.state(), State::Empty));
}
