//! Uniform Resource encode/decode and multi-part fountain transport.
//!
//! ```
//! use bcur::ur::{Decoder, Encoder};
//! use bcur::UrType;
//!
//! let data = b"Ten chars!".repeat(10);
//! let mut encoder = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
//! let mut decoder = Decoder::default();
//! while !matches!(decoder.state(), bcur::fountain::State::Complete(_)) {
//!     decoder.receive(&encoder.next_part().unwrap()).unwrap();
//! }
//! assert_eq!(decoder.into_decoded().unwrap().message(), data);
//! ```

use alloc::{string::String, vec::Vec};

use crate::bytewords::{self, Style};
use crate::error::{Error, ErrorKind, Limit, Result};
use crate::fountain::{self, DecoderLimits, Progress, Received, State};

/// Validated UR type token (non-empty, stored lowercase).
///
/// Allowed characters after normalization: ASCII `[a-z0-9-]+`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UrType(String);

impl UrType {
    /// Validates and lowercases a type token.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidType`] if empty or containing illegal characters.
    pub fn new(s: &str) -> Result<Self> {
        let lower = s.to_ascii_lowercase();
        validate_type(&lower)?;
        Ok(Self(lower))
    }

    /// Returns the string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Well-known `bytes` type.
    #[must_use]
    pub fn bytes() -> Self {
        Self(String::from("bytes"))
    }
}

impl TryFrom<&str> for UrType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for UrType {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(&value)
    }
}

/// Conversion into a validated [`UrType`].
///
/// Implemented for [`UrType`], `&UrType`, [`&str`], and [`String`].
/// Not for downstream impls (sealed).
pub trait IntoUrType: sealed::Sealed {
    /// Validates or clones into a [`UrType`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidType`] for an empty or illegal type token.
    fn into_ur_type(self) -> Result<UrType>;
}

#[allow(
    unreachable_pub,
    reason = "Sealed must be pub so IntoUrType can be public; module is private"
)]
mod sealed {
    use alloc::string::String;

    use super::UrType;

    /// Not implementable outside this crate.
    pub trait Sealed {}
    impl Sealed for UrType {}
    impl Sealed for &UrType {}
    impl Sealed for &str {}
    impl Sealed for String {}
}

impl IntoUrType for UrType {
    fn into_ur_type(self) -> Result<UrType> {
        Ok(self)
    }
}

impl IntoUrType for &UrType {
    fn into_ur_type(self) -> Result<UrType> {
        Ok(self.clone())
    }
}

impl IntoUrType for &str {
    fn into_ur_type(self) -> Result<UrType> {
        UrType::new(self)
    }
}

impl IntoUrType for String {
    fn into_ur_type(self) -> Result<UrType> {
        UrType::new(&self)
    }
}

/// Whether a decoded UR is single- or multi-part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Full payload in one URI.
    SinglePart,
    /// One fountain part of a multi-part stream.
    MultiPart,
}

/// Owned parse of a UR string (body is case-folded to lowercase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUr {
    /// Normalized type.
    pub ur_type: UrType,
    /// Single- or multi-part.
    pub kind: Kind,
    /// Multi-part path indices `(seq, count)`, if multi-part.
    pub indices: Option<(u32, u32)>,
    /// Lowercased bytewords body.
    pub body: String,
}

/// Lowercases a UR string for case-insensitive QR transport.
#[must_use]
pub fn normalize_ur(uri: &str) -> String {
    uri.to_ascii_lowercase()
}

/// Encodes a single-part UR. Empty `data` is allowed.
///
/// `ur_type` is already validated, so this cannot fail.
#[must_use]
pub fn encode(data: &[u8], ur_type: &UrType) -> String {
    let body = bytewords::encode(data, Style::Minimal);
    alloc::format!("ur:{}/{body}", ur_type.as_str())
}

/// Decodes payload bytes from a single- or multi-part UR (type is discarded).
///
/// Multi-part returns the CBOR-encoded fountain part bytes, not the message.
///
/// # Errors
///
/// Returns parse, type, bytewords, or index errors.
pub fn decode(uri: &str) -> Result<(Kind, Vec<u8>)> {
    let (kind, payload, _) = decode_with_indices(uri)?;
    Ok((kind, payload))
}

/// Decodes a **single-part** UR to its payload bytes.
///
/// Multi-part URIs return [`ErrorKind::NotSinglePart`]; use [`Decoder`] for those.
///
/// # Errors
///
/// Parse, type, bytewords, or [`ErrorKind::NotSinglePart`].
pub fn decode_message(uri: &str) -> Result<Vec<u8>> {
    let (kind, payload) = decode(uri)?;
    match kind {
        Kind::SinglePart => Ok(payload),
        Kind::MultiPart => Err(Error::new(ErrorKind::NotSinglePart)),
    }
}

/// Like [`decode`] but retains the normalized type.
///
/// # Errors
///
/// Same as [`decode`].
pub fn decode_with_type(uri: &str) -> Result<(UrType, Kind, Vec<u8>)> {
    let parsed = parse(uri)?;
    let payload = bytewords::decode(&parsed.body, Style::Minimal)?;
    Ok((parsed.ur_type, parsed.kind, payload))
}

/// Parses a UR into an owned structure (full-URI case fold).
///
/// # Errors
///
/// Returns scheme, type, or index errors. Does not decode bytewords.
pub fn parse(uri: &str) -> Result<ParsedUr> {
    parse_lowered(&normalize_ur(uri))
}

fn parse_lowered(uri: &str) -> Result<ParsedUr> {
    let strip_scheme = uri
        .strip_prefix("ur:")
        .ok_or_else(|| Error::new(ErrorKind::InvalidScheme))?;
    let (type_str, rest) = strip_scheme
        .split_once('/')
        .ok_or_else(|| Error::new(ErrorKind::TypeUnspecified))?;
    let ur_type = UrType::new(type_str)?;

    match rest.rsplit_once('/') {
        None => Ok(ParsedUr {
            ur_type,
            kind: Kind::SinglePart,
            indices: None,
            body: rest.to_ascii_lowercase(),
        }),
        Some((indices, body)) => {
            let indices = decode_indices(indices)?;
            Ok(ParsedUr {
                ur_type,
                kind: Kind::MultiPart,
                indices: Some(indices),
                body: body.to_ascii_lowercase(),
            })
        }
    }
}

type DecodedPayload = (Kind, Vec<u8>, Option<(u32, u32)>);

fn decode_with_indices(value: &str) -> Result<DecodedPayload> {
    let parsed = parse(value)?;
    let payload = bytewords::decode(&parsed.body, Style::Minimal)?;
    Ok((parsed.kind, payload, parsed.indices))
}

fn decode_indices(indices: &str) -> Result<(u32, u32)> {
    // UR-ADR-029: `1*DIGIT "-" 1*DIGIT`, no sign or whitespace.
    let (idx, idx_total) = indices
        .split_once('-')
        .ok_or_else(|| Error::new(ErrorKind::InvalidIndices))?;
    if idx.is_empty()
        || idx_total.is_empty()
        || !idx.bytes().all(|b| b.is_ascii_digit())
        || !idx_total.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::new(ErrorKind::InvalidIndices));
    }
    let idx = idx
        .parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::InvalidIndices))?;
    let idx_total = idx_total
        .parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::InvalidIndices))?;
    if idx == 0 || idx_total == 0 {
        return Err(Error::new(ErrorKind::InvalidIndices));
    }
    Ok((idx, idx_total))
}

fn validate_type(s: &str) -> Result<()> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Error::new(ErrorKind::InvalidType));
    }
    Ok(())
}

/// UR encoder owning the payload (single-part when `K == 1`).
#[derive(Debug)]
pub struct Encoder {
    fountain: fountain::Encoder,
    ur_type: UrType,
    message: Vec<u8>,
    /// 0 before first emit; 1 after. Only used when `K == 1`.
    single_emitted: u32,
}

impl Encoder {
    /// Creates an encoder with the well-known `bytes` type.
    ///
    /// # Errors
    ///
    /// Propagates fountain construction errors.
    pub fn bytes(message: &[u8], max_fragment_length: usize) -> Result<Self> {
        Self::new(message, max_fragment_length, &UrType::bytes())
    }

    /// Creates an encoder with a custom type.
    ///
    /// When the payload fits in one fragment (`K == 1`), [`Self::next_part`]
    /// emits a single-part `ur:<type>/<bytewords>` string (BCR-2024-001).
    ///
    /// # Errors
    ///
    /// Propagates type validation and fountain construction errors.
    pub fn new(message: &[u8], max_fragment_length: usize, ur_type: &UrType) -> Result<Self> {
        Self::with_options(
            message.to_vec(),
            fountain::EncoderOptions::new(max_fragment_length),
            ur_type,
        )
    }

    /// Crate-internal constructor with full fountain options (vector runners).
    pub(crate) fn with_options(
        message: Vec<u8>,
        options: fountain::EncoderOptions,
        ur_type: &UrType,
    ) -> Result<Self> {
        Ok(Self {
            fountain: fountain::Encoder::new(message.clone(), options)?,
            ur_type: ur_type.clone(),
            message,
            single_emitted: 0,
        })
    }

    /// Whether this encoder emits a single-part UR (`K == 1`).
    #[must_use]
    pub const fn is_single_part(&self) -> bool {
        self.fountain.fragment_count() == 1
    }

    /// Emits the next UR string.
    ///
    /// Single-fragment messages (`K == 1`) use the single-part form and re-emit
    /// the same `ur:<type>/<bytewords>` string on every call. The fountain
    /// encoder is not advanced. Larger messages use fountain
    /// `ur:<type>/<seq>-<count>/<bytewords>`.
    ///
    /// # Errors
    ///
    /// Multi-part only: sequence resource limits from the fountain encoder.
    pub fn next_part(&mut self) -> Result<String> {
        if self.is_single_part() {
            self.single_emitted = 1;
            return Ok(encode(&self.message, &self.ur_type));
        }
        let part = self.fountain.next().ok_or_else(Error::internal)?;
        let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
        Ok(alloc::format!(
            "ur:{}/{}-{}/{body}",
            self.ur_type.as_str(),
            part.sequence(),
            part.sequence_count()
        ))
    }

    /// Current emitted part count.
    ///
    /// Single-part: `0` before the first emit, then `1`. Multi-part: fountain
    /// `seqNum`.
    #[must_use]
    pub const fn current_index(&self) -> u32 {
        if self.is_single_part() {
            self.single_emitted
        } else {
            self.fountain.sequence()
        }
    }

    /// Whether a single-part UR has been emitted, or every source fragment has
    /// been emitted at least once.
    #[must_use]
    pub const fn complete(&self) -> bool {
        if self.is_single_part() {
            self.single_emitted == 1
        } else {
            self.fountain.is_complete()
        }
    }

    /// Source fragment count `K`.
    #[must_use]
    pub const fn fragment_count(&self) -> u32 {
        self.fountain.fragment_count()
    }
}

/// Reconstructed UR payload and type: the terminal value of [`Decoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    ur_type: UrType,
    message: Vec<u8>,
}

impl Decoded {
    /// UR type token of the decoded message.
    #[must_use]
    pub const fn ur_type(&self) -> &UrType {
        &self.ur_type
    }

    /// Decoded message bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Consumes the value into `(type, message)`.
    #[must_use]
    pub fn into_parts(self) -> (UrType, Vec<u8>) {
        (self.ur_type, self.message)
    }
}

/// Terminal session payload of [`Decoder`].
#[derive(Debug)]
enum Terminal {
    Complete(Decoded),
    Failed(Error),
}

/// UR decoder (single-part or fountain).
///
/// Frame results follow the fountain [`crate::fountain::Decoder`]: `Ok` is
/// `Accepted`/`Duplicate`; `Err(e)` rejects (`!e.is_fatal()`, session
/// unchanged) or fails (`e.is_fatal()` → [`State::Failed`]). Terminal
/// sessions return [`Received::Duplicate`] for every further frame without
/// parsing it (UR-ADR-014).
#[derive(Debug)]
pub struct Decoder {
    fountain: fountain::Decoder,
    limits: DecoderLimits,
    /// Allowed types; empty means "any". The first successfully ingested
    /// frame still locks the type.
    accept: Vec<UrType>,
    locked: Option<UrType>,
    terminal: Option<Terminal>,
    /// Frames that were `accepted` or `duplicate`, including single-part and
    /// post-terminal frames the fountain decoder never sees.
    processed: u64,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(DecoderLimits::default())
    }
}

impl Decoder {
    /// Creates a decoder with the given limits.
    #[must_use]
    pub const fn new(limits: DecoderLimits) -> Self {
        Self {
            fountain: fountain::Decoder::new(limits),
            limits,
            accept: Vec::new(),
            locked: None,
            terminal: None,
            processed: 0,
        }
    }

    /// Restricts the session to these UR types (empty accepts any).
    #[must_use]
    pub fn accept(mut self, types: impl IntoIterator<Item = UrType>) -> Self {
        self.accept = types.into_iter().collect();
        self
    }

    /// Receives one UR string (single-part or fountain part).
    ///
    /// A single-part URI completes the session immediately; a `1-1`
    /// multi-part URI completes it through the fountain path. The first
    /// successfully ingested frame locks the type.
    ///
    /// # Errors
    ///
    /// Rejected (state unchanged): parse, type, index, bytewords, part CBOR,
    /// and consistency errors. Fatal ([`State::Failed`]):
    /// [`ErrorKind::ResourceLimit`], [`ErrorKind::InvalidPadding`],
    /// [`ErrorKind::InvalidMessageChecksum`], [`ErrorKind::Internal`].
    pub fn receive(&mut self, text: &str) -> Result<Received> {
        if self.terminal.is_some() {
            self.processed = self.processed.saturating_add(1);
            return Ok(Received::Duplicate);
        }
        if text.len() > self.limits.max_uri_length {
            return Err(self.fail(Error::resource_limit(Limit::UriLength)));
        }
        let parsed = parse(text)?;
        self.check_type(&parsed.ur_type)?;
        match parsed.kind {
            Kind::SinglePart => self.receive_single(&parsed),
            Kind::MultiPart => self.receive_fountain(&parsed),
        }
    }

    /// Type admission: `accept` list (when non-empty), then the locked type.
    fn check_type(&self, ur_type: &UrType) -> Result<()> {
        if !self.accept.is_empty() && !self.accept.iter().any(|t| t == ur_type) {
            return Err(Error::unexpected_type(self.accept.clone(), ur_type.clone()));
        }
        if let Some(locked) = &self.locked
            && locked != ur_type
        {
            return Err(Error::unexpected_type(
                alloc::vec![locked.clone()],
                ur_type.clone(),
            ));
        }
        Ok(())
    }

    fn receive_single(&mut self, parsed: &ParsedUr) -> Result<Received> {
        // A single-part URI inside a collecting fountain session is
        // inconsistent (the reverse order is unreachable: a completed
        // single-part session is already terminal).
        if !matches!(self.fountain.state(), State::Empty) {
            return Err(Error::new(ErrorKind::InconsistentPart));
        }
        let data = bytewords::decode(&parsed.body, Style::Minimal)?;
        if data.len() > self.limits.max_message_length {
            return Err(self.fail(Error::resource_limit(Limit::MessageLength)));
        }
        self.locked.get_or_insert_with(|| parsed.ur_type.clone());
        self.terminal = Some(Terminal::Complete(Decoded {
            ur_type: parsed.ur_type.clone(),
            message: data,
        }));
        self.processed = self.processed.saturating_add(1);
        Ok(Received::Accepted)
    }

    fn receive_fountain(&mut self, parsed: &ParsedUr) -> Result<Received> {
        let decoded = bytewords::decode(&parsed.body, Style::Minimal)?;
        let part =
            fountain::Part::from_cbor(&decoded, &self.limits).map_err(|e| self.fatalize(e))?;
        let (seq, count) = parsed
            .indices
            .ok_or_else(|| Error::new(ErrorKind::InvalidIndices))?;
        if part.sequence() != seq || part.sequence_count() != count {
            return Err(Error::new(ErrorKind::InvalidIndices));
        }
        let received = self.fountain.receive(&part).map_err(|e| self.fatalize(e))?;
        self.locked.get_or_insert_with(|| parsed.ur_type.clone());
        self.processed = self.processed.saturating_add(1);
        if let State::Complete(message) = self.fountain.state() {
            self.terminal = Some(Terminal::Complete(Decoded {
                ur_type: parsed.ur_type.clone(),
                message: message.to_vec(),
            }));
        }
        Ok(received)
    }

    /// Fails the session on fatal errors; non-fatal errors pass through.
    fn fatalize(&mut self, error: Error) -> Error {
        if error.is_fatal() {
            self.terminal = Some(Terminal::Failed(error.clone()));
        }
        error
    }

    /// Moves the session to [`State::Failed`] and returns the fatal error.
    fn fail(&mut self, error: Error) -> Error {
        self.terminal = Some(Terminal::Failed(error.clone()));
        error
    }

    /// Current session state.
    #[must_use]
    pub const fn state(&self) -> State<'_, Decoded> {
        match &self.terminal {
            Some(Terminal::Complete(decoded)) => State::Complete(decoded),
            Some(Terminal::Failed(error)) => State::Failed(error),
            None => {
                let progress = self.progress();
                // `fragment_count == 0` iff the fountain decoder has not
                // ingested a part yet.
                if progress.fragment_count() == 0 {
                    State::Empty
                } else {
                    State::Collecting(progress)
                }
            }
        }
    }

    /// Progress snapshot (`Empty` reports all zeros; a session completed via
    /// a single-part URI reports `K = 1`).
    #[must_use]
    pub const fn progress(&self) -> Progress {
        let base = self.fountain.progress();
        if base.fragment_count() == 0 && matches!(self.terminal, Some(Terminal::Complete(_))) {
            return Progress::new(1, 1, 1, self.processed);
        }
        Progress::new(
            base.fragment_count(),
            base.rank(),
            base.recovered(),
            self.processed,
        )
    }

    /// Fragment indexes of the most recent `accepted`/`duplicate` part.
    #[must_use]
    pub fn last_indexes(&self) -> &[u32] {
        self.fountain.last_indexes()
    }

    /// Consumes the decoder and returns the decoded UR.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NotComplete`] while still collecting; the stored fatal
    /// error when the session is [`State::Failed`].
    pub fn into_decoded(self) -> Result<Decoded> {
        match self.terminal {
            Some(Terminal::Complete(decoded)) => Ok(decoded),
            Some(Terminal::Failed(error)) => Err(error),
            None => Err(Error::new(ErrorKind::NotComplete)),
        }
    }

    /// Returns the session to [`State::Empty`]; limits and the `accept` list
    /// are kept.
    pub fn reset(&mut self) {
        self.fountain = fountain::Decoder::new(self.limits);
        self.locked = None;
        self.terminal = None;
        self.processed = 0;
    }
}

/// Uppercase UR string for QR efficiency.
#[must_use]
pub fn qr_string(ur: &str) -> String {
    ur.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use minicbor::bytes::ByteVec;

    use super::*;
    use crate::consensus::xoshiro::test_utils::make_message;
    use crate::fountain::DecoderLimits;

    fn make_message_ur(length: usize, seed: &str) -> Vec<u8> {
        let message = make_message(seed, length);
        minicbor::to_vec(ByteVec::from(message)).unwrap()
    }

    fn testdata_lines(raw: &str) -> Vec<&str> {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }

    #[test]
    fn test_single_part_ur() {
        let ur = make_message_ur(50, "Wolf");
        let encoded = encode(&ur, &UrType::bytes());
        let expected = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
        assert_eq!(encoded, expected);
        let decoded = decode(&encoded).unwrap();
        assert_eq!((Kind::SinglePart, ur), decoded);
    }

    #[test]
    fn test_ur_encoder() {
        // Full 20-URI table from ur-rs 0.5 `test_ur_encoder` (MIT).
        let ur = make_message_ur(256, "Wolf");
        let mut encoder = Encoder::bytes(&ur, 30).unwrap();
        let expected = testdata_lines(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/ur-rs/multipart-20.txt"
        )));
        assert_eq!(expected.len(), 20);
        assert_eq!(encoder.fragment_count(), 9);
        for (index, e) in expected.into_iter().enumerate() {
            assert_eq!(encoder.current_index() as usize, index);
            assert_eq!(encoder.next_part().unwrap(), e);
        }
    }

    #[test]
    fn test_ur_encoder_decoder_bc_crypto_request() {
        // ur-rs / Blockchain Commons crypto-request seed vector.
        fn crypto_seed() -> Vec<u8> {
            let mut e = minicbor::Encoder::new(Vec::new());
            let uuid = hex::decode("020C223A86F7464693FC650EF3CAC047").unwrap();
            let seed_digest =
                hex::decode("E824467CAFFEAF3BBC3E0CA095E660A9BAD80DDB6A919433A37161908B9A3986")
                    .unwrap();
            e.map(2)
                .unwrap()
                .u8(1)
                .unwrap()
                .tag(minicbor::data::Tag::new(37))
                .unwrap()
                .bytes(&uuid)
                .unwrap()
                .u8(2)
                .unwrap()
                .tag(minicbor::data::Tag::new(500))
                .unwrap()
                .map(1)
                .unwrap()
                .u8(1)
                .unwrap()
                .tag(minicbor::data::Tag::new(600))
                .unwrap()
                .bytes(&seed_digest)
                .unwrap();
            e.into_writer()
        }

        let data = crypto_seed();
        let encoded = encode(&data, &UrType::new("crypto-request").unwrap());
        let expected = "ur:crypto-request/oeadtpdagdaobncpftlnylfgfgmuztihbawfsgrtflaotaadwkoyadtaaohdhdcxvsdkfgkepezepefrrffmbnnbmdvahnptrdtpbtuyimmemweootjshsmhlunyeslnameyhsdi";
        assert_eq!(encoded, expected);
        let decoded = decode(&encoded).unwrap();
        assert_eq!((Kind::SinglePart, data), decoded);
    }

    #[test]
    fn test_multipart_ur() {
        let ur = make_message_ur(32767, "Wolf");
        let mut encoder = Encoder::bytes(&ur, 1000).unwrap();
        let mut decoder = Decoder::default();
        loop {
            assert!(matches!(
                decoder.state(),
                State::Empty | State::Collecting(_)
            ));
            decoder.receive(&encoder.next_part().unwrap()).unwrap();
            if matches!(decoder.state(), State::Complete(_)) {
                break;
            }
        }
        let decoded = decoder.into_decoded().unwrap();
        assert_eq!(decoded.ur_type(), &UrType::bytes());
        assert_eq!(decoded.message(), ur.as_slice());
    }

    #[test]
    fn test_data_encode() {
        assert_eq!(
            encode(b"data", &UrType::bytes()),
            "ur:bytes/iehsjyhspmwfwfia"
        );
    }

    #[test]
    fn test_case_fold() {
        let lower = encode(b"data", &UrType::bytes());
        let upper = qr_string(&lower);
        assert_eq!(decode(&upper).unwrap(), decode(&lower).unwrap());
    }

    #[test]
    fn test_type_stickiness() {
        let data = b"Ten chars!".repeat(5);
        let mut enc_a = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
        let mut enc_b = Encoder::new(&data, 10, &UrType::new("beta").unwrap()).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&enc_a.next_part().unwrap()).unwrap();
        assert!(matches!(
            decoder.receive(&enc_b.next_part().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedType
        ));
    }

    #[test]
    fn test_invalid_scheme() {
        assert!(matches!(
            decode("uhr:bytes/aeadaolazmjendeoti"),
            Err(ref e) if e.kind() == ErrorKind::InvalidScheme
        ));
    }

    #[test]
    fn test_custom_encoder() {
        let data = b"Ten chars!";
        let mut encoder = Encoder::with_options(
            data.to_vec(),
            fountain::EncoderOptions {
                min_fragment_len: 5,
                ..fountain::EncoderOptions::new(5)
            },
            &UrType::new("my-scheme").unwrap(),
        )
        .unwrap();
        assert_eq!(
            encoder.next_part().unwrap(),
            "ur:my-scheme/1-2/lpadaobkcywkwmhfwnfeghihjtcxiansvomopr"
        );
    }

    #[test]
    fn test_single_part_receive_completes() {
        let mut decoder = Decoder::default();
        assert_eq!(
            decoder.receive("ur:bytes/iehsjyhspmwfwfia").unwrap(),
            Received::Accepted
        );
        assert!(matches!(decoder.state(), State::Complete(_)));
        let decoded = decoder.into_decoded().unwrap();
        assert_eq!(decoded.message(), b"data");
        assert_eq!(decoded.ur_type(), &UrType::bytes());
    }

    #[test]
    fn test_uppercase_qr_form_decodes() {
        let mut decoder = Decoder::default();
        assert_eq!(
            decoder.receive("UR:BYTES/IEHSJYHSPMWFWFIA").unwrap(),
            Received::Accepted
        );
        assert_eq!(decoder.into_decoded().unwrap().message(), b"data");
    }

    #[test]
    fn test_encoder_k1_is_single_part() {
        let data = b"hello";
        let mut encoder = Encoder::bytes(data, 64).unwrap();
        assert!(encoder.is_single_part());
        let part = encoder.next_part().unwrap();
        assert!(!part.contains("/1-1/"));
        assert_eq!(part, encode(data, &UrType::bytes()));
        let mut decoder = Decoder::default();
        decoder.receive(&part).unwrap();
        assert_eq!(decoder.into_decoded().unwrap().message(), data.as_slice());
    }

    #[test]
    fn test_encoder_k1_next_part_is_idempotent() {
        let data = b"hello";
        let mut encoder = Encoder::bytes(data, 64).unwrap();
        assert!(!encoder.complete());
        assert_eq!(encoder.current_index(), 0);
        let first = encoder.next_part().unwrap();
        assert_eq!(first, encode(data, &UrType::bytes()));
        assert_eq!(encoder.current_index(), 1);
        assert!(encoder.complete());
        let second = encoder.next_part().unwrap();
        assert_eq!(second, first);
        assert_eq!(encoder.current_index(), 1);
        for _ in 0..10 {
            assert_eq!(encoder.next_part().unwrap(), first);
            assert_eq!(encoder.current_index(), 1);
            assert!(encoder.complete());
        }
    }

    #[test]
    fn test_foreign_1_1_fountain_uri_decodes() {
        let mut fountain =
            fountain::Encoder::new(b"hello".to_vec(), fountain::EncoderOptions::new(64)).unwrap();
        let part = fountain.next().unwrap();
        let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
        let uri = alloc::format!("ur:bytes/1-1/{body}");
        let mut decoder = Decoder::default();
        assert_eq!(decoder.receive(&uri).unwrap(), Received::Accepted);
        assert!(matches!(decoder.state(), State::Complete(_)));
        assert_eq!(decoder.into_decoded().unwrap().message(), b"hello");
    }

    #[test]
    fn test_decode_message_rejects_multipart() {
        let data = b"Ten chars!".repeat(8);
        let mut encoder = Encoder::bytes(&data, 10).unwrap();
        let part = encoder.next_part().unwrap();
        assert_eq!(
            decode_message(&part).unwrap_err().kind(),
            ErrorKind::NotSinglePart
        );
        assert_eq!(
            decode_message(&encode(b"data", &UrType::bytes())).unwrap(),
            b"data"
        );
    }

    #[test]
    fn test_garbage_does_not_pin_type() {
        let data = b"Ten chars!".repeat(6);
        let mut encoder = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
        let mut decoder = Decoder::default();
        assert!(decoder.receive("ur:beta/1-2/zzzz").is_err());
        assert!(matches!(decoder.state(), State::Empty));
        decoder.receive(&encoder.next_part().unwrap()).unwrap();
        assert!(matches!(decoder.state(), State::Collecting(_)));
        // A different type after the lock is rejected.
        let mut other = Encoder::new(&data, 10, &UrType::new("beta").unwrap()).unwrap();
        assert!(matches!(
            decoder.receive(&other.next_part().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedType
        ));
    }

    #[test]
    fn test_single_after_multi_is_inconsistent() {
        let data = b"Ten chars!".repeat(6);
        let mut encoder = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&encoder.next_part().unwrap()).unwrap();
        let single = encode(b"x", &UrType::new("alpha").unwrap());
        assert!(matches!(
            decoder.receive(&single),
            Err(ref e) if e.kind() == ErrorKind::InconsistentPart && !e.is_fatal()
        ));
        // State unchanged: still collecting with the same progress.
        assert_eq!(decoder.progress().rank(), 1);
    }

    #[test]
    fn test_bc_ur_example() {
        // CBOR array [1, 2, 3] as single-part ur:test (bc-ur golden)
        // We only check roundtrip of raw CBOR bytes through bytewords path
        // using the known string from bc-ur docs when payload is correct CBOR.
        let cbor = hex::decode("83010203").unwrap(); // array(3) [1,2,3]
        let ur = encode(&cbor, &UrType::new("test").unwrap());
        assert_eq!(ur, "ur:test/lsadaoaxjygonesw");
        let (kind, data) = decode(&ur).unwrap();
        assert_eq!(kind, Kind::SinglePart);
        assert_eq!(data, cbor);
    }

    #[test]
    fn test_parse_and_decode_with_type() {
        let ur = encode(b"data", &UrType::bytes());
        let parsed = parse(&ur).unwrap();
        assert_eq!(parsed.kind, Kind::SinglePart);
        assert_eq!(parsed.ur_type.as_str(), "bytes");
        assert!(parsed.indices.is_none());

        let (ty, kind, payload) = decode_with_type(&ur).unwrap();
        assert_eq!(ty.as_str(), "bytes");
        assert_eq!(kind, Kind::SinglePart);
        assert_eq!(payload, b"data");
    }

    #[test]
    fn test_into_ur_type_accepts_owned_and_borrowed() {
        let t = UrType::new("bytes").unwrap();
        assert_eq!(t.clone().into_ur_type().unwrap(), t);
        assert_eq!(IntoUrType::into_ur_type(&t).unwrap(), t);
        assert_eq!("bytes".into_ur_type().unwrap(), t);
        assert_eq!(String::from("bytes").into_ur_type().unwrap(), t);
        assert!(matches!("".into_ur_type(), Err(ref e) if e.kind() == ErrorKind::InvalidType));
    }

    #[test]
    fn test_invalid_type_and_indices() {
        assert!(matches!(UrType::new(""), Err(ref e) if e.kind() == ErrorKind::InvalidType));
        assert!(
            matches!(UrType::new("Bad_Type"), Err(ref e) if e.kind() == ErrorKind::InvalidType)
        );
        assert!(matches!(
            parse("ur:bytes/0-1/aeadaolazmjendeoti"),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
        assert!(matches!(
            parse("ur:bytes/1-0/aeadaolazmjendeoti"),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
        assert!(matches!(
            parse("ur:bytes/foo/aeadaolazmjendeoti"),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
    }

    #[test]
    fn test_accept_list_and_uri_limit() {
        let data = b"Ten chars!".repeat(5);
        let mut enc = Encoder::new(&data, 10, &UrType::new("alpha").unwrap()).unwrap();
        let part = enc.next_part().unwrap();

        let mut decoder = Decoder::default().accept([UrType::new("beta").unwrap()]);
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedType
                && e.expected_types() == [UrType::new("beta").unwrap()]
        ));

        let limits = DecoderLimits {
            max_uri_length: 8,
            ..DecoderLimits::default()
        };
        let mut short = Decoder::new(limits);
        assert!(matches!(
            short.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::UriLength)
                && e.is_fatal()
        ));
    }

    #[test]
    fn test_multipart_index_mismatch() {
        let data = b"Ten chars!".repeat(5);
        let mut enc = Encoder::bytes(&data, 10).unwrap();
        let part = enc.next_part().unwrap();
        // Corrupt path indices while keeping a valid multi-part shape.
        let corrupted = part.replacen("/1-", "/2-", 1);
        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(&corrupted),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
    }

    #[test]
    fn test_empty_single_part() {
        let ur = encode(&[], &UrType::bytes());
        let (kind, payload) = decode(&ur).unwrap();
        assert_eq!(kind, Kind::SinglePart);
        assert_eq!(payload, Vec::<u8>::new());
    }

    #[test]
    fn test_parse_folds_body() {
        let parsed = parse("ur:bytes/IEHSJYHSPMWFWFIA").unwrap();
        assert_eq!(parsed.body, "iehsjyhspmwfwfia");
        assert_eq!(parsed.ur_type.as_str(), "bytes");
    }

    #[test]
    fn test_uri_len_resource_limit_fails() {
        let data = b"Ten chars!".repeat(5);
        let mut enc = Encoder::bytes(&data, 10).unwrap();
        let part = enc.next_part().unwrap();

        let limits = DecoderLimits {
            max_uri_length: 8,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::new(limits);
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit && e.limit() == Some(Limit::UriLength)
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
        // Terminal: every further frame is a duplicate, no parse.
        assert_eq!(decoder.receive(&part).unwrap(), Received::Duplicate);
        assert_eq!(decoder.receive("garbage").unwrap(), Received::Duplicate);
        assert!(matches!(
            decoder.into_decoded().unwrap_err().kind(),
            ErrorKind::ResourceLimit
        ));
    }

    #[test]
    fn test_decoder_progress_accessors() {
        let ur = make_message_ur(256, "Wolf");
        let mut encoder = Encoder::bytes(&ur, 30).unwrap();
        let mut decoder = Decoder::default();
        assert!(matches!(decoder.state(), State::Empty));
        assert_eq!(decoder.progress().fragment_count(), 0);
        assert_eq!(decoder.progress().ratio(), 0.0);

        decoder.receive(&encoder.next_part().unwrap()).unwrap();
        assert_eq!(
            decoder.progress().fragment_count(),
            encoder.fragment_count()
        );
        assert_eq!(decoder.progress().rank(), 1);
        assert_eq!(decoder.progress().recovered(), 1);
        assert_eq!(decoder.progress().processed(), 1);
        assert_ne!(decoder.last_indexes().len(), 0);

        let mut prev_rank = 1;
        while !matches!(decoder.state(), State::Complete(_)) {
            decoder.receive(&encoder.next_part().unwrap()).unwrap();
            let now = decoder.progress().rank();
            assert!(now >= prev_rank);
            assert!(now <= decoder.progress().fragment_count());
            prev_rank = now;
        }
        assert_eq!(decoder.progress().rank(), encoder.fragment_count());
        assert_eq!(decoder.progress().ratio(), 1.0);
    }

    #[test]
    fn test_terminal_duplicate_and_reset() {
        let mut decoder = Decoder::default();
        decoder.receive("ur:bytes/iehsjyhspmwfwfia").unwrap();
        assert_eq!(
            decoder.receive("ur:bytes/iehsjyhspmwfwfia").unwrap(),
            Received::Duplicate
        );
        assert_eq!(decoder.progress().processed(), 2);
        decoder.reset();
        assert!(matches!(decoder.state(), State::Empty));
        assert!(matches!(
            decoder.into_decoded().unwrap_err().kind(),
            ErrorKind::NotComplete
        ));
    }
}
