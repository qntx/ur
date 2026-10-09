//! Uniform Resource encode/decode and multi-part fountain transport.
//!
//! ```
//! use bcur::fountain::EncoderOptions;
//! use bcur::ur::{Decoder, Encoder};
//! use bcur::ur_type;
//!
//! let data = b"Ten chars!".repeat(10);
//! let mut encoder = Encoder::new(ur_type!("alpha"), data.clone(), EncoderOptions::new(10)).unwrap();
//! let mut decoder = Decoder::default();
//! for frame in encoder.by_ref() {
//!     decoder.receive(&frame).unwrap();
//!     if matches!(decoder.state(), bcur::State::Complete(_)) {
//!         break;
//!     }
//! }
//! assert_eq!(decoder.into_decoded().unwrap().message(), data);
//! ```

use alloc::{borrow::Cow, format, string::String, vec::Vec};
use core::{fmt, iter::FusedIterator, str::FromStr};

use crate::bytewords::{self, Style};
use crate::error::{Error, ErrorKind, Limit, Result};
use crate::fountain::{self, DecoderLimits, EncoderOptions, Part, Progress, Received, State};

/// Validated UR type token: canonical lowercase ASCII `[a-z0-9-]+`.
///
/// [`UrType::new`] lowercases then validates; [`UrType::new_static`] validates
/// a `&'static str` at compile time (see [`ur_type!`](crate::ur_type!)).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UrType(Cow<'static, str>);

impl UrType {
    /// Validates and lowercases a type token.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidType`] if empty or containing illegal
    /// characters.
    pub fn new(s: &str) -> Result<Self> {
        let lower = s.to_ascii_lowercase();
        if !is_valid_type(&lower) {
            return Err(Error::new(ErrorKind::InvalidType));
        }
        Ok(Self(Cow::Owned(lower)))
    }

    /// Validates a `&'static str` that is already canonical lowercase.
    ///
    /// Usable in `const` context — see [`ur_type!`](crate::ur_type!).
    #[must_use]
    pub const fn new_static(s: &'static str) -> Option<Self> {
        if !is_valid_type_const(s) {
            return None;
        }
        Some(Self(Cow::Borrowed(s)))
    }

    /// Returns the string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// UR type literal validated at compile time: `ur_type!("seed")` expands to
/// an inline `const` block, so an invalid token is a compile error.
///
/// ```
/// use bcur::ur_type;
/// const SEED: bcur::UrType = ur_type!("seed");
/// assert_eq!(SEED.as_str(), "seed");
/// ```
///
/// ```compile_fail
/// let _invalid = bcur::ur_type!("Not A Type");
/// ```
#[macro_export]
macro_rules! ur_type {
    ($t:literal) => {
        const { $crate::UrType::new_static($t).expect("invalid UR type literal") }
    };
}

impl fmt::Display for UrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for UrType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for UrType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
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

fn is_valid_type(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

const fn is_valid_type_const(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

/// A decoded UR: a single-part message or one validated fountain part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedUr {
    /// `ur:<type>/<bytewords>` with the decoded message bytes.
    Single {
        /// Normalized type token.
        ur_type: UrType,
        /// Bytewords-decoded message.
        message: Vec<u8>,
    },
    /// `ur:<type>/<seq>-<count>/<bytewords>` with the decoded fountain part.
    Multi {
        /// Normalized type token.
        ur_type: UrType,
        /// Fountain part decoded from the body (header indices verified
        /// against the part CBOR fields).
        part: Part,
    },
}

/// Parses and decodes a UR string.
///
/// Case-insensitive for the URI and the bytewords body. `limits` bounds the
/// URI length and the multi-part CBOR fields (UR-ADR-029 header grammar).
///
/// # Errors
///
/// Scheme, type, index, bytewords, part-CBOR, or limit errors.
pub fn parse(text: &str, limits: &DecoderLimits) -> Result<ParsedUr> {
    if text.len() > limits.max_uri_length {
        return Err(Error::resource_limit(Limit::UriLength));
    }
    let uri = text.to_ascii_lowercase();
    let rest0 = uri
        .strip_prefix("ur:")
        .ok_or_else(|| Error::new(ErrorKind::InvalidScheme))?;
    let (type_str, rest) = rest0
        .split_once('/')
        .ok_or_else(|| Error::new(ErrorKind::TypeUnspecified))?;
    let ur_type = UrType::new(type_str)?;

    match rest.rsplit_once('/') {
        None => Ok(ParsedUr::Single {
            ur_type,
            message: bytewords::decode(rest, Style::Minimal)?,
        }),
        Some((indices, body)) => {
            let (seq, count) = decode_indices(indices)?;
            let cbor = bytewords::decode(body, Style::Minimal)?;
            let part = Part::from_cbor(&cbor, limits)?;
            if part.sequence() != seq || part.sequence_count() != count {
                return Err(Error::new(ErrorKind::InvalidIndices));
            }
            Ok(ParsedUr::Multi { ur_type, part })
        }
    }
}

/// Encodes a single-part UR. Empty `message` is allowed.
#[must_use]
pub fn encode(ur_type: &UrType, message: &[u8]) -> String {
    let body = bytewords::encode(message, Style::Minimal);
    format!("ur:{}/{body}", ur_type.as_str())
}

/// Uppercase UR string for denser QR alphanumeric mode.
#[must_use]
pub fn to_qr_string(ur: &str) -> String {
    ur.to_ascii_uppercase()
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

/// UR string encoder.
///
/// `K == 1` emits the same single-part UR on every step; larger messages emit
/// `ur:<type>/<seq>-<count>/<bytewords>` fountain parts until sequence
/// `0xFFFFFFFF`, where iteration ends (UR-ADR-016).
#[derive(Debug)]
pub struct Encoder {
    fountain: fountain::Encoder,
    ur_type: UrType,
    /// `K == 1`: the precomputed single-part URI, emitted forever.
    single: Option<String>,
    /// Whether the single-part URI has been emitted at least once.
    emitted: bool,
}

impl Encoder {
    /// Creates an encoder for `message` under `ur_type`.
    ///
    /// # Errors
    ///
    /// Propagates fountain construction errors.
    pub fn new(
        ur_type: UrType,
        message: impl Into<Vec<u8>>,
        options: EncoderOptions,
    ) -> Result<Self> {
        let message = message.into();
        let fountain = fountain::Encoder::new(message.clone(), options)?;
        let single = (fountain.fragment_count() == 1).then(|| encode(&ur_type, &message));
        Ok(Self {
            fountain,
            ur_type,
            single,
            emitted: false,
        })
    }

    /// The UR type token this encoder emits.
    #[must_use]
    pub const fn ur_type(&self) -> &UrType {
        &self.ur_type
    }

    /// Source fragment count `K`.
    #[must_use]
    pub const fn fragment_count(&self) -> u32 {
        self.fountain.fragment_count()
    }

    /// Whether this encoder emits a single-part UR (`K == 1`).
    #[must_use]
    pub const fn is_single_part(&self) -> bool {
        self.fountain.fragment_count() == 1
    }

    /// Whether the single-part URI has been emitted, or every source fragment
    /// has been emitted at least once.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        if self.single.is_some() {
            self.emitted
        } else {
            self.fountain.is_complete()
        }
    }

    /// Fragment indexes mixed into the most recently produced part.
    #[must_use]
    pub fn last_fragment_indexes(&self) -> &[u32] {
        self.fountain.last_fragment_indexes()
    }
}

impl Iterator for Encoder {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(single) = &self.single {
            self.emitted = true;
            return Some(single.clone());
        }
        let part = self.fountain.next()?;
        let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
        Some(format!(
            "ur:{}/{}-{}/{body}",
            self.ur_type.as_str(),
            part.sequence(),
            part.sequence_count()
        ))
    }
}

impl FusedIterator for Encoder {}

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
        let parsed = parse(text, &self.limits).map_err(|e| self.fatalize(e))?;
        let ur_type = match &parsed {
            ParsedUr::Single { ur_type, .. } | ParsedUr::Multi { ur_type, .. } => ur_type,
        };
        self.check_type(ur_type)?;
        match parsed {
            ParsedUr::Single {
                ur_type: ty,
                message,
            } => self.receive_single(ty, message),
            ParsedUr::Multi { ur_type: ty, part } => self.receive_fountain(ty, &part),
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

    fn receive_single(&mut self, ur_type: UrType, message: Vec<u8>) -> Result<Received> {
        // A single-part URI inside a collecting fountain session is
        // inconsistent (the reverse order is unreachable: a completed
        // single-part session is already terminal).
        if !matches!(self.fountain.state(), State::Empty) {
            return Err(Error::new(ErrorKind::InconsistentPart));
        }
        if message.len() > self.limits.max_message_length {
            return Err(self.fail(Error::resource_limit(Limit::MessageLength)));
        }
        self.locked.get_or_insert_with(|| ur_type.clone());
        self.terminal = Some(Terminal::Complete(Decoded { ur_type, message }));
        self.processed = self.processed.saturating_add(1);
        Ok(Received::Accepted)
    }

    fn receive_fountain(&mut self, ur_type: UrType, part: &Part) -> Result<Received> {
        let received = self.fountain.receive(part).map_err(|e| self.fatalize(e))?;
        self.locked.get_or_insert_with(|| ur_type.clone());
        self.processed = self.processed.saturating_add(1);
        if let State::Complete(message) = self.fountain.state() {
            self.terminal = Some(Terminal::Complete(Decoded {
                ur_type,
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

#[cfg(test)]
mod tests {
    use minicbor::bytes::ByteVec;

    use super::*;
    use crate::consensus::xoshiro::test_utils::make_message;

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

    fn parsed_single(parsed: ParsedUr) -> Vec<u8> {
        match parsed {
            ParsedUr::Single { message, .. } => message,
            ParsedUr::Multi { .. } => unreachable!("expected single"),
        }
    }

    fn bytes_encoder(data: &[u8], max_fragment_len: usize) -> Encoder {
        Encoder::new(
            ur_type!("bytes"),
            data.to_vec(),
            EncoderOptions::new(max_fragment_len),
        )
        .unwrap()
    }

    #[test]
    fn test_single_part_ur() {
        let ur = make_message_ur(50, "Wolf");
        let encoded = encode(&ur_type!("bytes"), &ur);
        let expected = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
        assert_eq!(encoded, expected);
        assert_eq!(
            parsed_single(parse(&encoded, &DecoderLimits::default()).unwrap()),
            ur
        );
    }

    #[test]
    fn test_ur_encoder() {
        // Full 20-URI table from ur-rs 0.5 `test_ur_encoder` (MIT).
        let ur = make_message_ur(256, "Wolf");
        let mut encoder = bytes_encoder(&ur, 30);
        let expected = testdata_lines(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/ur-rs/multipart-20.txt"
        )));
        assert_eq!(expected.len(), 20);
        assert_eq!(encoder.fragment_count(), 9);
        for e in expected {
            assert_eq!(encoder.next().unwrap(), e);
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
        let encoded = encode(&UrType::new("crypto-request").unwrap(), &data);
        let expected = "ur:crypto-request/oeadtpdagdaobncpftlnylfgfgmuztihbawfsgrtflaotaadwkoyadtaaohdhdcxvsdkfgkepezepefrrffmbnnbmdvahnptrdtpbtuyimmemweootjshsmhlunyeslnameyhsdi";
        assert_eq!(encoded, expected);
        assert_eq!(
            parsed_single(parse(&encoded, &DecoderLimits::default()).unwrap()),
            data
        );
    }

    #[test]
    fn test_multipart_ur() {
        let ur = make_message_ur(32767, "Wolf");
        let mut encoder = bytes_encoder(&ur, 1000);
        let mut decoder = Decoder::default();
        loop {
            assert!(matches!(
                decoder.state(),
                State::Empty | State::Collecting(_)
            ));
            decoder.receive(&encoder.next().unwrap()).unwrap();
            if matches!(decoder.state(), State::Complete(_)) {
                break;
            }
        }
        let decoded = decoder.into_decoded().unwrap();
        assert_eq!(decoded.ur_type(), &ur_type!("bytes"));
        assert_eq!(decoded.message(), ur.as_slice());
    }

    #[test]
    fn test_data_encode() {
        assert_eq!(
            encode(&ur_type!("bytes"), b"data"),
            "ur:bytes/iehsjyhspmwfwfia"
        );
    }

    #[test]
    fn test_case_fold() {
        let lower = encode(&ur_type!("bytes"), b"data");
        let upper = to_qr_string(&lower);
        assert_eq!(
            parse(&upper, &DecoderLimits::default()).unwrap(),
            parse(&lower, &DecoderLimits::default()).unwrap()
        );
    }

    #[test]
    fn test_type_stickiness() {
        let data = b"Ten chars!".repeat(5);
        let mut enc_a = Encoder::new(
            UrType::new("alpha").unwrap(),
            data.clone(),
            EncoderOptions::new(10),
        )
        .unwrap();
        let mut enc_b =
            Encoder::new(UrType::new("beta").unwrap(), data, EncoderOptions::new(10)).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&enc_a.next().unwrap()).unwrap();
        assert!(matches!(
            decoder.receive(&enc_b.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedType
        ));
    }

    #[test]
    fn test_invalid_scheme() {
        assert!(matches!(
            parse("uhr:bytes/aeadaolazmjendeoti", &DecoderLimits::default()),
            Err(ref e) if e.kind() == ErrorKind::InvalidScheme
        ));
    }

    #[test]
    fn test_custom_encoder() {
        let data = b"Ten chars!";
        let mut encoder = Encoder::new(
            UrType::new("my-scheme").unwrap(),
            data.to_vec(),
            EncoderOptions {
                min_fragment_len: 5,
                ..EncoderOptions::new(5)
            },
        )
        .unwrap();
        assert_eq!(
            encoder.next().unwrap(),
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
        assert_eq!(decoded.ur_type(), &ur_type!("bytes"));
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
        let mut encoder = bytes_encoder(data, 64);
        assert!(encoder.is_single_part());
        let part = encoder.next().unwrap();
        assert!(!part.contains("/1-1/"));
        assert_eq!(part, encode(&ur_type!("bytes"), data));
        let mut decoder = Decoder::default();
        decoder.receive(&part).unwrap();
        assert_eq!(decoder.into_decoded().unwrap().message(), data.as_slice());
    }

    #[test]
    fn test_encoder_k1_repeats_forever() {
        let data = b"hello";
        let mut encoder = bytes_encoder(data, 64);
        assert!(!encoder.is_complete());
        let first = encoder.next().unwrap();
        assert_eq!(first, encode(&ur_type!("bytes"), data));
        assert!(encoder.is_complete());
        for _ in 0..10 {
            assert_eq!(encoder.next().unwrap(), first);
            assert!(encoder.is_complete());
        }
    }

    #[test]
    fn test_foreign_1_1_fountain_uri_decodes() {
        let mut fountain =
            fountain::Encoder::new(b"hello".to_vec(), EncoderOptions::new(64)).unwrap();
        let part = fountain.next().unwrap();
        let body = bytewords::encode(&part.to_cbor(), Style::Minimal);
        let uri = alloc::format!("ur:bytes/1-1/{body}");
        let mut decoder = Decoder::default();
        assert_eq!(decoder.receive(&uri).unwrap(), Received::Accepted);
        assert!(matches!(decoder.state(), State::Complete(_)));
        assert_eq!(decoder.into_decoded().unwrap().message(), b"hello");
    }

    #[test]
    fn test_parse_identifies_multipart() {
        let data = b"Ten chars!".repeat(8);
        let mut encoder = bytes_encoder(&data, 10);
        let parsed = parse(&encoder.next().unwrap(), &DecoderLimits::default()).unwrap();
        assert!(matches!(parsed, ParsedUr::Multi { .. }));
        assert_eq!(
            parsed_single(
                parse(
                    &encode(&ur_type!("bytes"), b"data"),
                    &DecoderLimits::default()
                )
                .unwrap()
            ),
            b"data"
        );
    }

    #[test]
    fn test_garbage_does_not_pin_type() {
        let data = b"Ten chars!".repeat(6);
        let mut encoder = Encoder::new(
            UrType::new("alpha").unwrap(),
            data.clone(),
            EncoderOptions::new(10),
        )
        .unwrap();
        let mut decoder = Decoder::default();
        assert!(decoder.receive("ur:beta/1-2/zzzz").is_err());
        assert!(matches!(decoder.state(), State::Empty));
        decoder.receive(&encoder.next().unwrap()).unwrap();
        assert!(matches!(decoder.state(), State::Collecting(_)));
        // A different type after the lock is rejected.
        let mut other =
            Encoder::new(UrType::new("beta").unwrap(), data, EncoderOptions::new(10)).unwrap();
        assert!(matches!(
            decoder.receive(&other.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedType
        ));
    }

    #[test]
    fn test_single_after_multi_is_inconsistent() {
        let data = b"Ten chars!".repeat(6);
        let mut encoder =
            Encoder::new(UrType::new("alpha").unwrap(), data, EncoderOptions::new(10)).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&encoder.next().unwrap()).unwrap();
        let single = encode(&UrType::new("alpha").unwrap(), b"x");
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
        let cbor = hex::decode("83010203").unwrap(); // array(3) [1,2,3]
        let ur = encode(&UrType::new("test").unwrap(), &cbor);
        assert_eq!(ur, "ur:test/lsadaoaxjygonesw");
        assert_eq!(
            parsed_single(parse(&ur, &DecoderLimits::default()).unwrap()),
            cbor
        );
    }

    #[test]
    fn test_parse_shape() {
        let ur = encode(&ur_type!("bytes"), b"data");
        let parsed = parse(&ur, &DecoderLimits::default()).unwrap();
        let ParsedUr::Single { ur_type, message } = parsed else {
            unreachable!("expected single");
        };
        assert_eq!(ur_type.as_str(), "bytes");
        assert_eq!(message, b"data");
    }

    #[test]
    fn test_ur_type_conversions() {
        let t = UrType::new("BYTES").unwrap();
        assert_eq!(t.as_str(), "bytes");
        assert_eq!("bytes".parse::<UrType>().unwrap(), t);
        assert_eq!(UrType::try_from("bytes").unwrap(), t);
        assert_eq!(UrType::try_from(String::from("bytes")).unwrap(), t);
        let as_ref: &str = t.as_ref();
        assert_eq!(as_ref, "bytes");
        assert_eq!(t.to_string(), "bytes");
        assert!(matches!(
            "".parse::<UrType>(),
            Err(ref e) if e.kind() == ErrorKind::InvalidType
        ));
    }

    #[test]
    fn test_new_static_and_macro() {
        const T: UrType = ur_type!("seed");
        assert_eq!(T.as_str(), "seed");
        assert!(UrType::new_static("SEED").is_none());
        assert!(UrType::new_static("not_a_type").is_none());
        assert!(UrType::new_static("").is_none());
        assert!(UrType::new_static("crypto-request").is_some());
    }

    #[test]
    fn test_invalid_type_and_indices() {
        assert!(matches!(
            UrType::new(""),
            Err(ref e) if e.kind() == ErrorKind::InvalidType
        ));
        assert!(matches!(
            UrType::new("Bad_Type"),
            Err(ref e) if e.kind() == ErrorKind::InvalidType
        ));
        let limits = DecoderLimits::default();
        assert!(matches!(
            parse("ur:bytes/0-1/aeadaolazmjendeoti", &limits),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
        assert!(matches!(
            parse("ur:bytes/1-0/aeadaolazmjendeoti", &limits),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
        assert!(matches!(
            parse("ur:bytes/foo/aeadaolazmjendeoti", &limits),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices
        ));
    }

    #[test]
    fn test_accept_list_and_uri_limit() {
        let data = b"Ten chars!".repeat(5);
        let mut enc =
            Encoder::new(UrType::new("alpha").unwrap(), data, EncoderOptions::new(10)).unwrap();
        let part = enc.next().unwrap();

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
        let mut enc = bytes_encoder(&data, 10);
        let part = enc.next().unwrap();
        let corrupted = part.replace("/1-", "/2-");
        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(&corrupted),
            Err(ref e) if e.kind() == ErrorKind::InvalidIndices && !e.is_fatal()
        ));
    }

    #[test]
    fn test_empty_single_part() {
        let ur = encode(&ur_type!("bytes"), &[]);
        assert_eq!(
            parsed_single(parse(&ur, &DecoderLimits::default()).unwrap()),
            Vec::<u8>::new()
        );
        let mut decoder = Decoder::default();
        decoder.receive(&ur).unwrap();
        assert_eq!(decoder.into_decoded().unwrap().message(), b"".as_slice());
    }

    #[test]
    fn test_parse_folds_body() {
        let lower = encode(&ur_type!("bytes"), b"data");
        let upper = lower.to_ascii_uppercase();
        assert_eq!(
            parsed_single(parse(&upper, &DecoderLimits::default()).unwrap()),
            b"data"
        );
    }

    #[test]
    fn test_uri_len_resource_limit_fails() {
        let data = b"Ten chars!".repeat(5);
        let mut enc = bytes_encoder(&data, 10);
        let part = enc.next().unwrap();
        let short = "ur:bytes/iehsjyhspmwfwfia";
        assert!(part.len() > short.len());
        let limits = DecoderLimits {
            max_uri_length: short.len(),
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::new(limits);
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::UriLength)
                && e.is_fatal()
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
        assert_eq!(decoder.receive(short).unwrap(), Received::Duplicate);
    }

    #[test]
    fn test_decoder_progress_accessors() {
        let data = b"Ten chars!".repeat(8);
        let mut encoder = bytes_encoder(&data, 10);
        let mut decoder = Decoder::default();
        assert!(matches!(decoder.state(), State::Empty));
        assert_eq!(decoder.progress().fragment_count(), 0);

        decoder.receive(&encoder.next().unwrap()).unwrap();
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
            decoder.receive(&encoder.next().unwrap()).unwrap();
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
