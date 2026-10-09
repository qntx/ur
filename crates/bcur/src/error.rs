//! Unified error type for the `bcur` crate.

#[cfg(feature = "dcbor")]
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ur::UrType;

/// Which decoder/encoder budget was exceeded.
///
/// `ReceivedParts` and `BufferParts` are transitional and leave with the
/// decoder redesign (R1c).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    /// Original payload length (`max_message_length` or `u32` wire field).
    MessageLength,
    /// Fragment count `K` (`max_fragment_count` or `u32` wire field).
    FragmentCount,
    /// Part payload length (`max_fragment_data_length`).
    FragmentLength,
    /// UR string length (`max_uri_len`).
    UriLength,
    /// Unique received index-set count (`max_received_parts`).
    ReceivedParts,
    /// Mixed-part XOR buffer size (`max_buffer_parts`).
    BufferParts,
}

impl Limit {
    /// TS `UrLimit` string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MessageLength => "messageLength",
            Self::FragmentCount => "fragmentCount",
            Self::FragmentLength => "fragmentLength",
            Self::UriLength => "uriLength",
            Self::ReceivedParts => "receivedParts",
            Self::BufferParts => "bufferParts",
        }
    }
}

/// Error kinds, one-to-one with the TS `UrErrorCode` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input contained non-ASCII characters.
    NonAscii,
    /// An unrecognized or malformed byteword token was encountered.
    InvalidWord,
    /// The bytewords string length is inconsistent with the selected style.
    InvalidBytewordsLength,
    /// The CRC-32 checksum appended to a bytewords payload did not match.
    InvalidBytewordsChecksum,
    /// The URI did not start with the `ur:` scheme.
    InvalidScheme,
    /// No type token was present after the scheme.
    TypeUnspecified,
    /// The UR type token is empty or contains illegal characters.
    InvalidType,
    /// Multi-part sequence indices were missing or inconsistent with the part.
    InvalidIndices,
    /// The UR type did not match the expected type.
    UnexpectedType,
    /// The fountain part CBOR was malformed for our schema.
    InvalidPartCbor,
    /// A fountain part had zero/empty fields or inconsistent padding.
    InvalidPart,
    /// A part is inconsistent with previously received parts.
    InconsistentPart,
    /// A configured resource limit was exceeded.
    ResourceLimit,
    /// Joined fragments had non-zero padding past the message length.
    InvalidPadding,
    /// Joined fountain payload failed its CRC-32 check.
    InvalidMessageChecksum,
    /// The fountain encoder was given an empty message.
    EmptyMessage,
    /// Fragment length bounds are not positive or `min > max`.
    InvalidFragmentLength,
    /// The message exceeds the `u32` wire length field.
    MessageTooLong,
    /// A single-part API was used on a multi-part UR.
    NotSinglePart,
    /// The payload is not well-formed deterministic CBOR.
    CborDecode,
    /// Well-formed CBOR that cannot become the requested type.
    CborType,
    /// An internal invariant was broken.
    Internal,
}

impl ErrorKind {
    /// TS `UrError.message` text for kinds without detail.
    const fn message(self) -> &'static str {
        match self {
            Self::NonAscii => "bytewords string is not ASCII",
            Self::InvalidWord => "invalid bytewords word",
            Self::InvalidBytewordsLength => "invalid bytewords length",
            Self::InvalidBytewordsChecksum => "invalid bytewords checksum",
            Self::InvalidScheme => "invalid UR scheme",
            Self::TypeUnspecified => "UR type unspecified",
            Self::InvalidType => "invalid UR type",
            Self::InvalidIndices => "invalid multi-part indices",
            Self::UnexpectedType => "unexpected UR type",
            Self::InvalidPartCbor => "invalid fountain part CBOR",
            Self::InvalidPart => "invalid fountain part",
            Self::InconsistentPart => "fountain part inconsistent with previous parts",
            Self::ResourceLimit => "resource limit exceeded",
            Self::InvalidPadding => "invalid fountain part padding",
            Self::InvalidMessageChecksum => "invalid fountain message checksum",
            Self::EmptyMessage => "empty message",
            Self::InvalidFragmentLength => "invalid fragment length",
            Self::MessageTooLong => "message too long",
            Self::NotSinglePart => "expected single-part UR",
            Self::CborDecode => "dCBOR decode failed",
            Self::CborType => "dCBOR type mismatch",
            Self::Internal => "internal error",
        }
    }
}

#[derive(Debug, Clone)]
enum Detail {
    None,
    Limit(Limit),
    UnexpectedType {
        expected: Vec<UrType>,
        found: UrType,
    },
    #[cfg(feature = "dcbor")]
    Cbor {
        source: Arc<dcbor::Error>,
    },
}

/// Errors that can occur while encoding or decoding Uniform Resources.
///
/// Opaque: match on [`Self::kind`] (a `#[non_exhaustive]` [`ErrorKind`]) and
/// read details through [`Self::limit`], [`Self::expected_types`], and
/// [`Self::found_type`].
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    detail: Detail,
}

impl Error {
    /// Error kind.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether this error is session-fatal for a decoder (the decoder enters
    /// the failed state).
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::ResourceLimit
                | ErrorKind::InvalidPadding
                | ErrorKind::InvalidMessageChecksum
                | ErrorKind::Internal
        )
    }

    /// The exceeded budget, for [`ErrorKind::ResourceLimit`].
    #[must_use]
    pub const fn limit(&self) -> Option<Limit> {
        match &self.detail {
            Detail::Limit(limit) => Some(*limit),
            _ => None,
        }
    }

    /// Accepted types, for [`ErrorKind::UnexpectedType`]; empty otherwise.
    #[must_use]
    pub fn expected_types(&self) -> &[UrType] {
        match &self.detail {
            Detail::UnexpectedType { expected, .. } => expected,
            _ => &[],
        }
    }

    /// The mismatched type, for [`ErrorKind::UnexpectedType`].
    #[must_use]
    pub const fn found_type(&self) -> Option<&UrType> {
        match &self.detail {
            Detail::UnexpectedType { found, .. } => Some(found),
            _ => None,
        }
    }

    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            detail: Detail::None,
        }
    }

    pub(crate) const fn internal() -> Self {
        Self::new(ErrorKind::Internal)
    }

    pub(crate) const fn resource_limit(limit: Limit) -> Self {
        Self {
            kind: ErrorKind::ResourceLimit,
            detail: Detail::Limit(limit),
        }
    }

    pub(crate) const fn unexpected_type(expected: Vec<UrType>, found: UrType) -> Self {
        Self {
            kind: ErrorKind::UnexpectedType,
            detail: Detail::UnexpectedType { expected, found },
        }
    }

    /// `kind` must be [`ErrorKind::CborDecode`] or [`ErrorKind::CborType`].
    #[cfg(feature = "dcbor")]
    pub(crate) fn cbor(kind: ErrorKind, source: dcbor::Error) -> Self {
        Self {
            kind,
            detail: Detail::Cbor {
                source: Arc::new(source),
            },
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match (&self.detail, &other.detail) {
            (Detail::None, Detail::None) => true,
            (Detail::Limit(a), Detail::Limit(b)) => a == b,
            (
                Detail::UnexpectedType {
                    expected: ae,
                    found: af,
                },
                Detail::UnexpectedType {
                    expected: be,
                    found: bf,
                },
            ) => ae == be && af == bf,
            #[cfg(feature = "dcbor")]
            (Detail::Cbor { .. }, Detail::Cbor { .. }) => true,
            #[allow(unreachable_patterns, reason = "dcbor-gated variants")]
            _ => false,
        }
    }
}

impl Eq for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.detail {
            Detail::Limit(limit) => {
                write!(f, "{}: {}", self.kind.message(), limit.as_str())
            }
            Detail::UnexpectedType { expected, found } => {
                let expected = expected
                    .iter()
                    .map(UrType::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "{}: expected {expected}, found {}",
                    self.kind.message(),
                    found.as_str()
                )
            }
            Detail::None => f.write_str(self.kind.message()),
            #[cfg(feature = "dcbor")]
            Detail::Cbor { .. } => f.write_str(self.kind.message()),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.detail {
            #[cfg(feature = "dcbor")]
            Detail::Cbor { source } => Some(&**source),
            _ => None,
        }
    }
}

/// Fail-closed decoder poison. Not re-exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Poison {
    Limit(Limit),
    Internal,
}

impl Poison {
    pub(crate) const fn to_error(self) -> Error {
        match self {
            Self::Limit(limit) => Error::resource_limit(limit),
            Self::Internal => Error::internal(),
        }
    }
}

/// Result alias for `bcur` operations.
pub type Result<T> = core::result::Result<T, Error>;
