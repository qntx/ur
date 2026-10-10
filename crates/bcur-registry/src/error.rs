//! Registry error type.

use core::fmt;

/// Registry validation and decode error.
///
/// Carries enough context to stand alone: the failing CBOR map key or tag,
/// the field name, or the offending value's length. `Cbor` wraps a
/// structural [`dcbor::Error`] (wrong major type, malformed input) and is the
/// only variant with a `source()`.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A structural dCBOR failure (wrong major type, malformed input).
    Cbor(dcbor::Error),
    /// A map key outside the type's closed key set.
    UnknownKey {
        /// The unexpected key.
        key: u64,
    },
    /// A required map key was absent.
    MissingKey {
        /// The missing key.
        key: u64,
    },
    /// A CBOR tag the type does not accept.
    UnexpectedTag {
        /// The unexpected tag value.
        tag: u64,
    },
    /// A byte or item count fell outside the allowed range.
    InvalidLength {
        /// The field that failed.
        field: &'static str,
        /// The offending length.
        len: usize,
    },
    /// A numeric value fell outside the allowed range.
    OutOfRange {
        /// The field that failed.
        field: &'static str,
    },
    /// A value had the right shape but was semantically invalid.
    Invalid {
        /// The field that failed.
        field: &'static str,
        /// Why the value is invalid.
        reason: &'static str,
    },
    /// The `@n` placeholders were not exactly the set `0..keys.len()`.
    Placeholders,
    /// A script expression that cannot be represented (unknown tag or
    /// disallowed nesting).
    UnsupportedScript {
        /// The offending script-expression tag.
        tag: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The dcbor error is exposed through `source()`, not repeated here.
            Self::Cbor(_) => f.write_str("malformed dCBOR"),
            Self::UnknownKey { key } => write!(f, "unknown map key {key}"),
            Self::MissingKey { key } => write!(f, "missing map key {key}"),
            Self::UnexpectedTag { tag } => write!(f, "unexpected tag {tag}"),
            Self::InvalidLength { field, len } => {
                write!(f, "{field} length {len} is outside the allowed range")
            }
            Self::OutOfRange { field } => write!(f, "{field} is out of range"),
            Self::Invalid { field, reason } => write!(f, "{field} is invalid: {reason}"),
            Self::Placeholders => f.write_str("placeholders are not exactly the set 0..keys.len()"),
            Self::UnsupportedScript { tag } => {
                write!(f, "script expression tag {tag} is not supported here")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(source) => Some(source),
            _ => None,
        }
    }
}

impl From<dcbor::Error> for Error {
    fn from(source: dcbor::Error) -> Self {
        Self::Cbor(source)
    }
}

impl From<Error> for dcbor::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Cbor(source) => source,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Registry result type.
pub type Result<T> = core::result::Result<T, Error>;
