//! Registry validation error type.

use core::fmt;

/// Why a registry value failed validation.
///
/// In the dcbor decode path the kinds map through
/// `From<Error> for dcbor::Error`: [`ErrorKind::InvalidValue`] becomes
/// `dcbor::Error::WrongType` and every other kind becomes
/// `dcbor::Error::OutOfRange`, matching the TypeScript `CborError` classes
/// (`wrongType` / `outOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A length fell outside the allowed range.
    InvalidLength,
    /// A numeric value fell outside the allowed range.
    OutOfRange,
    /// A value had the right shape but was semantically invalid.
    InvalidValue,
    /// A descriptor placeholder was invalid (reserved for descriptor types).
    InvalidPlaceholder,
}

/// Validation error raised by registry constructors.
///
/// Carries the failure [`ErrorKind`] plus the name of the offending field.
/// dcbor structural failures (unknown map key, wrong CBOR type, missing key)
/// use `dcbor::Error` directly and never surface as this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    kind: ErrorKind,
    field: &'static str,
}

impl Error {
    /// Creates an error for `field` with `kind`.
    #[must_use]
    pub const fn new(kind: ErrorKind, field: &'static str) -> Self {
        Self { kind, field }
    }

    /// The failure category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The name of the field that failed validation.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            ErrorKind::InvalidLength => "invalid length",
            ErrorKind::OutOfRange => "out of range",
            ErrorKind::InvalidValue => "invalid value",
            ErrorKind::InvalidPlaceholder => "invalid placeholder",
        };
        write!(f, "{}: {reason}", self.field)
    }
}

impl core::error::Error for Error {}

impl From<Error> for dcbor::Error {
    fn from(error: Error) -> Self {
        match error.kind {
            ErrorKind::InvalidValue => Self::WrongType,
            _ => Self::OutOfRange,
        }
    }
}

/// Registry result type.
pub type Result<T> = core::result::Result<T, Error>;
