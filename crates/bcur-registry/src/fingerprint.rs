//! `Fingerprint`: the 4-byte key identifier used across BCR-2020-007.

use core::fmt;
use core::str::FromStr;

use crate::{Error, Result};

/// A 4-byte key fingerprint (`source-fingerprint` / `parent-fingerprint` /
/// `master-fingerprint` on the wire).
///
/// The all-zero value is representable: [`crate::Keypath`] and
/// [`crate::DerivedKey`] reject it (`uint32 .ne 0` in BCR-2020-007) while
/// [`crate::AccountDescriptor`] accepts it (BCR-2023-019).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 4]);

impl Fingerprint {
    /// The fingerprint bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0
    }
}

impl From<[u8; 4]> for Fingerprint {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Fingerprint {
    /// Eight lowercase hex digits (`d973bee1`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    /// Parses eight hexadecimal digits (either case).
    fn from_str(text: &str) -> Result<Self> {
        const REASON: &str = "expected 8 hexadecimal digits";
        let invalid = || Error::Invalid {
            field: "fingerprint",
            reason: REASON,
        };
        let bytes = hex::decode(text).map_err(|_| invalid())?;
        Ok(Self(bytes.try_into().map_err(|_| invalid())?))
    }
}
