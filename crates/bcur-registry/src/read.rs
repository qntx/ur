//! dCBOR value readers. Structural failures surface as [`Error::Cbor`]
//! (`WrongType`); semantic failures carry the offending field name.

use dcbor::{CBOR, CBORCase, Map};

use crate::{Error, Result};

/// Inclusive upper bound of a `uint31` (`0x7fffffff`).
pub(crate) const UINT31_MAX: u32 = 0x7fff_ffff;

/// A closed registry map: every key is an unsigned integer on the allowlist.
pub(crate) struct MapReader(Map);

impl MapReader {
    /// Reads `cbor` as a map whose unsigned keys are all in `allowed`.
    ///
    /// # Errors
    ///
    /// `Error::Cbor`(`WrongType`) when `cbor` is not a map or a key is not
    /// an unsigned integer; [`Error::UnknownKey`] for a key off the list.
    pub(crate) fn closed(cbor: &CBOR, allowed: &[u64]) -> Result<Self> {
        let map = cbor.clone().try_into_map()?;
        for (key, _) in map.iter() {
            match key.as_case() {
                CBORCase::Unsigned(n) if allowed.contains(n) => {}
                CBORCase::Unsigned(n) => return Err(Error::UnknownKey { key: *n }),
                _ => return Err(Error::Cbor(dcbor::Error::WrongType)),
            }
        }
        Ok(Self(map))
    }

    /// The value at `key` ([`Error::MissingKey`] when absent).
    pub(crate) fn required(&self, key: u64) -> Result<CBOR> {
        self.optional(key).ok_or(Error::MissingKey { key })
    }

    /// The value at `key`, when present.
    pub(crate) fn optional(&self, key: u64) -> Option<CBOR> {
        let key = i32::try_from(key).ok()?;
        self.0.get::<i32, CBOR>(key)
    }
}

/// Unwraps a tagged value whose tag is in `expected`; returns the content.
///
/// # Errors
///
/// [`Error::UnexpectedTag`] for a foreign tag; `Error::Cbor`(`WrongType`)
/// when the value is not tagged.
pub(crate) fn untag(cbor: CBOR, expected: &[dcbor::Tag]) -> Result<CBOR> {
    match cbor.into_case() {
        CBORCase::Tagged(tag, item) if expected.contains(&tag) => Ok(item),
        CBORCase::Tagged(tag, _) => Err(Error::UnexpectedTag { tag: tag.value() }),
        _ => Err(Error::Cbor(dcbor::Error::WrongType)),
    }
}

/// An unsigned integer (`Cbor(WrongType)` for other major types).
pub(crate) fn uint(cbor: &CBOR) -> Result<u64> {
    match cbor.as_case() {
        CBORCase::Unsigned(n) => Ok(*n),
        _ => Err(Error::Cbor(dcbor::Error::WrongType)),
    }
}

/// An unsigned integer bounded by `max` (`OutOfRange` above it).
pub(crate) fn uint_below(cbor: &CBOR, field: &'static str, max: u64) -> Result<u64> {
    let n = uint(cbor)?;
    if n > max {
        return Err(Error::OutOfRange { field });
    }
    Ok(n)
}

/// A `uint8`.
pub(crate) fn uint8(cbor: &CBOR, field: &'static str) -> Result<u8> {
    u8::try_from(uint_below(cbor, field, u64::from(u8::MAX))?)
        .map_err(|_| Error::OutOfRange { field })
}

/// A `uint31`.
pub(crate) fn uint31(cbor: &CBOR, field: &'static str) -> Result<u32> {
    u32::try_from(uint_below(cbor, field, u64::from(UINT31_MAX))?)
        .map_err(|_| Error::OutOfRange { field })
}

/// A `uint32` that must not be zero.
pub(crate) fn uint32_ne0(cbor: &CBOR, field: &'static str) -> Result<u32> {
    let n = uint_below(cbor, field, u64::from(u32::MAX))?;
    let v = u32::try_from(n).map_err(|_| Error::OutOfRange { field })?;
    if v == 0 {
        return Err(Error::OutOfRange { field });
    }
    Ok(v)
}

/// A signed integer within `i32` range (`Cbor(WrongType)` for non-integers).
pub(crate) fn int32(cbor: &CBOR, field: &'static str) -> Result<i32> {
    let v = match cbor.as_case() {
        CBORCase::Unsigned(n) => i128::from(*n),
        CBORCase::Negative(n) => -1 - i128::from(*n),
        _ => return Err(Error::Cbor(dcbor::Error::WrongType)),
    };
    i32::try_from(v).map_err(|_| Error::OutOfRange { field })
}

/// A signed integer within `i64` range (`Cbor(WrongType)` for non-integers).
pub(crate) fn int64(cbor: &CBOR) -> Result<i64> {
    let v = match cbor.as_case() {
        CBORCase::Unsigned(n) => i128::from(*n),
        CBORCase::Negative(n) => -1 - i128::from(*n),
        _ => return Err(Error::Cbor(dcbor::Error::WrongType)),
    };
    i64::try_from(v).map_err(|_| Error::OutOfRange { field: "value" })
}

/// A boolean (`Cbor(WrongType)` otherwise).
pub(crate) fn boolean(cbor: &CBOR) -> Result<bool> {
    cbor.clone().try_into_bool().map_err(Error::from)
}

/// A text string (`Cbor(WrongType)` otherwise).
pub(crate) fn text(cbor: &CBOR) -> Result<String> {
    cbor.clone().try_into_text().map_err(Error::from)
}

/// A byte string, copied (`Cbor(WrongType)` otherwise).
pub(crate) fn bytes(cbor: &CBOR) -> Result<Vec<u8>> {
    cbor.clone().try_into_byte_string().map_err(Error::from)
}

/// A byte string of exactly `N` bytes (`InvalidLength` otherwise).
pub(crate) fn bytes_fixed<const N: usize>(cbor: &CBOR, field: &'static str) -> Result<[u8; N]> {
    let bytes = bytes(cbor)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| Error::InvalidLength { field, len })
}

/// An array, copied (`Cbor(WrongType)` otherwise).
pub(crate) fn array(cbor: &CBOR) -> Result<Vec<CBOR>> {
    cbor.clone().try_into_array().map_err(Error::from)
}
