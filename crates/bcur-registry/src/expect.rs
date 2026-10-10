//! dcbor extraction helpers mirroring the TypeScript `map.ts` semantics.
//! Structural failures raise `dcbor::Error` directly (`WrongType`,
//! `OutOfRange`, `MissingMapKey`); semantic validation is the types' job.

use core::num::NonZeroU32;

use dcbor::{CBOR, CBORCase, Map};

/// Inclusive upper bound of a `uint31` (`0x7fffffff`).
pub(crate) const UINT31_MAX: u32 = 0x7fff_ffff;

/// `expectUnsigned`: unsigned major type only (`WrongType` otherwise).
pub(crate) fn expect_unsigned(cbor: &CBOR) -> dcbor::Result<u64> {
    match cbor.as_case() {
        CBORCase::Unsigned(n) => Ok(*n),
        _ => Err(dcbor::Error::WrongType),
    }
}

/// `expectUint`: unsigned with an inclusive upper bound (`OutOfRange` above it).
pub(crate) fn expect_uint(cbor: &CBOR, max: u64) -> dcbor::Result<u64> {
    let n = expect_unsigned(cbor)?;
    if n > max {
        return Err(dcbor::Error::OutOfRange);
    }
    Ok(n)
}

/// `expectUint8`.
pub(crate) fn expect_uint8(cbor: &CBOR) -> dcbor::Result<u8> {
    let n = expect_uint(cbor, u64::from(u8::MAX))?;
    u8::try_from(n).map_err(|_| dcbor::Error::OutOfRange)
}

/// `expectUint31`.
pub(crate) fn expect_uint31(cbor: &CBOR) -> dcbor::Result<u32> {
    let n = expect_uint(cbor, u64::from(UINT31_MAX))?;
    u32::try_from(n).map_err(|_| dcbor::Error::OutOfRange)
}

/// `expectUint32Ne0`: nonzero `u32` (`OutOfRange` on 0 or above `u32::MAX`).
pub(crate) fn expect_uint32_ne0(cbor: &CBOR) -> dcbor::Result<NonZeroU32> {
    let n = expect_uint(cbor, u64::from(u32::MAX))?;
    let v = u32::try_from(n).map_err(|_| dcbor::Error::OutOfRange)?;
    NonZeroU32::new(v).ok_or(dcbor::Error::OutOfRange)
}

/// `expectInt32`: unsigned or negative major type within `i32` range
/// (`OutOfRange` outside, `WrongType` for non-integers).
pub(crate) fn expect_int32(cbor: &CBOR) -> dcbor::Result<i32> {
    let v = match cbor.as_case() {
        CBORCase::Unsigned(n) => i128::from(*n),
        CBORCase::Negative(n) => -1 - i128::from(*n),
        _ => return Err(dcbor::Error::WrongType),
    };
    i32::try_from(v).map_err(|_| dcbor::Error::OutOfRange)
}

/// `expectInteger`: unsigned or negative major type within `i64` range
/// (`OutOfRange` outside, `WrongType` for non-integers).
pub(crate) fn expect_int64(cbor: &CBOR) -> dcbor::Result<i64> {
    let v = match cbor.as_case() {
        CBORCase::Unsigned(n) => i128::from(*n),
        CBORCase::Negative(n) => -1 - i128::from(*n),
        _ => return Err(dcbor::Error::WrongType),
    };
    i64::try_from(v).map_err(|_| dcbor::Error::OutOfRange)
}

/// `expectBoolean`.
pub(crate) fn expect_bool(cbor: &CBOR) -> dcbor::Result<bool> {
    cbor.clone().try_into_bool()
}

/// `expectText`.
pub(crate) fn expect_text(cbor: &CBOR) -> dcbor::Result<String> {
    cbor.clone().try_into_text()
}

/// `expectBytes`: copies the byte string.
pub(crate) fn expect_bytes(cbor: &CBOR) -> dcbor::Result<Vec<u8>> {
    cbor.clone().try_into_byte_string()
}

/// `expectArray`.
pub(crate) fn expect_array(cbor: &CBOR) -> dcbor::Result<Vec<CBOR>> {
    cbor.clone().try_into_array()
}

/// Fixed-length byte string (`OutOfRange` on length mismatch).
pub(crate) fn expect_bytes_len<const N: usize>(
    cbor: &CBOR,
    field: &'static str,
) -> dcbor::Result<[u8; N]> {
    let bytes = expect_bytes(cbor)?;
    bytes
        .try_into()
        .map_err(|_| crate::Error::new(crate::ErrorKind::InvalidLength, field).into())
}

/// `map.get(key)` returning the raw CBOR.
pub(crate) fn get(map: &Map, key: i32) -> Option<CBOR> {
    map.get::<i32, CBOR>(key)
}

/// `map.getOrThrow(key)` (`MissingMapKey` when absent).
pub(crate) fn extract(map: &Map, key: i32) -> dcbor::Result<CBOR> {
    map.extract::<i32, CBOR>(key)
}

/// `expectClosedIntMap`: the value is a map and every key is an unsigned
/// integer listed in `allowed` (`WrongType` otherwise).
pub(crate) fn closed_int_map(cbor: &CBOR, allowed: &[u64]) -> dcbor::Result<Map> {
    let map = cbor.clone().try_into_map()?;
    for (key, _) in map.iter() {
        match key.as_case() {
            CBORCase::Unsigned(n) if allowed.contains(n) => {}
            _ => return Err(dcbor::Error::WrongType),
        }
    }
    Ok(map)
}
