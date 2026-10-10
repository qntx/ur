//! Fixed-schema CBOR codec for fountain [`Part`](super::Part) (5-element array).
//!
//! Wire layout: `array(5) [ sequence:u32, sequence_count:u32, message_len:u32,
//! checksum:u32, data:bstr ]`.
//!
//! Encoding is always shortest-form. Decoding is lenient about integer widths:
//! the array header, uint fields, and bstr length accept any definite-width
//! encoding (UR-ADR-017); tags, indefinite lengths, other major types,
//! overflows, truncation, and trailing bytes are rejected.

use alloc::vec::Vec;

use super::{DecoderLimits, Part};
use crate::error::{Error, ErrorKind, Limit, Result};

/// Encodes a part to deterministic (shortest-form) CBOR bytes.
#[must_use]
pub(crate) fn encode_part(part: &Part) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + part.data().len());
    out.push(0x85); // array of 5
    encode_u32(&mut out, part.sequence());
    encode_u32(&mut out, part.sequence_count());
    encode_u32(&mut out, part.message_len());
    encode_u32(&mut out, part.checksum());
    encode_bstr(&mut out, part.data());
    out
}

/// Decodes a part from CBOR, enforcing `limits` and semantic validation.
pub(crate) fn decode_part(bytes: &[u8], limits: &DecoderLimits) -> Result<Part> {
    decode_part_inner(bytes, Some(limits))
}

/// Decodes a part without the resource caps; used where the input is already
/// bounded by `max_uri_length` (the UR decoder).
pub(crate) fn decode_part_unlimited(bytes: &[u8]) -> Result<Part> {
    decode_part_inner(bytes, None)
}

fn decode_part_inner(bytes: &[u8], limits: Option<&DecoderLimits>) -> Result<Part> {
    let mut i = 0;
    let head = next_byte(bytes, &mut i)?;
    let array_len = decode_argument(head, &mut i, bytes)?;
    if head >> 5 != 4 || array_len != 5 {
        return Err(Error::new(ErrorKind::InvalidPartCbor));
    }
    let sequence = decode_u32(bytes, &mut i)?;
    let sequence_count = decode_u32(bytes, &mut i)?;
    let message_len = decode_u32(bytes, &mut i)?;
    let checksum = decode_u32(bytes, &mut i)?;
    let data = decode_bstr(bytes, &mut i, limits.map(|l| l.max_fragment_length))?;
    if i != bytes.len() {
        return Err(Error::new(ErrorKind::InvalidPartCbor));
    }
    let part = Part::new(sequence, sequence_count, message_len, checksum, data)?;
    if limits.is_some_and(|l| {
        usize::try_from(part.sequence_count()).unwrap_or(usize::MAX) > l.max_fragment_count
    }) {
        return Err(Error::resource_limit(Limit::FragmentCount));
    }
    Ok(part)
}

/// Reads the additional-information argument for `head` in any width
/// (`ai` 0..=27). Returns `None` for `ai` 28..=31 (indefinite/reserved).
fn decode_argument(head: u8, i: &mut usize, bytes: &[u8]) -> Result<u64> {
    match head & 0x1f {
        n @ 0..=23 => Ok(u64::from(n)),
        24 => Ok(u64::from(next_byte(bytes, i)?)),
        25 => {
            let b0 = next_byte(bytes, i)?;
            let b1 = next_byte(bytes, i)?;
            Ok(u64::from(u16::from_be_bytes([b0, b1])))
        }
        26 => {
            let b0 = next_byte(bytes, i)?;
            let b1 = next_byte(bytes, i)?;
            let b2 = next_byte(bytes, i)?;
            let b3 = next_byte(bytes, i)?;
            Ok(u64::from(u32::from_be_bytes([b0, b1, b2, b3])))
        }
        27 => {
            let mut buf = [0_u8; 8];
            for slot in &mut buf {
                *slot = next_byte(bytes, i)?;
            }
            Ok(u64::from_be_bytes(buf))
        }
        _ => Err(Error::new(ErrorKind::InvalidPartCbor)),
    }
}

fn decode_u32(bytes: &[u8], i: &mut usize) -> Result<u32> {
    let head = next_byte(bytes, i)?;
    if head >> 5 != 0 {
        return Err(Error::new(ErrorKind::InvalidPartCbor));
    }
    u32::try_from(decode_argument(head, i, bytes)?)
        .map_err(|_| Error::new(ErrorKind::InvalidPartCbor))
}

fn decode_bstr(bytes: &[u8], i: &mut usize, max_len: Option<usize>) -> Result<Vec<u8>> {
    let head = next_byte(bytes, i)?;
    if head >> 5 != 2 {
        return Err(Error::new(ErrorKind::InvalidPartCbor));
    }
    let len = usize::try_from(decode_argument(head, i, bytes)?)
        .map_err(|_| Error::new(ErrorKind::InvalidPartCbor))?;
    if max_len.is_some_and(|max| len > max) {
        return Err(Error::resource_limit(Limit::FragmentLength));
    }
    let end = i
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidPartCbor))?;
    let slice = bytes
        .get(*i..end)
        .ok_or_else(|| Error::new(ErrorKind::InvalidPartCbor))?;
    *i = end;
    Ok(slice.to_vec())
}

fn encode_u32(out: &mut Vec<u8>, v: u32) {
    if v <= 23 {
        #[allow(clippy::cast_possible_truncation, reason = "v is checked <= 23")]
        {
            out.push(v as u8);
        }
    } else if v <= 0xff {
        out.push(0x18);
        #[allow(clippy::cast_possible_truncation, reason = "v is checked <= 0xff")]
        {
            out.push(v as u8);
        }
    } else if v <= 0xffff {
        out.push(0x19);
        #[allow(clippy::cast_possible_truncation, reason = "v is checked <= 0xffff")]
        {
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    } else {
        out.push(0x1a);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn encode_bstr(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 23 {
        #[allow(clippy::cast_possible_truncation, reason = "len is checked <= 23")]
        {
            out.push(0x40 | (len as u8));
        }
    } else if len <= 0xff {
        out.push(0x58);
        #[allow(clippy::cast_possible_truncation, reason = "len is checked <= 0xff")]
        {
            out.push(len as u8);
        }
    } else if len <= 0xffff {
        out.push(0x59);
        #[allow(clippy::cast_possible_truncation, reason = "len is checked <= 0xffff")]
        {
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    } else {
        out.push(0x5a);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "bstr lengths used here fit u32 (fragment data is capped)"
        )]
        {
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(data);
}

fn next_byte(bytes: &[u8], i: &mut usize) -> Result<u8> {
    let b = *bytes
        .get(*i)
        .ok_or_else(|| Error::new(ErrorKind::InvalidPartCbor))?;
    *i += 1;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part() -> Part {
        Part::new(
            1,
            9,
            256,
            23_570_951,
            hex::decode("916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_golden() {
        let cbor = encode_part(&part());
        assert_eq!(
            hex::encode(&cbor),
            "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c"
        );
        let decoded = decode_part(&cbor, &DecoderLimits::default()).unwrap();
        assert_eq!(decoded, part());
    }

    #[test]
    fn accepts_non_shortest_integers() {
        // array(5) with sequence encoded as 0x18 0x01 (non-shortest for 1)
        let cbor = hex::decode(
            "851801091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
        )
        .unwrap();
        assert_eq!(
            decode_part(&cbor, &DecoderLimits::default()).unwrap(),
            part()
        );
        // 8-byte uint encoding of 1
        let cbor_wide = hex::decode(
            "851b0000000000000001091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
        )
        .unwrap();
        assert_eq!(
            decode_part(&cbor_wide, &DecoderLimits::default()).unwrap(),
            part()
        );
    }

    #[test]
    fn rejects_invalid_schema() {
        // tag(5)
        assert_eq!(
            decode_part(&hex::decode("c505").unwrap(), &DecoderLimits::default())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidPartCbor
        );
        // indefinite array
        assert_eq!(
            decode_part(
                &hex::decode("9f01010101ff").unwrap(),
                &DecoderLimits::default()
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidPartCbor
        );
        // uint64 value over u32
        assert_eq!(
            decode_part(
                &hex::decode("851b00000001000000000101014100").unwrap(),
                &DecoderLimits::default()
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidPartCbor
        );
        // truncated
        assert_eq!(
            decode_part(&hex::decode("8501").unwrap(), &DecoderLimits::default())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidPartCbor
        );
    }

    #[test]
    fn rejects_zero_fields() {
        // [0, 1, 1, 0, h'00']
        assert_eq!(
            decode_part(
                &hex::decode("85000101004100").unwrap(),
                &DecoderLimits::default()
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidPart
        );
        // [1, 0, 1, 0, h'00']
        assert_eq!(
            decode_part(
                &hex::decode("85010001004100").unwrap(),
                &DecoderLimits::default()
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidPart
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut cbor = encode_part(&part());
        cbor.push(0x00);
        assert_eq!(
            decode_part(&cbor, &DecoderLimits::default())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidPartCbor
        );
    }

    #[test]
    fn rejects_oversized_data() {
        let part = Part::new(1, 1, 32, 0, alloc::vec![0; 32]).unwrap();
        let cbor = encode_part(&part);
        let limits = DecoderLimits {
            max_fragment_length: 16,
            ..DecoderLimits::default()
        };
        let err = decode_part(&cbor, &limits).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ResourceLimit);
        assert_eq!(err.limit(), Some(Limit::FragmentLength));
    }

    #[test]
    fn rejects_oversize_fragment_count() {
        let part = Part::new(1, 9, 17, 0, alloc::vec![0xab; 2]).unwrap();
        let cbor = encode_part(&part);
        let limits = DecoderLimits {
            max_fragment_count: 8,
            ..DecoderLimits::default()
        };
        let err = decode_part(&cbor, &limits).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ResourceLimit);
        assert_eq!(err.limit(), Some(Limit::FragmentCount));
    }
}
