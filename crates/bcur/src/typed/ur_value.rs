//! [`Ur`] value object: validated type plus untagged dCBOR payload.

use std::fmt;
use std::str::FromStr;

use dcbor::CBOR;

use super::map_cbor;
use crate::error::ErrorKind;
use crate::fountain::EncoderOptions;
use crate::ur::{self, ParsedUr};
use crate::{DecoderLimits, Error, Result, UrType};

/// A Uniform Resource whose payload is deterministic CBOR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ur {
    ur_type: UrType,
    cbor: CBOR,
}

impl Ur {
    /// Builds a UR from a validated type and a dCBOR value.
    #[must_use]
    pub fn new(ur_type: UrType, cbor: impl Into<CBOR>) -> Self {
        Self {
            ur_type,
            cbor: cbor.into(),
        }
    }

    /// Builds a UR from a validated type and serialized dCBOR data.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::CborDecode`] if `data` is not deterministic CBOR.
    pub fn from_cbor_data(ur_type: UrType, data: &[u8]) -> Result<Self> {
        let cbor = map_cbor(CBOR::try_from_data(data), ErrorKind::CborDecode)?;
        Ok(Self::new(ur_type, cbor))
    }

    /// Validated UR type.
    #[must_use]
    pub const fn ur_type(&self) -> &UrType {
        &self.ur_type
    }

    /// Borrow the untagged dCBOR payload.
    #[must_use]
    pub const fn cbor(&self) -> &CBOR {
        &self.cbor
    }

    /// Consume the UR and return the dCBOR payload.
    #[must_use]
    pub fn into_cbor(self) -> CBOR {
        self.cbor
    }

    /// Serialized dCBOR payload.
    #[must_use]
    pub fn to_cbor_data(&self) -> Vec<u8> {
        self.cbor.to_cbor_data()
    }

    /// Uppercase form of the single-part URI for QR payloads.
    #[must_use]
    pub fn to_qr_string(&self) -> String {
        ur::to_qr_string(&self.to_string())
    }

    /// UR-string encoder for this value's dCBOR payload (repeating
    /// single-part when `K == 1`, fountain otherwise).
    ///
    /// # Errors
    ///
    /// Propagates fountain construction errors ([`ErrorKind::EmptyMessage`],
    /// [`ErrorKind::InvalidFragmentLength`], [`ErrorKind::MessageTooLong`]).
    pub fn encoder(&self, options: EncoderOptions) -> Result<ur::Encoder> {
        ur::Encoder::new(self.ur_type.clone(), self.to_cbor_data(), options)
    }
}

impl fmt::Display for Ur {
    /// Single-part `ur:<type>/<bytewords>` string (lowercase).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&ur::encode(&self.ur_type, &self.to_cbor_data()))
    }
}

impl FromStr for Ur {
    type Err = Error;

    /// Parses a **single-part** UR string into typed dCBOR (case-insensitive;
    /// QR uppercase accepted).
    ///
    /// # Errors
    ///
    /// Transport parse/decode errors, [`ErrorKind::NotSinglePart`] for
    /// multi-part URIs, or [`ErrorKind::CborDecode`] if the payload is not
    /// dCBOR.
    fn from_str(s: &str) -> Result<Self> {
        match ur::parse(s, &DecoderLimits::default())? {
            ParsedUr::Single { ur_type, message } => Self::from_cbor_data(ur_type, &message),
            ParsedUr::Multi { .. } => Err(Error::new(ErrorKind::NotSinglePart)),
        }
    }
}

impl TryFrom<ur::Decoded> for Ur {
    type Error = Error;

    /// dCBOR-checks the decoded message (UR-ADR-031).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::CborDecode`] when the payload is not deterministic CBOR.
    fn try_from(decoded: ur::Decoded) -> Result<Self> {
        let (ur_type, message) = decoded.into_parts();
        Self::from_cbor_data(ur_type, &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytewords::{self, Style};
    use crate::ur_type;

    const GOLDEN: &str = "ur:test/lsadaoaxjygonesw";

    #[test]
    fn array_123_matches_published_golden() {
        let ur = Ur::new(ur_type!("test"), vec![1, 2, 3]);
        assert_eq!(ur.to_string(), GOLDEN);
        assert_eq!(ur.ur_type().as_str(), "test");

        let parsed = Ur::from_str(GOLDEN).unwrap();
        assert_eq!(parsed, ur);
        assert_eq!(parsed.cbor(), ur.cbor());

        let upper = Ur::from_str("UR:TEST/LSADAOAXJYGONESW").unwrap();
        assert_eq!(upper, ur);
        assert_eq!(ur.to_qr_string(), "UR:TEST/LSADAOAXJYGONESW");
    }

    #[test]
    fn rejects_illegal_types() {
        assert_eq!(
            UrType::new("Bad_Type").unwrap_err().kind(),
            ErrorKind::InvalidType
        );
    }

    #[test]
    fn from_str_rejects_multipart_and_bad_cbor() {
        let ur = Ur::new(ur_type!("test"), (0_u8..64).collect::<Vec<_>>());
        let mut encoder = ur.encoder(EncoderOptions::new(12)).unwrap();
        let part = encoder.next().unwrap();
        assert_eq!(
            Ur::from_str(&part).unwrap_err().kind(),
            ErrorKind::NotSinglePart
        );

        let body = bytewords::encode(&[0xff, 0xff], Style::Minimal);
        let uri = format!("ur:test/{body}");
        assert!(matches!(
            Ur::from_str(&uri).unwrap_err(),
            ref e if e.kind() == ErrorKind::CborDecode
        ));
    }

    #[test]
    fn from_cbor_data_and_into_cbor() {
        let ur = Ur::new(ur_type!("test"), vec![1, 2, 3]);
        let data = ur.to_cbor_data();
        let rebuilt = Ur::from_cbor_data(ur_type!("test"), &data).unwrap();
        assert_eq!(rebuilt, ur);
        assert!(matches!(
            Ur::from_cbor_data(ur_type!("test"), &[0xff, 0xff]).unwrap_err(),
            ref e if e.kind() == ErrorKind::CborDecode
        ));
        let cbor = ur.clone().into_cbor();
        assert_eq!(cbor, *ur.cbor());
    }
}
