//! Encode/decode traits for tagged dCBOR types.

use dcbor::{CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable};

use super::{Ur, map_cbor};
use crate::error::ErrorKind;
use crate::{Error, Result, UrType};

/// Valid UR types for `T`: every `cbor_tags()` name must be a valid type token.
fn tag_ur_types<T: CBORTagged>() -> Result<Vec<UrType>> {
    T::cbor_tags()
        .iter()
        .map(|tag| {
            let name = tag
                .name()
                .ok_or_else(|| Error::new(ErrorKind::InvalidType))?;
            UrType::new(&name)
        })
        .collect()
}

/// First registered CBOR tag name, validated as a UR type.
fn first_tag_ur_type<T: CBORTagged>() -> Result<UrType> {
    let name = T::cbor_tags()
        .first()
        .and_then(dcbor::Tag::name)
        .ok_or_else(|| Error::new(ErrorKind::InvalidType))?;
    UrType::new(&name)
}

/// Encode as a UR using the first registered CBOR tag **name** as the type.
///
/// The payload is **untagged** dCBOR. Missing or unnamed tags yield
/// [`ErrorKind::InvalidType`] — this method never panics.
pub trait UrEncodable {
    /// Typed UR for this value.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidType`] if the first `cbor_tags()` entry has no name
    /// or the name is not a valid UR type token.
    fn to_ur(&self) -> Result<Ur>;
}

/// Decode from a typed UR using untagged dCBOR.
pub trait UrDecodable: Sized {
    /// Decode from an already-parsed UR.
    ///
    /// The UR type must match the **name** of one of `cbor_tags()` (any
    /// registered alias is accepted).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidType`] if no `cbor_tags()` entry is named;
    /// [`ErrorKind::UnexpectedType`] if the UR type matches none of the tag
    /// names; [`ErrorKind::CborType`] if untagged decode fails.
    fn from_ur(ur: &Ur) -> Result<Self>;
}

impl<T: CBORTaggedEncodable> UrEncodable for T {
    fn to_ur(&self) -> Result<Ur> {
        Ok(Ur::new(first_tag_ur_type::<T>()?, self.untagged_cbor()))
    }
}

impl<T: CBORTaggedDecodable> UrDecodable for T {
    fn from_ur(ur: &Ur) -> Result<Self> {
        let expected = tag_ur_types::<T>()?;
        if expected.is_empty() {
            return Err(Error::new(ErrorKind::InvalidType));
        }
        if !expected.iter().any(|t| t == ur.ur_type()) {
            return Err(Error::unexpected_type(expected, ur.ur_type().clone()));
        }
        map_cbor(
            Self::from_untagged_cbor(ur.cbor().clone()),
            ErrorKind::CborType,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct NamedNote(String);

    impl CBORTagged for NamedNote {
        fn cbor_tags() -> Vec<Tag> {
            vec![Tag::with_static_name(40_000, "note")]
        }
    }

    impl CBORTaggedEncodable for NamedNote {
        fn untagged_cbor(&self) -> CBOR {
            self.0.clone().into()
        }
    }

    impl CBORTaggedDecodable for NamedNote {
        fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
            Ok(Self(cbor.try_into()?))
        }
    }

    impl TryFrom<CBOR> for NamedNote {
        type Error = dcbor::Error;

        fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
            Self::from_tagged_cbor(cbor)
        }
    }

    #[derive(Debug)]
    struct UnnamedByte(u8);

    impl CBORTagged for UnnamedByte {
        fn cbor_tags() -> Vec<Tag> {
            vec![Tag::with_value(40_001)]
        }
    }

    impl CBORTaggedEncodable for UnnamedByte {
        fn untagged_cbor(&self) -> CBOR {
            self.0.into()
        }
    }

    #[derive(Debug)]
    struct EmptyTags;

    impl CBORTagged for EmptyTags {
        fn cbor_tags() -> Vec<Tag> {
            Vec::new()
        }
    }

    impl CBORTaggedEncodable for EmptyTags {
        fn untagged_cbor(&self) -> CBOR {
            0_u8.into()
        }
    }

    #[test]
    fn named_tag_roundtrip() {
        let note = NamedNote(String::from("hi"));
        let ur = note.to_ur().unwrap();
        assert_eq!(ur.ur_type().as_str(), "note");
        let decoded = NamedNote::from_ur(&ur).unwrap();
        assert_eq!(decoded, note);
        let via_string = NamedNote::from_ur(&Ur::from_str(&ur.to_string()).unwrap()).unwrap();
        assert_eq!(via_string, note);
    }

    #[test]
    fn unnamed_or_empty_tags_are_invalid_type() {
        assert_eq!(
            UnnamedByte(1).to_ur().unwrap_err().kind(),
            ErrorKind::InvalidType
        );
        assert_eq!(
            EmptyTags.to_ur().unwrap_err().kind(),
            ErrorKind::InvalidType
        );
        let ur = Ur::new(crate::ur_type!("bytes"), 1_u8);
        assert_eq!(
            NamedNote::from_ur(&ur).unwrap_err().kind(),
            ErrorKind::UnexpectedType
        );
    }

    #[test]
    fn from_ur_rejects_wrong_type() {
        let ur = Ur::new(
            crate::ur_type!("bytes"),
            NamedNote(String::from("x")).untagged_cbor(),
        );
        assert!(matches!(
            NamedNote::from_ur(&ur).unwrap_err(),
            ref e if e.kind() == ErrorKind::UnexpectedType
        ));
    }

    #[test]
    fn from_ur_maps_untagged_type_mismatch_to_cbor_type() {
        let ur = Ur::new(crate::ur_type!("note"), 1_u8);
        assert!(matches!(
            NamedNote::from_ur(&ur).unwrap_err(),
            ref e if e.kind() == ErrorKind::CborType
        ));
    }
}
