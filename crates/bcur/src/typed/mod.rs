//! Typed dCBOR Uniform Resources (`feature = "dcbor"`, implies `std`).
//!
//! Transport payloads stay type-agnostic bytes. This module wraps those bytes
//! as [`dcbor::CBOR`] and maps the first registered CBOR tag **name** to the UR
//! type token.
//!
//! ```
//! use bcur::Ur;
//!
//! let ur = Ur::new("test", vec![1, 2, 3]).unwrap();
//! assert_eq!(ur.string(), "ur:test/lsadaoaxjygonesw");
//! ```

mod traits;
mod ur_value;

pub use traits::{UrCodable, UrDecodable, UrEncodable};
pub use ur_value::Ur;

use crate::error::{Error, ErrorKind, Result};

/// Maps a `dcbor` failure into [`ErrorKind::CborDecode`] or
/// [`ErrorKind::CborType`]; the `dcbor` error is kept as `source()`.
fn map_cbor<T>(result: dcbor::Result<T>, kind: ErrorKind) -> Result<T> {
    result.map_err(|e| Error::cbor(kind, e))
}

#[cfg(test)]
mod tests {
    const fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn typed_types_are_send_sync() {
        assert_send_sync::<super::Ur>();
    }
}
