//! Bytemoji identifiers (BCR-2024-008): a 4-byte digest shown as four
//! space-separated emoji from a fixed 256-entry table.

use alloc::{string::String, vec::Vec};

use crate::constants::BYTEMOJIS;

/// Four-emoji identifier of a 4-byte digest.
#[must_use]
pub fn identifier(data: [u8; 4]) -> String {
    let emojis: Vec<&str> = data
        .iter()
        .map(|&b| BYTEMOJIS.get(usize::from(b)).copied().unwrap_or(""))
        .collect();
    emojis.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier() {
        assert_eq!(identifier([0, 1, 2, 3]), "😀 😂 😆 😉");
        assert_eq!(identifier([255; 4]), "🐳 🐳 🐳 🐳");
    }
}
