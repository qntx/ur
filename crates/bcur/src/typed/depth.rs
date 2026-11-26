//! CBOR nesting bound checked before any bytes reach the dCBOR decoder.

/// Maximum CBOR nesting depth accepted when decoding serialized dCBOR.
///
/// Every array, map, and tag counts as one level, empty containers included:
/// depths `0..=64` are accepted and 65 is
/// [`ErrorKind::ResourceLimit`](crate::ErrorKind::ResourceLimit) with
/// [`Limit::CborDepth`](crate::Limit::CborDepth).
pub const CBOR_MAX_DEPTH: usize = 64;

/// Whether `data` opens more than [`CBOR_MAX_DEPTH`] nested containers.
///
/// Walks CBOR heads iteratively on a fixed stack of remaining item counts,
/// in the decoder's order, and stops at the end of the first item, the end of
/// input, or the first head the decoder rejects (reserved or indefinite
/// additional info). Everything else — canonical form, UTF-8, map order,
/// trailing bytes — is left to the decoder, which never reads past the point
/// where this walk stopped.
pub(super) fn exceeds_max_depth(data: &[u8]) -> bool {
    let mut open = [0_u64; CBOR_MAX_DEPTH];
    let mut depth = 0_usize;
    let mut rest = data;
    loop {
        let Some((major, arg, after_head)) = head(rest) else {
            return false;
        };
        rest = after_head;
        let items = match major {
            2 | 3 => {
                // `as usize` mirrors dcbor's own length conversion, so on
                // 32-bit targets the walk skips exactly what the decoder skips.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "must match dcbor's `value as usize`"
                )]
                let Some(after_string) = rest.get(arg as usize..) else {
                    return false;
                };
                rest = after_string;
                0
            }
            4 => arg,
            5 => arg.saturating_mul(2),
            6 => 1,
            _ => 0,
        };
        if (4..=6).contains(&major) {
            let Some(slot) = open.get_mut(depth) else {
                return true;
            };
            if items > 0 {
                *slot = items;
                depth += 1;
                continue;
            }
        }
        if close_completed(&mut open, &mut depth) {
            return false;
        }
    }
}

/// Splits one head into `(major type, argument, rest)`; `None` on a
/// truncated head or additional info 28..=31.
fn head(data: &[u8]) -> Option<(u8, u64, &[u8])> {
    let (&initial, rest) = data.split_first()?;
    let info = initial & 0x1f;
    let len = match info {
        0..=23 => return Some((initial >> 5, u64::from(info), rest)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let (bytes, rest) = rest.split_at_checked(len)?;
    let arg = bytes
        .iter()
        .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b));
    Some((initial >> 5, arg, rest))
}

/// Counts one finished item against the innermost open container and closes
/// every container it completes; `true` once the outermost item is done.
fn close_completed(open: &mut [u64], depth: &mut usize) -> bool {
    loop {
        let Some(remaining) = depth.checked_sub(1).and_then(|i| open.get_mut(i)) else {
            return true;
        };
        *remaining -= 1;
        if *remaining > 0 {
            return false;
        }
        *depth -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(head: &[u8], count: usize, tail: &[u8]) -> Vec<u8> {
        let mut data = head.repeat(count);
        data.extend_from_slice(tail);
        data
    }

    #[test]
    fn counts_arrays_maps_and_tags_as_one_level_each() {
        for head in [&[0x81][..], &[0xa1, 0x00], &[0xc6], &[0xd9, 0x9c, 0x40]] {
            assert!(!exceeds_max_depth(&nested(head, CBOR_MAX_DEPTH, &[0x00])));
            assert!(exceeds_max_depth(&nested(
                head,
                CBOR_MAX_DEPTH + 1,
                &[0x00]
            )));
        }
        assert!(!exceeds_max_depth(&nested(
            &[0x81],
            CBOR_MAX_DEPTH - 1,
            &[0x80]
        )));
        assert!(exceeds_max_depth(&nested(&[0x81], CBOR_MAX_DEPTH, &[0x80])));
        assert!(exceeds_max_depth(&nested(&[0x81], CBOR_MAX_DEPTH, &[0xa0])));
    }

    #[test]
    fn map_keys_and_later_siblings_are_walked() {
        let mut keys = [0xa1].repeat(CBOR_MAX_DEPTH + 1);
        keys.extend([0x00].repeat(CBOR_MAX_DEPTH + 2));
        assert!(exceeds_max_depth(&keys));

        let mut siblings = vec![0x83, 0x01, 0x42, 0xaa, 0xbb];
        siblings.extend(nested(&[0x81], CBOR_MAX_DEPTH, &[0x00]));
        assert!(exceeds_max_depth(&siblings));
    }

    #[test]
    fn stops_where_the_decoder_stops() {
        let deep = nested(&[0x81], 100_000, &[0x00]);
        for prefix in [
            &[0x9f][..],
            &[0xbf],
            &[0x5f],
            &[0xff],
            &[0x9c],
            &[0x9d],
            &[0x9e],
        ] {
            let mut data = prefix.to_vec();
            data.extend_from_slice(&deep);
            assert!(!exceeds_max_depth(&data), "{prefix:02x?}");
        }
        let mut after_item = nested(&[0x81], CBOR_MAX_DEPTH, &[0x00]);
        after_item.extend_from_slice(&deep);
        assert!(!exceeds_max_depth(&after_item));
        assert!(!exceeds_max_depth(&[]));
        assert!(!exceeds_max_depth(&nested(
            &[0x81],
            10,
            &[0x9a, 0x00, 0x01]
        )));
    }

    #[test]
    fn oversized_lengths_cannot_hide_nesting() {
        for count in [&[0x9b][..], &[0xbb]] {
            let mut data = count.to_vec();
            data.extend([0xff; 8]);
            data.extend(nested(&[0x81], CBOR_MAX_DEPTH, &[0x00]));
            assert!(exceeds_max_depth(&data), "{count:02x?}");
        }
        for string in [0x5b, 0x7b] {
            let mut data = vec![0x82, string];
            data.extend([0xff; 8]);
            data.extend(nested(&[0x81], 100_000, &[0x00]));
            assert!(!exceeds_max_depth(&data));
        }
    }
}
