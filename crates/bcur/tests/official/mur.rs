//! Official MUR vectors exercised through the public `fountain` API.

use bcur::DecoderLimits;
use bcur::fountain::Part;

use crate::{hex, unhex, vector};

#[test]
fn official_part_cbor() {
    let doc = vector("official/mur/part-cbor.json");
    for case in doc["cases"].as_array().unwrap() {
        let cbor = unhex(case["cborHex"].as_str().unwrap());
        // R1b semantic validation: `K * fragLen < messageLen` is rejected at
        // decode. The official case is a synthetic CBOR fixture with
        // inconsistent geometry — the reference implementation does not check.
        let k = case["seqLen"].as_u64().unwrap();
        let frag_len = case["dataHex"].as_str().unwrap().len() as u64 / 2;
        let message_len = case["messageLen"].as_u64().unwrap();
        if k * frag_len < message_len {
            assert_eq!(
                Part::from_cbor(&cbor, &DecoderLimits::default())
                    .unwrap_err()
                    .kind(),
                bcur::ErrorKind::InvalidPart
            );
            continue;
        }
        let part = Part::from_cbor(&cbor, &DecoderLimits::default()).unwrap();
        assert_eq!(u64::from(part.sequence()), case["seqNum"].as_u64().unwrap());
        assert_eq!(
            u64::from(part.sequence_count()),
            case["seqLen"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(part.message_len()),
            case["messageLen"].as_u64().unwrap()
        );
        assert_eq!(
            format!("{:08x}", part.checksum()),
            case["checksum"].as_str().unwrap()
        );
        assert_eq!(hex(part.data()), case["dataHex"].as_str().unwrap());
        assert_eq!(part.to_cbor(), cbor);
    }
}
