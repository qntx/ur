//! Official MUR vectors exercised through the public `fountain` API.

use bcur::fountain::Part;

use crate::{hex, unhex, vector};

#[test]
fn official_part_cbor() {
    let doc = vector("official/mur/part-cbor.json");
    for case in doc["cases"].as_array().unwrap() {
        let cbor = unhex(case["cborHex"].as_str().unwrap());
        let part = Part::from_cbor(&cbor).unwrap();
        assert_eq!(u64::from(part.sequence()), case["seqNum"].as_u64().unwrap());
        assert_eq!(
            u64::from(part.sequence_count()),
            case["seqLen"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(part.message_length()),
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
