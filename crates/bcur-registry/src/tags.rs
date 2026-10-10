//! BCR-2020-006/010 CBOR tag constants.
//!
//! `SEED`–`ACCOUNT_DESCRIPTOR` are the v2 tags (40300–40311); `CRYPTO_*` are
//! the deprecated v1 tags (300–311, read-only); `SH`–`COSIGNER` are the
//! BCR-2020-010 script-expression tags (400–410) embedded inside v1
//! `crypto-output` bodies. `envelope` (200) is not part of this crate.
//!
//! Constants are not registered anywhere implicitly; call [`register_tags`]
//! when dcbor diagnostic output should print these names.

use dcbor::{Tag, TagsStore};

/// `seed` (BCR-2020-006).
pub const SEED: Tag = Tag::with_static_name(40_300, "seed");
/// `hdkey` (BCR-2020-007).
pub const HDKEY: Tag = Tag::with_static_name(40_303, "hdkey");
/// `keypath` (BCR-2020-007).
pub const KEYPATH: Tag = Tag::with_static_name(40_304, "keypath");
/// `coin-info` (BCR-2020-007).
pub const COIN_INFO: Tag = Tag::with_static_name(40_305, "coin-info");
/// `eckey` (BCR-2020-008).
pub const ECKEY: Tag = Tag::with_static_name(40_306, "eckey");
/// `address` (BCR-2020-009).
pub const ADDRESS: Tag = Tag::with_static_name(40_307, "address");
/// `output-descriptor` (BCR-2023-010).
pub const OUTPUT_DESCRIPTOR: Tag = Tag::with_static_name(40_308, "output-descriptor");
/// `sskr` (BCR-2020-011).
pub const SSKR: Tag = Tag::with_static_name(40_309, "sskr");
/// `psbt` (BCR-2020-006).
pub const PSBT: Tag = Tag::with_static_name(40_310, "psbt");
/// `account-descriptor` (BCR-2023-019).
pub const ACCOUNT_DESCRIPTOR: Tag = Tag::with_static_name(40_311, "account-descriptor");

/// `crypto-seed` (v1, read-only).
pub const CRYPTO_SEED: Tag = Tag::with_static_name(300, "crypto-seed");
/// `crypto-hdkey` (v1, read-only).
pub const CRYPTO_HDKEY: Tag = Tag::with_static_name(303, "crypto-hdkey");
/// `crypto-keypath` (v1, read-only).
pub const CRYPTO_KEYPATH: Tag = Tag::with_static_name(304, "crypto-keypath");
/// `crypto-coin-info` (v1, read-only).
pub const CRYPTO_COIN_INFO: Tag = Tag::with_static_name(305, "crypto-coin-info");
/// `crypto-eckey` (v1, read-only).
pub const CRYPTO_ECKEY: Tag = Tag::with_static_name(306, "crypto-eckey");
/// `crypto-address` (v1, read-only; BCR-2020-006 assigns 307 to
/// `crypto-address`, not `crypto-output` — `bc-tags` mislabels it).
pub const CRYPTO_ADDRESS: Tag = Tag::with_static_name(307, "crypto-address");
/// `crypto-output` (v1, read-only).
pub const CRYPTO_OUTPUT: Tag = Tag::with_static_name(308, "crypto-output");
/// `crypto-sskr` (v1, read-only).
pub const CRYPTO_SSKR: Tag = Tag::with_static_name(309, "crypto-sskr");
/// `crypto-psbt` (v1, read-only).
pub const CRYPTO_PSBT: Tag = Tag::with_static_name(310, "crypto-psbt");
/// `crypto-account` (v1, read-only).
pub const CRYPTO_ACCOUNT: Tag = Tag::with_static_name(311, "crypto-account");

/// `sh` script expression (BCR-2020-010).
pub const SH: Tag = Tag::with_static_name(400, "sh");
/// `wsh` script expression (BCR-2020-010).
pub const WSH: Tag = Tag::with_static_name(401, "wsh");
/// `pk` script expression (BCR-2020-010).
pub const PK: Tag = Tag::with_static_name(402, "pk");
/// `pkh` script expression (BCR-2020-010).
pub const PKH: Tag = Tag::with_static_name(403, "pkh");
/// `wpkh` script expression (BCR-2020-010).
pub const WPKH: Tag = Tag::with_static_name(404, "wpkh");
/// `combo` script expression (BCR-2020-010).
pub const COMBO: Tag = Tag::with_static_name(405, "combo");
/// `multi` script expression (BCR-2020-010).
pub const MULTI: Tag = Tag::with_static_name(406, "multi");
/// `sortedmulti` script expression (BCR-2020-010).
pub const SORTEDMULTI: Tag = Tag::with_static_name(407, "sortedmulti");
/// `raw` script expression (BCR-2020-010).
pub const RAW: Tag = Tag::with_static_name(408, "raw");
/// `tr` script expression (BCR-2020-010).
pub const TR: Tag = Tag::with_static_name(409, "tr");
/// `cosigner` script expression (BCR-2020-010).
pub const COSIGNER: Tag = Tag::with_static_name(410, "cosigner");

/// Every registry tag constant (v2, v1, script expressions).
const ALL_TAGS: [Tag; 31] = [
    SEED,
    HDKEY,
    KEYPATH,
    COIN_INFO,
    ECKEY,
    ADDRESS,
    OUTPUT_DESCRIPTOR,
    SSKR,
    PSBT,
    ACCOUNT_DESCRIPTOR,
    CRYPTO_SEED,
    CRYPTO_HDKEY,
    CRYPTO_KEYPATH,
    CRYPTO_COIN_INFO,
    CRYPTO_ECKEY,
    CRYPTO_ADDRESS,
    CRYPTO_OUTPUT,
    CRYPTO_SSKR,
    CRYPTO_PSBT,
    CRYPTO_ACCOUNT,
    SH,
    WSH,
    PK,
    PKH,
    WPKH,
    COMBO,
    MULTI,
    SORTEDMULTI,
    RAW,
    TR,
    COSIGNER,
];

/// Inserts every registry tag into `tags_store` (same name convention as
/// dcbor's own `register_tags_in`).
pub fn register_tags_in(tags_store: &mut TagsStore) {
    for tag in &ALL_TAGS {
        tags_store.insert(tag.clone());
    }
}

/// Registers every registry tag in the global tag store, so dcbor
/// diagnostic/diagnostic-flat output prints these names.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the with_tags_mut! lock guard must live for the whole registration loop"
)]
pub fn register_tags() {
    dcbor::with_tags_mut!(|tags: &mut TagsStore| register_tags_in(tags));
}
