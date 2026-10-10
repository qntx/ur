//! v1 `crypto-output` script-expression trees (BCR-2020-010 tags 400–410)
//! rendered as BIP-380 descriptor text, a line-for-line port of the
//! TypeScript `script-expression.ts`.
//!
//! Keys become `@0`, `@1`, … in order of appearance and are collected as v2
//! [`DescriptorKey`] values. The grammar gives every script function at most
//! one child subtree (multikey's list is handled inline), so each node's
//! local `@n` numbering is already the global order.

use dcbor::CBOR;

use crate::descriptor_key::{DescriptorKey, is_key_tag};
use crate::expect::{closed_int_map, expect_array, expect_bytes, expect_uint31, get};
use crate::tags;

/// `scriptExp` result: the rendered text plus collected keys.
struct ScriptResult {
    text: String,
    keys: Vec<DescriptorKey>,
}

/// `KEY_FN`: single-key script functions.
fn key_fn(tag: u64) -> Option<&'static str> {
    if tag == tags::PK.value() {
        Some("pk")
    } else if tag == tags::PKH.value() {
        Some("pkh")
    } else if tag == tags::WPKH.value() {
        Some("wpkh")
    } else if tag == tags::COMBO.value() {
        Some("combo")
    } else if tag == tags::COSIGNER.value() {
        Some("cosigner")
    } else {
        None
    }
}

/// `WRAPPER_FN`: the two script wrappers.
fn wrapper_fn(tag: u64) -> Option<&'static str> {
    if tag == tags::SH.value() {
        Some("sh")
    } else if tag == tags::WSH.value() {
        Some("wsh")
    } else {
        None
    }
}

/// `keyExp`: the value must be a tagged `hdkey`/`eckey`/`address` (`WrongType`
/// otherwise).
fn key_exp(cbor: &CBOR) -> dcbor::Result<DescriptorKey> {
    DescriptorKey::try_from(cbor.clone())
}

fn script_exp(cbor: &CBOR, parent: Option<u64>) -> dcbor::Result<ScriptResult> {
    // `tagNumber` + `extractTaggedContent`: anything but a tagged value is
    // `WrongType`.
    let Some((tagged, content)) = cbor.as_tagged_value() else {
        return Err(dcbor::Error::WrongType);
    };
    let tag = tagged.value();

    if let Some(name) = key_fn(tag) {
        return Ok(ScriptResult {
            text: format!("{name}(@0)"),
            keys: vec![key_exp(content)?],
        });
    }

    if let Some(name) = wrapper_fn(tag) {
        // BIP-380/381/382: sh() is top-level only; wsh() is top-level or
        // directly inside sh().
        let allowed = parent.is_none_or(|p| p == tags::SH.value() && tag == tags::WSH.value());
        if !allowed {
            return Err(dcbor::Error::WrongType);
        }
        // Lenient read: KeystoneHQ writes `sh(key_exp)` where BCR-2020-010
        // uses `sh(410(key_exp))` (cosigner). Restore the cosigner marker;
        // only sh/wsh accept it, so the fallback lives here.
        if let Some((inner_tag, _)) = content.as_tagged_value()
            && is_key_tag(inner_tag.value())
        {
            return Ok(ScriptResult {
                text: format!("{name}(cosigner(@0))"),
                keys: vec![key_exp(content)?],
            });
        }
        let inner = script_exp(content, Some(tag))?;
        let text = inner.text;
        return Ok(ScriptResult {
            text: format!("{name}({text})"),
            keys: inner.keys,
        });
    }

    if tag == tags::MULTI.value() || tag == tags::SORTEDMULTI.value() {
        let map = closed_int_map(content, &[1, 2])?;
        // Missing multikey entries are WrongType, not MissingMapKey.
        let (Some(threshold_v), Some(keys_v)) = (get(&map, 1), get(&map, 2)) else {
            return Err(dcbor::Error::WrongType);
        };
        let threshold = expect_uint31(&threshold_v)?;
        let key_items = expect_array(&keys_v)?;
        if threshold == 0
            || usize::try_from(threshold).unwrap_or(usize::MAX) > key_items.len()
            || key_items.is_empty()
        {
            return Err(dcbor::Error::OutOfRange);
        }
        let mut parts = Vec::with_capacity(key_items.len());
        let mut collected = Vec::with_capacity(key_items.len());
        for key in key_items {
            collected.push(key_exp(&key)?);
            parts.push(format!("@{}", collected.len() - 1));
        }
        let name = if tag == tags::MULTI.value() {
            "multi"
        } else {
            "sortedmulti"
        };
        return Ok(ScriptResult {
            text: format!("{name}({threshold},{})", parts.join(",")),
            keys: collected,
        });
    }

    if tag == tags::RAW.value() {
        return Ok(ScriptResult {
            text: format!("raw({})", hex::encode(expect_bytes(content)?)),
            keys: Vec::new(),
        });
    }

    if tag == tags::TR.value() {
        // BIP-386 tr(KEY) only; a tr script tree is unsupported (registry
        // design).
        return Ok(ScriptResult {
            text: "tr(@0)".to_owned(),
            keys: vec![key_exp(content)?],
        });
    }

    Err(dcbor::Error::WrongType)
}

/// `scriptExpressionToDescriptor`: convert a v1 `crypto-output` body (a
/// script-expression tagged value) into the v2 `OutputDescriptor` parts
/// `(source, keys)`.
pub(crate) fn to_descriptor(cbor: &CBOR) -> dcbor::Result<(String, Vec<DescriptorKey>)> {
    let out = script_exp(cbor, None)?;
    Ok((out.text, out.keys))
}
