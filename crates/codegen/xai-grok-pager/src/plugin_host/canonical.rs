//! Stable canonical JSON digests for host lifecycle receipts.
//!
//! Preimage: RFC-8785-style sorted-key compact JSON (no whitespace).
//! Digest fields named `*Digest` / `digest` are omitted from their own preimage.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Hex-encoded SHA-256 length.
pub const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("json: {0}")]
    Json(String),
    #[error("digest field missing or not a 64-hex string: {0}")]
    BadDigestField(String),
    #[error("digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },
}

/// SHA-256 hex of raw bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Canonical compact JSON bytes with object keys sorted recursively.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let sorted = sort_value(value);
    serde_json::to_vec(&sorted).map_err(|e| CanonicalError::Json(e.to_string()))
}

/// SHA-256 hex of canonical JSON for `value`.
pub fn canonical_digest(value: &Value) -> Result<String, CanonicalError> {
    Ok(sha256_hex(&canonical_bytes(value)?))
}

/// Digest of `value` after removing `omit_field` (self-digest pattern).
pub fn digest_omitting(value: &Value, omit_field: &str) -> Result<String, CanonicalError> {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove(omit_field);
    }
    canonical_digest(&clone)
}

/// Verify `value[field]` equals digest_omitting(value, field).
pub fn verify_self_digest(value: &Value, field: &str) -> Result<(), CanonicalError> {
    let got = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| CanonicalError::BadDigestField(field.into()))?;
    if got.len() != SHA256_HEX_LEN || !got.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CanonicalError::BadDigestField(field.into()));
    }
    let expected = digest_omitting(value, field)?;
    if got != expected {
        return Err(CanonicalError::DigestMismatch {
            expected,
            got: got.into(),
        });
    }
    Ok(())
}

/// Attach computed self-digest into `field` on a serde value.
pub fn with_self_digest(mut value: Value, field: &str) -> Result<Value, CanonicalError> {
    let d = digest_omitting(&value, field)?;
    if let Value::Object(map) = &mut value {
        map.insert(field.into(), Value::String(d));
    }
    Ok(value)
}

fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut ordered: BTreeMap<String, Value> = BTreeMap::new();
            for (k, child) in map {
                ordered.insert(k.clone(), sort_value(child));
            }
            let mut out = Map::new();
            for (k, child) in ordered {
                out.insert(k, child);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_digest() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(
            canonical_digest(&a).unwrap(),
            canonical_digest(&b).unwrap()
        );
    }

    #[test]
    fn self_digest_round_trip() {
        let base = json!({"schemaVersion": 1, "kind": "x", "payload": {"n": 1}});
        let with = with_self_digest(base, "digest").unwrap();
        verify_self_digest(&with, "digest").unwrap();
    }
}
