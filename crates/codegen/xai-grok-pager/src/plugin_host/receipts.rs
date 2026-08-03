//! Host install inventory, trust, activation, default, and registry-v2 receipts.
//!
//! // allow: SIZE_OK — plan Task 6 freezes the full receipt/registry surface in one module

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::canonical::{
    canonical_digest, digest_omitting, sha256_hex, verify_self_digest, with_self_digest,
    CanonicalError, SHA256_HEX_LEN,
};

/// Registry document major for side-by-side install receipts.
pub const REGISTRY_SCHEMA_V2: u32 = 2;
/// Legacy content-plugin registry major (preview-only migration source).
pub const REGISTRY_SCHEMA_V1: u32 = 1;

const MAX_FILES: usize = 4096;
const MAX_STR: usize = 512;
const MAX_PATH: usize = 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("json: {0}")]
    Json(String),
    #[error("canonical: {0}")]
    Canonical(String),
    #[error("unsupported schemaVersion {0}")]
    UnsupportedSchema(u32),
    #[error("invalid field {0}: {1}")]
    InvalidField(&'static str, String),
    #[error("same version with changed bytes: {0}")]
    VersionByteConflict(String),
    #[error("logical default must not carry receipt or version")]
    DefaultCarriesReceipt,
    #[error("v1 migration is preview-only; cannot fabricate native receipt")]
    V1CannotFabricateNative,
    #[error("duplicate install identity {0}")]
    DuplicateInstall(String),
    #[error("inventory path escapes or is absolute: {0}")]
    PathEscape(String),
    #[error("digest verification failed: {0}")]
    Digest(String),
}

impl From<CanonicalError> for ReceiptError {
    fn from(e: CanonicalError) -> Self {
        Self::Canonical(e.to_string())
    }
}

/// Closed trust state bound to an install receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustState {
    Untrusted,
    Consented {
        consent_digest: String,
        consented_at: String,
    },
    Revoked {
        revoked_at: String,
        prior_consent_digest: Option<String>,
    },
}

/// One file in an immutable install inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryFile {
    pub relative_path: String,
    pub role: FileRole,
    pub mode_octal: String,
    pub length: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileRole {
    Executable,
    Library,
    Manifest,
    Config,
    Notice,
    Other,
}

/// Immutable install receipt for one version+digest tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReceiptV1 {
    pub schema_version: u32,
    pub plugin_id: String,
    pub version: String,
    pub archive_sha256: String,
    pub install_root: String,
    pub target: String,
    pub files: Vec<InventoryFile>,
    pub trust: TrustState,
    pub native_code: bool,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub installed_at: String,
    pub receipt_digest: String,
}

/// New-session activation pointer (never a mutable `current` executable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationPointerV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub install_receipt_digest: String,
    pub activated_at: String,
    pub pointer_digest: String,
}

/// User default for future sessions — logical selector only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalDefaultV1 {
    pub schema_version: u32,
    pub backend_id: String,
    /// Always `followActivation` — never embeds a receipt or version.
    pub version_policy: String,
    pub default_digest: String,
}

/// Host registry document v2: side-by-side receipts + activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryDocumentV2 {
    pub schema_version: u32,
    pub receipts: BTreeMap<String, InstallReceiptV1>,
    pub activation: BTreeMap<String, ActivationPointerV1>,
    pub defaults: BTreeMap<String, LogicalDefaultV1>,
    pub document_digest: String,
}

/// Preview-only result of reading a legacy v1 content registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryV1MigrationPreview {
    pub schema_version: u32,
    pub source_schema_version: u32,
    pub content_plugin_ids: Vec<String>,
    /// Always empty — v1 cannot fabricate native install receipts.
    pub native_receipts: Vec<String>,
    pub candidate_pointer: String,
    pub preview_only: bool,
    pub preview_digest: String,
}

impl InstallReceiptV1 {
    pub fn parse_json(raw: &str) -> Result<Self, ReceiptError> {
        let v: Value = serde_json::from_str(raw).map_err(|e| ReceiptError::Json(e.to_string()))?;
        Self::from_value(v)
    }

    pub fn from_value(v: Value) -> Result<Self, ReceiptError> {
        let receipt: Self =
            serde_json::from_value(v).map_err(|e| ReceiptError::Json(e.to_string()))?;
        receipt.validate()?;
        let expected = receipt.compute_digest()?;
        if receipt.receipt_digest != expected {
            return Err(ReceiptError::Digest(format!(
                "receiptDigest want {expected} got {}",
                receipt.receipt_digest
            )));
        }
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != 1 {
            return Err(ReceiptError::UnsupportedSchema(self.schema_version));
        }
        require_id("pluginId", &self.plugin_id)?;
        require_semverish("version", &self.version)?;
        require_sha256("archiveSha256", &self.archive_sha256)?;
        require_bound("installRoot", &self.install_root, MAX_PATH)?;
        require_bound("target", &self.target, MAX_STR)?;
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(ReceiptError::InvalidField(
                "files",
                format!("count {}", self.files.len()),
            ));
        }
        let mut seen = BTreeSet::new();
        for f in &self.files {
            validate_relative_path(&f.relative_path)?;
            if !seen.insert(f.relative_path.clone()) {
                return Err(ReceiptError::InvalidField(
                    "files",
                    format!("duplicate {}", f.relative_path),
                ));
            }
            require_sha256("contentSha256", &f.content_sha256)?;
            if f.mode_octal.len() != 4 || !f.mode_octal.chars().all(|c| matches!(c, '0'..='7')) {
                return Err(ReceiptError::InvalidField(
                    "modeOctal",
                    f.mode_octal.clone(),
                ));
            }
        }
        match &self.trust {
            TrustState::Untrusted => {}
            TrustState::Consented { consent_digest, .. } => {
                require_sha256("consentDigest", consent_digest)?;
            }
            TrustState::Revoked {
                prior_consent_digest,
                ..
            } => {
                if let Some(d) = prior_consent_digest {
                    require_sha256("priorConsentDigest", d)?;
                }
            }
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ReceiptError> {
        let v = serde_json::to_value(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        Ok(digest_omitting(&v, "receiptDigest")?)
    }

    pub fn seal(mut self) -> Result<Self, ReceiptError> {
        self.validate()?;
        self.receipt_digest = self.compute_digest()?;
        Ok(self)
    }

    pub fn identity_key(&self) -> String {
        format!("{}@{}#{}", self.plugin_id, self.version, self.archive_sha256)
    }
}

impl LogicalDefaultV1 {
    pub fn parse_json(raw: &str) -> Result<Self, ReceiptError> {
        let d: Self =
            serde_json::from_str(raw).map_err(|e| ReceiptError::Json(e.to_string()))?;
        d.validate()?;
        let expected = d.compute_digest()?;
        if d.default_digest != expected {
            return Err(ReceiptError::Digest(expected));
        }
        Ok(d)
    }

    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != 1 {
            return Err(ReceiptError::UnsupportedSchema(self.schema_version));
        }
        require_id("backendId", &self.backend_id)?;
        if self.version_policy != "followActivation" {
            return Err(ReceiptError::InvalidField(
                "versionPolicy",
                self.version_policy.clone(),
            ));
        }
        // Structural guard: serde shape has no receipt/version fields.
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ReceiptError> {
        let v = serde_json::to_value(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        Ok(digest_omitting(&v, "defaultDigest")?)
    }

    pub fn seal(mut self) -> Result<Self, ReceiptError> {
        self.validate()?;
        self.default_digest = self.compute_digest()?;
        Ok(self)
    }
}

impl ActivationPointerV1 {
    pub fn seal(mut self) -> Result<Self, ReceiptError> {
        if self.schema_version != 1 {
            return Err(ReceiptError::UnsupportedSchema(self.schema_version));
        }
        require_id("backendId", &self.backend_id)?;
        require_sha256("installReceiptDigest", &self.install_receipt_digest)?;
        self.pointer_digest = {
            let v = serde_json::to_value(&self).map_err(|e| ReceiptError::Json(e.to_string()))?;
            digest_omitting(&v, "pointerDigest")?
        };
        Ok(self)
    }
}

impl RegistryDocumentV2 {
    pub fn empty() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_V2,
            receipts: BTreeMap::new(),
            activation: BTreeMap::new(),
            defaults: BTreeMap::new(),
            document_digest: String::new(),
        }
    }

    pub fn parse_json(raw: &str) -> Result<Self, ReceiptError> {
        let doc: Self =
            serde_json::from_str(raw).map_err(|e| ReceiptError::Json(e.to_string()))?;
        doc.validate()?;
        let expected = doc.compute_digest()?;
        if doc.document_digest != expected {
            return Err(ReceiptError::Digest(expected));
        }
        Ok(doc)
    }

    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != REGISTRY_SCHEMA_V2 {
            return Err(ReceiptError::UnsupportedSchema(self.schema_version));
        }
        let mut by_version: BTreeMap<(String, String), String> = BTreeMap::new();
        for (key, r) in &self.receipts {
            r.validate()?;
            if key != &r.receipt_digest {
                return Err(ReceiptError::InvalidField(
                    "receipts",
                    format!("key {key} != receiptDigest"),
                ));
            }
            let expected = r.compute_digest()?;
            if r.receipt_digest != expected {
                return Err(ReceiptError::Digest(r.receipt_digest.clone()));
            }
            let vk = (r.plugin_id.clone(), r.version.clone());
            if let Some(prev) = by_version.insert(vk, r.archive_sha256.clone()) {
                if prev != r.archive_sha256 {
                    return Err(ReceiptError::VersionByteConflict(format!(
                        "{}@{}",
                        r.plugin_id, r.version
                    )));
                }
                return Err(ReceiptError::DuplicateInstall(r.identity_key()));
            }
        }
        for (backend_id, act) in &self.activation {
            if backend_id != &act.backend_id {
                return Err(ReceiptError::InvalidField(
                    "activation",
                    "backendId key mismatch".into(),
                ));
            }
            if !self.receipts.contains_key(&act.install_receipt_digest) {
                return Err(ReceiptError::InvalidField(
                    "activation",
                    format!("missing receipt {}", act.install_receipt_digest),
                ));
            }
        }
        for (backend_id, def) in &self.defaults {
            if backend_id != &def.backend_id {
                return Err(ReceiptError::InvalidField(
                    "defaults",
                    "backendId key mismatch".into(),
                ));
            }
            def.validate()?;
        }
        Ok(())
    }

    pub fn insert_receipt(&mut self, receipt: InstallReceiptV1) -> Result<(), ReceiptError> {
        receipt.validate()?;
        let sealed = receipt.seal()?;
        for existing in self.receipts.values() {
            if existing.plugin_id == sealed.plugin_id
                && existing.version == sealed.version
                && existing.archive_sha256 != sealed.archive_sha256
            {
                return Err(ReceiptError::VersionByteConflict(format!(
                    "{}@{}",
                    sealed.plugin_id, sealed.version
                )));
            }
        }
        self.receipts
            .insert(sealed.receipt_digest.clone(), sealed);
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ReceiptError> {
        let v = serde_json::to_value(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        Ok(digest_omitting(&v, "documentDigest")?)
    }

    pub fn seal(mut self) -> Result<Self, ReceiptError> {
        self.validate()?;
        self.document_digest = self.compute_digest()?;
        Ok(self)
    }
}

/// Preview-only migration from legacy install_registry v1 JSON.
///
/// Never fabricates a native install receipt or activation pointer.
/// Publishes only a verified candidate pointer digest over the preview payload.
pub fn preview_migrate_registry_v1(raw: &str) -> Result<RegistryV1MigrationPreview, ReceiptError> {
    let v: Value = serde_json::from_str(raw).map_err(|e| ReceiptError::Json(e.to_string()))?;
    let version = v
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| ReceiptError::InvalidField("version", "missing".into()))?
        as u32;
    if version != REGISTRY_SCHEMA_V1 {
        return Err(ReceiptError::UnsupportedSchema(version));
    }
    let repos = v
        .get("repos")
        .and_then(Value::as_object)
        .ok_or_else(|| ReceiptError::InvalidField("repos", "missing".into()))?;

    let mut content_plugin_ids = BTreeSet::new();
    for repo in repos.values() {
        let plugins = repo
            .get("plugins")
            .and_then(Value::as_object)
            .ok_or_else(|| ReceiptError::InvalidField("plugins", "missing".into()))?;
        for id in plugins.keys() {
            // v1 content plugins only — refuse any native-code marker.
            if let Some(true) = plugins[id].get("nativeCode").and_then(Value::as_bool) {
                return Err(ReceiptError::V1CannotFabricateNative);
            }
            if let Some(true) = plugins[id].get("native_code").and_then(Value::as_bool) {
                return Err(ReceiptError::V1CannotFabricateNative);
            }
            content_plugin_ids.insert(id.clone());
        }
    }

    let mut preview = RegistryV1MigrationPreview {
        schema_version: 1,
        source_schema_version: REGISTRY_SCHEMA_V1,
        content_plugin_ids: content_plugin_ids.into_iter().collect(),
        native_receipts: Vec::new(),
        candidate_pointer: String::new(),
        preview_only: true,
        preview_digest: String::new(),
    };
    let v = serde_json::to_value(&preview).map_err(|e| ReceiptError::Json(e.to_string()))?;
    let d = digest_omitting(&v, "previewDigest")?;
    preview.preview_digest = d.clone();
    preview.candidate_pointer = format!("sha256:{d}");
    // Re-seal after candidate_pointer assignment.
    let v = serde_json::to_value(&preview).map_err(|e| ReceiptError::Json(e.to_string()))?;
    preview.preview_digest = digest_omitting(&v, "previewDigest")?;
    if !preview.native_receipts.is_empty() || !preview.preview_only {
        return Err(ReceiptError::V1CannotFabricateNative);
    }
    Ok(preview)
}

/// Detect same-version / different-bytes conflict between two receipts.
pub fn conflict_same_version(a: &InstallReceiptV1, b: &InstallReceiptV1) -> Result<(), ReceiptError> {
    if a.plugin_id == b.plugin_id && a.version == b.version && a.archive_sha256 != b.archive_sha256
    {
        return Err(ReceiptError::VersionByteConflict(format!(
            "{}@{}",
            a.plugin_id, a.version
        )));
    }
    Ok(())
}

fn require_id(field: &'static str, s: &str) -> Result<(), ReceiptError> {
    require_bound(field, s, MAX_STR)?;
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ReceiptError::InvalidField(field, s.into()));
    }
    Ok(())
}

fn require_semverish(field: &'static str, s: &str) -> Result<(), ReceiptError> {
    require_bound(field, s, MAX_STR)?;
    if s.is_empty() || s.contains("..") {
        return Err(ReceiptError::InvalidField(field, s.into()));
    }
    Ok(())
}

fn require_bound(field: &'static str, s: &str, max: usize) -> Result<(), ReceiptError> {
    if s.is_empty() || s.len() > max {
        return Err(ReceiptError::InvalidField(field, format!("len {}", s.len())));
    }
    Ok(())
}

fn require_sha256(field: &'static str, s: &str) -> Result<(), ReceiptError> {
    if s.len() != SHA256_HEX_LEN || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ReceiptError::InvalidField(field, s.into()));
    }
    // lowercase only
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(ReceiptError::InvalidField(field, "uppercase hex".into()));
    }
    Ok(())
}

fn validate_relative_path(p: &str) -> Result<(), ReceiptError> {
    require_bound("relativePath", p, MAX_PATH)?;
    if p.starts_with('/') || p.starts_with('\\') || p.contains("..") {
        return Err(ReceiptError::PathEscape(p.into()));
    }
    if p.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(ReceiptError::PathEscape(p.into()));
    }
    Ok(())
}

/// Stable digest of an arbitrary sealed JSON object (for fixtures/QA).
pub fn sealed_object_digest(v: &Value) -> Result<String, ReceiptError> {
    Ok(canonical_digest(v)?)
}

pub fn attach_digest(v: Value, field: &str) -> Result<Value, ReceiptError> {
    Ok(with_self_digest(v, field)?)
}

pub fn check_digest(v: &Value, field: &str) -> Result<(), ReceiptError> {
    verify_self_digest(v, field).map_err(|e| ReceiptError::Digest(e.to_string()))
}

pub fn content_address(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

#[cfg(test)]
#[path = "receipts_test.rs"]
mod receipts_test;
