//! Host session pins, barriers, provision, purge, holds, rollback, and GC schemas.
//!
//! // allow: SIZE_OK — plan Task 6 freezes the full lifecycle/compatibility surface here

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::canonical::{digest_omitting, SHA256_HEX_LEN};

const MAX_ENTRIES: usize = 8192;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("json: {0}")]
    Json(String),
    #[error("canonical: {0}")]
    Canonical(String),
    #[error("unsupported schemaVersion {0}")]
    UnsupportedSchema(u32),
    #[error("invalid field {0}: {1}")]
    InvalidField(&'static str, String),
    #[error("session pin schema invalid: {0}")]
    PinSchema(String),
    #[error("native pin must not contain plugin fields")]
    NativeHasPluginFields,
    #[error("host is the sole external barrier writer")]
    NonHostBarrierWriter,
    #[error("deletion intent must precede unlink")]
    IntentBeforeUnlink,
    #[error("completion must precede cursor advance")]
    CompletionBeforeAdvance,
    #[error("illegal barrier transition {from} -> {to}")]
    IllegalBarrierTransition { from: String, to: String },
    #[error("purge entry order invalid: {0}")]
    PurgeOrder(String),
    #[error("null identity illegal in Open barrier")]
    NullOpenIdentity,
    #[error("digest: {0}")]
    Digest(String),
    #[error("unknown discriminator {0}")]
    UnknownDiscriminator(String),
    #[error("illegal entry phase transition")]
    IllegalEntryPhase,
}

fn require_bound(field: &'static str, s: &str, max: usize) -> Result<(), LifecycleError> {
    if s.is_empty() || s.len() > max {
        return Err(LifecycleError::InvalidField(field, format!("len {}", s.len())));
    }
    Ok(())
}

fn require_sha256(field: &'static str, s: &str) -> Result<(), LifecycleError> {
    if s.len() != SHA256_HEX_LEN || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LifecycleError::InvalidField(field, s.into()));
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(LifecycleError::InvalidField(field, "uppercase hex".into()));
    }
    Ok(())
}

fn require_id(field: &'static str, s: &str) -> Result<(), LifecycleError> {
    require_bound(field, s, 512)?;
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(LifecycleError::InvalidField(field, s.into()));
    }
    Ok(())
}

fn require_hex_min(field: &'static str, s: &str) -> Result<(), LifecycleError> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LifecycleError::InvalidField(field, s.into()));
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(LifecycleError::InvalidField(field, "uppercase hex".into()));
    }
    Ok(())
}

fn require_decimal(s: &str) -> Result<(), LifecycleError> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(LifecycleError::InvalidField("decimal", s.into()));
    }
    Ok(())
}

/// Filesystem descriptor identity (closed preimage for path binding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescriptorIdentityV1 {
    pub schema: String,
    pub platform: PlatformKind,
    pub kind: EntryKind,
    pub stable_object: StableObject,
    pub security: SecurityIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlatformKind {
    Unix,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Directory,
    Regular,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StableObject {
    Unix {
        device_hex: String,
        inode_hex: String,
    },
    Windows {
        volume_serial_hex: String,
        file_id128_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SecurityIdentity {
    Unix {
        uid_decimal: String,
        gid_decimal: String,
        mode_octal: String,
        file_type: EntryKind,
    },
    Windows {
        owner_sid: String,
        canonical_dacl_sha256: String,
        reparse_tag_hex: String,
        file_attributes_hex: String,
        file_type: EntryKind,
    },
}

impl DescriptorIdentityV1 {
    pub fn parse_json(raw: &str) -> Result<Self, LifecycleError> {
        let id: Self =
            serde_json::from_str(raw).map_err(|e| LifecycleError::Json(e.to_string()))?;
        id.validate()?;
        Ok(id)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema != "descriptor-identity/v1" {
            return Err(LifecycleError::InvalidField("schema", self.schema.clone()));
        }
        match (&self.platform, &self.stable_object, &self.security) {
            (
                PlatformKind::Unix,
                StableObject::Unix {
                    device_hex,
                    inode_hex,
                },
                SecurityIdentity::Unix {
                    uid_decimal,
                    gid_decimal,
                    mode_octal,
                    file_type,
                },
            ) => {
                require_hex_min("deviceHex", device_hex)?;
                require_hex_min("inodeHex", inode_hex)?;
                require_decimal(uid_decimal)?;
                require_decimal(gid_decimal)?;
                if mode_octal.len() != 4 || !mode_octal.chars().all(|c| matches!(c, '0'..='7')) {
                    return Err(LifecycleError::InvalidField("modeOctal", mode_octal.clone()));
                }
                if *file_type != self.kind {
                    return Err(LifecycleError::InvalidField(
                        "fileType",
                        "mismatch with kind".into(),
                    ));
                }
            }
            (
                PlatformKind::Windows,
                StableObject::Windows {
                    volume_serial_hex,
                    file_id128_hex,
                },
                SecurityIdentity::Windows {
                    owner_sid,
                    canonical_dacl_sha256,
                    reparse_tag_hex,
                    file_attributes_hex,
                    file_type,
                },
            ) => {
                if volume_serial_hex.len() != 8
                    || !volume_serial_hex.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(LifecycleError::InvalidField(
                        "volumeSerialHex",
                        volume_serial_hex.clone(),
                    ));
                }
                if file_id128_hex.len() != 32
                    || !file_id128_hex.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(LifecycleError::InvalidField(
                        "fileId128Hex",
                        file_id128_hex.clone(),
                    ));
                }
                if !owner_sid.starts_with("S-") {
                    return Err(LifecycleError::InvalidField("ownerSid", owner_sid.clone()));
                }
                require_sha256("canonicalDaclSha256", canonical_dacl_sha256)?;
                if reparse_tag_hex != "00000000" {
                    return Err(LifecycleError::InvalidField(
                        "reparseTagHex",
                        reparse_tag_hex.clone(),
                    ));
                }
                if file_attributes_hex.len() != 8 {
                    return Err(LifecycleError::InvalidField(
                        "fileAttributesHex",
                        file_attributes_hex.clone(),
                    ));
                }
                if *file_type != self.kind {
                    return Err(LifecycleError::InvalidField(
                        "fileType",
                        "mismatch with kind".into(),
                    ));
                }
            }
            _ => {
                return Err(LifecycleError::InvalidField(
                    "platform",
                    "stableObject/security mismatch".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, LifecycleError> {
        let v = serde_json::to_value(self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        super::canonical::canonical_digest(&v).map_err(|e| LifecycleError::Canonical(e.to_string()))
    }
}

/// Session pin: closed NativeV1 | ExternalV1 union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionPinV1 {
    #[serde(rename = "native")]
    Native(NativePinV1),
    #[serde(rename = "external")]
    External(ExternalPinV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePinV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub host_session_id: String,
    pub native_session_identity: String,
    pub pin_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExternalPinState {
    Creating,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalPinV1 {
    pub schema_version: u32,
    pub state: ExternalPinState,
    pub host_session_id: String,
    pub creation_key: String,
    pub request_digest: String,
    pub backend_id: String,
    pub install_receipt_digest: String,
    pub cohort_key: String,
    pub extension_schema_digest: String,
    pub renderer_contract_version: String,
    pub acp_session_id: Option<String>,
    pub committed_revision: u64,
    pub committed_cursor: u64,
    pub pin_digest: String,
}

impl SessionPinV1 {
    pub fn parse_json(raw: &str) -> Result<Self, LifecycleError> {
        let v: Value = serde_json::from_str(raw).map_err(|e| LifecycleError::Json(e.to_string()))?;
        let kind = v
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| LifecycleError::PinSchema("missing kind".into()))?;
        match kind {
            "native" => {
                refuse_plugin_fields_on_native(&v)?;
                let pin: NativePinV1 =
                    serde_json::from_value(v).map_err(|e| LifecycleError::Json(e.to_string()))?;
                pin.validate()?;
                let expected = pin.compute_digest()?;
                if pin.pin_digest != expected {
                    return Err(LifecycleError::Digest(expected));
                }
                Ok(SessionPinV1::Native(pin))
            }
            "external" => {
                let pin: ExternalPinV1 =
                    serde_json::from_value(v).map_err(|e| LifecycleError::Json(e.to_string()))?;
                pin.validate()?;
                let expected = pin.compute_digest()?;
                if pin.pin_digest != expected {
                    return Err(LifecycleError::Digest(expected));
                }
                Ok(SessionPinV1::External(pin))
            }
            other => Err(LifecycleError::UnknownDiscriminator(other.into())),
        }
    }
}

impl NativePinV1 {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        if self.backend_id != "native" {
            return Err(LifecycleError::InvalidField(
                "backendId",
                self.backend_id.clone(),
            ));
        }
        require_id("hostSessionId", &self.host_session_id)?;
        require_id("nativeSessionIdentity", &self.native_session_identity)?;
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, LifecycleError> {
        let v = serde_json::to_value(self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        digest_omitting(&v, "pinDigest").map_err(|e| LifecycleError::Canonical(e.to_string()))
    }

    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        self.validate()?;
        self.pin_digest = self.compute_digest()?;
        Ok(self)
    }
}

impl ExternalPinV1 {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_id("hostSessionId", &self.host_session_id)?;
        require_id("backendId", &self.backend_id)?;
        if self.backend_id == "native" {
            return Err(LifecycleError::InvalidField(
                "backendId",
                "external cannot be native".into(),
            ));
        }
        if self.creation_key.len() != 32
            || !self.creation_key.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(LifecycleError::InvalidField(
                "creationKey",
                self.creation_key.clone(),
            ));
        }
        require_sha256("requestDigest", &self.request_digest)?;
        require_sha256("installReceiptDigest", &self.install_receipt_digest)?;
        require_sha256("cohortKey", &self.cohort_key)?;
        require_sha256("extensionSchemaDigest", &self.extension_schema_digest)?;
        require_bound(
            "rendererContractVersion",
            &self.renderer_contract_version,
            64,
        )?;
        match self.state {
            ExternalPinState::Creating => {
                if self.acp_session_id.is_some() {
                    return Err(LifecycleError::InvalidField(
                        "acpSessionId",
                        "must be null while Creating".into(),
                    ));
                }
            }
            ExternalPinState::Active => {
                let id = self.acp_session_id.as_deref().ok_or_else(|| {
                    LifecycleError::InvalidField("acpSessionId", "required when Active".into())
                })?;
                require_id("acpSessionId", id)?;
            }
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, LifecycleError> {
        let v = serde_json::to_value(self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        digest_omitting(&v, "pinDigest").map_err(|e| LifecycleError::Canonical(e.to_string()))
    }

    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        self.validate()?;
        self.pin_digest = self.compute_digest()?;
        Ok(self)
    }
}

fn refuse_plugin_fields_on_native(v: &Value) -> Result<(), LifecycleError> {
    const FORBIDDEN: &[&str] = &[
        "installReceiptDigest",
        "cohortKey",
        "extensionSchemaDigest",
        "rendererContractVersion",
        "creationKey",
        "requestDigest",
        "acpSessionId",
        "committedRevision",
        "committedCursor",
    ];
    for f in FORBIDDEN {
        if v.get(*f).is_some() {
            return Err(LifecycleError::NativeHasPluginFields);
        }
    }
    Ok(())
}

/// Who may write the external barrier file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BarrierWriter {
    Host,
}

/// Host barrier states (closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum BarrierStateV1 {
    Absent,
    Provisioning {
        provision_nonce: String,
        epoch_candidate: u64,
        root_identity: Option<String>,
        store_identity: Option<String>,
    },
    ProvisionFailed {
        failure_code: String,
        root_identity: Option<String>,
        store_identity: Option<String>,
    },
    Open {
        root_generation: u64,
        root_identity: String,
        store_identity: String,
        provision_epoch: u64,
    },
    PreparedStartupGate {
        transaction_id: String,
        plan_digest: String,
    },
    CommitArmed {
        transaction_id: String,
        plan_digest: String,
        member_index: u32,
    },
    DestructivePurgeFence {
        transaction_id: String,
        plan_digest: String,
        member_index: u32,
    },
    Completed {
        transaction_id: String,
        plan_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostBarrierV1 {
    pub schema_version: u32,
    pub plugin_id: String,
    pub install_receipt_digest: String,
    pub cohort_key: String,
    pub revision: u64,
    pub writer: BarrierWriter,
    pub body: BarrierStateV1,
    pub barrier_digest: String,
}

impl HostBarrierV1 {
    pub fn parse_json(raw: &str) -> Result<Self, LifecycleError> {
        let b: Self =
            serde_json::from_str(raw).map_err(|e| LifecycleError::Json(e.to_string()))?;
        b.validate()?;
        let expected = b.compute_digest()?;
        if b.barrier_digest != expected {
            return Err(LifecycleError::Digest(expected));
        }
        Ok(b)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        if self.writer != BarrierWriter::Host {
            return Err(LifecycleError::NonHostBarrierWriter);
        }
        require_id("pluginId", &self.plugin_id)?;
        require_sha256("installReceiptDigest", &self.install_receipt_digest)?;
        require_sha256("cohortKey", &self.cohort_key)?;
        match &self.body {
            BarrierStateV1::Open {
                root_identity,
                store_identity,
                ..
            } => {
                require_sha256("rootIdentity", root_identity)?;
                require_sha256("storeIdentity", store_identity)?;
            }
            BarrierStateV1::Provisioning {
                root_identity,
                store_identity,
                provision_nonce,
                ..
            } => {
                if let Some(r) = root_identity {
                    require_sha256("rootIdentity", r)?;
                }
                if let Some(s) = store_identity {
                    require_sha256("storeIdentity", s)?;
                }
                if provision_nonce.len() != 32
                    || !provision_nonce.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(LifecycleError::InvalidField(
                        "provisionNonce",
                        provision_nonce.clone(),
                    ));
                }
            }
            BarrierStateV1::ProvisionFailed {
                root_identity,
                store_identity,
                failure_code,
            } => {
                if let Some(r) = root_identity {
                    require_sha256("rootIdentity", r)?;
                }
                if let Some(s) = store_identity {
                    require_sha256("storeIdentity", s)?;
                }
                require_id("failureCode", failure_code)?;
            }
            BarrierStateV1::Absent => {}
            BarrierStateV1::PreparedStartupGate {
                transaction_id,
                plan_digest,
            }
            | BarrierStateV1::CommitArmed {
                transaction_id,
                plan_digest,
                ..
            }
            | BarrierStateV1::DestructivePurgeFence {
                transaction_id,
                plan_digest,
                ..
            }
            | BarrierStateV1::Completed {
                transaction_id,
                plan_digest,
            } => {
                require_id("transactionId", transaction_id)?;
                require_sha256("planDigest", plan_digest)?;
            }
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, LifecycleError> {
        let v = serde_json::to_value(self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        digest_omitting(&v, "barrierDigest").map_err(|e| LifecycleError::Canonical(e.to_string()))
    }

    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        self.validate()?;
        self.barrier_digest = self.compute_digest()?;
        Ok(self)
    }

    pub fn can_transition(from: &BarrierStateV1, to: &BarrierStateV1) -> bool {
        use BarrierStateV1::{
            Absent, CommitArmed, Completed, DestructivePurgeFence, Open, PreparedStartupGate,
            ProvisionFailed, Provisioning,
        };
        matches!(
            (from, to),
            (Absent, Provisioning { .. })
                | (Completed { .. }, Provisioning { .. })
                | (ProvisionFailed { .. }, Provisioning { .. })
                | (Provisioning { .. }, Open { .. })
                | (Provisioning { .. }, ProvisionFailed { .. })
                | (Open { .. }, PreparedStartupGate { .. })
                | (PreparedStartupGate { .. }, Open { .. })
                | (PreparedStartupGate { .. }, CommitArmed { .. })
                | (CommitArmed { .. }, PreparedStartupGate { .. })
                | (CommitArmed { .. }, DestructivePurgeFence { .. })
                | (DestructivePurgeFence { .. }, Completed { .. })
        )
    }

    pub fn transition(self, to: BarrierStateV1) -> Result<Self, LifecycleError> {
        if self.writer != BarrierWriter::Host {
            return Err(LifecycleError::NonHostBarrierWriter);
        }
        if !Self::can_transition(&self.body, &to) {
            return Err(LifecycleError::IllegalBarrierTransition {
                from: format!("{:?}", self.body),
                to: format!("{to:?}"),
            });
        }
        if let BarrierStateV1::Open {
            root_identity,
            store_identity,
            ..
        } = &to
        {
            if root_identity.is_empty() || store_identity.is_empty() {
                return Err(LifecycleError::NullOpenIdentity);
            }
        }
        Self {
            revision: self.revision.saturating_add(1),
            body: to,
            barrier_digest: String::new(),
            ..self
        }
        .seal()
    }
}

/// Reject non-host barrier mutation attempts.
pub fn assert_host_barrier_writer(writer: BarrierWriter) -> Result<(), LifecycleError> {
    if writer != BarrierWriter::Host {
        return Err(LifecycleError::NonHostBarrierWriter);
    }
    Ok(())
}

/// Version/cohort hold preventing destructive ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CohortHoldV1 {
    pub schema_version: u32,
    pub hold_id: String,
    pub cohort_key: String,
    pub reason: HoldReason,
    pub revision: u64,
    pub hold_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HoldReason {
    ActiveSession,
    BackgroundWork,
    BackupReference,
    PurgeInProgress,
    Operator,
}

impl CohortHoldV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_id("holdId", &self.hold_id)?;
        require_sha256("cohortKey", &self.cohort_key)?;
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.hold_digest =
            digest_omitting(&v, "holdDigest").map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }
}

/// Canonical purge plan (immutable once Prepared).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgePlanV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub transaction_id: String,
    pub plugin_id: String,
    pub install_receipt_digest: String,
    pub members: Vec<PurgeMemberV1>,
    pub eligible_bytes: u64,
    pub created_at: String,
    pub expires_at: String,
    pub plan_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeMemberV1 {
    pub cohort_key: String,
    pub lease_id: String,
    pub daemon_epoch: u64,
    pub root_identity: String,
    pub store_identity: String,
    pub hold_revision: u64,
    pub entries: Vec<PurgeEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeEntryV1 {
    pub entry_index: u32,
    pub relative_components: Vec<String>,
    pub kind: EntryKind,
    pub expected_entry_identity_sha256: String,
    pub expected_parent_identity_sha256: String,
}

/// Deletion journal phase for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryPhase {
    Ready,
    IntentCommitted,
    DeletionObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeEntryDeleteIntentV1 {
    pub schema_version: u32,
    pub plan_digest: String,
    pub entry_index: u32,
    pub entry_digest: String,
    pub expected_parent_identity_sha256: String,
    pub expected_entry_identity_sha256: String,
    pub intended_at: String,
    pub intent_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeEntryDeleteCompletedV1 {
    pub schema_version: u32,
    pub plan_digest: String,
    pub entry_index: u32,
    pub entry_digest: String,
    pub intent_digest: String,
    pub parent_absence_observation_sha256: String,
    pub reclaimed_bytes: u64,
    pub completed_at: String,
    pub completion_digest: String,
}

/// Mutable purge journal (arming → intent → fence → deleting).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeJournalV1 {
    pub schema_version: u32,
    pub plan_digest: String,
    pub phase: PurgeJournalPhase,
    pub arm_cursor: u32,
    pub fence_cursor: u32,
    pub member_cursor: u32,
    pub entry_cursor: u32,
    pub entry_phase: EntryPhase,
    /// Intent record exists for the current entry cursor.
    pub intent_present: bool,
    /// Completion record exists for the current entry cursor.
    pub completion_present: bool,
    pub journal_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PurgeJournalPhase {
    Prepared,
    Arming,
    CommitIntent,
    Consumed,
    Deleting,
    Completed,
    AbortedPreCommit,
}

impl PurgePlanV1 {
    pub fn parse_json(raw: &str) -> Result<Self, LifecycleError> {
        let p: Self =
            serde_json::from_str(raw).map_err(|e| LifecycleError::Json(e.to_string()))?;
        p.validate()?;
        let expected = p.compute_digest()?;
        if p.plan_digest != expected {
            return Err(LifecycleError::Digest(expected));
        }
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_id("planId", &self.plan_id)?;
        require_id("transactionId", &self.transaction_id)?;
        require_id("pluginId", &self.plugin_id)?;
        require_sha256("installReceiptDigest", &self.install_receipt_digest)?;
        if self.members.is_empty() {
            return Err(LifecycleError::InvalidField("members", "empty".into()));
        }
        let mut prev: Option<&str> = None;
        for m in &self.members {
            require_sha256("cohortKey", &m.cohort_key)?;
            require_id("leaseId", &m.lease_id)?;
            require_sha256("rootIdentity", &m.root_identity)?;
            require_sha256("storeIdentity", &m.store_identity)?;
            if let Some(p) = prev {
                if m.cohort_key.as_str() <= p {
                    return Err(LifecycleError::PurgeOrder(
                        "members must be ascending by cohortKey".into(),
                    ));
                }
            }
            prev = Some(&m.cohort_key);
            validate_entry_order(&m.entries)?;
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, LifecycleError> {
        let v = serde_json::to_value(self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        digest_omitting(&v, "planDigest").map_err(|e| LifecycleError::Canonical(e.to_string()))
    }

    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        self.validate()?;
        self.plan_digest = self.compute_digest()?;
        Ok(self)
    }
}

fn kind_rank(k: EntryKind) -> u8 {
    match k {
        EntryKind::Regular => 0,
        EntryKind::Directory => 1,
    }
}

/// Canonical bottom-up: deeper first, path ascending, files before dirs at equal depth.
pub fn validate_entry_order(entries: &[PurgeEntryV1]) -> Result<(), LifecycleError> {
    if entries.len() > MAX_ENTRIES {
        return Err(LifecycleError::PurgeOrder("too many entries".into()));
    }
    let mut expected = entries.to_vec();
    expected.sort_by(|a, b| {
        b.relative_components
            .len()
            .cmp(&a.relative_components.len())
            .then_with(|| a.relative_components.cmp(&b.relative_components))
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
    });
    if entries != expected.as_slice() {
        return Err(LifecycleError::PurgeOrder(
            "entries must be canonical bottom-up order".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut root_count = 0u32;
    for (i, e) in entries.iter().enumerate() {
        if e.entry_index as usize != i {
            return Err(LifecycleError::PurgeOrder(format!(
                "entryIndex {i} mismatch"
            )));
        }
        if e.relative_components.is_empty() {
            root_count += 1;
            if e.kind != EntryKind::Directory {
                return Err(LifecycleError::PurgeOrder("root must be directory".into()));
            }
        }
        let path = e.relative_components.join("/");
        if !seen.insert(path) {
            return Err(LifecycleError::PurgeOrder("duplicate path".into()));
        }
        require_sha256(
            "expectedEntryIdentitySha256",
            &e.expected_entry_identity_sha256,
        )?;
        require_sha256(
            "expectedParentIdentitySha256",
            &e.expected_parent_identity_sha256,
        )?;
    }
    if root_count != 1 {
        return Err(LifecycleError::PurgeOrder(
            "exactly one depth-zero root required".into(),
        ));
    }
    if let Some(last) = entries.last() {
        if !last.relative_components.is_empty() {
            return Err(LifecycleError::PurgeOrder(
                "cohort root must be final entry".into(),
            ));
        }
    }
    Ok(())
}

impl PurgeEntryDeleteIntentV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_sha256("planDigest", &self.plan_digest)?;
        require_sha256("entryDigest", &self.entry_digest)?;
        require_sha256(
            "expectedParentIdentitySha256",
            &self.expected_parent_identity_sha256,
        )?;
        require_sha256(
            "expectedEntryIdentitySha256",
            &self.expected_entry_identity_sha256,
        )?;
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.intent_digest = digest_omitting(&v, "intentDigest")
            .map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }
}

impl PurgeEntryDeleteCompletedV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_sha256("planDigest", &self.plan_digest)?;
        require_sha256("entryDigest", &self.entry_digest)?;
        require_sha256("intentDigest", &self.intent_digest)?;
        require_sha256(
            "parentAbsenceObservationSha256",
            &self.parent_absence_observation_sha256,
        )?;
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.completion_digest = digest_omitting(&v, "completionDigest")
            .map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }
}

impl PurgeJournalV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_sha256("planDigest", &self.plan_digest)?;
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.journal_digest = digest_omitting(&v, "journalDigest")
            .map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }

    /// Commit deletion intent before unlink. Enforces Ready -> IntentCommitted.
    pub fn commit_intent_before_unlink(mut self) -> Result<Self, LifecycleError> {
        if self.phase != PurgeJournalPhase::Deleting {
            return Err(LifecycleError::IllegalEntryPhase);
        }
        if self.entry_phase != EntryPhase::Ready || self.intent_present {
            return Err(LifecycleError::IntentBeforeUnlink);
        }
        self.entry_phase = EntryPhase::IntentCommitted;
        self.intent_present = true;
        self.seal()
    }

    /// Observe absence after intent; does not advance cursor.
    pub fn observe_deletion(mut self) -> Result<Self, LifecycleError> {
        if self.entry_phase != EntryPhase::IntentCommitted || !self.intent_present {
            return Err(LifecycleError::IntentBeforeUnlink);
        }
        self.entry_phase = EntryPhase::DeletionObserved;
        self.seal()
    }

    /// Durably record completion for the current entry (no cursor move yet).
    pub fn commit_completion(mut self) -> Result<Self, LifecycleError> {
        if self.entry_phase != EntryPhase::DeletionObserved || !self.intent_present {
            return Err(LifecycleError::CompletionBeforeAdvance);
        }
        if self.completion_present {
            return Err(LifecycleError::CompletionBeforeAdvance);
        }
        self.completion_present = true;
        self.seal()
    }

    /// Advance cursor only after completion is durable.
    pub fn advance_after_completion(mut self) -> Result<Self, LifecycleError> {
        if !self.completion_present {
            return Err(LifecycleError::CompletionBeforeAdvance);
        }
        if self.entry_phase != EntryPhase::DeletionObserved || !self.intent_present {
            return Err(LifecycleError::CompletionBeforeAdvance);
        }
        self.entry_cursor = self.entry_cursor.saturating_add(1);
        self.entry_phase = EntryPhase::Ready;
        self.intent_present = false;
        self.completion_present = false;
        self.seal()
    }
}

/// Activation rollback receipt (new sessions only; never moves pins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackReceiptV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub from_receipt_digest: String,
    pub to_receipt_digest: String,
    pub rolled_back_at: String,
    pub rollback_digest: String,
}

impl RollbackReceiptV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_id("backendId", &self.backend_id)?;
        require_sha256("fromReceiptDigest", &self.from_receipt_digest)?;
        require_sha256("toReceiptDigest", &self.to_receipt_digest)?;
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.rollback_digest = digest_omitting(&v, "rollbackDigest")
            .map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }
}

/// GC candidate for unreferenced payload/staging only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcPlanV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub candidates: Vec<GcCandidateV1>,
    pub plan_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcCandidateV1 {
    pub kind: GcCandidateKind,
    pub path_digest: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GcCandidateKind {
    UnreferencedPayload,
    CompletedStaging,
}

impl GcPlanV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleError> {
        if self.schema_version != 1 {
            return Err(LifecycleError::UnsupportedSchema(self.schema_version));
        }
        require_id("planId", &self.plan_id)?;
        for c in &self.candidates {
            require_sha256("pathDigest", &c.path_digest)?;
        }
        let v = serde_json::to_value(&self).map_err(|e| LifecycleError::Json(e.to_string()))?;
        self.plan_digest = digest_omitting(&v, "planDigest")
            .map_err(|e| LifecycleError::Canonical(e.to_string()))?;
        Ok(self)
    }
}

/// Sort relative components into canonical purge entry list (includes root).
pub fn sort_purge_entries(mut entries: Vec<PurgeEntryV1>) -> Vec<PurgeEntryV1> {
    entries.sort_by(|a, b| {
        b.relative_components
            .len()
            .cmp(&a.relative_components.len())
            .then_with(|| a.relative_components.cmp(&b.relative_components))
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
    });
    for (i, e) in entries.iter_mut().enumerate() {
        e.entry_index = i as u32;
    }
    entries
}

#[cfg(test)]
#[path = "lifecycle_test.rs"]
mod lifecycle_test;
