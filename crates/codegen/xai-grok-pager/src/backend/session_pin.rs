//! Immutable session pins: NativeV1 and crash-safe ExternalV1 Creating→Active.
//!
//! // allow: SIZE_OK — plan Task 12 freezes pin store + transaction in one module

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::plugin_host::lifecycle::{
    ExternalPinState, ExternalPinV1, LifecycleError, NativePinV1, SessionPinV1,
};

/// On-disk pin store under `state/session-pins/`.
#[derive(Debug, Clone)]
pub struct PinStore {
    dir: PathBuf,
}

/// Inputs for a new external session pin (pre-bridge dispatch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCreateRequest {
    pub host_session_id: String,
    pub creation_key: String,
    pub request_digest: String,
    pub backend_id: String,
    pub install_receipt_digest: String,
    pub cohort_key: String,
    pub extension_schema_digest: String,
    pub renderer_contract_version: String,
}

/// Stable ACP identity filled only on Creating→Active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalActivateRequest {
    pub host_session_id: String,
    pub acp_session_id: String,
    pub committed_revision: u64,
    pub committed_cursor: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PinStoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("lifecycle: {0}")]
    Lifecycle(String),
    #[error("pin missing: {0}")]
    Missing(String),
    #[error("pin schema: {0}")]
    Schema(String),
    #[error("idempotency conflict: {0}")]
    Idempotency(String),
    #[error("active pin is immutable: {0}")]
    ActiveImmutable(String),
    #[error("pending Creating pin: {0}")]
    PendingCreating(String),
    #[error("receipt missing for pin: {0}")]
    MissingReceipt(String),
    #[error("stale pin version/cohort: {0}")]
    Stale(String),
}

impl From<LifecycleError> for PinStoreError {
    fn from(e: LifecycleError) -> Self {
        Self::Lifecycle(e.to_string())
    }
}

impl From<io::Error> for PinStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl PinStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, PinStoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, host_session_id: &str) -> PathBuf {
        self.dir.join(format!("{host_session_id}.json"))
    }

    /// Load a pin if present. Corrupt/unknown variants fail closed.
    pub fn load(&self, host_session_id: &str) -> Result<Option<SessionPinV1>, PinStoreError> {
        let path = self.path_for(host_session_id);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        let pin = SessionPinV1::parse_json(&raw).map_err(|e| match e {
            LifecycleError::UnknownDiscriminator(k) => {
                PinStoreError::Schema(format!("unknown kind {k}"))
            }
            LifecycleError::NativeHasPluginFields => {
                PinStoreError::Schema("native pin has plugin fields".into())
            }
            other => PinStoreError::Schema(other.to_string()),
        })?;
        Ok(Some(pin))
    }

    /// Resume path: pin must exist and parse.
    pub fn load_required(&self, host_session_id: &str) -> Result<SessionPinV1, PinStoreError> {
        self.load(host_session_id)?
            .ok_or_else(|| PinStoreError::Missing(host_session_id.into()))
    }

    /// Write NativeV1 after a successful native session identity exists.
    pub fn write_native(
        &self,
        host_session_id: &str,
        native_session_identity: &str,
    ) -> Result<NativePinV1, PinStoreError> {
        if let Some(existing) = self.load(host_session_id)? {
            return Err(PinStoreError::Idempotency(format!(
                "pin already exists for {host_session_id}: {existing:?}"
            )));
        }
        let pin = NativePinV1 {
            schema_version: 1,
            backend_id: "native".into(),
            host_session_id: host_session_id.into(),
            native_session_identity: native_session_identity.into(),
            pin_digest: String::new(),
        }
        .seal()?;
        self.persist(&SessionPinV1::Native(pin.clone()))?;
        Ok(pin)
    }

    /// Persist Creating pin (null ACP session) and fsync before bridge dispatch.
    pub fn begin_external_create(
        &self,
        req: &ExternalCreateRequest,
    ) -> Result<ExternalPinV1, PinStoreError> {
        if req.backend_id == "native" {
            return Err(PinStoreError::Schema(
                "external create cannot use backendId=native".into(),
            ));
        }
        if let Some(existing) = self.load(&req.host_session_id)? {
            return self.replay_or_conflict(existing, req);
        }
        let pin = ExternalPinV1 {
            schema_version: 1,
            state: ExternalPinState::Creating,
            host_session_id: req.host_session_id.clone(),
            creation_key: req.creation_key.clone(),
            request_digest: req.request_digest.clone(),
            backend_id: req.backend_id.clone(),
            install_receipt_digest: req.install_receipt_digest.clone(),
            cohort_key: req.cohort_key.clone(),
            extension_schema_digest: req.extension_schema_digest.clone(),
            renderer_contract_version: req.renderer_contract_version.clone(),
            acp_session_id: None,
            committed_revision: 0,
            committed_cursor: 0,
            pin_digest: String::new(),
        }
        .seal()?;
        self.persist(&SessionPinV1::External(pin.clone()))?;
        Ok(pin)
    }

    /// Creating→Active: fill only authenticated ACP session identity.
    pub fn activate_external(
        &self,
        req: &ExternalActivateRequest,
    ) -> Result<ExternalPinV1, PinStoreError> {
        let existing = self.load_required(&req.host_session_id)?;
        let SessionPinV1::External(mut pin) = existing else {
            return Err(PinStoreError::Schema(
                "activate requires ExternalV1 Creating pin".into(),
            ));
        };
        match pin.state {
            ExternalPinState::Active => {
                if pin.acp_session_id.as_deref() == Some(req.acp_session_id.as_str())
                    && pin.committed_revision == req.committed_revision
                    && pin.committed_cursor == req.committed_cursor
                {
                    return Ok(pin);
                }
                return Err(PinStoreError::ActiveImmutable(
                    "Active pin cannot change ACP identity".into(),
                ));
            }
            ExternalPinState::Creating => {}
        }
        pin.state = ExternalPinState::Active;
        pin.acp_session_id = Some(req.acp_session_id.clone());
        pin.committed_revision = req.committed_revision;
        pin.committed_cursor = req.committed_cursor;
        pin.pin_digest.clear();
        let pin = pin.seal()?;
        self.persist(&SessionPinV1::External(pin.clone()))?;
        Ok(pin)
    }

    /// Restart reconciliation: return Creating pin for exact receipt/cohort replay.
    /// Never deletes, never selects another version, never infers failure.
    pub fn reconcile_creating(
        &self,
        host_session_id: &str,
    ) -> Result<ExternalPinV1, PinStoreError> {
        let pin = self.load_required(host_session_id)?;
        match pin {
            SessionPinV1::External(p) if p.state == ExternalPinState::Creating => Ok(p),
            SessionPinV1::External(p) if p.state == ExternalPinState::Active => Err(
                PinStoreError::ActiveImmutable(format!("session {host_session_id} already Active")),
            ),
            SessionPinV1::Native(_) => Err(PinStoreError::Schema(
                "native pin has no Creating reconciliation".into(),
            )),
            SessionPinV1::External(_) => {
                Err(PinStoreError::Schema("unexpected external state".into()))
            }
        }
    }

    /// Refuse moving an Active external pin across receipt or cohort.
    pub fn assert_active_identity_stable(
        &self,
        host_session_id: &str,
        receipt_digest: &str,
        cohort_key: &str,
    ) -> Result<(), PinStoreError> {
        let pin = self.load_required(host_session_id)?;
        match pin {
            SessionPinV1::External(p) if p.state == ExternalPinState::Active => {
                if p.install_receipt_digest != receipt_digest || p.cohort_key != cohort_key {
                    return Err(PinStoreError::Stale(format!(
                        "active pin receipt/cohort immutable for {host_session_id}"
                    )));
                }
                Ok(())
            }
            SessionPinV1::External(p) if p.state == ExternalPinState::Creating => {
                Err(PinStoreError::PendingCreating(p.host_session_id))
            }
            SessionPinV1::Native(_) => Ok(()),
            SessionPinV1::External(_) => Ok(()),
        }
    }

    /// Generate a 128-bit creation key as 32 lowercase hex chars.
    pub fn new_creation_key(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn replay_or_conflict(
        &self,
        existing: SessionPinV1,
        req: &ExternalCreateRequest,
    ) -> Result<ExternalPinV1, PinStoreError> {
        match existing {
            SessionPinV1::External(p) if p.state == ExternalPinState::Creating => {
                if p.creation_key == req.creation_key
                    && p.request_digest == req.request_digest
                    && p.backend_id == req.backend_id
                    && p.install_receipt_digest == req.install_receipt_digest
                    && p.cohort_key == req.cohort_key
                    && p.extension_schema_digest == req.extension_schema_digest
                    && p.renderer_contract_version == req.renderer_contract_version
                {
                    return Ok(p);
                }
                Err(PinStoreError::Idempotency(
                    "Creating pin replay with changed request".into(),
                ))
            }
            SessionPinV1::External(p) if p.state == ExternalPinState::Active => {
                Err(PinStoreError::ActiveImmutable(format!(
                    "cannot recreate Active session {}",
                    p.host_session_id
                )))
            }
            SessionPinV1::Native(_) => Err(PinStoreError::Idempotency(
                "native pin blocks external create".into(),
            )),
            SessionPinV1::External(_) => {
                Err(PinStoreError::Schema("unexpected external state".into()))
            }
        }
    }

    fn persist(&self, pin: &SessionPinV1) -> Result<(), PinStoreError> {
        let host_session_id = match pin {
            SessionPinV1::Native(n) => n.host_session_id.as_str(),
            SessionPinV1::External(e) => e.host_session_id.as_str(),
        };
        let path = self.path_for(host_session_id);
        let raw = serde_json::to_vec(pin).map_err(|e| PinStoreError::Io(e.to_string()))?;
        atomic_write_fsync(&path, &raw)
    }
}

fn atomic_write_fsync(path: &Path, bytes: &[u8]) -> Result<(), PinStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| PinStoreError::Io("no parent".into()))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("pin")
    ));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
#[path = "session_pin_test.rs"]
mod session_pin_test;
