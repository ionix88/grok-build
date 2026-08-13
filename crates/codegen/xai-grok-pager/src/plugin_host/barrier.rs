//! External backend lifecycle barrier orchestration and persistence.
//!
//! The host is the sole writer. Connection construction seals a concrete Open
//! barrier only after supervisor readiness, then dispatches transport.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::lifecycle::{BarrierStateV1, HostBarrierV1, LifecycleError};
use super::supervisor::SupervisorReady;

#[derive(Debug, Error)]
pub enum BarrierError {
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    #[error("external backend barrier is not open")]
    NotOpen,
    #[error("barrier drift: {0}")]
    Drift(String),
    #[error("barrier io: {0}")]
    Io(String),
}

impl From<io::Error> for BarrierError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// On-disk barrier store under a host-owned directory (typically runtime).
#[derive(Debug, Clone)]
pub struct BarrierStore {
    dir: PathBuf,
}

impl BarrierStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, BarrierError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, plugin_id: &str, cohort_key: &str) -> PathBuf {
        // One sealed barrier document per plugin+cohort pair.
        self.dir
            .join(format!("{plugin_id}-{cohort_key}.barrier.json"))
    }

    pub fn load(
        &self,
        plugin_id: &str,
        cohort_key: &str,
    ) -> Result<Option<HostBarrierV1>, BarrierError> {
        let path = self.path_for(plugin_id, cohort_key);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        let barrier = HostBarrierV1::parse_json(&raw)?;
        Ok(Some(barrier))
    }

    pub fn persist(&self, barrier: &HostBarrierV1) -> Result<(), BarrierError> {
        let path = self.path_for(&barrier.plugin_id, &barrier.cohort_key);
        let raw = serde_json::to_vec(barrier).map_err(|e| BarrierError::Io(e.to_string()))?;
        atomic_write_fsync(&path, &raw)
    }
}

fn atomic_write_fsync(path: &Path, bytes: &[u8]) -> Result<(), BarrierError> {
    let parent = path
        .parent()
        .ok_or_else(|| BarrierError::Io("no parent".into()))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("barrier")
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

/// Refuse any non-Open barrier before transport dispatch.
pub fn require_open(barrier: HostBarrierV1) -> Result<HostBarrierV1, BarrierError> {
    match barrier.body {
        BarrierStateV1::Open { .. } => Ok(barrier),
        BarrierStateV1::Absent
        | BarrierStateV1::Provisioning { .. }
        | BarrierStateV1::ProvisionFailed { .. }
        | BarrierStateV1::PreparedStartupGate { .. }
        | BarrierStateV1::CommitArmed { .. }
        | BarrierStateV1::DestructivePurgeFence { .. }
        | BarrierStateV1::Completed { .. } => Err(BarrierError::NotOpen),
    }
}

/// Transition a sealed Provisioning barrier to Open using supervisor identities.
pub fn open_after_ready(
    barrier: HostBarrierV1,
    ready: SupervisorReady,
) -> Result<HostBarrierV1, BarrierError> {
    let BarrierStateV1::Provisioning {
        epoch_candidate, ..
    } = &barrier.body
    else {
        return Err(BarrierError::NotOpen);
    };
    let epoch = *epoch_candidate;
    barrier
        .transition(BarrierStateV1::Open {
            root_generation: epoch,
            root_identity: ready.root_identity,
            store_identity: ready.store_identity,
            provision_epoch: epoch,
        })
        .map_err(BarrierError::from)
}

/// Mark provision failure on a Provisioning barrier (best-effort diagnostics).
pub fn mark_provision_failed(
    barrier: HostBarrierV1,
    failure_code: impl Into<String>,
) -> Result<HostBarrierV1, BarrierError> {
    barrier
        .transition(BarrierStateV1::ProvisionFailed {
            failure_code: failure_code.into(),
            root_identity: None,
            store_identity: None,
        })
        .map_err(BarrierError::from)
}

/// Ensure an Open barrier still matches the pin's receipt and cohort.
pub fn assert_open_matches_pin(
    barrier: &HostBarrierV1,
    plugin_id: &str,
    receipt_digest: &str,
    cohort_key: &str,
) -> Result<(), BarrierError> {
    require_open(barrier.clone())?;
    if barrier.plugin_id != plugin_id
        || barrier.install_receipt_digest != receipt_digest
        || barrier.cohort_key != cohort_key
    {
        return Err(BarrierError::Drift(format!(
            "open barrier identity drift plugin={} receipt={} cohort={}",
            barrier.plugin_id, barrier.install_receipt_digest, barrier.cohort_key
        )));
    }
    Ok(())
}
