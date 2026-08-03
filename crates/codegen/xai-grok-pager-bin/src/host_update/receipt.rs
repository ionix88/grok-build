// allow: SIZE_OK — plan Task 16 owns host receipt/LKG/transaction schemas.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use xai_grok_config::{resolve_orca_paths_current, OrcaPathEnv, OrcaPaths, OrcaPlatform};

pub const RECEIPT_SCHEMA: u32 = 1;
pub const LKG_SCHEMA: u32 = 1;
pub const TXN_SCHEMA: u32 = 1;
pub const CURRENT_SCHEMA: u32 = 1;
pub const ARCHIVE_FORMAT_ID: &str = "tar-gzip-rfc1952-ustar-v1";
pub const TEST_SIG_ALGORITHM: &str = "test-only-sha512-v1";

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("digest mismatch")]
    DigestMismatch,
    #[error("version byte conflict: {0}")]
    VersionByteConflict(String),
    #[error("path: {0}")]
    Path(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostFileEntry {
    pub relative_path: String,
    pub mode_octal: String,
    pub length: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateReceiptV1 {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub target: String,
    pub archive_sha256: String,
    pub archive_format: String,
    pub signature_algorithm: String,
    pub signature_sha256: String,
    pub install_root: String,
    pub files: Vec<HostFileEntry>,
    pub installed_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receipt_digest: String,
}

impl HostUpdateReceiptV1 {
    pub fn seal(mut self) -> Result<Self, ReceiptError> {
        self.files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        self.receipt_digest.clear();
        let bytes = serde_json::to_vec(&self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        self.receipt_digest = sha256_hex(&bytes);
        Ok(self)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), ReceiptError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        write_atomic(path, &bytes)
    }

    pub fn load(path: &Path) -> Result<Self, ReceiptError> {
        let bytes = fs::read(path)?;
        let r: Self = serde_json::from_slice(&bytes).map_err(|e| ReceiptError::Json(e.to_string()))?;
        let mut tmp = r.clone();
        tmp.receipt_digest.clear();
        let got = sha256_hex(&serde_json::to_vec(&tmp).map_err(|e| ReceiptError::Json(e.to_string()))?);
        if got != r.receipt_digest {
            return Err(ReceiptError::DigestMismatch);
        }
        Ok(r)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastKnownGoodV1 {
    pub schema_version: u32,
    pub version: String,
    pub archive_sha256: String,
    pub receipt_digest: String,
    pub retained_at: String,
}

impl LastKnownGoodV1 {
    pub fn write_atomic(&self, path: &Path) -> Result<(), ReceiptError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> Result<Self, ReceiptError> {
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| ReceiptError::Json(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CurrentHostV1 {
    pub schema_version: u32,
    pub version: String,
    pub archive_sha256: String,
    pub receipt_digest: String,
    pub binary_path: String,
    pub updated_at: String,
}

impl CurrentHostV1 {
    pub fn write_atomic(&self, path: &Path) -> Result<(), ReceiptError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> Result<Self, ReceiptError> {
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| ReceiptError::Json(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TxnPhase {
    Created,
    Staged,
    Prepared,
    Applying,
    Committed,
    Aborted,
    RolledBack,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateTransactionV1 {
    pub schema_version: u32,
    pub transaction_id: String,
    pub phase: TxnPhase,
    pub target_version: String,
    pub archive_sha256: String,
    pub staged_root: String,
    pub install_root: String,
    pub prior_receipt_digest: Option<String>,
    pub candidate_receipt_digest: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub error: Option<String>,
}

impl HostUpdateTransactionV1 {
    pub fn set_phase(&mut self, phase: TxnPhase) {
        self.phase = phase;
        self.updated_at = now_rfc3339();
    }
    pub fn write_atomic(&self, path: &Path) -> Result<(), ReceiptError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ReceiptError::Json(e.to_string()))?;
        write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> Result<Self, ReceiptError> {
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| ReceiptError::Json(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct HostLayout {
    pub install_root: PathBuf,
    pub managed_bin: PathBuf,
    pub state_host: PathBuf,
    pub receipts_dir: PathBuf,
    pub transactions_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub archives_dir: PathBuf,
    pub current_path: PathBuf,
    pub lkg_path: PathBuf,
}

impl HostLayout {
    pub fn from_paths(orca: &OrcaPaths, install_root: impl AsRef<Path>) -> Self {
        let install_root = install_root.as_ref().to_path_buf();
        let state_host = orca.state_root.join("host");
        let managed_bin = install_root.join(host_bin_name());
        Self {
            managed_bin,
            install_root,
            receipts_dir: state_host.join("receipts"),
            transactions_dir: state_host.join("transactions"),
            staging_dir: orca.cache_root.join("host-staging"),
            archives_dir: state_host.join("archives"),
            current_path: state_host.join("current.json"),
            lkg_path: state_host.join("last-known-good.json"),
            state_host,
        }
    }

    pub fn resolve_current() -> Result<Self, ReceiptError> {
        let orca = resolve_orca_paths_current().map_err(|e| ReceiptError::Path(e.to_string()))?;
        let install_root = if orca.from_orca_home {
            orca.config_file
                .parent()
                .map(|p| p.join("bin"))
                .unwrap_or_else(|| PathBuf::from("bin"))
        } else {
            #[allow(deprecated)]
            let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home.join(".orca").join("bin")
        };
        Ok(Self::from_paths(&orca, install_root))
    }

    pub fn ensure_dirs(&self) -> Result<(), ReceiptError> {
        for d in [
            &self.state_host,
            &self.receipts_dir,
            &self.transactions_dir,
            &self.staging_dir,
            &self.archives_dir,
            &self.install_root,
        ] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }

    pub fn receipt_path(&self, digest: &str) -> PathBuf {
        self.receipts_dir.join(format!("{digest}.json"))
    }

    pub fn txn_path(&self, id: &str) -> PathBuf {
        self.transactions_dir.join(format!("{id}.json"))
    }

    pub fn archive_path(&self, sha: &str) -> PathBuf {
        self.archives_dir.join(format!("{sha}.tar.gz"))
    }
}

pub fn host_bin_name() -> &'static str {
    if cfg!(windows) {
        "orca.exe"
    } else {
        "orca"
    }
}

pub fn host_target_triple() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else {
        "unknown"
    };
    format!("{os}-{arch}")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String, ReceiptError> {
    Ok(sha256_hex(&fs::read(path)?))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Compact deterministic-enough timestamp for receipts (not wall-clock critical).
    format!("1970-01-01T00:00:{secs:02}Z")
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReceiptError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn check_version_byte_conflict(
    layout: &HostLayout,
    candidate_version: &str,
    candidate_archive_sha: &str,
) -> Result<(), ReceiptError> {
    if !layout.current_path.is_file() {
        return Ok(());
    }
    let cur = CurrentHostV1::load(&layout.current_path)?;
    if cur.version == candidate_version && cur.archive_sha256 != candidate_archive_sha {
        return Err(ReceiptError::VersionByteConflict(candidate_version.into()));
    }
    Ok(())
}

/// Test helper: build layout under an absolute ORCA_HOME root.
pub fn test_layout(orca_home: &Path) -> Result<HostLayout, ReceiptError> {
    let env = OrcaPathEnv {
        orca_home: Some(orca_home.to_path_buf()),
        ..Default::default()
    };
    let paths = xai_grok_config::resolve_orca_paths(OrcaPlatform::Macos, &env)
        .map_err(|e| ReceiptError::Path(e.to_string()))?;
    let install = paths.config_file.parent().unwrap().join("bin");
    Ok(HostLayout::from_paths(&paths, install))
}
