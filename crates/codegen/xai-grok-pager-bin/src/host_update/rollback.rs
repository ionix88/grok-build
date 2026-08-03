// allow: SIZE_OK — plan Task 16 owns host rollback to LKG / retained receipt.
//! Restore last-known-good or a retained host receipt. Never touches plugins.

use super::apply::{self, ApplyError};
use super::receipt::{
    self, host_bin_name, now_rfc3339, HostLayout, HostUpdateReceiptV1, HostUpdateTransactionV1,
    LastKnownGoodV1, TxnPhase, TXN_SCHEMA,
};
use super::stage::{self, StageError};
use std::fs;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RollbackError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("receipt: {0}")]
    Receipt(#[from] receipt::ReceiptError),
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),
    #[error("stage: {0}")]
    Stage(#[from] StageError),
    #[error("no last-known-good host receipt")]
    NoLkg,
    #[error("receipt not found for version {0}")]
    VersionNotFound(String),
    #[error("archive missing for receipt {0}")]
    ArchiveMissing(String),
}

pub struct RollbackResult {
    pub version: String,
    pub receipt_digest: String,
}

/// `orca update rollback [--to <version>]`
pub fn rollback(layout: &HostLayout, to_version: Option<&str>) -> Result<RollbackResult, RollbackError> {
    layout.ensure_dirs()?;
    let _ = apply::recover_abandoned(layout);

    let (receipt, archive_path) = if let Some(ver) = to_version {
        find_receipt_for_version(layout, ver)?
    } else {
        let lkg = LastKnownGoodV1::load(&layout.lkg_path).map_err(|_| RollbackError::NoLkg)?;
        let rpath = layout.receipt_path(&lkg.receipt_digest);
        let receipt = HostUpdateReceiptV1::load(&rpath).map_err(|_| RollbackError::NoLkg)?;
        let ap = layout.archive_path(&receipt.archive_sha256);
        if !ap.is_file() {
            return Err(RollbackError::ArchiveMissing(receipt.archive_sha256));
        }
        (receipt, ap)
    };

    // Re-stage from retained archive + sig (re-sign test sig from bytes).
    let bytes = fs::read(&archive_path)?;
    let sig_path = {
        // Ensure detached sig exists beside retained archive.
        stage::write_sig_file(&archive_path, &bytes)?
    };
    let staged = stage::stage_archive(layout, &archive_path, Some(&sig_path), false)?;

    // Force candidate receipt to match retained identity where possible.
    let mut receipt = receipt;
    receipt.installed_at = now_rfc3339();
    receipt = receipt.seal()?;

    // Write receipt before apply so child/in-process can load it.
    receipt.write_atomic(&layout.receipt_path(&receipt.receipt_digest))?;

    let mut txn = staged.transaction;
    txn.candidate_receipt_digest = Some(receipt.receipt_digest.clone());
    txn.target_version = receipt.version.clone();
    txn.set_phase(TxnPhase::Staged);
    txn.write_atomic(&staged.txn_path)?;

    let staged = stage::StagedUpdate {
        transaction: txn,
        receipt: receipt.clone(),
        staged_bin: staged.staged_bin,
        archive_sha256: staged.archive_sha256,
        txn_path: staged.txn_path,
    };

    let applied = apply::promote(layout, &staged)?;
    Ok(RollbackResult {
        version: applied.version,
        receipt_digest: applied.receipt_digest,
    })
}

fn find_receipt_for_version(
    layout: &HostLayout,
    version: &str,
) -> Result<(HostUpdateReceiptV1, PathBuf), RollbackError> {
    if !layout.receipts_dir.is_dir() {
        return Err(RollbackError::VersionNotFound(version.into()));
    }
    for ent in fs::read_dir(&layout.receipts_dir)? {
        let ent = ent?;
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(r) = HostUpdateReceiptV1::load(&path) else {
            continue;
        };
        if r.version == version {
            let ap = layout.archive_path(&r.archive_sha256);
            if !ap.is_file() {
                return Err(RollbackError::ArchiveMissing(r.archive_sha256));
            }
            return Ok((r, ap));
        }
    }
    Err(RollbackError::VersionNotFound(version.into()))
}

/// Build a synthetic rollback transaction record (audit).
#[allow(dead_code)]
pub fn record_rollback_txn(
    layout: &HostLayout,
    version: &str,
    archive_sha256: &str,
) -> Result<(), RollbackError> {
    let id = format!("rollback-{}-{}", now_rfc3339(), &archive_sha256[..8.min(archive_sha256.len())]);
    let txn = HostUpdateTransactionV1 {
        schema_version: TXN_SCHEMA,
        transaction_id: id.clone(),
        phase: TxnPhase::RolledBack,
        target_version: version.into(),
        archive_sha256: archive_sha256.into(),
        staged_root: String::new(),
        install_root: layout.install_root.display().to_string(),
        prior_receipt_digest: None,
        candidate_receipt_digest: None,
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
        error: None,
    };
    txn.write_atomic(&layout.txn_path(&id))?;
    let _ = host_bin_name();
    Ok(())
}
