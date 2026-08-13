// allow: SIZE_OK — plan Task 16 owns host rollback to LKG / retained receipt.
//! Restore last-known-good or a retained host receipt. Never touches plugins.

use super::apply::{self, ApplyError};
use super::receipt::{
    self, host_bin_name, now_rfc3339, HostLayout, HostUpdateReceiptV1, HostUpdateTransactionV1,
    LastKnownGoodV1, TxnPhase, TXN_SCHEMA,
};
use super::stage::{self, target_compatible, StageError};
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
    #[error("incompatible rollback target: {0}")]
    IncompatibleTarget(String),
    #[error("retained signature missing for archive {0}")]
    SignatureMissing(String),
}

#[derive(Debug)]
pub struct RollbackResult {
    pub version: String,
    pub receipt_digest: String,
}

/// `orca update rollback [--to <version>]`
///
/// Re-stages from retained archive + retained Ed25519 signature only.
/// Never fabricates signatures. Rejects target-incompatible receipts.
pub fn rollback(
    layout: &HostLayout,
    to_version: Option<&str>,
) -> Result<RollbackResult, RollbackError> {
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

    if !target_compatible(&receipt.target) {
        return Err(RollbackError::IncompatibleTarget(receipt.target));
    }

    // Retained detached signature only — never re-sign.
    let sig_path = layout.archive_sig_path(&receipt.archive_sha256);
    if !sig_path.is_file() {
        return Err(RollbackError::SignatureMissing(receipt.archive_sha256));
    }

    let staged = stage::stage_archive(layout, &archive_path, Some(&sig_path), false)?;

    // Force candidate receipt to match retained identity where possible.
    let mut receipt = receipt;
    receipt.installed_at = now_rfc3339();
    // Preserve original signature metadata from retained receipt.
    receipt.signature_algorithm = staged.receipt.signature_algorithm.clone();
    receipt.signature_key_id = staged.receipt.signature_key_id.clone();
    receipt.signature_sha256 = staged.receipt.signature_sha256.clone();
    receipt.archive_sha256 = staged.archive_sha256.clone();
    receipt.files = staged.receipt.files.clone();
    receipt.install_root = layout.install_root.display().to_string();
    receipt.receipt_digest = String::new();
    receipt = receipt.seal()?;

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
        signature_key_id: staged.signature_key_id,
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
            // Compatibility gate before any promote path.
            if !target_compatible(&r.target) {
                return Err(RollbackError::IncompatibleTarget(r.target));
            }
            let ap = layout.archive_path(&r.archive_sha256);
            if !ap.is_file() {
                return Err(RollbackError::ArchiveMissing(r.archive_sha256));
            }
            let sp = layout.archive_sig_path(&r.archive_sha256);
            if !sp.is_file() {
                return Err(RollbackError::SignatureMissing(r.archive_sha256));
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
    let id = format!(
        "rollback-{}-{}",
        now_rfc3339(),
        &archive_sha256[..8.min(archive_sha256.len())]
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_update::receipt::{
        sha256_hex, HostFileEntry, ARCHIVE_FORMAT_ID, RECEIPT_SCHEMA, SIG_ALG_ED25519,
    };
    use crate::host_update::stage::{
        build_r5_archive, clear_fixture_trust_env, install_fixture_trust_env,
        sign_and_write_fixture_sig, stage_archive,
    };
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn layout_at(root: &std::path::Path) -> HostLayout {
        let paths = xai_grok_config::OrcaPaths {
            config_file: root.join("config.toml"),
            data_root: root.join("data"),
            state_root: root.join("state"),
            cache_root: root.join("cache"),
            runtime_root: root.join("runtime"),
            logs_dir: root.join("state/logs"),
            from_orca_home: true,
        };
        HostLayout::from_paths(&paths, root)
    }

    #[test]
    fn rollback_incompatible_target_refused() {
        let _g = env_lock();
        install_fixture_trust_env();
        unsafe {
            std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1");
            std::env::remove_var("ORCA_HOST_UPDATE_FAILPOINT");
        }
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();

        let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"payload-a").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &bytes).unwrap();
        let staged = stage_archive(&layout, &ap, None, false).unwrap();
        let ash = staged.archive_sha256.clone();
        fs::copy(&ap, layout.archive_path(&ash)).unwrap();
        let sig = fs::read({
            let mut p = ap.as_os_str().to_os_string();
            p.push(".sig");
            PathBuf::from(p)
        })
        .unwrap();
        fs::write(layout.archive_sig_path(&ash), &sig).unwrap();

        let forged = HostUpdateReceiptV1 {
            schema_version: RECEIPT_SCHEMA,
            product: "orca".into(),
            version: "0.0.0-test-incompatible".into(),
            target: "windows-x86_64".into(),
            archive_sha256: ash.clone(),
            archive_format: ARCHIVE_FORMAT_ID.into(),
            signature_algorithm: SIG_ALG_ED25519.into(),
            signature_key_id: staged.signature_key_id.clone(),
            signature_sha256: sha256_hex(&sig),
            install_root: layout.install_root.display().to_string(),
            files: vec![HostFileEntry {
                relative_path: "orca".into(),
                mode_octal: "0755".into(),
                length: 9,
                content_sha256: sha256_hex(b"payload-a"),
            }],
            installed_at: now_rfc3339(),
            receipt_digest: String::new(),
        }
        .seal()
        .unwrap();
        forged
            .write_atomic(&layout.receipt_path(&forged.receipt_digest))
            .unwrap();

        let err = rollback(&layout, Some("0.0.0-test-incompatible")).unwrap_err();
        assert!(
            matches!(err, RollbackError::IncompatibleTarget(_)),
            "incompatible rollback must refuse: {err}"
        );

        unsafe { std::env::remove_var("ORCA_HOST_UPDATE_IN_PROCESS") };
        clear_fixture_trust_env();
    }
}
