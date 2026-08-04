// allow: SIZE_OK — plan Task 16 owns atomic host promote / hidden apply path.
//! Atomic promotion of a staged host update. Never touches plugins/pins/cohorts.

use super::receipt::{
    self, host_bin_name, now_rfc3339, CurrentHostV1, HostLayout, HostUpdateReceiptV1,
    HostUpdateTransactionV1, LastKnownGoodV1, TxnPhase, CURRENT_SCHEMA, LKG_SCHEMA,
};
use super::stage::StagedUpdate;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("receipt: {0}")]
    Receipt(#[from] receipt::ReceiptError),
    #[error("transaction phase {0:?} cannot apply")]
    BadPhase(TxnPhase),
    #[error("staged binary missing: {0}")]
    MissingStaged(String),
    #[error("spawn apply child: {0}")]
    Spawn(String),
    #[error("apply failed: {0}")]
    Failed(String),
    #[error("failpoint:{0}")]
    Failpoint(&'static str),
}

/// Deterministic crash-boundary injection. No wall-clock sleep.
/// Set `ORCA_HOST_UPDATE_FAILPOINT` to one of:
/// `before_applying`, `after_promote_before_receipt`, `before_commit`.
fn hit_failpoint(name: &'static str) -> Result<(), ApplyError> {
    match std::env::var("ORCA_HOST_UPDATE_FAILPOINT") {
        Ok(v) if v == name => Err(ApplyError::Failpoint(name)),
        _ => Ok(()),
    }
}

/// Promote staged update: either in-process (tests / ORCA_HOST_UPDATE_IN_PROCESS=1)
/// or via hidden `__apply-host-update --transaction <path>` child.
pub fn promote(
    layout: &HostLayout,
    staged: &StagedUpdate,
) -> Result<HostUpdateReceiptV1, ApplyError> {
    if staged.transaction.phase != TxnPhase::Staged {
        return Err(ApplyError::BadPhase(staged.transaction.phase));
    }
    if std::env::var_os("ORCA_HOST_UPDATE_IN_PROCESS").is_some_and(|v| v == "1") {
        return apply_transaction_in_process(layout, &staged.txn_path, &staged.receipt);
    }
    let child_bin = if staged.staged_bin.is_file() {
        staged.staged_bin.clone()
    } else {
        std::env::current_exe()?
    };
    let status = Command::new(&child_bin)
        .arg("__apply-host-update")
        .arg("--transaction")
        .arg(&staged.txn_path)
        .env("ORCA_HOST_UPDATE_RECEIPT", {
            let p = layout.receipt_path(&staged.receipt.receipt_digest);
            staged.receipt.write_atomic(&p)?;
            p
        })
        .status()
        .map_err(|e| ApplyError::Spawn(e.to_string()))?;
    if !status.success() {
        return Err(ApplyError::Failed(format!("child exit {status}")));
    }
    HostUpdateReceiptV1::load(&layout.receipt_path(&staged.receipt.receipt_digest))
        .map_err(ApplyError::Receipt)
}

/// Hidden entry: `__apply-host-update --transaction <path>`
/// No fixed sleep — Unix rename-over-busy keeps the old inode; failpoints are deterministic.
pub fn run_apply_host_update(txn_path: &Path) -> Result<(), ApplyError> {
    let layout = HostLayout::resolve_current().map_err(ApplyError::Receipt)?;
    let receipt = match std::env::var_os("ORCA_HOST_UPDATE_RECEIPT") {
        Some(p) => HostUpdateReceiptV1::load(Path::new(&p))?,
        None => {
            let txn = HostUpdateTransactionV1::load(txn_path)?;
            let dig = txn
                .candidate_receipt_digest
                .as_deref()
                .ok_or_else(|| ApplyError::Failed("no candidate receipt".into()))?;
            HostUpdateReceiptV1::load(&layout.receipt_path(dig))?
        }
    };
    apply_transaction_in_process(&layout, txn_path, &receipt)?;
    Ok(())
}

pub fn apply_transaction_in_process(
    layout: &HostLayout,
    txn_path: &Path,
    receipt: &HostUpdateReceiptV1,
) -> Result<HostUpdateReceiptV1, ApplyError> {
    layout.ensure_dirs()?;
    let mut txn = HostUpdateTransactionV1::load(txn_path)?;
    match txn.phase {
        TxnPhase::Staged | TxnPhase::Prepared => {}
        TxnPhase::Committed => return Ok(receipt.clone()),
        other => return Err(ApplyError::BadPhase(other)),
    }

    hit_failpoint("before_applying")?;

    // Crash at Staged abandons: only transition to Applying when we begin replace.
    txn.set_phase(TxnPhase::Applying);
    txn.write_atomic(txn_path)?;

    let staged_root = PathBuf::from(&txn.staged_root);
    let bin_name = host_bin_name();
    let staged_bin = staged_root.join(bin_name);
    if !staged_bin.is_file() {
        txn.set_phase(TxnPhase::Aborted);
        txn.error = Some("missing staged binary".into());
        let _ = txn.write_atomic(txn_path);
        return Err(ApplyError::MissingStaged(staged_bin.display().to_string()));
    }

    let dest = layout.managed_bin.clone();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    if dest.exists() {
        let bak = dest.with_extension("bak");
        let _ = fs::remove_file(&bak);
        let _ = fs::copy(&dest, &bak);
    }

    let tmp = dest.with_extension("new");
    fs::copy(&staged_bin, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    }
    fs::rename(&tmp, &dest)?;

    for f in &receipt.files {
        if f.relative_path == bin_name || f.relative_path == "orca" {
            continue;
        }
        let src = staged_root.join(&f.relative_path);
        let dst = layout.install_root.join(&f.relative_path);
        if src.is_file() {
            if let Some(p) = dst.parent() {
                fs::create_dir_all(p)?;
            }
            fs::copy(&src, &dst)?;
        }
    }

    hit_failpoint("after_promote_before_receipt")?;

    let rpath = layout.receipt_path(&receipt.receipt_digest);
    receipt.write_atomic(&rpath)?;

    if layout.current_path.is_file() {
        if let Ok(cur) = receipt::CurrentHostV1::load(&layout.current_path) {
            let lkg = LastKnownGoodV1 {
                schema_version: LKG_SCHEMA,
                version: cur.version,
                archive_sha256: cur.archive_sha256,
                receipt_digest: cur.receipt_digest,
                retained_at: now_rfc3339(),
            };
            lkg.write_atomic(&layout.lkg_path)?;
        }
    }

    hit_failpoint("before_commit")?;

    let current = CurrentHostV1 {
        schema_version: CURRENT_SCHEMA,
        version: receipt.version.clone(),
        archive_sha256: receipt.archive_sha256.clone(),
        receipt_digest: receipt.receipt_digest.clone(),
        binary_path: dest.display().to_string(),
        updated_at: now_rfc3339(),
    };
    current.write_atomic(&layout.current_path)?;

    txn.set_phase(TxnPhase::Committed);
    txn.candidate_receipt_digest = Some(receipt.receipt_digest.clone());
    txn.write_atomic(txn_path)?;

    let _ = fs::remove_dir_all(&staged_root);

    Ok(receipt.clone())
}

/// Recover abandoned Staged transactions (crash before Applying): leave old host.
pub fn recover_abandoned(layout: &HostLayout) -> Result<usize, ApplyError> {
    if !layout.transactions_dir.is_dir() {
        return Ok(0);
    }
    let mut n = 0;
    for ent in fs::read_dir(&layout.transactions_dir)? {
        let ent = ent?;
        let path = ent.path();
        let Ok(mut txn) = HostUpdateTransactionV1::load(&path) else {
            continue;
        };
        if txn.phase == TxnPhase::Staged {
            txn.set_phase(TxnPhase::Aborted);
            txn.error = Some("abandoned staged after crash; old host retained".into());
            txn.write_atomic(&path)?;
            let staged = PathBuf::from(&txn.staged_root);
            let _ = fs::remove_dir_all(staged);
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_update::stage::{
        build_r5_archive, clear_fixture_trust_env, install_fixture_trust_env,
        sign_and_write_fixture_sig, stage_archive,
    };
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn layout_at(root: &Path) -> HostLayout {
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
    fn failpoint_before_applying_keeps_old_host() {
        let _g = ENV_LOCK.lock().unwrap();
        install_fixture_trust_env();
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1") };
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_FAILPOINT", "before_applying") };
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();
        fs::write(&layout.managed_bin, b"old-host").unwrap();
        let bytes = build_r5_archive("0.0.0-test-b", "test-any", b"new-host").unwrap();
        let ap = dir.path().join("b.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &bytes).unwrap();
        let staged = stage_archive(&layout, &ap, None, false).unwrap();
        staged
            .receipt
            .write_atomic(&layout.receipt_path(&staged.receipt.receipt_digest))
            .unwrap();
        let err = promote(&layout, &staged).unwrap_err();
        assert!(matches!(err, ApplyError::Failpoint("before_applying")));
        assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"old-host");
        let txn = HostUpdateTransactionV1::load(&staged.txn_path).unwrap();
        assert_eq!(txn.phase, TxnPhase::Staged);
        unsafe { std::env::remove_var("ORCA_HOST_UPDATE_FAILPOINT") };
        unsafe { std::env::remove_var("ORCA_HOST_UPDATE_IN_PROCESS") };
        clear_fixture_trust_env();
    }

    #[test]
    fn no_fixed_sleep_in_apply_source() {
        let src = include_str!("apply.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(!prod.contains("thread::sleep"), "apply must not sleep");
        assert!(
            !prod.contains("std::time::Duration"),
            "apply must not use wall-clock delay"
        );
    }
}
