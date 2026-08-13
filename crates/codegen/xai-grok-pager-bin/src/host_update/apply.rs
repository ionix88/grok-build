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

/// Recover abandoned Staged/Applying transactions after crash.
///
/// Transaction-scoped only: aborts the txn record and removes that txn's
/// staging directory when it lies under `layout.staging_dir`. Never walks
/// the whole staging tree, never touches receipts/current/plugins.
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
        let reason = match txn.phase {
            TxnPhase::Staged => "abandoned staged after crash; old host retained",
            TxnPhase::Applying => {
                "abandoned applying after crash; staging removed, host converges via check/rollback"
            }
            _ => continue,
        };
        txn.set_phase(TxnPhase::Aborted);
        txn.error = Some(reason.into());
        txn.write_atomic(&path)?;
        remove_owned_staging(layout, Path::new(&txn.staged_root));
        n += 1;
    }
    Ok(n)
}

/// Remove a staging directory only when it is a descendant of `layout.staging_dir`.
fn remove_owned_staging(layout: &HostLayout, staged_root: &Path) {
    if staged_root.as_os_str().is_empty() {
        return;
    }
    if !staged_root.exists() {
        return;
    }
    let staging_base =
        dunce::canonicalize(&layout.staging_dir).unwrap_or_else(|_| layout.staging_dir.clone());
    let candidate = dunce::canonicalize(staged_root).unwrap_or_else(|_| staged_root.to_path_buf());
    if candidate.starts_with(&staging_base) && candidate != staging_base {
        let _ = fs::remove_dir_all(&candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_update::rollback::rollback;
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

    struct EnvClean;
    impl Drop for EnvClean {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("ORCA_HOST_UPDATE_FAILPOINT");
                std::env::remove_var("ORCA_HOST_UPDATE_IN_PROCESS");
            }
            clear_fixture_trust_env();
        }
    }

    fn plant_canaries(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let items = [
            (
                root.join("data/plugins/payload/.canary"),
                b"plugin-payload-v1".to_vec(),
            ),
            (
                root.join("data/plugins/registry/.canary"),
                b"plugin-registry-v1".to_vec(),
            ),
            (
                root.join("state/session-pins/.canary"),
                b"session-pins-v1".to_vec(),
            ),
            (root.join("state/cohorts/.canary"), b"cohort-v1".to_vec()),
            (root.join("grok-home/.canary"), b"grok-home-v1".to_vec()),
        ];
        for (p, bytes) in &items {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, bytes).unwrap();
        }
        items.to_vec()
    }

    fn assert_canaries(canaries: &[(PathBuf, Vec<u8>)]) {
        for (p, expect) in canaries {
            assert_eq!(
                fs::read(p).unwrap(),
                *expect,
                "canary drifted: {}",
                p.display()
            );
        }
    }

    fn promote_version(layout: &HostLayout, dir: &Path, name: &str, version: &str, payload: &[u8]) {
        let bytes = build_r5_archive(version, "test-any", payload).unwrap();
        let ap = dir.join(name);
        fs::write(&ap, &bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &bytes).unwrap();
        let staged = stage_archive(layout, &ap, None, false).unwrap();
        staged
            .receipt
            .write_atomic(&layout.receipt_path(&staged.receipt.receipt_digest))
            .unwrap();
        promote(layout, &staged).unwrap();
    }

    #[test]
    fn failpoint_before_applying_keeps_old_host() {
        let _g = env_lock();
        install_fixture_trust_env();
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1") };
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_FAILPOINT", "before_applying") };
        let _env = EnvClean;
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

    /// Given Applying-phase crash at after_promote_before_receipt,
    /// When recover_abandoned runs,
    /// Then that txn's staging is removed and phase becomes Aborted.
    #[test]
    fn applying_failpoint_staging_cleaned_by_recovery() {
        let _g = env_lock();
        install_fixture_trust_env();
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1") };
        let _env = EnvClean;
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();

        promote_version(&layout, dir.path(), "c.tar.gz", "0.0.0-test-c", b"host-c");
        assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"host-c");

        unsafe { std::env::set_var("ORCA_HOST_UPDATE_FAILPOINT", "after_promote_before_receipt") };
        let a_bytes = build_r5_archive("0.0.0-test-a", "test-any", b"host-a").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &a_bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &a_bytes).unwrap();
        let staged_a = stage_archive(&layout, &ap, None, false).unwrap();
        staged_a
            .receipt
            .write_atomic(&layout.receipt_path(&staged_a.receipt.receipt_digest))
            .unwrap();
        let abandoned_id = staged_a.transaction.transaction_id.clone();
        let staged_root = PathBuf::from(&staged_a.transaction.staged_root);
        assert!(staged_root.is_dir());
        let err = promote(&layout, &staged_a).unwrap_err();
        assert!(
            matches!(err, ApplyError::Failpoint("after_promote_before_receipt")),
            "got {err:?}"
        );
        assert!(
            staged_root.is_dir(),
            "leak pre-condition: abandoned staging still on disk"
        );
        let txn = HostUpdateTransactionV1::load(&staged_a.txn_path).unwrap();
        assert_eq!(txn.phase, TxnPhase::Applying);

        let n = recover_abandoned(&layout).unwrap();
        assert!(n >= 1, "must recover at least the Applying txn");
        assert!(
            !staged_root.exists(),
            "abandoned Applying staging must be removed"
        );
        let txn = HostUpdateTransactionV1::load(&staged_a.txn_path).unwrap();
        assert_eq!(txn.phase, TxnPhase::Aborted);
        assert_eq!(txn.transaction_id, abandoned_id);
    }

    /// Exact residual: after_promote_before_receipt then public rollback must
    /// clear only the abandoned Applying staging entry; foreign staging stays;
    /// plugin/pin/cohort/grok canaries unchanged; host converges to retained C.
    #[test]
    fn after_promote_before_receipt_public_rollback_clears_abandoned_staging() {
        let _g = env_lock();
        install_fixture_trust_env();
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1") };
        let _env = EnvClean;
        let dir = tempdir().unwrap();
        let root = dir.path();
        let layout = layout_at(root);
        layout.ensure_dirs().unwrap();
        let canaries = plant_canaries(root);

        // A -> B -> C retained history (matches independent reproduction).
        promote_version(&layout, root, "a0.tar.gz", "0.0.0-test-a", b"host-a0");
        promote_version(&layout, root, "b0.tar.gz", "0.0.0-test-b", b"host-b0");
        promote_version(&layout, root, "c0.tar.gz", "0.0.0-test-c", b"host-c");
        assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"host-c");

        // Foreign staging not referenced by any transaction — must survive cleanup.
        let foreign = layout.staging_dir.join("foreign-not-a-txn");
        fs::create_dir_all(&foreign).unwrap();
        fs::write(foreign.join("keep"), b"foreign").unwrap();

        // Interrupted promote of A at after_promote_before_receipt.
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_FAILPOINT", "after_promote_before_receipt") };
        let a_bytes = build_r5_archive("0.0.0-test-a", "test-any", b"host-a-interrupted").unwrap();
        let ap = root.join("a-int.tar.gz");
        fs::write(&ap, &a_bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &a_bytes).unwrap();
        let staged_a = stage_archive(&layout, &ap, None, false).unwrap();
        staged_a
            .receipt
            .write_atomic(&layout.receipt_path(&staged_a.receipt.receipt_digest))
            .unwrap();
        let abandoned_root = PathBuf::from(&staged_a.transaction.staged_root);
        let abandoned_name = abandoned_root
            .file_name()
            .map(|s| s.to_os_string())
            .expect("staging entry name");
        let err = promote(&layout, &staged_a).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::Failpoint("after_promote_before_receipt")
        ));
        assert!(
            abandoned_root.is_dir(),
            "pre-condition: abandoned staging present"
        );
        assert_eq!(
            HostUpdateTransactionV1::load(&staged_a.txn_path)
                .unwrap()
                .phase,
            TxnPhase::Applying
        );
        // Binary already replaced; current/receipt not committed — stale until rollback.
        assert_eq!(
            fs::read(&layout.managed_bin).unwrap(),
            b"host-a-interrupted"
        );

        // Clear failpoint; public rollback path (calls recover_abandoned then promote C).
        unsafe { std::env::remove_var("ORCA_HOST_UPDATE_FAILPOINT") };
        let rolled = rollback(&layout, Some("0.0.0-test-c")).unwrap();
        assert_eq!(rolled.version, "0.0.0-test-c");
        assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"host-c");

        // Abandoned Applying staging entry must be gone.
        assert!(
            !abandoned_root.exists(),
            "abandoned Applying staging must not survive public rollback"
        );
        let staging_names: Vec<_> = fs::read_dir(&layout.staging_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(
            !staging_names.iter().any(|n| n == &abandoned_name),
            "abandoned txn staging name must be absent; found {staging_names:?}"
        );
        // Foreign staging must remain (transaction-scoped cleanup, not broad wipe).
        assert!(
            foreign.join("keep").is_file(),
            "foreign staging must not be removed by recovery/rollback"
        );
        assert_eq!(
            HostUpdateTransactionV1::load(&staged_a.txn_path)
                .unwrap()
                .phase,
            TxnPhase::Aborted
        );

        assert_canaries(&canaries);
    }

    #[test]
    fn remove_owned_staging_refuses_paths_outside_staging_root() {
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();
        let outside = dir.path().join("not-staging");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        remove_owned_staging(&layout, &outside);
        assert!(
            outside.join("keep").is_file(),
            "must not delete paths outside staging_dir"
        );
        // Must not delete the staging root itself.
        fs::write(layout.staging_dir.join("marker"), b"m").unwrap();
        remove_owned_staging(&layout, &layout.staging_dir);
        assert!(
            layout.staging_dir.join("marker").is_file(),
            "must not delete staging_dir root"
        );
    }

    #[test]
    fn recover_abandoned_is_idempotent() {
        let _g = env_lock();
        install_fixture_trust_env();
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1") };
        let _env = EnvClean;
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();
        promote_version(&layout, dir.path(), "c.tar.gz", "0.0.0-test-c", b"host-c");
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_FAILPOINT", "after_promote_before_receipt") };
        let a_bytes = build_r5_archive("0.0.0-test-a", "test-any", b"host-a").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &a_bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &a_bytes).unwrap();
        let staged_a = stage_archive(&layout, &ap, None, false).unwrap();
        staged_a
            .receipt
            .write_atomic(&layout.receipt_path(&staged_a.receipt.receipt_digest))
            .unwrap();
        let _ = promote(&layout, &staged_a).unwrap_err();
        let first = recover_abandoned(&layout).unwrap();
        assert!(first >= 1);
        let second = recover_abandoned(&layout).unwrap();
        assert_eq!(second, 0, "second recovery must be a no-op");
    }
}
