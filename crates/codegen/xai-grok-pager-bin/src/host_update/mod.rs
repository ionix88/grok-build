// allow: SIZE_OK — plan Task 16 composition root for host_update CLI + orchestration tests.
//! Transactional independent Orca host update and rollback.
//!
//! Never reads/deletes plugin payloads, pins, cohorts, or ~/.grok.

mod apply;
mod receipt;
mod rollback;
mod stage;

pub use apply::{promote, run_apply_host_update, ApplyError};
pub use receipt::{
    HostLayout, HostUpdateReceiptV1, HostUpdateTransactionV1, LastKnownGoodV1, TxnPhase,
};
pub use rollback::{rollback, RollbackError};
pub use stage::{
    build_r5_archive, check_running_path, sign_test_archive, stage_archive, write_sig_file,
    StageError,
};

use receipt::{now_rfc3339, sha256_file, CurrentHostV1, CURRENT_SCHEMA};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERR: i32 = 2;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("{0}")]
    Stage(#[from] StageError),
    #[error("{0}")]
    Apply(#[from] ApplyError),
    #[error("{0}")]
    Rollback(#[from] RollbackError),
    #[error("{0}")]
    Receipt(#[from] receipt::ReceiptError),
    #[error("usage: orca update --check | --to <path.tar.gz|version> | rollback [--to <version>]")]
    Usage,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckStatus {
    pub schema_version: u32,
    pub kind: &'static str,
    pub version: Option<String>,
    pub archive_sha256: Option<String>,
    pub receipt_digest: Option<String>,
    pub binary_path: Option<String>,
    pub install_root: String,
    pub managed_bin_exists: bool,
    pub last_known_good_version: Option<String>,
    pub update_available: bool,
    pub checked_at: String,
}

/// CLI intercept: returns Some(exit_code) when argv is a host-update command.
pub fn try_run_from_args<I, S>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if args.first().map(String::as_str) == Some("__apply-host-update") {
        return Some(run_hidden_apply(&args[1..]));
    }
    if args.first().map(String::as_str) != Some("update") {
        return None;
    }
    match run_update(&args[1..]) {
        Ok(()) => Some(EXIT_OK),
        Err(UpdateError::Usage) => {
            eprintln!(
                "usage: orca update --check | --to <path.tar.gz|version> | rollback [--to <version>]"
            );
            Some(EXIT_ERR)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Some(EXIT_ERR)
        }
    }
}

fn run_hidden_apply(args: &[String]) -> i32 {
    let mut txn: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transaction" => {
                i += 1;
                match args.get(i) {
                    Some(p) => txn = Some(PathBuf::from(p)),
                    None => {
                        eprintln!("error: --transaction requires a path");
                        return EXIT_ERR;
                    }
                }
            }
            other => {
                eprintln!("error: unknown apply arg {other}");
                return EXIT_ERR;
            }
        }
        i += 1;
    }
    let Some(path) = txn else {
        eprintln!("error: __apply-host-update requires --transaction <path>");
        return EXIT_ERR;
    };
    match run_apply_host_update(&path) {
        Ok(()) => EXIT_OK,
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERR
        }
    }
}

fn run_update(args: &[String]) -> Result<(), UpdateError> {
    if args.first().map(String::as_str) == Some("rollback") {
        return run_rollback(&args[1..]);
    }
    let mut check = false;
    let mut to: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => check = true,
            "--to" => {
                i += 1;
                to = Some(args.get(i).ok_or(UpdateError::Usage)?.clone());
            }
            _ => return Err(UpdateError::Usage),
        }
        i += 1;
    }
    if check && to.is_some() {
        return Err(UpdateError::Usage);
    }
    if !check && to.is_none() {
        return Err(UpdateError::Usage);
    }
    let layout = HostLayout::resolve_current()?;
    layout.ensure_dirs()?;
    let _ = apply::recover_abandoned(&layout);

    if check {
        let status = build_check_status(&layout)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(|e| UpdateError::Msg(e.to_string()))?
        );
        return Ok(());
    }

    let target = to.ok_or(UpdateError::Usage)?;
    let archive_path = resolve_to_archive(&layout, &target)?;
let enforce_path = std::env::var_os("ORCA_HOST_UPDATE_IN_PROCESS").is_none();
    let staged = stage_archive(&layout, &archive_path, None, enforce_path)?;
    // Persist candidate receipt before promote.
    staged
        .receipt
        .write_atomic(&layout.receipt_path(&staged.receipt.receipt_digest))?;
    let applied = promote(&layout, &staged)?;
    let out = serde_json::json!({
        "schemaVersion": 1,
        "kind": "hostUpdateApplied",
        "version": applied.version,
        "archiveSha256": applied.archive_sha256,
        "receiptDigest": applied.receipt_digest,
        "installRoot": applied.install_root,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| UpdateError::Msg(e.to_string()))?
    );
    Ok(())
}

fn run_rollback(args: &[String]) -> Result<(), UpdateError> {
    let mut to: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                to = Some(args.get(i).ok_or(UpdateError::Usage)?.clone());
            }
            _ => return Err(UpdateError::Usage),
        }
        i += 1;
    }
    let layout = HostLayout::resolve_current()?;
    let result = rollback(&layout, to.as_deref())?;
    let out = serde_json::json!({
        "schemaVersion": 1,
        "kind": "hostUpdateRollback",
        "version": result.version,
        "receiptDigest": result.receipt_digest,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| UpdateError::Msg(e.to_string()))?
    );
    Ok(())
}

fn build_check_status(layout: &HostLayout) -> Result<UpdateCheckStatus, UpdateError> {
    let (version, archive_sha256, receipt_digest, binary_path) = if layout.current_path.is_file() {
        let c = CurrentHostV1::load(&layout.current_path)?;
        (
            Some(c.version),
            Some(c.archive_sha256),
            Some(c.receipt_digest),
            Some(c.binary_path),
        )
    } else {
        (None, None, None, None)
    };
    let lkg = if layout.lkg_path.is_file() {
        LastKnownGoodV1::load(&layout.lkg_path)
            .ok()
            .map(|l| l.version)
    } else {
        None
    };
    Ok(UpdateCheckStatus {
        schema_version: CURRENT_SCHEMA,
        kind: "hostUpdateCheck",
        version,
        archive_sha256,
        receipt_digest,
        binary_path,
        install_root: layout.install_root.display().to_string(),
        managed_bin_exists: layout.managed_bin.exists(),
        last_known_good_version: lkg,
        update_available: false,
        checked_at: now_rfc3339(),
    })
}

fn resolve_to_archive(layout: &HostLayout, target: &str) -> Result<PathBuf, UpdateError> {
    let p = Path::new(target);
    if p.exists() && target.ends_with(".tar.gz") {
        return Ok(p.to_path_buf());
    }
    // version lookup in retained archives via receipts
    if layout.receipts_dir.is_dir() {
        for ent in fs::read_dir(&layout.receipts_dir)? {
            let ent = ent?;
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(r) = HostUpdateReceiptV1::load(&path) {
                if r.version == target {
                    let ap = layout.archive_path(&r.archive_sha256);
                    if ap.is_file() {
                        // ensure sig
                        let bytes = fs::read(&ap)?;
                        let _ = write_sig_file(&ap, &bytes)?;
                        return Ok(ap);
                    }
                }
            }
        }
    }
    Err(UpdateError::Msg(format!(
        "update target not found: {target} (expected path.tar.gz or retained version)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_update::receipt::{host_bin_name, sha256_hex};
    use tempfile::tempdir;

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

    fn write_archive(dir: &Path, name: &str, version: &str, payload: &[u8]) -> PathBuf {
        let bytes = build_r5_archive(version, "test-any", payload).unwrap();
        let ap = dir.join(name);
        fs::write(&ap, &bytes).unwrap();
        write_sig_file(&ap, &bytes).unwrap();
        ap
    }

    #[test]
    fn va_to_vb_and_rollback() {
        unsafe { std::env::set_var("ORCA_HOST_UPDATE_IN_PROCESS", "1"); }
        let dir = tempdir().unwrap();
        let layout = layout_at(dir.path());
        layout.ensure_dirs().unwrap();

        let a = write_archive(dir.path(), "a.tar.gz", "0.0.0-test-a", b"payload-va");
        let staged_a = stage_archive(&layout, &a, None, false).unwrap();
        staged_a
            .receipt
            .write_atomic(&layout.receipt_path(&staged_a.receipt.receipt_digest))
            .unwrap();
        let ra = promote(&layout, &staged_a).unwrap();
        assert_eq!(ra.version, "0.0.0-test-a");
        assert_eq!(
            fs::read(&layout.managed_bin).unwrap(),
            b"payload-va"
        );

        let b = write_archive(dir.path(), "b.tar.gz", "0.0.0-test-b", b"payload-vb");
        let staged_b = stage_archive(&layout, &b, None, false).unwrap();
        staged_b
            .receipt
            .write_atomic(&layout.receipt_path(&staged_b.receipt.receipt_digest))
            .unwrap();
        let rb = promote(&layout, &staged_b).unwrap();
        assert_eq!(rb.version, "0.0.0-test-b");
        assert_eq!(
            fs::read(&layout.managed_bin).unwrap(),
            b"payload-vb"
        );

        // LKG should be va
        let lkg = LastKnownGoodV1::load(&layout.lkg_path).unwrap();
        assert_eq!(lkg.version, "0.0.0-test-a");

        let rolled = rollback(&layout, None).unwrap();
        assert_eq!(rolled.version, "0.0.0-test-a");
        assert_eq!(
            fs::read(&layout.managed_bin).unwrap(),
            b"payload-va"
        );
        unsafe { std::env::remove_var("ORCA_HOST_UPDATE_IN_PROCESS"); }
        let _ = host_bin_name();
        let _ = sha256_hex;
        let _ = sha256_file;
    }

    #[test]
    fn try_run_check_smoke() {
        // Without ORCA_HOME this still resolves; just ensure non-update args return None.
        assert!(try_run_from_args(["not-update"]).is_none());
        assert!(try_run_from_args(["import", "grok"]).is_none());
    }

    #[test]
    fn try_run_usage() {
        let code = try_run_from_args(["update"]).unwrap();
        assert_eq!(code, EXIT_ERR);
    }
}
