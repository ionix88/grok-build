//! Deterministic Orca fork source-sync replay and conflict report.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// One ordered patch in a source-sync replay plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSyncPatchV1 {
    pub id: String,
    pub path: String,
    /// UTF-8 patch body (unified diff or full replacement marker).
    pub body: String,
    pub expected_base_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSyncConflict {
    pub patch_id: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSyncReportV1 {
    pub schema_version: u32,
    pub schema: &'static str,
    pub pin_commit: String,
    pub pin_tree: String,
    pub patches_applied: Vec<String>,
    pub conflicts: Vec<SourceSyncConflict>,
    pub root_cargo_unchanged: bool,
    pub generated_cargo_drift: bool,
    pub status: SourceSyncStatus,
    pub report_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SourceSyncStatus {
    Clean,
    Conflict,
    GeneratedCargoDrift,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SourceSyncError {
    #[error("source-sync conflict: {0}")]
    Conflict(String),
    #[error("generated Cargo drift at {0}")]
    GeneratedCargoDrift(String),
    #[error("root Cargo.toml must not be modified by source-sync")]
    RootCargoMutation,
    #[error("invalid pin: {0}")]
    InvalidPin(String),
}

/// Replay ordered patches against an in-memory file map (path → bytes).
///
/// `root_cargo_before` is the baseline root Cargo.toml digest; any patch that
/// touches `Cargo.toml` at repo root fails closed.
pub fn replay_source_sync(
    pin_commit: &str,
    pin_tree: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    patches: &[SourceSyncPatchV1],
    root_cargo_before_sha256: &str,
) -> Result<SourceSyncReportV1, SourceSyncError> {
    if pin_commit.is_empty() || pin_tree.is_empty() {
        return Err(SourceSyncError::InvalidPin(
            "pin commit/tree required".into(),
        ));
    }
    let mut applied = Vec::new();
    let mut conflicts = Vec::new();
    let mut generated_cargo_drift = false;

    for patch in patches {
        if patch.path == "Cargo.toml" || patch.path == "./Cargo.toml" {
            return Err(SourceSyncError::RootCargoMutation);
        }
        if patch.path.contains("Cargo.toml") && patch.path.contains("generated") {
            generated_cargo_drift = true;
            conflicts.push(SourceSyncConflict {
                patch_id: patch.id.clone(),
                path: patch.path.clone(),
                reason: "generated Cargo.toml drift refused".into(),
            });
            continue;
        }
        if let Some(want) = &patch.expected_base_sha256 {
            let have = files
                .get(&patch.path)
                .map(|b| super::sha256_hex(b))
                .unwrap_or_default();
            if &have != want {
                conflicts.push(SourceSyncConflict {
                    patch_id: patch.id.clone(),
                    path: patch.path.clone(),
                    reason: format!("base digest mismatch have={have} want={want}"),
                });
                continue;
            }
        }
        // Full-replacement body when prefixed; otherwise append marker for replay evidence.
        if let Some(rest) = patch.body.strip_prefix("REPLACE\n") {
            files.insert(patch.path.clone(), rest.as_bytes().to_vec());
            applied.push(patch.id.clone());
        } else if files.contains_key(&patch.path) || patch.expected_base_sha256.is_none() {
            let entry = files.entry(patch.path.clone()).or_default();
            entry.extend_from_slice(b"\n# source-sync:");
            entry.extend_from_slice(patch.id.as_bytes());
            entry.push(b'\n');
            entry.extend_from_slice(patch.body.as_bytes());
            applied.push(patch.id.clone());
        } else {
            conflicts.push(SourceSyncConflict {
                patch_id: patch.id.clone(),
                path: patch.path.clone(),
                reason: "missing base file".into(),
            });
        }
    }

    let root_after = files
        .get("Cargo.toml")
        .map(|b| super::sha256_hex(b))
        .unwrap_or_default();
    let root_cargo_unchanged = root_after == root_cargo_before_sha256
        || (root_cargo_before_sha256.is_empty() && !files.contains_key("Cargo.toml"));

    if !root_cargo_unchanged {
        return Err(SourceSyncError::RootCargoMutation);
    }

    let status = if generated_cargo_drift {
        SourceSyncStatus::GeneratedCargoDrift
    } else if conflicts.is_empty() {
        SourceSyncStatus::Clean
    } else {
        SourceSyncStatus::Conflict
    };

    let mut report = SourceSyncReportV1 {
        schema_version: 1,
        schema: "SourceSyncReportV1",
        pin_commit: pin_commit.to_string(),
        pin_tree: pin_tree.to_string(),
        patches_applied: applied,
        conflicts: conflicts.clone(),
        root_cargo_unchanged,
        generated_cargo_drift,
        status: status.clone(),
        report_digest: String::new(),
    };
    // Digest omits report_digest itself (self-omit).
    let mut for_digest = report.clone();
    for_digest.report_digest.clear();
    let bytes = serde_json::to_vec(&for_digest).unwrap_or_default();
    report.report_digest = super::sha256_hex(&bytes);

    if matches!(
        status,
        SourceSyncStatus::Conflict | SourceSyncStatus::GeneratedCargoDrift
    ) {
        // Return Ok with conflict status so callers can persist the report;
        // promotion paths must fail closed on non-Clean.
        return Ok(report);
    }
    Ok(report)
}

/// Fail closed helper for promotion gates.
pub fn require_clean(report: &SourceSyncReportV1) -> Result<(), SourceSyncError> {
    match report.status {
        SourceSyncStatus::Clean => Ok(()),
        SourceSyncStatus::Conflict => Err(SourceSyncError::Conflict(format!(
            "{} conflict(s)",
            report.conflicts.len()
        ))),
        SourceSyncStatus::GeneratedCargoDrift => Err(SourceSyncError::GeneratedCargoDrift(
            "generated Cargo.toml".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_replay_applies_patches() {
        let mut files = BTreeMap::new();
        files.insert("docs/FORK_DELTA.md".into(), b"# fork\n".to_vec());
        files.insert("Cargo.toml".into(), b"[workspace]\n".to_vec());
        let root_sha = super::super::sha256_hex(b"[workspace]\n");
        let patches = vec![SourceSyncPatchV1 {
            id: "p1".into(),
            path: "docs/FORK_DELTA.md".into(),
            body: "note".into(),
            expected_base_sha256: Some(super::super::sha256_hex(b"# fork\n")),
        }];
        let report = replay_source_sync("abc", "def", &mut files, &patches, &root_sha).unwrap();
        assert_eq!(report.status, SourceSyncStatus::Clean);
        assert_eq!(report.patches_applied, vec!["p1".to_string()]);
        assert!(report.root_cargo_unchanged);
        require_clean(&report).unwrap();
    }

    #[test]
    fn base_mismatch_is_conflict() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".into(), b"x".to_vec());
        files.insert("Cargo.toml".into(), b"c".to_vec());
        let root_sha = super::super::sha256_hex(b"c");
        let patches = vec![SourceSyncPatchV1 {
            id: "bad".into(),
            path: "a.txt".into(),
            body: "y".into(),
            expected_base_sha256: Some("deadbeef".into()),
        }];
        let report = replay_source_sync("c", "t", &mut files, &patches, &root_sha).unwrap();
        assert_eq!(report.status, SourceSyncStatus::Conflict);
        assert!(require_clean(&report).is_err());
    }

    #[test]
    fn root_cargo_patch_refused() {
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".into(), b"c".to_vec());
        let root_sha = super::super::sha256_hex(b"c");
        let patches = vec![SourceSyncPatchV1 {
            id: "root".into(),
            path: "Cargo.toml".into(),
            body: "REPLACE\nmutated".into(),
            expected_base_sha256: None,
        }];
        let err = replay_source_sync("c", "t", &mut files, &patches, &root_sha).unwrap_err();
        assert_eq!(err, SourceSyncError::RootCargoMutation);
    }

    #[test]
    fn generated_cargo_drift_flagged() {
        let mut files = BTreeMap::new();
        files.insert("Cargo.toml".into(), b"c".to_vec());
        let root_sha = super::super::sha256_hex(b"c");
        let patches = vec![SourceSyncPatchV1 {
            id: "gen".into(),
            path: "crates/generated/Cargo.toml".into(),
            body: "x".into(),
            expected_base_sha256: None,
        }];
        let report = replay_source_sync("c", "t", &mut files, &patches, &root_sha).unwrap();
        assert_eq!(report.status, SourceSyncStatus::GeneratedCargoDrift);
        assert!(report.generated_cargo_drift);
    }
}
