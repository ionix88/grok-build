//! Host-only isolation: deny Go root/artifacts and plugin identity fields.

use serde_json::Value;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Forbidden JSON field names inside HostArtifactSetResultV1 / host-artifact-set.
const FORBIDDEN_HOST_RESULT_FIELDS: &[&str] = &[
    "pluginArtifact",
    "pluginArtifacts",
    "pluginArtifactVa",
    "pluginArtifactVb",
    "goOrcaCommit",
    "goOrcaTree",
    "goOrcaRoot",
    "goShardAggregate",
    "goShardAggregateDigest",
    "combinedResult",
    "artifactVerification",
    "vA",
    "vB",
    "fixtureBaseline",
    "releaseCandidate",
];

const FORBIDDEN_PATH_NEEDLES: &[&str] = &[
    "/go-orca/",
    "\\go-orca\\",
    "go-orca/internal",
    "go-orca/cmd",
    "PluginArtifactSetResultV1",
    "ArtifactVerificationResultV1",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostIsolationError {
    #[error("go input denied: {0}")]
    GoInput(String),
    #[error("plugin/combined field forbidden: {0}")]
    ForbiddenField(String),
    #[error("path embeds go or plugin identity: {0}")]
    EmbeddedPath(String),
    #[error("mode mismatch: expected host-artifact-set")]
    ModeMismatch,
}

/// Guard that records denied roots for a host-only packaging run.
#[derive(Debug, Clone)]
pub struct HostIsolationGuard {
    pub orca_root: PathBuf,
    pub denied_go_root: Option<PathBuf>,
    pub denied_task53: Option<PathBuf>,
}

impl HostIsolationGuard {
    pub fn new(orca_root: impl Into<PathBuf>) -> Self {
        let orca_root = orca_root.into();
        let parent = orca_root.parent().map(Path::to_path_buf);
        let denied_go_root = parent.as_ref().map(|p| p.join("go-orca"));
        let denied_task53 = parent
            .as_ref()
            .map(|p| p.join(".omo/attempts/task-53-go-orca-architecture-delivery"));
        Self {
            orca_root,
            denied_go_root,
            denied_task53,
        }
    }

    /// Fail closed if Go root or Task-53 outputs are supplied as inputs.
    pub fn deny_present_go_inputs(
        &self,
        go_root: Option<&Path>,
        task53: Option<&Path>,
    ) -> Result<(), HostIsolationError> {
        if let Some(g) = go_root {
            if g.exists() {
                return Err(HostIsolationError::GoInput(format!(
                    "go root present: {}",
                    g.display()
                )));
            }
        }
        if let Some(t) = task53 {
            if t.exists() {
                return Err(HostIsolationError::GoInput(format!(
                    "task-53 outputs present: {}",
                    t.display()
                )));
            }
        }
        Ok(())
    }
}

/// Explicit deny when a caller tries to pass Go paths into host packaging.
pub fn deny_go_inputs(
    go_root: Option<&Path>,
    go_artifact: Option<&Path>,
    task53_out: Option<&Path>,
) -> Result<(), HostIsolationError> {
    for (label, p) in [
        ("go_root", go_root),
        ("go_artifact", go_artifact),
        ("task53", task53_out),
    ] {
        if let Some(path) = p {
            if path.as_os_str().is_empty() {
                continue;
            }
            // Even if absent on disk, a non-empty Go path argument is denied.
            let s = path.to_string_lossy();
            if s.contains("go-orca") || label != "task53" && path.is_absolute() && label == "go_root"
            {
                if label == "go_root" || s.contains("go-orca") {
                    return Err(HostIsolationError::GoInput(format!(
                        "{label}={}",
                        path.display()
                    )));
                }
            }
            if label == "go_artifact" {
                return Err(HostIsolationError::GoInput(format!(
                    "go_artifact={}",
                    path.display()
                )));
            }
            if label == "task53" && (path.exists() || s.contains("task-53")) {
                return Err(HostIsolationError::GoInput(format!(
                    "task53={}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Reject plugin/combined identity fields and Go path embeddings in a JSON value.
pub fn assert_host_only_result(v: &Value) -> Result<(), HostIsolationError> {
    let schema = v
        .get("schema")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    if schema == "ArtifactVerificationResultV1" || schema == "PluginArtifactSetResultV1" {
        return Err(HostIsolationError::ModeMismatch);
    }
    if let Some(s) = v.get("schema").and_then(|x| x.as_str()) {
        if s != "HostArtifactSetResultV1" && s != "HostArtifactSetV1" && !s.is_empty() {
            // Allow nested objects without schema; top-level must be host if present.
            if s.contains("Plugin") || s.contains("Combined") || s.contains("Verification") {
                return Err(HostIsolationError::ModeMismatch);
            }
        }
    }
    scan_object(v, "")?;
    let dumped = v.to_string();
    for needle in FORBIDDEN_PATH_NEEDLES {
        if dumped.contains(needle) {
            return Err(HostIsolationError::EmbeddedPath((*needle).to_string()));
        }
    }
    Ok(())
}

fn scan_object(v: &Value, path: &str) -> Result<(), HostIsolationError> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if FORBIDDEN_HOST_RESULT_FIELDS.contains(&k.as_str()) {
                    return Err(HostIsolationError::ForbiddenField(format!("{path}{k}")));
                }
                let child_path = if path.is_empty() {
                    format!("{k}.")
                } else {
                    format!("{path}{k}.")
                };
                scan_object(child, &child_path)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                scan_object(child, &format!("{path}{i}."))?;
            }
            Ok(())
        }
        Value::String(s) => {
            for needle in FORBIDDEN_PATH_NEEDLES {
                if s.contains(needle) {
                    return Err(HostIsolationError::EmbeddedPath(format!(
                        "{path}={needle}"
                    )));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_plugin_artifact_field() {
        let v = json!({
            "schema": "HostArtifactSetResultV1",
            "pluginArtifact": {"id": "x"}
        });
        assert!(matches!(
            assert_host_only_result(&v),
            Err(HostIsolationError::ForbiddenField(_))
        ));
    }

    #[test]
    fn rejects_combined_envelope() {
        let v = json!({"schema": "ArtifactVerificationResultV1"});
        assert_eq!(
            assert_host_only_result(&v),
            Err(HostIsolationError::ModeMismatch)
        );
    }

    #[test]
    fn accepts_clean_host_result() {
        let v = json!({
            "schema": "HostArtifactSetResultV1",
            "hostVersion": "0.0.0-test",
            "advertisedTargets": ["darwin-aarch64", "linux-amd64"],
            "shardAggregate": {"expectedShardIds": [], "entries": []}
        });
        assert!(assert_host_only_result(&v).is_ok());
    }

    #[test]
    fn deny_go_root_argument() {
        let err = deny_go_inputs(Some(Path::new("/tmp/go-orca")), None, None);
        assert!(err.is_err());
    }
}
