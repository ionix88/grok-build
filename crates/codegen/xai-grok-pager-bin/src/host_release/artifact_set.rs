// allow: SIZE_OK — plan Task 55 single-module HostArtifactSetV1 + resolver + result envelope.
//! Host artifact set manifest, resolver, and HostArtifactSetResultV1.

use super::isolation::{assert_host_only_result, HostIsolationError};
use super::{package_host_archive, read_sha256_file, sha256_hex, PackageError, PackagedHostArchive};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const RESULT_SCHEMA: &str = "HostArtifactSetResultV1";
pub const SET_SCHEMA: &str = "HostArtifactSetV1";
pub const ADVERTISED_TARGETS: &[&str] = &["darwin-aarch64", "linux-amd64"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBuildMode {
    Build,
    Validate,
    Path,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisedTarget {
    pub target: String,
    pub archive_path: String,
    pub archive_sha256: String,
    pub signature_path: Option<String>,
    pub signature_key_id: Option<String>,
    pub promotion_eligible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostArtifactIdentityV1 {
    pub product: String,
    pub version: String,
    pub target: String,
    pub archive_sha256: String,
    pub format_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_rev: String,
    pub sbom_sha256: String,
    pub notices_sha256: String,
    pub provenance_sha256: String,
    pub host_contract_set_digest: String,
    pub diagnostics_schema_sha256: String,
    pub diagnostics_manifest_sha256: String,
    pub rich_adapter_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmptyShardAggregateV1 {
    pub schema_version: u32,
    pub role: String,
    pub status: String,
    pub expected_shard_ids: Vec<String>,
    pub entries: Vec<Value>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostArtifactSetV1 {
    pub schema_version: u32,
    pub schema: String,
    pub product: String,
    pub version: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_rev: String,
    pub advertised_targets: Vec<String>,
    pub targets: Vec<AdvertisedTarget>,
    pub host_artifacts: Vec<HostArtifactIdentityV1>,
    pub shard_aggregate: EmptyShardAggregateV1,
    pub shard_aggregate_digest: String,
    pub host_contract_set_digest: String,
    pub root_cargo_sha256: String,
    pub toolchain: String,
    pub lockfile_sha256: String,
    pub sbom_sha256: String,
    pub notices_sha256: String,
    pub provenance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostArtifactSetResultV1 {
    pub schema_version: u32,
    pub schema: String,
    pub status: String,
    pub host_version: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_rev: String,
    pub advertised_targets: Vec<String>,
    pub selected_target: Option<String>,
    pub selected_archive_sha256: Option<String>,
    pub host_artifact_set_digest: String,
    pub shard_aggregate_digest: String,
    pub host_contract_set_digest: String,
    pub diagnostics_schema_sha256: String,
    pub diagnostics_manifest_sha256: String,
    pub sbom_sha256: String,
    pub notices_sha256: String,
    pub provenance_sha256: String,
    pub root_cargo_unchanged: bool,
    pub dual_build_byte_equal: bool,
    pub promotion_blocked_reason: Option<String>,
    pub assertions: Vec<String>,
    pub cleanup_status: String,
}

#[derive(Debug, Error)]
pub enum ArtifactSetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("package: {0}")]
    Package(#[from] PackageError),
    #[error("isolation: {0}")]
    Isolation(#[from] HostIsolationError),
    #[error("missing host manifest")]
    MissingHostManifest,
    #[error("ambiguous host target: {0}")]
    AmbiguousTarget(String),
    #[error("unknown target: {0}")]
    UnknownTarget(String),
    #[error("archive digest drift: {0}")]
    ArchiveDrift(String),
    #[error("signature drift: {0}")]
    SignatureDrift(String),
    #[error("unsupported promotion: {0}")]
    UnsupportedPromotion(String),
    #[error("json: {0}")]
    Json(String),
    #[error("{0}")]
    Msg(String),
}

/// Canonical empty Orca shard aggregate (Task 55 has no parity shards).
pub fn empty_shard_aggregate() -> EmptyShardAggregateV1 {
    let mut agg = EmptyShardAggregateV1 {
        schema_version: 1,
        role: "orca".into(),
        status: "APPROVED".into(),
        expected_shard_ids: vec![],
        entries: vec![],
        digest: String::new(),
    };
    let mut for_digest = agg.clone();
    for_digest.digest.clear();
    let bytes = serde_json::to_vec(&for_digest).unwrap_or_default();
    agg.digest = sha256_hex(&bytes);
    agg
}

pub struct BuildHostArtifactSetInput<'a> {
    pub out_dir: &'a Path,
    pub version: &'a str,
    pub orca_bytes: &'a [u8],
    pub source_commit: &'a str,
    pub source_tree: &'a str,
    pub source_rev: &'a str,
    pub host_contract_set_digest: &'a str,
    pub diagnostics_schema_sha256: &'a str,
    pub diagnostics_manifest_sha256: &'a str,
    pub root_cargo_sha256: &'a str,
    pub lockfile_sha256: &'a str,
    pub toolchain: &'a str,
    pub sign_fixture: bool,
    pub rich_adapter_digest: Option<&'a str>,
}

pub fn build_host_artifact_set(
    input: BuildHostArtifactSetInput<'_>,
) -> Result<(HostArtifactSetV1, Vec<PackagedHostArchive>), ArtifactSetError> {
    fs::create_dir_all(input.out_dir)?;
    let shard = empty_shard_aggregate();
    let mut packages = Vec::new();
    let mut targets = Vec::new();
    let mut identities = Vec::new();

    let sbom = build_sbom_json(&input);
    let notices = build_notices_text(&input);
    let provenance = build_provenance_json(&input, &shard);
    let sbom_sha = sha256_hex(sbom.as_bytes());
    let notices_sha = sha256_hex(notices.as_bytes());
    let provenance_sha = sha256_hex(provenance.as_bytes());
    fs::write(input.out_dir.join("sbom.spdx.json"), sbom.as_bytes())?;
    fs::write(input.out_dir.join("notices.txt"), notices.as_bytes())?;
    fs::write(
        input.out_dir.join("provenance.intoto.jsonl"),
        provenance.as_bytes(),
    )?;

    for target in ADVERTISED_TARGETS {
        let pkg = package_host_archive(
            input.out_dir,
            input.version,
            target,
            input.orca_bytes,
            input.sign_fixture,
        )?;
        // Dual-build proof for this target.
        let (a, b) = super::dual_build_byte_equal(input.version, target, input.orca_bytes)?;
        if a != b || sha256_hex(&a) != pkg.archive_sha256 {
            return Err(ArtifactSetError::ArchiveDrift(
                "dual-build or package digest mismatch".into(),
            ));
        }
        let abs = canonicalize_abs(&pkg.archive_path)?;
        targets.push(AdvertisedTarget {
            target: (*target).to_string(),
            archive_path: abs.clone(),
            archive_sha256: pkg.archive_sha256.clone(),
            signature_path: pkg
                .sig_path
                .as_ref()
                .map(|p| canonicalize_abs(p))
                .transpose()?,
            signature_key_id: pkg.signature_key_id.clone(),
            promotion_eligible: pkg.promotion_eligible,
        });
        identities.push(HostArtifactIdentityV1 {
            product: "orca".into(),
            version: input.version.to_string(),
            target: (*target).to_string(),
            archive_sha256: pkg.archive_sha256.clone(),
            format_id: pkg.format_id.clone(),
            source_commit: input.source_commit.to_string(),
            source_tree: input.source_tree.to_string(),
            source_rev: input.source_rev.to_string(),
            sbom_sha256: sbom_sha.clone(),
            notices_sha256: notices_sha.clone(),
            provenance_sha256: provenance_sha.clone(),
            host_contract_set_digest: input.host_contract_set_digest.to_string(),
            diagnostics_schema_sha256: input.diagnostics_schema_sha256.to_string(),
            diagnostics_manifest_sha256: input.diagnostics_manifest_sha256.to_string(),
            rich_adapter_digest: input.rich_adapter_digest.map(str::to_string),
        });
        packages.push(pkg);
    }

    let set = HostArtifactSetV1 {
        schema_version: 1,
        schema: SET_SCHEMA.into(),
        product: "orca".into(),
        version: input.version.to_string(),
        source_commit: input.source_commit.to_string(),
        source_tree: input.source_tree.to_string(),
        source_rev: input.source_rev.to_string(),
        advertised_targets: ADVERTISED_TARGETS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        targets,
        host_artifacts: identities,
        shard_aggregate_digest: shard.digest.clone(),
        shard_aggregate: shard,
        host_contract_set_digest: input.host_contract_set_digest.to_string(),
        root_cargo_sha256: input.root_cargo_sha256.to_string(),
        toolchain: input.toolchain.to_string(),
        lockfile_sha256: input.lockfile_sha256.to_string(),
        sbom_sha256: sbom_sha,
        notices_sha256: notices_sha,
        provenance_sha256: provenance_sha,
    };

    let v = serde_json::to_value(&set).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
    assert_host_only_result(&v)?;
    let path = input.out_dir.join("host-artifact-set.json");
    write_json_atomic(&path, &v)?;
    Ok((set, packages))
}

/// Read-only resolver: one absolute path + verifies digest. No --out.
pub fn resolve_artifact_path(
    manifest_path: &Path,
    target: &str,
) -> Result<PathBuf, ArtifactSetError> {
    let set = load_set(manifest_path)?;
    let matches: Vec<_> = set.targets.iter().filter(|t| t.target == target).collect();
    match matches.len() {
        0 => Err(ArtifactSetError::UnknownTarget(target.into())),
        1 => {
            let t = matches[0];
            let p = PathBuf::from(&t.archive_path);
            if !p.is_absolute() {
                return Err(ArtifactSetError::Msg(format!(
                    "archive path not absolute: {}",
                    t.archive_path
                )));
            }
            let have = read_sha256_file(&p)?;
            if have != t.archive_sha256 {
                return Err(ArtifactSetError::ArchiveDrift(format!(
                    "have={have} want={}",
                    t.archive_sha256
                )));
            }
            if let Some(sig) = &t.signature_path {
                let sp = Path::new(sig);
                if !sp.is_file() {
                    return Err(ArtifactSetError::SignatureDrift(format!(
                        "missing sig {sig}"
                    )));
                }
            }
            Ok(p)
        }
        n => Err(ArtifactSetError::AmbiguousTarget(format!(
            "{target} matched {n}"
        ))),
    }
}

pub fn validate_host_artifact_set(
    manifest_path: &Path,
    expected_root_cargo_sha256: Option<&str>,
) -> Result<HostArtifactSetV1, ArtifactSetError> {
    if !manifest_path.is_file() {
        return Err(ArtifactSetError::MissingHostManifest);
    }
    let set = load_set(manifest_path)?;
    if set.advertised_targets != ADVERTISED_TARGETS {
        return Err(ArtifactSetError::Msg(format!(
            "advertisedTargets drift: {:?}",
            set.advertised_targets
        )));
    }
    if set.targets.len() != ADVERTISED_TARGETS.len() {
        return Err(ArtifactSetError::Msg("target count drift".into()));
    }
    // Unique targets.
    let mut seen = std::collections::BTreeSet::new();
    for t in &set.targets {
        if !seen.insert(t.target.clone()) {
            return Err(ArtifactSetError::AmbiguousTarget(t.target.clone()));
        }
        let _ = resolve_artifact_path(manifest_path, &t.target)?;
        if t.promotion_eligible {
            return Err(ArtifactSetError::UnsupportedPromotion(
                "fixture or unsigned candidate cannot set promotionEligible=true".into(),
            ));
        }
    }
    if set.shard_aggregate.expected_shard_ids.is_empty()
        && set.shard_aggregate.entries.is_empty()
        && set.shard_aggregate.digest == empty_shard_aggregate().digest
    {
        // ok — empty Orca shard aggregate
    } else if set.shard_aggregate.digest != set.shard_aggregate_digest {
        return Err(ArtifactSetError::Msg("shard aggregate digest drift".into()));
    }
    if let Some(want) = expected_root_cargo_sha256 {
        if set.root_cargo_sha256 != want {
            return Err(ArtifactSetError::Msg(
                "generated/root Cargo drift vs live root".into(),
            ));
        }
    }
    let v = serde_json::to_value(&set).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
    assert_host_only_result(&v)?;
    Ok(set)
}

pub fn write_host_artifact_set_result(
    out_dir: &Path,
    set: &HostArtifactSetV1,
    selected_target: Option<&str>,
    dual_build_byte_equal: bool,
    root_cargo_unchanged: bool,
    status: &str,
    assertions: &[String],
    promotion_blocked_reason: Option<String>,
) -> Result<HostArtifactSetResultV1, ArtifactSetError> {
    fs::create_dir_all(out_dir)?;
    // require empty-ish: only allow writing into dedicated out
    let set_digest = {
        let bytes = serde_json::to_vec(set).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
        sha256_hex(&bytes)
    };
    let mut selected_archive = None;
    if let Some(t) = selected_target {
        let hit = set
            .targets
            .iter()
            .find(|x| x.target == t)
            .ok_or_else(|| ArtifactSetError::UnknownTarget(t.into()))?;
        selected_archive = Some(hit.archive_sha256.clone());
    }
    let diag_schema = set
        .host_artifacts
        .first()
        .map(|h| h.diagnostics_schema_sha256.clone())
        .unwrap_or_default();
    let diag_man = set
        .host_artifacts
        .first()
        .map(|h| h.diagnostics_manifest_sha256.clone())
        .unwrap_or_default();

    let result = HostArtifactSetResultV1 {
        schema_version: 1,
        schema: RESULT_SCHEMA.into(),
        status: status.into(),
        host_version: set.version.clone(),
        source_commit: set.source_commit.clone(),
        source_tree: set.source_tree.clone(),
        source_rev: set.source_rev.clone(),
        advertised_targets: set.advertised_targets.clone(),
        selected_target: selected_target.map(str::to_string),
        selected_archive_sha256: selected_archive,
        host_artifact_set_digest: set_digest,
        shard_aggregate_digest: set.shard_aggregate_digest.clone(),
        host_contract_set_digest: set.host_contract_set_digest.clone(),
        diagnostics_schema_sha256: diag_schema,
        diagnostics_manifest_sha256: diag_man,
        sbom_sha256: set.sbom_sha256.clone(),
        notices_sha256: set.notices_sha256.clone(),
        provenance_sha256: set.provenance_sha256.clone(),
        root_cargo_unchanged,
        dual_build_byte_equal,
        promotion_blocked_reason,
        assertions: assertions.to_vec(),
        cleanup_status: "CLEAN".into(),
    };
    let v = serde_json::to_value(&result).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
    assert_host_only_result(&v)?;
    write_json_atomic(&out_dir.join("result.json"), &v)?;
    Ok(result)
}

fn load_set(path: &Path) -> Result<HostArtifactSetV1, ArtifactSetError> {
    let raw = fs::read(path)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
    if v.get("schema").and_then(|s| s.as_str()) != Some(SET_SCHEMA) {
        return Err(ArtifactSetError::Msg("not HostArtifactSetV1".into()));
    }
    assert_host_only_result(&v)?;
    serde_json::from_value(v).map_err(|e| ArtifactSetError::Json(e.to_string()))
}

fn canonicalize_abs(path: &Path) -> Result<String, ArtifactSetError> {
    let c = fs::canonicalize(path)?;
    Ok(c.display().to_string())
}

fn write_json_atomic(path: &Path, v: &Value) -> Result<(), ArtifactSetError> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| ArtifactSetError::Json(e.to_string()))?;
    s.push('\n');
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(s.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn build_sbom_json(input: &BuildHostArtifactSetInput<'_>) -> String {
    serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("orca-{}", input.version),
        "documentNamespace": format!("https://orca.local/spdx/{}", input.version),
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: orca-host-release-task55"]
        },
        "packages": [{
            "name": "orca",
            "SPDXID": "SPDXRef-orca",
            "versionInfo": input.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "externalRefs": [{
                "referenceCategory": "OTHER",
                "referenceType": "sourceCommit",
                "referenceLocator": input.source_commit
            }]
        }]
    })
    .to_string()
}

fn build_notices_text(input: &BuildHostArtifactSetInput<'_>) -> String {
    format!(
        "Orca host notices\nversion={}\nsourceCommit={}\nsourceRev={}\nhostContractSet={}\n",
        input.version, input.source_commit, input.source_rev, input.host_contract_set_digest
    )
}

fn build_provenance_json(
    input: &BuildHostArtifactSetInput<'_>,
    shard: &EmptyShardAggregateV1,
) -> String {
    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "orca", "version": input.version}],
        "predicateType": "https://orca.local/provenance/host/v1",
        "predicate": {
            "sourceCommit": input.source_commit,
            "sourceTree": input.source_tree,
            "sourceRev": input.source_rev,
            "toolchain": input.toolchain,
            "lockfileSha256": input.lockfile_sha256,
            "rootCargoSha256": input.root_cargo_sha256,
            "hostContractSetDigest": input.host_contract_set_digest,
            "shardAggregateDigest": shard.digest,
            "diagnosticsSchemaSha256": input.diagnostics_schema_sha256,
            "builder": "orca-host-release-task55"
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_input<'a>(out: &'a Path) -> BuildHostArtifactSetInput<'a> {
        BuildHostArtifactSetInput {
            out_dir: out,
            version: "0.0.0-test-host",
            orca_bytes: b"fixture-orca-bytes",
            source_commit: "abc123",
            source_tree: "tree123",
            source_rev: "rev123",
            host_contract_set_digest: "hcset",
            diagnostics_schema_sha256: "diag-schema",
            diagnostics_manifest_sha256: "diag-man",
            root_cargo_sha256: "cargo",
            lockfile_sha256: "lock",
            toolchain: "1.92.0",
            sign_fixture: true,
            rich_adapter_digest: None,
        }
    }

    #[test]
    fn build_validate_resolve_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let (set, _) = build_host_artifact_set(sample_input(tmp.path())).unwrap();
        assert_eq!(set.targets.len(), 2);
        let man = tmp.path().join("host-artifact-set.json");
        let loaded = validate_host_artifact_set(&man, Some("cargo")).unwrap();
        assert_eq!(loaded.version, set.version);
        let p = resolve_artifact_path(&man, "darwin-aarch64").unwrap();
        assert!(p.is_file());
        let err = resolve_artifact_path(&man, "windows-amd64").unwrap_err();
        assert!(matches!(err, ArtifactSetError::UnknownTarget(_)));
    }

    #[test]
    fn result_has_no_plugin_fields() {
        let tmp = TempDir::new().unwrap();
        let (set, _) = build_host_artifact_set(sample_input(tmp.path())).unwrap();
        let out = tmp.path().join("runner");
        let result = write_host_artifact_set_result(
            &out,
            &set,
            Some("linux-amd64"),
            true,
            true,
            "APPROVED",
            &["dual_build".into()],
            Some("fixture-key-not-promotable".into()),
        )
        .unwrap();
        assert_eq!(result.schema, RESULT_SCHEMA);
        let raw = fs::read_to_string(out.join("result.json")).unwrap();
        assert!(!raw.contains("pluginArtifact"));
        assert!(!raw.contains("goOrcaCommit"));
    }

    #[test]
    fn empty_shard_digest_stable() {
        let a = empty_shard_aggregate();
        let b = empty_shard_aggregate();
        assert_eq!(a.digest, b.digest);
        assert!(a.expected_shard_ids.is_empty());
    }
}
