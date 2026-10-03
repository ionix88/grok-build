// allow: SIZE_OK — plan Task 55 composition root for host release packaging.
//! Independent Orca host release packaging (Task 55).
//!
//! Host-only: denies Go root/source/artifacts, plugin artifact identity, and
//! combined ArtifactVerificationResultV1 envelopes. Consumes Task 16 R5/signing
//! and Task 7 Orca-released diagnostics fixtures only.

mod artifact_set;
mod isolation;
mod source_sync;

pub use artifact_set::{
    build_host_artifact_set, empty_shard_aggregate, resolve_artifact_path, validate_host_artifact_set,
    write_host_artifact_set_result, AdvertisedTarget, HostArtifactIdentityV1, HostArtifactSetResultV1,
    HostArtifactSetV1, HostBuildMode, ADVERTISED_TARGETS, RESULT_SCHEMA,
};
pub use isolation::{
    assert_host_only_result, deny_go_inputs, HostIsolationError, HostIsolationGuard,
};
pub use source_sync::{
    replay_source_sync, SourceSyncConflict, SourceSyncError, SourceSyncReportV1,
};

use crate::host_update::{
    build_r5_archive, fixture_key_id, fixture_keypair, sign_archive_ed25519, write_sig_file,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Build one deterministic R5 host archive + optional fixture signature.
pub fn package_host_archive(
    out_dir: &Path,
    version: &str,
    target: &str,
    orca_bytes: &[u8],
    sign_fixture: bool,
) -> Result<PackagedHostArchive, PackageError> {
    fs::create_dir_all(out_dir)?;
    let archive_bytes = build_r5_archive(version, target, orca_bytes)
        .map_err(|e| PackageError::Archive(e.to_string()))?;
    let name = format!("orca-{version}-{target}.tar.gz");
    let archive_path = out_dir.join(&name);
    fs::write(&archive_path, &archive_bytes)?;
    let archive_sha256 = sha256_hex(&archive_bytes);
    let mut sig_path = None;
    let mut signature_key_id = None;
    let mut promotion_eligible = false;
    if sign_fixture {
        let kp = fixture_keypair();
        let sig = sign_archive_ed25519(&archive_bytes, &kp);
        let sp = write_sig_file(&archive_path, &sig, &fixture_key_id())
            .map_err(|e| PackageError::Archive(e.to_string()))?;
        sig_path = Some(sp);
        signature_key_id = Some(fixture_key_id());
        // Fixture keys are test-only and cannot satisfy public promotion.
        promotion_eligible = false;
    }
    Ok(PackagedHostArchive {
        archive_path,
        archive_sha256,
        target: target.to_string(),
        version: version.to_string(),
        sig_path,
        signature_key_id,
        promotion_eligible,
        format_id: crate::host_update::ARCHIVE_FORMAT_ID.to_string(),
    })
}

/// Two clean builds of the same inputs must be byte-equal.
pub fn dual_build_byte_equal(
    version: &str,
    target: &str,
    orca_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PackageError> {
    let a = build_r5_archive(version, target, orca_bytes)
        .map_err(|e| PackageError::Archive(e.to_string()))?;
    let b = build_r5_archive(version, target, orca_bytes)
        .map_err(|e| PackageError::Archive(e.to_string()))?;
    if a != b {
        return Err(PackageError::ByteDrift);
    }
    Ok((a, b))
}

#[derive(Debug, Clone)]
pub struct PackagedHostArchive {
    pub archive_path: PathBuf,
    pub archive_sha256: String,
    pub target: String,
    pub version: String,
    pub sig_path: Option<PathBuf>,
    pub signature_key_id: Option<String>,
    pub promotion_eligible: bool,
    pub format_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive: {0}")]
    Archive(String),
    #[error("byte-equal dual build drifted")]
    ByteDrift,
    #[error("{0}")]
    Msg(String),
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    crate::host_update::sha256_hex(bytes)
}

pub(crate) fn read_sha256_file(path: &Path) -> Result<String, PackageError> {
    let b = fs::read(path)?;
    Ok(sha256_hex(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn dual_r5_builds_are_byte_equal() {
        let payload = b"orca-host-fixture-bin-v1";
        let (a, b) = dual_build_byte_equal("0.0.0-test-host", "darwin-aarch64", payload).unwrap();
        assert_eq!(a, b);
        assert!(a.len() > 32);
    }

    #[test]
    fn package_writes_archive_and_fixture_sig() {
        let tmp = TempDir::new().unwrap();
        let pkg = package_host_archive(
            tmp.path(),
            "0.0.0-test-host",
            "linux-amd64",
            b"payload-bytes",
            true,
        )
        .unwrap();
        assert!(pkg.archive_path.is_file());
        assert!(pkg.sig_path.as_ref().unwrap().is_file());
        assert!(!pkg.promotion_eligible, "fixture sig cannot promote");
        assert_eq!(pkg.format_id, "tar-gzip-rfc1952-ustar-v1");
    }

    #[test]
    fn linux_and_darwin_targets_differ() {
        let p = b"same-payload";
        let (d, _) = dual_build_byte_equal("0.0.0-t", "darwin-aarch64", p).unwrap();
        let (l, _) = dual_build_byte_equal("0.0.0-t", "linux-amd64", p).unwrap();
        assert_ne!(d, l, "target is bound into host-manifest");
    }
}
