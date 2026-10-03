//! Task 17 red/green corpus: baseline + valid archive + every hostile guard.

use super::*;
use std::path::PathBuf;
use tempfile::tempdir;
use xai_grok_agent::plugins::agent_backend::{
    ArtifactRef, BackendArtifact, BackendFiles, BackendTarget, EntrypointSpec,
};

fn assert_bad_archive_contains(err: AcquireError, needle: &str) {
    match err {
        AcquireError::BadArchive(m) => assert!(m.contains(needle), "msg={m} needle={needle}"),
        other => panic!("expected BadArchive containing {needle}, got {other:?}"),
    }
}

fn assert_redirect_contains(err: AcquireError, needle: &str) {
    match err {
        AcquireError::RedirectDenied(m) => assert!(m.contains(needle), "msg={m}"),
        other => panic!("expected RedirectDenied containing {needle}, got {other:?}"),
    }
}

fn sample_target(sha: &str, label_os: &str, label_arch: &str) -> BackendTarget {
    let bridge = format!("bin/{label_os}-{label_arch}/go-orca");
    let daemon = format!("bin/{label_os}-{label_arch}/go-orcad");
    BackendTarget {
        os: label_os.into(),
        arch: label_arch.into(),
        libc: None,
        artifact: BackendArtifact {
            url: "https://fixtures.invalid/go-orca.tar.gz".into(),
            sha256: sha.into(),
            signature: Some(ArtifactRef {
                kind: Some("ed25519-detached".into()),
                identity: Some(fixture_key_id()),
                path: None,
                sha256: None,
            }),
            provenance: None,
            sbom: None,
        },
        files: BackendFiles {
            bridge: bridge.clone(),
            daemon: daemon.clone(),
        },
        entrypoint: EntrypointSpec {
            argv: vec![
                "{bridge}".into(),
                "agent".into(),
                "stdio".into(),
                "--daemon".into(),
                "{daemon}".into(),
                "--plugin-data".into(),
                "{pluginData}".into(),
                "--runtime-dir".into(),
                "{runtimeDir}".into(),
                "--cohort".into(),
                "{cohortId}".into(),
                "--purge-barrier".into(),
                "{purgeBarrier}".into(),
                "--barrier-parent-identity".into(),
                "{purgeBarrierParentIdentity}".into(),
                "--barrier-revision".into(),
                "{purgeBarrierRevision}".into(),
            ],
            cwd: "{pluginRoot}".into(),
        },
    }
}

fn valid_archive_bytes() -> (Vec<u8>, BackendTarget, String) {
    let os = "darwin";
    let arch = "aarch64";
    let bridge = format!("bin/{os}-{arch}/go-orca");
    let daemon = format!("bin/{os}-{arch}/go-orcad");
    let bridge_bytes = b"#!/bin/sh\necho bridge\n";
    let daemon_bytes = b"#!/bin/sh\necho daemon\n";
    let notice = b"NOTICE\n";
    let files: Vec<(&str, &[u8], u32)> = vec![
        (bridge.as_str(), bridge_bytes.as_slice(), 0o755),
        (daemon.as_str(), daemon_bytes.as_slice(), 0o755),
        ("NOTICE", notice.as_slice(), 0o644),
    ];
    let bytes = build_r5_plugin_archive("go-orca", "1.2.0", "darwin-aarch64", &files).unwrap();
    let sha = sha256_hex(&bytes);
    let target = sample_target(&sha, os, arch);
    (bytes, target, sha)
}

fn write_signed(dir: &Path, name: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let ap = dir.join(name);
    fs::write(&ap, bytes).unwrap();
    let sig = sign_archive_ed25519(bytes);
    let sp = {
        let mut p = ap.as_os_str().to_os_string();
        p.push(".sig");
        PathBuf::from(p)
    };
    fs::write(&sp, sig).unwrap();
    (ap, sp)
}

fn req_for(target: BackendTarget, archive: PathBuf, sig: PathBuf) -> AcquisitionRequest {
    AcquisitionRequest {
        plugin_id: "go-orca".into(),
        version: "1.2.0".into(),
        target,
        local_archive: Some(archive),
        local_signature: Some(sig),
    }
}

/// Baseline: existing marketplace installer path APIs still compile/link (characterization).
#[test]
fn baseline_marketplace_relative_path_still_rejects_traversal() {
    use crate::types::MarketplaceRelativePath;
    assert!(MarketplaceRelativePath::parse("plugins/../etc").is_err());
    assert!(MarketplaceRelativePath::parse("plugins/foo").is_ok());
}

#[test]
fn happy_valid_archive_stages_without_promotion() {
    let dir = tempdir().unwrap();
    let (bytes, target, sha) = valid_archive_bytes();
    let (ap, sp) = write_signed(dir.path(), "good.tar.gz", &bytes);
    let staging = dir.path().join("stage-good");
    let req = req_for(target, ap, sp);
    let staged = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .expect("valid archive must stage");
    assert_eq!(staged.archive_sha256, sha);
    assert_eq!(staged.archive_format, ARCHIVE_FORMAT_ID);
    assert_eq!(staged.plugin_id, "go-orca");
    assert_eq!(staged.target_label, "darwin-aarch64");
    assert!(staged.bridge_abs.is_file());
    assert!(staged.daemon_abs.is_file());
    assert_eq!(staged.entrypoint_abs, staged.bridge_abs);
    assert!(staged.files.iter().any(|f| f.role == StagedFileRole::Executable));
    // No promotion markers — only staging tree.
    assert!(staging.is_dir());
    assert!(!dir.path().join("install").exists());
}

#[test]
fn digest_mismatch_refuses_and_leaves_no_staging() {
    let dir = tempdir().unwrap();
    let (bytes, mut target, _) = valid_archive_bytes();
    target.artifact.sha256 = "ff".repeat(32);
    let (ap, sp) = write_signed(dir.path(), "bad-digest.tar.gz", &bytes);
    let staging = dir.path().join("stage-digest");
    let req = req_for(target, ap, sp);
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::DigestMismatch { .. }));
    assert!(!staging.exists());
}

#[test]
fn bad_signature_rejected() {
    let dir = tempdir().unwrap();
    let (bytes, target, _) = valid_archive_bytes();
    let ap = dir.path().join("nosig.tar.gz");
    fs::write(&ap, &bytes).unwrap();
    let sp = dir.path().join("nosig.tar.gz.sig");
    fs::write(&sp, [0u8; 64]).unwrap();
    let staging = dir.path().join("stage-sig");
    let req = req_for(target, ap, sp);
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::BadSignature(_)));
    assert!(!staging.exists());
}

#[test]
fn traversal_path_rejected() {
    let dir = tempdir().unwrap();
    // Craft hostile tar with ../ path via raw builder (bypass validate on build).
    let mut entries = vec![(
        "../escape".into(),
        b"pwned".to_vec(),
        0o644u32,
        b'0',
    )];
    // Also need a fake manifest so we hit path check in parse.
    let err = test_write_ustar_raw(&entries).and_then(|b| test_extract_ustar_gz(&b));
    assert!(err.is_err(), "traversal must fail: {err:?}");
    let _ = dir;
    let _ = &mut entries;
}

#[test]
fn symlink_typeflag_rejected() {
    let entries = vec![("link".into(), b"".to_vec(), 0o644u32, b'2')];
    let bytes = test_write_ustar_raw(&entries).unwrap();
    let err = test_extract_ustar_gz(&bytes).unwrap_err();
    assert_bad_archive_contains(err, "forbidden");
}

#[test]
fn hardlink_typeflag_rejected() {
    let entries = vec![("hl".into(), b"".to_vec(), 0o644u32, b'1')];
    let bytes = test_write_ustar_raw(&entries).unwrap();
    let err = test_extract_ustar_gz(&bytes).unwrap_err();
    assert!(matches!(err, AcquireError::BadArchive(_)));
}

#[test]
fn device_typeflag_rejected() {
    for tf in [b'3', b'4', b'6'] {
        let entries = vec![("dev".into(), b"".to_vec(), 0o644u32, tf)];
        let bytes = test_write_ustar_raw(&entries).unwrap();
        let err = test_extract_ustar_gz(&bytes).unwrap_err();
        assert!(matches!(err, AcquireError::BadArchive(_)), "tf={}", tf as char);
    }
}

#[test]
fn duplicate_path_rejected() {
    let dir = tempdir().unwrap();
    let os = "darwin";
    let arch = "aarch64";
    let bridge = format!("bin/{os}-{arch}/go-orca");
    let daemon = format!("bin/{os}-{arch}/go-orcad");
    // Build valid then inject duplicate via raw: two same paths.
    let data = b"x".to_vec();
    let entries = vec![
        (bridge.clone(), data.clone(), 0o755, b'0'),
        (bridge.clone(), data.clone(), 0o755, b'0'),
        (daemon.clone(), data.clone(), 0o755, b'0'),
    ];
    let bytes = test_write_ustar_raw(&entries).unwrap();
    // extract may succeed path-wise but check_case_and_duplicate runs after manifest —
    // without manifest, parse_manifest fails. Directly test extract + duplicate check:
    let tar = test_gunzip_preflight(&bytes).unwrap();
    // parse_ustar allows duplicates; acquire path checks them.
    // Build a minimal flow: put duplicate in a full archive by using build then...
    // Use acquire with crafted archive that has manifest listing one path but tar has dups —
    // simpler: call check via acquire with two identical file paths in build_r5 — builder
    // would create one. Use raw extract list:
    let paths = super::parse_ustar(&tar).unwrap();
    let err = super::check_case_and_duplicate(&paths);
    match err {
        Err(AcquireError::BadArchive(m)) => assert!(m.contains("duplicate"), "{m}"),
        other => panic!("expected duplicate BadArchive, got {other:?}"),
    }
    let _ = dir;
}

#[test]
fn case_collision_rejected() {
    let a = TarEntry {
        path: "Bin/Foo".into(),
        data: b"1".to_vec(),
        mode: 0o644,
        is_dir: false,
    };
    let b = TarEntry {
        path: "bin/foo".into(),
        data: b"2".to_vec(),
        mode: 0o644,
        is_dir: false,
    };
    let err = check_case_and_duplicate(&[a, b]).unwrap_err();
    assert_bad_archive_contains(err, "case collision");
}

#[test]
fn gzip_flg_drift_rejected() {
    let (mut bytes, _, _) = valid_archive_bytes();
    // Corrupt FLG
    if bytes.len() > 4 {
        bytes[3] = 0x08; // FNAME
    }
    let err = test_gunzip_preflight(&bytes).unwrap_err();
    assert_bad_archive_contains(err, "FLG");
}

#[test]
fn gzip_os_drift_rejected() {
    let (mut bytes, _, _) = valid_archive_bytes();
    if bytes.len() > 10 {
        bytes[9] = 3; // Unix OS, not 255
    }
    let err = test_gunzip_preflight(&bytes).unwrap_err();
    assert_bad_archive_contains(err, "OS");
}

#[test]
fn gzip_trailing_bytes_rejected() {
    let (mut bytes, _, _) = valid_archive_bytes();
    // Second gzip member / junk after the single R5 member.
    bytes.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    bytes.extend_from_slice(b"TRAILING-JUNK");
    let err = test_gunzip_preflight(&bytes).unwrap_err();
    assert_bad_archive_contains(err, "trailing");
}

#[test]
fn not_ustar_rejected() {
    // gzip of non-ustar payload
    let garbage = gzip_level9(b"not a tar at all, just bytes!!!!").unwrap();
    let err = test_extract_ustar_gz(&garbage).unwrap_err();
    assert!(matches!(err, AcquireError::BadArchive(_)));
}

#[test]
fn target_mismatch_rejected() {
    let dir = tempdir().unwrap();
    let (bytes, mut target, _) = valid_archive_bytes();
    // Archive is darwin-aarch64; claim linux target in request while keeping same files paths —
    // identity check uses target_label_of(req) vs manifest.
    target.os = "linux".into();
    target.arch = "x86_64".into();
    let (ap, sp) = write_signed(dir.path(), "tgt.tar.gz", &bytes);
    let staging = dir.path().join("stage-tgt");
    let req = req_for(target, ap, sp);
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(
        matches!(err, AcquireError::TargetMismatch { .. } | AcquireError::Manifest(_)),
        "{err}"
    );
    assert!(!staging.exists());
}

#[test]
fn executable_role_drift_rejected() {
    let dir = tempdir().unwrap();
    let os = "darwin";
    let arch = "aarch64";
    let bridge = format!("bin/{os}-{arch}/go-orca");
    let daemon = format!("bin/{os}-{arch}/go-orcad");
    // Bridge mode 0644 — not executable.
    let files: Vec<(&str, &[u8], u32)> = vec![
        (bridge.as_str(), b"bridge".as_slice(), 0o644),
        (daemon.as_str(), b"daemon".as_slice(), 0o755),
    ];
    let bytes = build_r5_plugin_archive("go-orca", "1.2.0", "darwin-aarch64", &files).unwrap();
    let sha = sha256_hex(&bytes);
    let target = sample_target(&sha, os, arch);
    let (ap, sp) = write_signed(dir.path(), "role.tar.gz", &bytes);
    let staging = dir.path().join("stage-role");
    let req = req_for(target, ap, sp);
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::RoleDrift(_)), "{err}");
    assert!(!staging.exists());
}

#[test]
fn staging_must_be_absent() {
    let dir = tempdir().unwrap();
    let (bytes, target, _) = valid_archive_bytes();
    let (ap, sp) = write_signed(dir.path(), "x.tar.gz", &bytes);
    let staging = dir.path().join("already");
    fs::create_dir_all(&staging).unwrap();
    let req = req_for(target, ap, sp);
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::StagingExists(_)));
}

#[test]
fn egress_denied_without_grant() {
    let err = fetch_https_bounded(
        "https://example.com/a.tar.gz",
        &EgressGrant::default(),
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::EgressDenied));
}

#[test]
fn timeout_error_variant_is_typed() {
    // Given: a typed timeout refusal from the download boundary
    // When: Display is formatted
    // Then: message is stable and matchable without stringly HTTP errors
    let err = AcquireError::Timeout;
    assert!(matches!(err, AcquireError::Timeout));
    assert_eq!(err.to_string(), "download timeout");
}

#[test]
fn http_scheme_denied() {
    let grant = EgressGrant::allow_host("example.com");
    let err = fetch_https_bounded("http://example.com/a.tar.gz", &grant).unwrap_err();
    assert!(matches!(err, AcquireError::SchemeDenied(_)));
}

#[test]
fn redirect_http_downgrade_denied() {
    let err = resolve_redirect("https://example.com/a", "http://evil.com/b").unwrap_err();
    assert_redirect_contains(err, "downgrade");
}

#[test]
fn redirect_host_not_on_allowlist_denied() {
    // parse + host check path
    let grant = EgressGrant {
        authorized: true,
        allowed_hosts: vec!["good.example".into()],
        max_redirects: 3,
        timeout: Duration::from_secs(1),
        max_download_bytes: 1024,
    };
    // Without a live server we only unit-test host_allowed / resolve.
    assert!(!host_allowed("evil.example", &grant.allowed_hosts));
    assert!(host_allowed("good.example", &grant.allowed_hosts));
    let next = resolve_redirect("https://good.example/a", "https://evil.example/b").unwrap();
    let parsed = parse_https_url(&next).unwrap();
    assert!(!host_allowed(&parsed.host, &grant.allowed_hosts));
}

#[test]
fn absolute_path_in_tar_rejected() {
    let entries = vec![("/etc/passwd".into(), b"x".to_vec(), 0o644u32, b'0')];
    let bytes = test_write_ustar_raw(&entries).unwrap();
    let err = test_extract_ustar_gz(&bytes).unwrap_err();
    assert!(matches!(err, AcquireError::BadArchive(_)));
}

#[test]
fn device_path_colon_rejected() {
    let err = validate_rel_path("C:/Windows/System32", false).unwrap_err();
    assert!(matches!(err, AcquireError::BadArchive(_)));
}

#[test]
fn r5_level9_header_contract() {
    let (bytes, _, _) = valid_archive_bytes();
    assert_eq!(&bytes[0..4], &[0x1f, 0x8b, 8, 0]);
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    assert_eq!(bytes[8], 2);
    assert_eq!(bytes[9], 255);
}

#[test]
fn bomb_too_many_entries_rejected() {
    // Build tar with MAX_ENTRIES+1 tiny files via raw headers (no gzip bomb).
    let mut entries = Vec::new();
    for i in 0..(MAX_ENTRIES + 1) {
        let name = format!("f{i:04}");
        entries.push((name, vec![b'x'], 0o644u32, b'0'));
    }
    let bytes = test_write_ustar_raw(&entries).unwrap();
    let err = test_extract_ustar_gz(&bytes).unwrap_err();
    assert_bad_archive_contains(err, "too many");
}

#[test]
fn partial_failure_wipes_staging_tree() {
    let dir = tempdir().unwrap();
    // Valid bytes but wrong plugin id in request → fails after extract starts writing? 
    // Manifest identity fails before write if we order correctly — identity is before write.
    // Force failure after write by using role drift (write happens before role check).
    let os = "darwin";
    let arch = "aarch64";
    let bridge = format!("bin/{os}-{arch}/go-orca");
    let daemon = format!("bin/{os}-{arch}/go-orcad");
    let files: Vec<(&str, &[u8], u32)> = vec![
        (bridge.as_str(), b"bridge".as_slice(), 0o644), // drift
        (daemon.as_str(), b"daemon".as_slice(), 0o755),
    ];
    let bytes = build_r5_plugin_archive("go-orca", "1.2.0", "darwin-aarch64", &files).unwrap();
    let sha = sha256_hex(&bytes);
    let target = sample_target(&sha, os, arch);
    let (ap, sp) = write_signed(dir.path(), "partial.tar.gz", &bytes);
    let staging = dir.path().join("stage-partial");
    let req = req_for(target, ap, sp);
    let _ = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(
        !staging.exists(),
        "partial staging must be wiped; still exists"
    );
}

#[test]
fn missing_signature_when_required() {
    let dir = tempdir().unwrap();
    let (bytes, target, _) = valid_archive_bytes();
    let ap = dir.path().join("u.tar.gz");
    fs::write(&ap, &bytes).unwrap();
    let staging = dir.path().join("stage-nosig");
    let req = AcquisitionRequest {
        plugin_id: "go-orca".into(),
        version: "1.2.0".into(),
        target,
        local_archive: Some(ap),
        local_signature: None,
    };
    let err = acquire_and_stage(
        &req,
        &EgressGrant::default(),
        &fixture_trust_required(),
        &staging,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::BadSignature(_)));
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/r5-hostile")
}

#[test]
fn on_disk_hostile_gzip_fixtures_rejected() {
    let dir = fixture_dir();
    for name in [
        "gzip-os-drift.tar.gz",
        "gzip-flg-drift.tar.gz",
        "gzip-trailing-junk.tar.gz",
    ] {
        let bytes = fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let err = test_gunzip_preflight(&bytes).expect_err(name);
        assert!(
            matches!(err, AcquireError::BadArchive(_)),
            "{name} => {err}"
        );
    }
}

#[test]
fn on_disk_valid_fixture_roundtrip() {
    let p = fixture_dir()
        .parent()
        .unwrap()
        .join("r5-valid")
        .join("go-orca-1.2.0-darwin-aarch64.tar.gz");
    let bytes = fs::read(&p).expect("r5-valid fixture must exist");
    let tar = test_gunzip_preflight(&bytes).expect("valid fixture gunzip");
    assert!(!tar.is_empty());
    let paths = test_parse_ustar(&tar).expect("valid fixture ustar");
    assert!(paths.iter().any(|p| p == "artifact-manifest.json"));
}
