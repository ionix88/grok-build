//! Given/When/Then tests for installed backend registry discovery.

use super::*;
use crate::plugin_host::receipts::{
    FileRole, InstallReceiptV1, InventoryFile, RegistryDocumentV2, TrustState,
};
use xai_grok_agent::plugins::agent_backend::HostPlatform;

fn hex(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn host_darwin() -> HostPlatform {
    HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    }
}

fn host_linux() -> HostPlatform {
    HostPlatform {
        os: "linux".into(),
        arch: "x86_64".into(),
        libc: Some("gnu".into()),
    }
}

fn receipt(
    plugin_id: &str,
    version: &str,
    archive: String,
    target: &str,
    trust: TrustState,
) -> InstallReceiptV1 {
    InstallReceiptV1 {
        schema_version: 1,
        plugin_id: plugin_id.into(),
        version: version.into(),
        archive_sha256: archive,
        install_root: format!("plugins/{plugin_id}/{version}"),
        target: target.into(),
        files: vec![InventoryFile {
            relative_path: "bin/bridge".into(),
            role: FileRole::Executable,
            mode_octal: "0755".into(),
            length: 1,
            content_sha256: hex(2),
        }],
        trust,
        native_code: true,
        capabilities: vec!["acp".into()],
        permissions: vec![],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: String::new(),
    }
    .seal()
    .expect("seal")
}

fn consented() -> TrustState {
    TrustState::Consented {
        consent_digest: hex(3),
        consented_at: "2026-08-03T00:00:00.000Z".into(),
    }
}

#[test]
fn native_always_registered_and_selectable_when_empty_doc() {
    // Given no install receipts
    // When discovering
    let reg = BackendRegistry::discover(None, &host_darwin(), &DiscoverOpts::default()).unwrap();
    // Then native exists and is the only selectable backend
    assert_eq!(reg.list().len(), 1);
    let n = reg.native();
    assert_eq!(n.backend_id, NATIVE_BACKEND_ID);
    assert!(n.selectable);
    assert_eq!(n.source, NATIVE_SOURCE);
    assert_eq!(n.kind, BackendKind::Native);
    assert_eq!(n.health, HealthStatus::NotProbed);
    assert_eq!(reg.selectable().count(), 1);
}

#[test]
fn two_installed_versions_list_status_receipt_target_without_spawn() {
    // Given two side-by-side validated receipts for go-orca
    let mut doc = RegistryDocumentV2::empty();
    let r1 = receipt("go-orca", "1.0.0", hex(1), "darwin-aarch64", consented());
    let r2 = receipt("go-orca", "1.1.0", hex(4), "darwin-aarch64", consented());
    let d1 = r1.receipt_digest.clone();
    let d2 = r2.receipt_digest.clone();
    doc.insert_receipt(r1).unwrap();
    doc.insert_receipt(r2).unwrap();
    let doc = doc.seal().unwrap();

    // When discovering
    let reg =
        BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default()).unwrap();

    // Then both versions are listed with exact receipt/target; native remains
    assert!(reg.native().selectable);
    let versions = reg.versions_of("go-orca");
    assert_eq!(versions.len(), 2);
    let v1 = reg.by_id_version("go-orca", Some("1.0.0")).unwrap();
    let v2 = reg.by_id_version("go-orca", Some("1.1.0")).unwrap();
    assert_eq!(v1.receipt_digest.as_deref(), Some(d1.as_str()));
    assert_eq!(v2.receipt_digest.as_deref(), Some(d2.as_str()));
    assert_eq!(v1.target.as_deref(), Some("darwin-aarch64"));
    assert_eq!(v2.target.as_deref(), Some("darwin-aarch64"));
    assert!(v1.selectable);
    assert!(v2.selectable);
    assert_eq!(v1.health, HealthStatus::NotProbed);
    assert_eq!(reg.selectable().count(), 3); // native + 2
}

#[test]
fn disabled_quarantined_incompatible_diagnosable_not_selectable() {
    let mut doc = RegistryDocumentV2::empty();
    // disabled via trust untrusted
    doc.insert_receipt(receipt(
        "go-orca",
        "1.0.0",
        hex(1),
        "darwin-aarch64",
        TrustState::Untrusted,
    ))
    .unwrap();
    // quarantined via revoked
    doc.insert_receipt(receipt(
        "go-orca",
        "1.1.0",
        hex(4),
        "darwin-aarch64",
        TrustState::Revoked {
            revoked_at: "t".into(),
            prior_consent_digest: None,
        },
    ))
    .unwrap();
    // incompatible target
    doc.insert_receipt(receipt(
        "go-orca",
        "2.0.0",
        hex(5),
        "linux-x86_64",
        consented(),
    ))
    .unwrap();
    let doc = doc.seal().unwrap();

    let reg =
        BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default()).unwrap();

    let u = reg.by_id_version("go-orca", Some("1.0.0")).unwrap();
    assert!(!u.selectable);
    assert!(matches!(u.enablement, Enablement::Disabled { .. }));

    let q = reg.by_id_version("go-orca", Some("1.1.0")).unwrap();
    assert!(!q.selectable);
    assert!(matches!(q.enablement, Enablement::Quarantined { .. }));

    let i = reg.by_id_version("go-orca", Some("2.0.0")).unwrap();
    assert!(!i.selectable);
    assert!(matches!(
        i.compatibility,
        Compatibility::Incompatible { .. }
    ));

    // native still selectable
    assert!(reg.native().selectable);
    assert_eq!(reg.selectable().count(), 1);
}

#[test]
fn forged_receipt_digest_rejected_native_remains() {
    let mut r = receipt("go-orca", "1.0.0", hex(1), "darwin-aarch64", consented());
    r.receipt_digest = hex(9); // forged
    let mut doc = RegistryDocumentV2::empty();
    doc.schema_version = REGISTRY_SCHEMA_V2;
    doc.receipts.insert(r.receipt_digest.clone(), r);
    let err = BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default())
        .unwrap_err();
    assert!(matches!(
        err,
        BackendRegistryError::ForgedRow(_) | BackendRegistryError::Receipt(_)
    ));
    // Caller keeps native-only on error path
    let fallback = BackendRegistry::native_only();
    assert!(fallback.native().selectable);
    assert_eq!(fallback.list().len(), 1);
}

#[test]
fn missing_registry_file_errors_native_only_fallback() {
    let err = BackendRegistry::load_from_path(
        Path::new("/no/such/registry-v2.json"),
        &host_darwin(),
        &DiscoverOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(err, BackendRegistryError::MissingReceipt(_)));
}

#[test]
fn path_only_executable_cannot_register() {
    let err = BackendRegistry::register_path_executable("go-orca").unwrap_err();
    assert!(matches!(err, BackendRegistryError::PathOnlyExecutable(_)));
    assert!(BackendRegistry::native_only().native().selectable);
}

#[test]
fn project_local_native_cannot_register() {
    let err = BackendRegistry::register_project_native(".grok/plugins/evil").unwrap_err();
    assert!(matches!(err, BackendRegistryError::ProjectLocalNative(_)));
}

#[test]
fn v1_manifest_cannot_register_native() {
    let err = BackendRegistry::register_v1_manifest("legacy").unwrap_err();
    assert!(matches!(err, BackendRegistryError::V1Manifest(_)));
}

#[test]
fn source_checkout_cannot_register() {
    let err = BackendRegistry::register_source_checkout("/src/go-orca").unwrap_err();
    assert!(matches!(err, BackendRegistryError::SourceCheckout(_)));
}

#[test]
fn content_only_receipt_without_native_code_excluded() {
    let mut r = receipt(
        "skills-pack",
        "1.0.0",
        hex(1),
        "darwin-aarch64",
        consented(),
    );
    r.native_code = false;
    r.receipt_digest.clear();
    let r = r.seal().unwrap();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r).unwrap();
    let doc = doc.seal().unwrap();
    let reg =
        BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default()).unwrap();
    assert_eq!(reg.list().len(), 1); // native only
    assert!(reg.versions_of("skills-pack").is_empty());
}

#[test]
fn install_root_escape_plugins_dir_rejected() {
    let r = receipt("go-orca", "1.0.0", hex(1), "darwin-aarch64", consented());
    let mut escaped = r.clone();
    // Re-seal with absolute escape path
    escaped.install_root = "/etc/passwd".into();
    escaped.receipt_digest.clear();
    let escaped = escaped.seal().unwrap();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(escaped).unwrap();
    let doc = doc.seal().unwrap();
    let opts = DiscoverOpts {
        plugins_root: Some(PathBuf::from("/tmp/orca-plugins")),
        ..DiscoverOpts::default()
    };
    let err = BackendRegistry::discover(Some(&doc), &host_darwin(), &opts).unwrap_err();
    assert!(matches!(err, BackendRegistryError::PathOwner(_)));
}

#[test]
fn bad_target_label_not_selectable_but_diagnosable() {
    let mut r = receipt("go-orca", "1.0.0", hex(1), "not-a-target", consented());
    r.receipt_digest.clear();
    let r = r.seal().unwrap();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r).unwrap();
    let doc = doc.seal().unwrap();
    let reg =
        BackendRegistry::discover(Some(&doc), &host_linux(), &DiscoverOpts::default()).unwrap();
    let d = reg.by_id_version("go-orca", Some("1.0.0")).unwrap();
    assert!(!d.selectable);
    assert!(matches!(
        d.compatibility,
        Compatibility::Incompatible { .. }
    ));
    assert!(reg.native().selectable);
}

#[test]
fn user_disabled_backend_id_not_selectable() {
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(receipt(
        "go-orca",
        "1.0.0",
        hex(1),
        "darwin-aarch64",
        consented(),
    ))
    .unwrap();
    let doc = doc.seal().unwrap();
    let mut opts = DiscoverOpts::default();
    opts.disabled_backend_ids.insert("go-orca".into());
    let reg = BackendRegistry::discover(Some(&doc), &host_darwin(), &opts).unwrap();
    let d = reg.by_id_version("go-orca", Some("1.0.0")).unwrap();
    assert!(!d.selectable);
    assert!(matches!(d.enablement, Enablement::Disabled { .. }));
    assert!(reg.native().selectable);
}

#[test]
fn receipt_claiming_native_id_is_conflict_not_selectable() {
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(receipt(
        "native",
        "1.0.0",
        hex(1),
        "darwin-aarch64",
        consented(),
    ))
    .unwrap();
    let doc = doc.seal().unwrap();
    let reg =
        BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default()).unwrap();
    assert!(!reg.conflicts().is_empty());
    assert_eq!(reg.conflicts()[0].backend_id, "native");
    // builtin native still selectable
    assert!(reg.native().selectable);
    // forged external "native" not selectable
    let ext = reg
        .list()
        .iter()
        .find(|d| d.kind == BackendKind::External)
        .unwrap();
    assert!(!ext.selectable);
    assert!(ext.diagnostic.as_ref().unwrap().contains("duplicate"));
}

#[test]
fn corrupt_registry_json_rejected() {
    let dir = std::env::temp_dir().join(format!("orca-backend-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("registry-v2.json");
    std::fs::write(&path, "{not-json").unwrap();
    let err = BackendRegistry::load_from_path(&path, &host_darwin(), &DiscoverOpts::default())
        .unwrap_err();
    assert!(matches!(
        err,
        BackendRegistryError::Json(_)
            | BackendRegistryError::Corrupt(_)
            | BackendRegistryError::Receipt(_)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn format_status_lines_lists_native_and_versions_without_spawn() {
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(receipt(
        "go-orca",
        "1.0.0",
        hex(1),
        "darwin-aarch64",
        consented(),
    ))
    .unwrap();
    doc.insert_receipt(receipt(
        "go-orca",
        "1.1.0",
        hex(4),
        "darwin-aarch64",
        consented(),
    ))
    .unwrap();
    let doc = doc.seal().unwrap();
    let reg =
        BackendRegistry::discover(Some(&doc), &host_darwin(), &DiscoverOpts::default()).unwrap();
    let lines = reg.format_status_lines();
    assert_eq!(lines.len(), 3);
    assert!(lines
        .iter()
        .any(|l| l.contains("id=native") && l.contains("selectable=yes")));
    assert!(lines
        .iter()
        .any(|l| l.contains("id=go-orca") && l.contains("version=1.0.0")));
    assert!(lines
        .iter()
        .any(|l| l.contains("id=go-orca") && l.contains("version=1.1.0")));
    assert!(lines.iter().all(|l| l.contains("health=not_probed")));
}

#[cfg(unix)]
#[test]
fn owner_uid_drift_rejected_when_install_tree_exists() {
    let dir = std::env::temp_dir().join(format!("orca-backend-owner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let install = dir.join("plugins/go-orca/1.0.0");
    std::fs::create_dir_all(&install).unwrap();
    let mut r = receipt("go-orca", "1.0.0", hex(1), "darwin-aarch64", consented());
    r.install_root = install.to_string_lossy().into_owned();
    r.receipt_digest.clear();
    let r = r.seal().unwrap();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r).unwrap();
    let doc = doc.seal().unwrap();
    // Expect root ownership; tree is owned by the current user → drift.
    let opts = DiscoverOpts {
        plugins_root: Some(dir.clone()),
        expected_owner_uid: Some(0),
        ..DiscoverOpts::default()
    };
    let err = BackendRegistry::discover(Some(&doc), &host_darwin(), &opts).unwrap_err();
    assert!(matches!(err, BackendRegistryError::PathOwner(_)));
    let _ = std::fs::remove_dir_all(&dir);
}
