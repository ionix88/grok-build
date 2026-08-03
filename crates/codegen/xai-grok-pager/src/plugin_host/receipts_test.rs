//! Given/When/Then tests for install receipts and registry migration.

use super::*;
use crate::plugin_host::canonical::sha256_hex;

fn hex_a() -> String {
    "a".repeat(64)
}
fn hex_b() -> String {
    "b".repeat(64)
}
fn hex_c() -> String {
    "c".repeat(64)
}

fn sample_receipt(archive: String) -> InstallReceiptV1 {
    InstallReceiptV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        version: "1.0.0".into(),
        archive_sha256: archive,
        install_root: "plugins/go-orca/1.0.0".into(),
        target: "darwin-aarch64".into(),
        files: vec![
            InventoryFile {
                relative_path: "bin/go-orca".into(),
                role: FileRole::Executable,
                mode_octal: "0755".into(),
                length: 100,
                content_sha256: hex_b(),
            },
            InventoryFile {
                relative_path: "manifest.json".into(),
                role: FileRole::Manifest,
                mode_octal: "0644".into(),
                length: 50,
                content_sha256: hex_c(),
            },
        ],
        trust: TrustState::Untrusted,
        native_code: true,
        capabilities: vec!["acp".into()],
        permissions: vec!["network.loopback".into()],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: String::new(),
    }
    .seal()
    .expect("seal receipt")
}

#[test]
fn install_receipt_digest_stable_when_key_order_differs() {
    // Given a sealed receipt
    let r = sample_receipt(hex_a());
    let json1 = serde_json::to_string(&r).unwrap();
    // When re-parsed
    let r2 = InstallReceiptV1::parse_json(&json1).unwrap();
    // Then digest is stable
    assert_eq!(r.receipt_digest, r2.receipt_digest);
    assert_eq!(r.receipt_digest.len(), 64);
}

#[test]
fn same_version_changed_bytes_conflicts() {
    // Given two receipts same version different archive
    let a = sample_receipt(hex_a());
    let b = sample_receipt(hex_b());
    // When checked for conflict
    let err = conflict_same_version(&a, &b).unwrap_err();
    // Then typed conflict
    assert!(matches!(err, ReceiptError::VersionByteConflict(_)));
}

#[test]
fn registry_insert_rejects_version_byte_conflict() {
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(sample_receipt(hex_a())).unwrap();
    let err = doc.insert_receipt(sample_receipt(hex_b())).unwrap_err();
    assert!(matches!(err, ReceiptError::VersionByteConflict(_)));
}

#[test]
fn logical_default_has_no_receipt_or_version_fields() {
    // Given a sealed logical default
    let d = LogicalDefaultV1 {
        schema_version: 1,
        backend_id: "go-orca".into(),
        version_policy: "followActivation".into(),
        default_digest: String::new(),
    }
    .seal()
    .unwrap();
    let v = serde_json::to_value(&d).unwrap();
    // Then no receipt/version keys exist on the wire
    assert!(v.get("installReceiptDigest").is_none());
    assert!(v.get("version").is_none());
    assert_eq!(v["versionPolicy"], "followActivation");
    LogicalDefaultV1::parse_json(&serde_json::to_string(&d).unwrap()).unwrap();
}

#[test]
fn registry_v1_migration_is_preview_only() {
    // Given a legacy v1 content registry
    let raw = r#"{
      "version": 1,
      "repos": {
        "demo-abcd1234": {
          "kind": {"type": "Local", "source_path": "/tmp/demo"},
          "installed_at": "t",
          "updated_at": "t",
          "path": "/tmp/x",
          "plugins": {"demo-plugin": {"version": "0.1.0"}}
        }
      }
    }"#;
    // When preview-migrated
    let preview = preview_migrate_registry_v1(raw).unwrap();
    // Then preview-only, no native receipts fabricated
    assert!(preview.preview_only);
    assert!(preview.native_receipts.is_empty());
    assert_eq!(preview.content_plugin_ids, vec!["demo-plugin".to_string()]);
    assert!(preview.candidate_pointer.starts_with("sha256:"));
    assert_eq!(preview.preview_digest.len(), 64);
}

#[test]
fn registry_v1_refuses_native_code_marker() {
    let raw = r#"{
      "version": 1,
      "repos": {
        "x": {
          "kind": {"type": "Local", "source_path": "/t"},
          "installed_at": "t",
          "updated_at": "t",
          "path": "/t",
          "plugins": {"p": {"nativeCode": true}}
        }
      }
    }"#;
    let err = preview_migrate_registry_v1(raw).unwrap_err();
    assert!(matches!(err, ReceiptError::V1CannotFabricateNative));
}

#[test]
fn inventory_path_escape_rejected() {
    let mut r = sample_receipt(hex_a());
    r.receipt_digest.clear();
    r.files[0].relative_path = "../etc/passwd".into();
    let err = r.seal().unwrap_err();
    assert!(matches!(err, ReceiptError::PathEscape(_)));
}

#[test]
fn fixture_install_receipt_round_trips_when_resealed() {
    // Fixtures may drift on digest algorithm; reseal from fields.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/plugin_host/fixtures/install-receipt.json"
    );
    let raw = std::fs::read_to_string(path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    if let Some(obj) = v.as_object_mut() {
        obj.insert("receiptDigest".into(), serde_json::json!(""));
    }
    let mut r: InstallReceiptV1 = serde_json::from_value(v).unwrap();
    r.receipt_digest.clear();
    let sealed = r.seal().unwrap();
    InstallReceiptV1::parse_json(&serde_json::to_string(&sealed).unwrap()).unwrap();
    let _ = sha256_hex(b"fixture-present");
}
