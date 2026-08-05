//! Given/When/Then tests for immutable session pins.

use super::*;
use crate::plugin_host::lifecycle::SessionPinV1;

fn h(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn key() -> String {
    "0123456789abcdef0123456789abcdef".into()
}

fn ext_req(host: &str) -> ExternalCreateRequest {
    ExternalCreateRequest {
        host_session_id: host.into(),
        creation_key: key(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: h(0xb),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    }
}

fn store() -> (tempfile::TempDir, PinStore) {
    let tmp = tempfile::TempDir::new().unwrap();
    let s = PinStore::open(tmp.path().join("session-pins")).unwrap();
    (tmp, s)
}

#[test]
fn native_pin_written_after_identity_has_no_plugin_fields() {
    // Given: empty pin store
    let (_t, s) = store();
    // When: native identity is sealed
    let pin = s.write_native("host-n1", "native-id-1").unwrap();
    // Then: NativeV1 only; reload parses; no plugin fields
    assert_eq!(pin.backend_id, "native");
    assert_eq!(pin.native_session_identity, "native-id-1");
    let loaded = s.load_required("host-n1").unwrap();
    match loaded {
        SessionPinV1::Native(n) => assert_eq!(n.pin_digest, pin.pin_digest),
        SessionPinV1::External(_) => panic!("expected native"),
    }
    let raw = std::fs::read_to_string(s.path_for("host-n1")).unwrap();
    assert!(!raw.contains("installReceiptDigest"));
    assert!(!raw.contains("creationKey"));
}

#[test]
fn native_pin_with_plugin_fields_on_disk_fails_closed() {
    let (_t, s) = store();
    let path = s.path_for("bad-native");
    std::fs::write(
        &path,
        r#"{"kind":"native","schemaVersion":1,"backendId":"native","hostSessionId":"bad-native","nativeSessionIdentity":"x","installReceiptDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pinDigest":"00"}"#,
    )
    .unwrap();
    let err = s.load("bad-native").unwrap_err();
    assert!(matches!(err, PinStoreError::Schema(_)), "{err:?}");
}

#[test]
fn mixed_discriminator_fails_closed() {
    let (_t, s) = store();
    std::fs::write(s.path_for("hyb"), r#"{"kind":"hybrid","schemaVersion":1}"#).unwrap();
    let err = s.load("hyb").unwrap_err();
    assert!(matches!(err, PinStoreError::Schema(_)), "{err:?}");
}

#[test]
fn external_creating_fsync_before_activate_and_replay_same_key() {
    let (_t, s) = store();
    let req = ext_req("host-e1");
    // When: begin create
    let creating = s.begin_external_create(&req).unwrap();
    assert_eq!(creating.state, ExternalPinState::Creating);
    assert!(creating.acp_session_id.is_none());
    // Then: on-disk Creating survives "crash" (reload)
    let reloaded = s.reconcile_creating("host-e1").unwrap();
    assert_eq!(reloaded.creation_key, req.creation_key);
    assert_eq!(reloaded.install_receipt_digest, req.install_receipt_digest);
    // When: replay identical request
    let again = s.begin_external_create(&req).unwrap();
    assert_eq!(again.pin_digest, creating.pin_digest);
}

#[test]
fn external_replay_changed_request_is_idempotency_conflict() {
    let (_t, s) = store();
    let mut req = ext_req("host-e2");
    s.begin_external_create(&req).unwrap();
    req.request_digest = h(0xf);
    let err = s.begin_external_create(&req).unwrap_err();
    assert!(matches!(err, PinStoreError::Idempotency(_)), "{err:?}");
    // Creating pin still present, not deleted
    let still = s.reconcile_creating("host-e2").unwrap();
    assert_eq!(still.state, ExternalPinState::Creating);
}

#[test]
fn external_replay_changed_extension_schema_or_renderer_conflicts() {
    let (_t, s) = store();
    let mut req = ext_req("host-e2b");
    s.begin_external_create(&req).unwrap();
    req.extension_schema_digest = h(0x1);
    let err = s.begin_external_create(&req).unwrap_err();
    assert!(matches!(err, PinStoreError::Idempotency(_)), "{err:?}");
    req = ext_req("host-e2c");
    s.begin_external_create(&req).unwrap();
    req.renderer_contract_version = "9.9.9".into();
    let err = s.begin_external_create(&req).unwrap_err();
    assert!(matches!(err, PinStoreError::Idempotency(_)), "{err:?}");
}

#[test]
fn external_activate_yields_stable_acp_session_once() {
    let (_t, s) = store();
    s.begin_external_create(&ext_req("host-e3")).unwrap();
    let active = s
        .activate_external(&ExternalActivateRequest {
            host_session_id: "host-e3".into(),
            acp_session_id: "acp-stable-1".into(),
            committed_revision: 1,
            committed_cursor: 0,
        })
        .unwrap();
    assert_eq!(active.state, ExternalPinState::Active);
    assert_eq!(active.acp_session_id.as_deref(), Some("acp-stable-1"));
    // Idempotent same activate
    let again = s
        .activate_external(&ExternalActivateRequest {
            host_session_id: "host-e3".into(),
            acp_session_id: "acp-stable-1".into(),
            committed_revision: 1,
            committed_cursor: 0,
        })
        .unwrap();
    assert_eq!(again.pin_digest, active.pin_digest);
    // Different ACP id refused
    let err = s
        .activate_external(&ExternalActivateRequest {
            host_session_id: "host-e3".into(),
            acp_session_id: "acp-other".into(),
            committed_revision: 1,
            committed_cursor: 0,
        })
        .unwrap_err();
    assert!(matches!(err, PinStoreError::ActiveImmutable(_)), "{err:?}");
}

#[test]
fn active_pin_cannot_move_receipt_or_cohort() {
    let (_t, s) = store();
    let req = ext_req("host-e4");
    s.begin_external_create(&req).unwrap();
    s.activate_external(&ExternalActivateRequest {
        host_session_id: "host-e4".into(),
        acp_session_id: "acp-1".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .unwrap();
    s.assert_active_identity_stable("host-e4", &req.install_receipt_digest, &req.cohort_key)
        .unwrap();
    let err = s
        .assert_active_identity_stable("host-e4", &h(1), &req.cohort_key)
        .unwrap_err();
    assert!(matches!(err, PinStoreError::Stale(_)), "{err:?}");
}

#[test]
fn creation_key_is_32_hex() {
    let k = PinStore::new_creation_key(&[0u8; 16]);
    assert_eq!(k.len(), 32);
    assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
}
