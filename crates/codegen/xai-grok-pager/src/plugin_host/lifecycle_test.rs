//! Given/When/Then tests for pins, barriers, purge ordering, and deletion algebra.

use super::*;

fn h(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn sample_native() -> NativePinV1 {
    NativePinV1 {
        schema_version: 1,
        backend_id: "native".into(),
        host_session_id: "host-1".into(),
        native_session_identity: "native-1".into(),
        pin_digest: String::new(),
    }
    .seal()
    .unwrap()
}

fn sample_external(state: ExternalPinState, acp: Option<&str>) -> ExternalPinV1 {
    ExternalPinV1 {
        schema_version: 1,
        state,
        host_session_id: "host-2".into(),
        creation_key: "0".repeat(32),
        request_digest: h(1),
        backend_id: "go-orca".into(),
        install_receipt_digest: h(2),
        cohort_key: h(3),
        extension_schema_digest: h(4),
        renderer_contract_version: "1.0.0".into(),
        acp_session_id: acp.map(str::to_string),
        committed_revision: if acp.is_some() { 1 } else { 0 },
        committed_cursor: 0,
        pin_digest: String::new(),
    }
    .seal()
    .unwrap()
}

#[test]
fn native_pin_round_trip_stable_digest() {
    // Given a sealed native pin
    let pin = sample_native();
    let raw = serde_json::to_string(&SessionPinV1::Native(pin.clone())).unwrap();
    // When parsed
    let parsed = SessionPinV1::parse_json(&raw).unwrap();
    // Then identity preserved
    match parsed {
        SessionPinV1::Native(n) => assert_eq!(n.pin_digest, pin.pin_digest),
        _ => panic!("expected native"),
    }
}

#[test]
fn native_pin_rejects_plugin_fields() {
    // Given native JSON polluted with plugin fields
    let mut v = serde_json::to_value(SessionPinV1::Native(sample_native())).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("installReceiptDigest".into(), serde_json::json!(h(9)));
    let raw = serde_json::to_string(&v).unwrap();
    // When parsed
    let err = SessionPinV1::parse_json(&raw).unwrap_err();
    // Then refused
    assert!(matches!(err, LifecycleError::NativeHasPluginFields));
}

#[test]
fn external_creating_and_active_transitions_fields() {
    let creating = sample_external(ExternalPinState::Creating, None);
    assert!(creating.acp_session_id.is_none());
    let active = sample_external(ExternalPinState::Active, Some("acp-1"));
    assert_eq!(active.acp_session_id.as_deref(), Some("acp-1"));
    let raw = serde_json::to_string(&SessionPinV1::External(active)).unwrap();
    SessionPinV1::parse_json(&raw).unwrap();
}

#[test]
fn unknown_pin_discriminator_fails_closed() {
    let err = SessionPinV1::parse_json(r#"{"kind":"hybrid","schemaVersion":1}"#).unwrap_err();
    assert!(matches!(err, LifecycleError::UnknownDiscriminator(_)));
}

#[test]
fn host_is_sole_barrier_writer() {
    assert_host_barrier_writer(BarrierWriter::Host).unwrap();
    // Non-host cannot be constructed via public enum — only Host exists.
    // Transition path still checks writer field.
    let b = HostBarrierV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        install_receipt_digest: h(1),
        cohort_key: h(2),
        revision: 0,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Absent,
        barrier_digest: String::new(),
    }
    .seal()
    .unwrap();
    let open = b
        .transition(BarrierStateV1::Provisioning {
            provision_nonce: "0".repeat(32),
            epoch_candidate: 1,
            root_identity: None,
            store_identity: None,
        })
        .unwrap()
        .transition(BarrierStateV1::Open {
            root_generation: 1,
            root_identity: h(3),
            store_identity: h(4),
            provision_epoch: 1,
        })
        .unwrap();
    match open.body {
        BarrierStateV1::Open { .. } => {}
        other => panic!("expected Open, got {other:?}"),
    }
}

#[test]
fn open_barrier_rejects_null_identities() {
    let b = HostBarrierV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        install_receipt_digest: h(1),
        cohort_key: h(2),
        revision: 0,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Provisioning {
            provision_nonce: "0".repeat(32),
            epoch_candidate: 1,
            root_identity: None,
            store_identity: None,
        },
        barrier_digest: String::new(),
    }
    .seal()
    .unwrap();
    let err = b
        .transition(BarrierStateV1::Open {
            root_generation: 1,
            root_identity: String::new(),
            store_identity: h(4),
            provision_epoch: 1,
        })
        .unwrap_err();
    assert!(matches!(err, LifecycleError::NullOpenIdentity));
}

#[test]
fn illegal_barrier_transition_refused() {
    let b = HostBarrierV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        install_receipt_digest: h(1),
        cohort_key: h(2),
        revision: 0,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Absent,
        barrier_digest: String::new(),
    }
    .seal()
    .unwrap();
    let err = b
        .transition(BarrierStateV1::Open {
            root_generation: 1,
            root_identity: h(3),
            store_identity: h(4),
            provision_epoch: 1,
        })
        .unwrap_err();
    assert!(matches!(err, LifecycleError::IllegalBarrierTransition { .. }));
}

#[test]
fn purge_entry_order_enforced() {
    let good = sort_purge_entries(vec![
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec![],
            kind: EntryKind::Directory,
            expected_entry_identity_sha256: h(1),
            expected_parent_identity_sha256: h(2),
        },
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec!["data".into()],
            kind: EntryKind::Directory,
            expected_entry_identity_sha256: h(3),
            expected_parent_identity_sha256: h(1),
        },
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec!["data".into(), "state.sqlite".into()],
            kind: EntryKind::Regular,
            expected_entry_identity_sha256: h(4),
            expected_parent_identity_sha256: h(3),
        },
    ]);
    validate_entry_order(&good).unwrap();
    // Root last
    assert!(good.last().unwrap().relative_components.is_empty());
    // Bad: reverse order
    let mut bad = good.clone();
    bad.reverse();
    for (i, e) in bad.iter_mut().enumerate() {
        e.entry_index = i as u32;
    }
    assert!(validate_entry_order(&bad).is_err());
}

#[test]
fn deletion_intent_precedes_unlink_and_completion_precedes_advance() {
    // Given a deleting journal at Ready
    let j = PurgeJournalV1 {
        schema_version: 1,
        plan_digest: h(1),
        phase: PurgeJournalPhase::Deleting,
        arm_cursor: 1,
        fence_cursor: 1,
        member_cursor: 0,
        entry_cursor: 0,
        entry_phase: EntryPhase::Ready,
        intent_present: false,
        completion_present: false,
        journal_digest: String::new(),
    }
    .seal()
    .unwrap();

    // When advancing without intent/completion
    assert!(matches!(
        j.clone().advance_after_completion().unwrap_err(),
        LifecycleError::CompletionBeforeAdvance
    ));

    // When intent committed before unlink
    let j = j.commit_intent_before_unlink().unwrap();
    assert_eq!(j.entry_phase, EntryPhase::IntentCommitted);
    assert!(j.intent_present);

    // Double intent refused
    assert!(matches!(
        j.clone().commit_intent_before_unlink().unwrap_err(),
        LifecycleError::IntentBeforeUnlink
    ));

    // Observe deletion then complete then advance
    let j = j.observe_deletion().unwrap();
    assert!(matches!(
        j.clone().advance_after_completion().unwrap_err(),
        LifecycleError::CompletionBeforeAdvance
    ));
    let j = j.commit_completion().unwrap();
    let j = j.advance_after_completion().unwrap();
    assert_eq!(j.entry_cursor, 1);
    assert_eq!(j.entry_phase, EntryPhase::Ready);
    assert!(!j.intent_present);
}

#[test]
fn descriptor_identity_unix_validates() {
    let id = DescriptorIdentityV1 {
        schema: "descriptor-identity/v1".into(),
        platform: PlatformKind::Unix,
        kind: EntryKind::Directory,
        stable_object: StableObject::Unix {
            device_hex: "1a".into(),
            inode_hex: "2b".into(),
        },
        security: SecurityIdentity::Unix {
            uid_decimal: "501".into(),
            gid_decimal: "20".into(),
            mode_octal: "0755".into(),
            file_type: EntryKind::Directory,
        },
    };
    id.validate().unwrap();
    assert_eq!(id.identity_digest().unwrap().len(), 64);
}

#[test]
fn purge_plan_seals_with_ordered_members() {
    let entries = sort_purge_entries(vec![
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec!["f".into()],
            kind: EntryKind::Regular,
            expected_entry_identity_sha256: h(1),
            expected_parent_identity_sha256: h(2),
        },
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec![],
            kind: EntryKind::Directory,
            expected_entry_identity_sha256: h(2),
            expected_parent_identity_sha256: h(3),
        },
    ]);
    let plan = PurgePlanV1 {
        schema_version: 1,
        plan_id: "plan-1".into(),
        transaction_id: "tx-1".into(),
        plugin_id: "go-orca".into(),
        install_receipt_digest: h(4),
        members: vec![PurgeMemberV1 {
            cohort_key: h(5),
            lease_id: "lease-1".into(),
            daemon_epoch: 1,
            root_identity: h(6),
            store_identity: h(7),
            hold_revision: 0,
            entries,
        }],
        eligible_bytes: 10,
        created_at: "2026-08-03T00:00:00.000Z".into(),
        expires_at: "2026-08-03T00:10:00.000Z".into(),
        plan_digest: String::new(),
    }
    .seal()
    .unwrap();
    PurgePlanV1::parse_json(&serde_json::to_string(&plan).unwrap()).unwrap();
}

#[test]
fn rollback_and_gc_seal() {
    let rb = RollbackReceiptV1 {
        schema_version: 1,
        backend_id: "go-orca".into(),
        from_receipt_digest: h(1),
        to_receipt_digest: h(2),
        rolled_back_at: "t".into(),
        rollback_digest: String::new(),
    }
    .seal()
    .unwrap();
    assert_eq!(rb.rollback_digest.len(), 64);

    let gc = GcPlanV1 {
        schema_version: 1,
        plan_id: "gc-1".into(),
        candidates: vec![GcCandidateV1 {
            kind: GcCandidateKind::UnreferencedPayload,
            path_digest: h(3),
            bytes: 1,
        }],
        plan_digest: String::new(),
    }
    .seal()
    .unwrap();
    assert_eq!(gc.plan_digest.len(), 64);
}
