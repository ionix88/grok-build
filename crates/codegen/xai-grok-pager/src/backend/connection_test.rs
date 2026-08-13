//! Given/When/Then tests for the shared backend connection factory.
//!
//! Task-7 lifecycle fixtures back happy/failure paths. An event ledger proves
//! selection and pin/barrier steps precede transport; auth is never inside the
//! connection ledger.

use super::connection::{
    connect_external, construct, construct_with, events, BackendConnection, ConnectionError,
    ConnectionLedger, ExternalBackendTransport, ExternalConnectionError, ExternalConnectionRequest,
    ExternalOrchestration, UnavailableExternalTransport,
};
use super::{BackendKind, ExternalActivateRequest, PinStore, ResolvedBackend, SelectionOrigin};
use crate::plugin_host::lifecycle::{
    BarrierStateV1, BarrierWriter, ExternalPinState, HostBarrierV1, SessionPinV1,
};
use crate::plugin_host::{BarrierStore, Supervisor, SupervisorError, SupervisorReady};

fn h(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn key() -> String {
    "0123456789abcdef0123456789abcdef".into()
}

fn fixture_receipt() -> String {
    // Matches plugin_host/fixtures/install-receipt.json receiptDigest.
    "fd289aa1458324082cfac42747b709a263a11e5a159db751df76eb3edfb62cb4".into()
}

fn fixture_cohort() -> String {
    // Matches session-pin-external-*.json cohortKey.
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into()
}

fn fixture_root() -> String {
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into()
}

fn fixture_store() -> String {
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into()
}

#[derive(Debug)]
struct FixtureError;

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("fixture error")
    }
}

impl std::error::Error for FixtureError {}

struct LedgerTransport {
    dispatches: u32,
}

impl ExternalBackendTransport for LedgerTransport {
    type Connection = &'static str;
    type Error = FixtureError;

    fn dispatch(&mut self, _backend: &ResolvedBackend) -> Result<Self::Connection, Self::Error> {
        self.dispatches += 1;
        Ok("fixture-external")
    }
}

struct ReadySupervisor {
    ready: Result<SupervisorReady, SupervisorError>,
}

impl Supervisor for ReadySupervisor {
    fn await_ready(&mut self) -> Result<SupervisorReady, SupervisorError> {
        self.ready.clone()
    }
}

fn native() -> ResolvedBackend {
    ResolvedBackend {
        backend_id: "native".into(),
        version: None,
        kind: BackendKind::Native,
        origin: SelectionOrigin::NativeBuiltin,
        receipt_digest: None,
        pin: None,
        warning: None,
        native_start: true,
    }
}

fn external_backend(receipt: &str) -> ResolvedBackend {
    ResolvedBackend {
        backend_id: "go-orca".into(),
        version: Some("1.0.0".into()),
        kind: BackendKind::External,
        origin: SelectionOrigin::SessionPin,
        receipt_digest: Some(receipt.into()),
        pin: None,
        warning: None,
        native_start: false,
    }
}

fn ext_req(host: &str) -> ExternalConnectionRequest {
    ExternalConnectionRequest {
        host_session_id: host.into(),
        creation_key: key(),
        request_digest: h(0xa),
        cohort_key: fixture_cohort(),
        extension_schema_digest: h(0xe),
        renderer_contract_version: "1.0.0".into(),
    }
}

fn stores() -> (tempfile::TempDir, PinStore, BarrierStore) {
    let tmp = tempfile::TempDir::new().unwrap();
    let pins = PinStore::open(tmp.path().join("session-pins")).unwrap();
    let barriers = BarrierStore::open(tmp.path().join("barriers")).unwrap();
    (tmp, pins, barriers)
}

fn ready_ok() -> ReadySupervisor {
    ReadySupervisor {
        ready: Ok(SupervisorReady {
            root_identity: fixture_root(),
            store_identity: fixture_store(),
        }),
    }
}

#[test]
fn native_connection_when_selected_preserves_native_branch() {
    // Given: the native backend selected by Task 12.
    let mut transport = LedgerTransport { dispatches: 0 };
    let mut ledger = Vec::new();
    // When: both launch modes ask the factory for a connection.
    let connection = construct_with(
        &native(),
        None::<ExternalOrchestration<'_, ReadySupervisor>>,
        &mut transport,
        &mut ledger,
    )
    .unwrap();
    // Then: the native branch remains transport-free.
    assert_eq!(connection, BackendConnection::Native);
    assert_eq!(transport.dispatches, 0);
    assert_eq!(ledger, vec![events::NATIVE_SELECTED]);
}

#[test]
fn external_without_orchestration_refuses_bare_dispatch() {
    // Given: external selection and no pin/barrier orchestration.
    let mut transport = UnavailableExternalTransport;
    // When: the thin factory is used (TUI/headless until composition wires orch).
    let err = construct(&external_backend(&fixture_receipt()), &mut transport).unwrap_err();
    // Then: no transport dispatch; orchestration is required.
    assert!(matches!(
        err,
        ConnectionError::ExternalRequiresOrchestration
    ));
}

#[test]
fn first_start_provisions_persists_open_then_dispatches() {
    // Given: empty pin/barrier stores and a ready supervisor (Task-7 identities).
    let (_tmp, pins, barriers) = stores();
    let receipt = fixture_receipt();
    let backend = external_backend(&receipt);
    let req = ext_req("host-first");
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    let mut ledger = Vec::new();
    let orch = ExternalOrchestration {
        pins: &pins,
        barriers: &barriers,
        supervisor: &mut supervisor,
        request: &req,
    };
    // When: first-start external connection construction runs.
    let connection = connect_external(&backend, orch, &mut transport, &mut ledger).unwrap();
    // Then: Creating pin + sealed Open barrier + single transport dispatch, in order.
    assert_eq!(connection, BackendConnection::External("fixture-external"));
    assert_eq!(transport.dispatches, 1);
    assert_eq!(
        ledger,
        vec![
            events::PIN_CREATING,
            events::RECEIPT_VALIDATED,
            events::PROVISION_STARTED,
            events::SUPERVISOR_READY,
            events::BARRIER_OPEN_PERSISTED,
            events::TRANSPORT_DISPATCH,
        ]
    );
    let pin_idx = ledger
        .iter()
        .position(|e| *e == events::PIN_CREATING)
        .unwrap();
    let receipt_idx = ledger
        .iter()
        .position(|e| *e == events::RECEIPT_VALIDATED)
        .unwrap();
    assert!(
        pin_idx < receipt_idx,
        "Creating pin must precede receipt validation"
    );
    let pin = pins.load_required("host-first").unwrap();
    match pin {
        SessionPinV1::External(p) => {
            assert_eq!(p.state, ExternalPinState::Creating);
            assert_eq!(p.install_receipt_digest, receipt);
            assert!(p.acp_session_id.is_none());
        }
        SessionPinV1::Native(_) => panic!("expected external pin"),
    }
    let barrier = barriers
        .load("go-orca", &fixture_cohort())
        .unwrap()
        .unwrap();
    match &barrier.body {
        BarrierStateV1::Open {
            root_identity,
            store_identity,
            ..
        } => {
            assert_eq!(root_identity, &fixture_root());
            assert_eq!(store_identity, &fixture_store());
        }
        other => panic!("expected Open barrier, got {other:?}"),
    }
    // Auth is outside connection construction.
    assert!(!ledger.contains(&events::AUTH_BEGIN));
}

#[test]
fn resume_active_with_open_barrier_dispatches_without_reprovision() {
    // Given: Task-7 fixture Active pin + Open barrier on disk.
    let (_tmp, pins, barriers) = stores();
    let receipt = fixture_receipt();
    let backend = external_backend(&receipt);
    let req = ExternalConnectionRequest {
        host_session_id: "host-sess-2".into(),
        creation_key: "00000000000000000000000000000000".into(),
        request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        cohort_key: fixture_cohort(),
        extension_schema_digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .into(),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&crate::backend::ExternalCreateRequest {
        host_session_id: req.host_session_id.clone(),
        creation_key: req.creation_key.clone(),
        request_digest: req.request_digest.clone(),
        backend_id: backend.backend_id.clone(),
        install_receipt_digest: receipt.clone(),
        cohort_key: req.cohort_key.clone(),
        extension_schema_digest: req.extension_schema_digest.clone(),
        renderer_contract_version: req.renderer_contract_version.clone(),
    })
    .unwrap();
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: req.host_session_id.clone(),
        acp_session_id: "acp-session-2".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .unwrap();
    let open = HostBarrierV1 {
        schema_version: 1,
        plugin_id: backend.backend_id.clone(),
        install_receipt_digest: receipt,
        cohort_key: req.cohort_key.clone(),
        revision: 1,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Open {
            root_generation: 1,
            root_identity: fixture_root(),
            store_identity: fixture_store(),
            provision_epoch: 1,
        },
        barrier_digest: String::new(),
    }
    .seal()
    .unwrap();
    barriers.persist(&open).unwrap();
    let mut supervisor = ReadySupervisor {
        ready: Err(SupervisorError::Crashed(
            "must not await on resume-open".into(),
        )),
    };
    let mut transport = LedgerTransport { dispatches: 0 };
    let mut ledger = Vec::new();
    let orch = ExternalOrchestration {
        pins: &pins,
        barriers: &barriers,
        supervisor: &mut supervisor,
        request: &req,
    };
    // When: resume with Active pin and Open barrier.
    let connection = connect_external(&backend, orch, &mut transport, &mut ledger).unwrap();
    // Then: dispatch without re-entering provision/supervisor.
    assert_eq!(connection, BackendConnection::External("fixture-external"));
    assert_eq!(transport.dispatches, 1);
    assert!(!ledger.contains(&events::PROVISION_STARTED));
    assert!(!ledger.contains(&events::SUPERVISOR_READY));
    assert!(ledger.contains(&events::BARRIER_OPEN_PERSISTED));
    assert!(ledger.contains(&events::TRANSPORT_DISPATCH));
}

#[test]
fn provision_rejection_persists_failed_and_skips_transport() {
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ext_req("host-rej");
    let mut supervisor = ReadySupervisor {
        ready: Err(SupervisorError::Rejected("ROOT_EXISTS".into())),
    };
    let mut transport = LedgerTransport { dispatches: 0 };
    let mut ledger = Vec::new();
    let orch = ExternalOrchestration {
        pins: &pins,
        barriers: &barriers,
        supervisor: &mut supervisor,
        request: &req,
    };
    let err = connect_external(&backend, orch, &mut transport, &mut ledger).unwrap_err();
    assert!(matches!(
        err,
        ExternalConnectionError::Supervisor(SupervisorError::Rejected(_))
    ));
    assert_eq!(transport.dispatches, 0);
    assert!(!ledger.contains(&events::TRANSPORT_DISPATCH));
    let barrier = barriers
        .load("go-orca", &fixture_cohort())
        .unwrap()
        .unwrap();
    assert!(matches!(
        barrier.body,
        BarrierStateV1::ProvisionFailed { .. }
    ));
    // Creating pin remains for crash-safe replay.
    let pin = pins.load_required("host-rej").unwrap();
    match pin {
        SessionPinV1::External(p) => assert_eq!(p.state, ExternalPinState::Creating),
        SessionPinV1::Native(_) => panic!("expected external"),
    }
}

#[test]
fn provision_crash_skips_transport() {
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ext_req("host-crash");
    let mut supervisor = ReadySupervisor {
        ready: Err(SupervisorError::Crashed("segfault".into())),
    };
    let mut transport = LedgerTransport { dispatches: 0 };
    let err = connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExternalConnectionError::Supervisor(SupervisorError::Crashed(_))
    ));
    assert_eq!(transport.dispatches, 0);
}

#[test]
fn supervisor_timeout_skips_transport() {
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ext_req("host-to");
    let mut supervisor = ReadySupervisor {
        ready: Err(SupervisorError::Timeout),
    };
    let mut transport = LedgerTransport { dispatches: 0 };
    let err = connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExternalConnectionError::Supervisor(SupervisorError::Timeout)
    ));
    assert_eq!(transport.dispatches, 0);
}

#[test]
fn stale_receipt_refused_before_transport() {
    let (_tmp, pins, barriers) = stores();
    // Pin with fixture receipt; connect with a different receipt.
    let mut req = ext_req("host-stale");
    req.cohort_key = fixture_cohort();
    pins.begin_external_create(&crate::backend::ExternalCreateRequest {
        host_session_id: req.host_session_id.clone(),
        creation_key: req.creation_key.clone(),
        request_digest: req.request_digest.clone(),
        backend_id: "go-orca".into(),
        install_receipt_digest: fixture_receipt(),
        cohort_key: fixture_cohort(),
        extension_schema_digest: req.extension_schema_digest.clone(),
        renderer_contract_version: req.renderer_contract_version.clone(),
    })
    .unwrap();
    let backend = external_backend(&h(1)); // different receipt
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    let err = connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalConnectionError::Stale(_)), "{err:?}");
    assert_eq!(transport.dispatches, 0);
}

#[test]
fn barrier_drift_refused_on_resume() {
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ExternalConnectionRequest {
        host_session_id: "host-sess-2".into(),
        creation_key: "00000000000000000000000000000000".into(),
        request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        cohort_key: fixture_cohort(),
        extension_schema_digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .into(),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&crate::backend::ExternalCreateRequest {
        host_session_id: req.host_session_id.clone(),
        creation_key: req.creation_key.clone(),
        request_digest: req.request_digest.clone(),
        backend_id: backend.backend_id.clone(),
        install_receipt_digest: fixture_receipt(),
        cohort_key: req.cohort_key.clone(),
        extension_schema_digest: req.extension_schema_digest.clone(),
        renderer_contract_version: req.renderer_contract_version.clone(),
    })
    .unwrap();
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: req.host_session_id.clone(),
        acp_session_id: "acp-session-2".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .unwrap();
    // Given an Open barrier that loads under the pin cohort but has a drifted receipt.
    let drifted_receipt = HostBarrierV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        install_receipt_digest: h(2), // drift vs pin
        cohort_key: fixture_cohort(),
        revision: 1,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Open {
            root_generation: 1,
            root_identity: fixture_root(),
            store_identity: fixture_store(),
            provision_epoch: 1,
        },
        barrier_digest: String::new(),
    }
    .seal()
    .unwrap();
    barriers.persist(&drifted_receipt).unwrap();
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    let err = connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap_err();
    assert!(
        matches!(err, ExternalConnectionError::Barrier(_)),
        "{err:?}"
    );
    assert_eq!(transport.dispatches, 0);
}

#[test]
fn missing_receipt_refused() {
    let (_tmp, pins, barriers) = stores();
    let mut backend = external_backend(&fixture_receipt());
    backend.receipt_digest = None;
    let req = ext_req("host-miss");
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    let err = connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalConnectionError::MissingReceipt));
    assert_eq!(transport.dispatches, 0);
}

#[test]
fn construct_with_orchestration_records_selection_before_transport() {
    // Given: external selection + full orchestration (simulates composed launcher).
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ext_req("host-ord");
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    let mut ledger = Vec::new();
    // When: unified factory runs with orchestration.
    let connection = construct_with(
        &backend,
        Some(ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        }),
        &mut transport,
        &mut ledger,
    )
    .unwrap();
    // Then: selection is first; transport last; auth never in ledger.
    assert_eq!(connection, BackendConnection::External("fixture-external"));
    assert_eq!(ledger.first().copied(), Some(events::EXTERNAL_SELECTED));
    assert_eq!(ledger.last().copied(), Some(events::TRANSPORT_DISPATCH));
    let transport_idx = ledger
        .iter()
        .position(|e| *e == events::TRANSPORT_DISPATCH)
        .unwrap();
    let pin_idx = ledger
        .iter()
        .position(|e| *e == events::PIN_CREATING)
        .unwrap();
    let receipt_idx = ledger
        .iter()
        .position(|e| *e == events::RECEIPT_VALIDATED)
        .unwrap();
    let open_idx = ledger
        .iter()
        .position(|e| *e == events::BARRIER_OPEN_PERSISTED)
        .unwrap();
    assert!(pin_idx < receipt_idx, "pin before receipt validation");
    assert!(receipt_idx < open_idx && open_idx < transport_idx);
    assert!(!ledger.contains(&events::AUTH_BEGIN));
}

#[test]
fn interactive_and_headless_share_native_construct_contract() {
    // Given: the same native ResolvedBackend both launchers receive after prepare_launch.
    let backend = native();
    let mut tui_transport = UnavailableExternalTransport;
    let mut headless_transport = UnavailableExternalTransport;
    let mut tui_ledger = Vec::new();
    let mut headless_ledger = Vec::new();
    // When: interactive and headless both call the shared factory.
    let tui = construct_with(
        &backend,
        None::<ExternalOrchestration<'_, ReadySupervisor>>,
        &mut tui_transport,
        &mut tui_ledger,
    )
    .unwrap();
    let headless = construct_with(
        &backend,
        None::<ExternalOrchestration<'_, ReadySupervisor>>,
        &mut headless_transport,
        &mut headless_ledger,
    )
    .unwrap();
    // Then: both stay native, transport-free, and ledger-identical.
    assert_eq!(tui, BackendConnection::Native);
    assert_eq!(headless, BackendConnection::Native);
    assert_eq!(tui_ledger, headless_ledger);
    assert_eq!(tui_ledger, vec![events::NATIVE_SELECTED]);
}

#[test]
fn selection_precedes_backend_auth_in_launcher_contract() {
    // Given: native construct completes (launcher would then auth).
    let mut transport = UnavailableExternalTransport;
    let mut ledger = Vec::new();
    let _ = construct_with(
        &native(),
        None::<ExternalOrchestration<'_, ReadySupervisor>>,
        &mut transport,
        &mut ledger,
    )
    .unwrap();
    // When: launcher records auth only after construct (contract under test).
    ledger.record(events::AUTH_BEGIN);
    // Then: selection is strictly before auth.
    assert_eq!(ledger, vec![events::NATIVE_SELECTED, events::AUTH_BEGIN]);
}

#[test]
fn activate_after_connect_is_separate_from_transport() {
    // Pin stays Creating through connect; Active is a later ACP step (Task 12).
    let (_tmp, pins, barriers) = stores();
    let backend = external_backend(&fixture_receipt());
    let req = ext_req("host-act");
    let mut supervisor = ready_ok();
    let mut transport = LedgerTransport { dispatches: 0 };
    connect_external(
        &backend,
        ExternalOrchestration {
            pins: &pins,
            barriers: &barriers,
            supervisor: &mut supervisor,
            request: &req,
        },
        &mut transport,
        &mut (),
    )
    .unwrap();
    let before = pins.load_required("host-act").unwrap();
    match before {
        SessionPinV1::External(p) => assert_eq!(p.state, ExternalPinState::Creating),
        SessionPinV1::Native(_) => panic!("external"),
    }
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: "host-act".into(),
        acp_session_id: "acp-99".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .unwrap();
    let after = pins.load_required("host-act").unwrap();
    match after {
        SessionPinV1::External(p) => {
            assert_eq!(p.state, ExternalPinState::Active);
            assert_eq!(p.acp_session_id.as_deref(), Some("acp-99"));
        }
        SessionPinV1::Native(_) => panic!("external"),
    }
}
