//! Backend connection construction shared by interactive and headless launchers.
//!
//! Selection (Task 12) runs first. This module is the single factory both the
//! TUI and `-p` headless path call before backend-specific auth. Native stays
//! transport-free. External orchestration persists a Creating pin, validates
//! receipt/cohort, awaits supervisor readiness, seals a concrete Open barrier,
//! then invokes a generic transport seam (Task 14 owns stdio/process details).
//!
//! // allow: SIZE_OK — plan Task 13 freezes the shared factory in one module

use crate::backend::registry::BackendKind;
use crate::backend::selection::ResolvedBackend;
use crate::backend::session_pin::{ExternalCreateRequest, PinStore, PinStoreError};
use crate::plugin_host::lifecycle::{
    BarrierStateV1, BarrierWriter, ExternalPinState, HostBarrierV1, SessionPinV1,
};
use crate::plugin_host::{
    BarrierError, BarrierStore, Supervisor, SupervisorError, assert_open_matches_pin,
    mark_provision_failed, open_after_ready, require_open,
};
use thiserror::Error;

/// Ordered lifecycle events recorded by tests (and optional production tracing).
pub mod events {
    pub const NATIVE_SELECTED: &str = "native_selected";
    pub const EXTERNAL_SELECTED: &str = "external_selected";
    pub const PIN_CREATING: &str = "pin_creating";
    pub const RECEIPT_VALIDATED: &str = "receipt_validated";
    pub const PROVISION_STARTED: &str = "provision_started";
    pub const SUPERVISOR_READY: &str = "supervisor_ready";
    pub const BARRIER_OPEN_PERSISTED: &str = "barrier_open_persisted";
    pub const TRANSPORT_DISPATCH: &str = "transport_dispatch";
    /// Recorded by launchers after `construct` returns and before auth — tests
    /// assert this never appears in the connection ledger itself.
    pub const AUTH_BEGIN: &str = "auth_begin";
}

/// Append-only ledger used to prove connection step ordering.
pub trait ConnectionLedger {
    fn record(&mut self, event: &'static str);
}

impl ConnectionLedger for () {
    fn record(&mut self, _event: &'static str) {}
}

impl ConnectionLedger for Vec<&'static str> {
    fn record(&mut self, event: &'static str) {
        self.push(event);
    }
}

/// A typed external transport boundary. Task 14 provides the stdio implementation.
pub trait ExternalBackendTransport {
    type Connection;
    type Error: std::error::Error + Send + Sync + 'static;

    fn dispatch(&mut self, backend: &ResolvedBackend) -> Result<Self::Connection, Self::Error>;
}

/// The selected connection origin, before ACP-specific authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendConnection<C> {
    Native,
    External(C),
}

/// Inputs for first-start external session construction (pre-bridge dispatch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalConnectionRequest {
    pub host_session_id: String,
    pub creation_key: String,
    pub request_digest: String,
    pub cohort_key: String,
    pub extension_schema_digest: String,
    pub renderer_contract_version: String,
}

/// Host-owned deps required to open an external backend connection.
pub struct ExternalOrchestration<'a, S> {
    pub pins: &'a PinStore,
    pub barriers: &'a BarrierStore,
    pub supervisor: &'a mut S,
    pub request: &'a ExternalConnectionRequest,
}

#[derive(Debug, Error)]
#[error("external backend transport is not installed")]
pub struct ExternalTransportUnavailable;

/// Placeholder transport until Task 14 wires verified stdio.
pub struct UnavailableExternalTransport;

impl ExternalBackendTransport for UnavailableExternalTransport {
    type Connection = ();
    type Error = ExternalTransportUnavailable;

    fn dispatch(&mut self, _backend: &ResolvedBackend) -> Result<Self::Connection, Self::Error> {
        Err(ExternalTransportUnavailable)
    }
}

/// Errors from the unified connection factory.
#[derive(Debug, Error)]
pub enum ConnectionError<E: std::error::Error + Send + Sync + 'static> {
    #[error("external backend requires pin/barrier orchestration before transport")]
    ExternalRequiresOrchestration,
    #[error(transparent)]
    External(#[from] ExternalConnectionError<E>),
}

/// Errors specific to the external orchestration path.
#[derive(Debug, Error)]
pub enum ExternalConnectionError<E: std::error::Error + Send + Sync + 'static> {
    #[error("external backend is missing a sealed receipt")]
    MissingReceipt,
    #[error("stale receipt or cohort: {0}")]
    Stale(String),
    #[error("external session pin: {0}")]
    Pin(String),
    #[error(transparent)]
    Barrier(#[from] BarrierError),
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
    #[error("external transport: {0}")]
    Transport(E),
}

impl<E: std::error::Error + Send + Sync + 'static> From<PinStoreError>
    for ExternalConnectionError<E>
{
    fn from(e: PinStoreError) -> Self {
        match e {
            PinStoreError::Stale(s) | PinStoreError::MissingReceipt(s) => Self::Stale(s),
            other => Self::Pin(other.to_string()),
        }
    }
}

/// Unified factory used by interactive and headless launchers after selection
/// and before backend-specific auth.
///
/// - Native: transport-free, returns [`BackendConnection::Native`].
/// - External without orchestration: fail-closed (no bare dispatch).
/// - External with orchestration: Creating pin → validate → provision → Open
///   barrier → generic transport seam.
pub fn construct<T: ExternalBackendTransport>(
    backend: &ResolvedBackend,
    transport: &mut T,
) -> Result<BackendConnection<T::Connection>, ConnectionError<T::Error>> {
    construct_with(
        backend,
        None::<ExternalOrchestration<'_, ReadyNever>>,
        transport,
        &mut (),
    )
}

/// Same factory with an explicit ledger (tests prove ordering).
pub fn construct_with<T, S, L>(
    backend: &ResolvedBackend,
    external: Option<ExternalOrchestration<'_, S>>,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    S: Supervisor,
    L: ConnectionLedger,
{
    match backend.kind {
        BackendKind::Native => {
            ledger.record(events::NATIVE_SELECTED);
            Ok(BackendConnection::Native)
        }
        BackendKind::External => {
            ledger.record(events::EXTERNAL_SELECTED);
            let Some(orch) = external else {
                return Err(ConnectionError::ExternalRequiresOrchestration);
            };
            connect_external(backend, orch, transport, ledger).map_err(ConnectionError::External)
        }
    }
}

/// External-only orchestration entry (first-start or resume/Open).
pub fn connect_external<T, S, L>(
    backend: &ResolvedBackend,
    orch: ExternalOrchestration<'_, S>,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ExternalConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    S: Supervisor,
    L: ConnectionLedger,
{
    let receipt = backend
        .receipt_digest
        .as_deref()
        .ok_or(ExternalConnectionError::MissingReceipt)?;
    let req = orch.request;

    // Resume path: existing pin decides Creating replay vs Active Open.
    if let Some(existing) = orch
        .pins
        .load(&req.host_session_id)
        .map_err(|e| ExternalConnectionError::Pin(e.to_string()))?
    {
        return resume_external(backend, receipt, existing, orch, transport, ledger);
    }

    first_start_external(backend, receipt, orch, transport, ledger)
}

fn first_start_external<T, S, L>(
    backend: &ResolvedBackend,
    receipt: &str,
    orch: ExternalOrchestration<'_, S>,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ExternalConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    S: Supervisor,
    L: ConnectionLedger,
{
    let req = orch.request;
    // Crash-safe order: persist Creating pin before receipt/cohort validation
    // and before any provision/supervisor/transport side effects.
    orch.pins
        .begin_external_create(&ExternalCreateRequest {
            host_session_id: req.host_session_id.clone(),
            creation_key: req.creation_key.clone(),
            request_digest: req.request_digest.clone(),
            backend_id: backend.backend_id.clone(),
            install_receipt_digest: receipt.into(),
            cohort_key: req.cohort_key.clone(),
            extension_schema_digest: req.extension_schema_digest.clone(),
            renderer_contract_version: req.renderer_contract_version.clone(),
        })
        .map_err(ExternalConnectionError::from)?;
    ledger.record(events::PIN_CREATING);

    validate_receipt_cohort(backend, receipt, &req.cohort_key)?;
    ledger.record(events::RECEIPT_VALIDATED);

    provision_open_dispatch(
        backend,
        receipt,
        &req.cohort_key,
        &req.creation_key,
        orch,
        transport,
        ledger,
    )
}

fn resume_external<T, S, L>(
    backend: &ResolvedBackend,
    receipt: &str,
    existing: SessionPinV1,
    orch: ExternalOrchestration<'_, S>,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ExternalConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    S: Supervisor,
    L: ConnectionLedger,
{
    let req = orch.request;
    let SessionPinV1::External(pin) = existing else {
        return Err(ExternalConnectionError::Pin(
            "native pin blocks external connect".into(),
        ));
    };

    if pin.backend_id != backend.backend_id {
        return Err(ExternalConnectionError::Stale(format!(
            "pin backend {} != selected {}",
            pin.backend_id, backend.backend_id
        )));
    }
    if pin.install_receipt_digest != receipt || pin.cohort_key != req.cohort_key {
        return Err(ExternalConnectionError::Stale(format!(
            "pin receipt/cohort mismatch for {}",
            pin.host_session_id
        )));
    }

    match pin.state {
        ExternalPinState::Active => {
            orch.pins
                .assert_active_identity_stable(&pin.host_session_id, receipt, &req.cohort_key)
                .map_err(ExternalConnectionError::from)?;
            ledger.record(events::RECEIPT_VALIDATED);
            // Prefer a persisted Open barrier; otherwise re-provision.
            if let Some(barrier) = orch
                .barriers
                .load(&backend.backend_id, &req.cohort_key)
                .map_err(ExternalConnectionError::from)?
            {
                assert_open_matches_pin(&barrier, &backend.backend_id, receipt, &req.cohort_key)
                    .map_err(ExternalConnectionError::from)?;
                let open = require_open(barrier).map_err(ExternalConnectionError::from)?;
                let _ = open;
                ledger.record(events::BARRIER_OPEN_PERSISTED);
                return dispatch_transport(backend, transport, ledger);
            }
            provision_open_dispatch(
                backend,
                receipt,
                &req.cohort_key,
                &pin.creation_key,
                orch,
                transport,
                ledger,
            )
        }
        ExternalPinState::Creating => {
            // Idempotent Creating replay before re-validating receipt/cohort.
            let _ = orch
                .pins
                .begin_external_create(&ExternalCreateRequest {
                    host_session_id: req.host_session_id.clone(),
                    creation_key: req.creation_key.clone(),
                    request_digest: req.request_digest.clone(),
                    backend_id: backend.backend_id.clone(),
                    install_receipt_digest: receipt.into(),
                    cohort_key: req.cohort_key.clone(),
                    extension_schema_digest: req.extension_schema_digest.clone(),
                    renderer_contract_version: req.renderer_contract_version.clone(),
                })
                .map_err(ExternalConnectionError::from)?;
            ledger.record(events::PIN_CREATING);
            ledger.record(events::RECEIPT_VALIDATED);
            provision_open_dispatch(
                backend,
                receipt,
                &req.cohort_key,
                &req.creation_key,
                orch,
                transport,
                ledger,
            )
        }
    }
}

fn provision_open_dispatch<T, S, L>(
    backend: &ResolvedBackend,
    receipt: &str,
    cohort_key: &str,
    provision_nonce: &str,
    orch: ExternalOrchestration<'_, S>,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ExternalConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    S: Supervisor,
    L: ConnectionLedger,
{
    let provisioning = HostBarrierV1 {
        schema_version: 1,
        plugin_id: backend.backend_id.clone(),
        install_receipt_digest: receipt.into(),
        cohort_key: cohort_key.into(),
        revision: 0,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Provisioning {
            provision_nonce: provision_nonce.into(),
            epoch_candidate: 1,
            root_identity: None,
            store_identity: None,
        },
        barrier_digest: String::new(),
    }
    .seal()
    .map_err(BarrierError::from)
    .map_err(ExternalConnectionError::from)?;
    orch.barriers
        .persist(&provisioning)
        .map_err(ExternalConnectionError::from)?;
    ledger.record(events::PROVISION_STARTED);

    let ready = match orch.supervisor.await_ready() {
        Ok(ready) => ready,
        Err(err) => {
            let code = match &err {
                SupervisorError::Timeout => "TIMEOUT",
                SupervisorError::Rejected(_) => "REJECTED",
                SupervisorError::Crashed(_) => "CRASHED",
            };
            if let Ok(failed) = mark_provision_failed(provisioning, code) {
                let _ = orch.barriers.persist(&failed);
            }
            return Err(ExternalConnectionError::Supervisor(err));
        }
    };
    ledger.record(events::SUPERVISOR_READY);

    let open = open_after_ready(provisioning, ready).map_err(ExternalConnectionError::from)?;
    assert_open_matches_pin(&open, &backend.backend_id, receipt, cohort_key)
        .map_err(ExternalConnectionError::from)?;
    orch.barriers
        .persist(&open)
        .map_err(ExternalConnectionError::from)?;
    ledger.record(events::BARRIER_OPEN_PERSISTED);

    dispatch_transport(backend, transport, ledger)
}

fn dispatch_transport<T, L>(
    backend: &ResolvedBackend,
    transport: &mut T,
    ledger: &mut L,
) -> Result<BackendConnection<T::Connection>, ExternalConnectionError<T::Error>>
where
    T: ExternalBackendTransport,
    L: ConnectionLedger,
{
    let conn = transport
        .dispatch(backend)
        .map_err(ExternalConnectionError::Transport)?;
    ledger.record(events::TRANSPORT_DISPATCH);
    Ok(BackendConnection::External(conn))
}

fn validate_receipt_cohort<E>(
    backend: &ResolvedBackend,
    receipt: &str,
    cohort_key: &str,
) -> Result<(), ExternalConnectionError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if backend.backend_id == "native" {
        return Err(ExternalConnectionError::Stale(
            "external connect cannot use backendId=native".into(),
        ));
    }
    if receipt.len() != 64 || !receipt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ExternalConnectionError::Stale(format!(
            "invalid receipt digest length/charset"
        )));
    }
    if cohort_key.len() != 64 || !cohort_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ExternalConnectionError::Stale(format!(
            "invalid cohort key length/charset"
        )));
    }
    if let Some(pin_receipt) = backend.receipt_digest.as_deref() {
        if pin_receipt != receipt {
            return Err(ExternalConnectionError::Stale(
                "resolved receipt drifted from connect receipt".into(),
            ));
        }
    }
    Ok(())
}

/// Supervisor stub used only as a type parameter when orchestration is absent.
struct ReadyNever;

impl Supervisor for ReadyNever {
    fn await_ready(&mut self) -> Result<crate::plugin_host::SupervisorReady, SupervisorError> {
        Err(SupervisorError::Crashed("ReadyNever".into()))
    }
}
