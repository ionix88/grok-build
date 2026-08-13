//! Typed supervisor readiness boundary for external backends.
//!
//! Task 14 owns process/stdio details. This trait is the host-side readiness
//! seam used by connection construction after a Creating pin is persisted.

use thiserror::Error;

/// Identities returned once the external backend has finished provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorReady {
    pub root_identity: String,
    pub store_identity: String,
}

/// Fail-closed supervisor outcomes observed during provision/readiness.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    #[error("supervisor readiness timed out")]
    Timeout,
    #[error("supervisor rejected provisioning: {0}")]
    Rejected(String),
    #[error("supervisor crashed: {0}")]
    Crashed(String),
}

/// Host-owned readiness wait. Implementations may be fixture fakes or the
/// future process supervisor (Task 14+); connection construction only needs
/// this contract.
pub trait Supervisor {
    fn await_ready(&mut self) -> Result<SupervisorReady, SupervisorError>;
}
