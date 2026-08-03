//! Host backend discovery and selection surface.
//!
//! Task 11 owns the installed-backend registry. Later tasks add selection,
//! connection construction, and external stdio transport under this module.

pub mod registry;

pub use registry::{
    BackendConflict, BackendDescriptor, BackendKind, BackendRegistry, BackendRegistryError,
    Compatibility, DiscoverOpts, Enablement, HealthStatus, NATIVE_BACKEND_ID, NATIVE_SOURCE,
};
