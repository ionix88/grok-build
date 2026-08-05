//! Host backend discovery and selection surface.
//!
//! Task 11: installed-backend registry.
//! Task 12: `--backend`, defaults, immutable session pins.

pub mod registry;
pub mod selection;
pub mod session_pin;

pub use registry::{
    BackendConflict, BackendDescriptor, BackendKind, BackendRegistry, BackendRegistryError,
    Compatibility, DiscoverOpts, Enablement, HealthStatus, NATIVE_BACKEND_ID, NATIVE_SOURCE,
};
pub use selection::{
    BackendCliPaths, BackendSelector, LaunchMode, ResolvedBackend, SelectionError, SelectionInput,
    SelectionOrigin, load_user_default, parse_selector, resolve, run_backend_cli, set_user_default,
    try_run_from_args as try_run_backend_cli,
};
pub use session_pin::{ExternalActivateRequest, ExternalCreateRequest, PinStore, PinStoreError};
