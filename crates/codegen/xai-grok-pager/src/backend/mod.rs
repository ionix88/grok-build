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
    format_list_status_json, load_user_default, parse_selector, persist_native_session_pin,
    persist_native_session_pin_best_effort, persist_native_session_pin_in, prepare_launch,
    prepare_launch_with_paths, resolve, run_backend_cli, set_user_default,
    try_run_from_args as try_run_backend_cli, BackendCliPaths, BackendSelector,
    LaunchBackendDecision, LaunchBackendRequest, LaunchMode, ResolvedBackend, SelectionError,
    SelectionInput, SelectionOrigin,
};
pub use session_pin::{ExternalActivateRequest, ExternalCreateRequest, PinStore, PinStoreError};
