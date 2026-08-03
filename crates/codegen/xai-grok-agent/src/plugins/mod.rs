//! Plugin system — discover, load, and manage plugins (including compat layouts).
//!
//! A plugin is a self-contained directory that bundles skills, agents,
//! MCP server configs, and hooks into a namespaced unit.  Plugins can
//! live under `~/.grok/plugins/`, `.grok/plugins/` (project-level),
//! or be passed via `--plugin-dir` on the CLI.
//!
//! This module handles:
//! - `manifest` — parsing `plugin.json` manifests
//! - `discovery` — scanning the filesystem for plugin directories
//! - `trust` — project-plugin trust management
//! - `registry` — in-memory registry of active plugins

pub mod agent_backend;
pub mod discovery;
pub mod git_install;
pub mod hooks_adapter;
pub mod install_registry;
pub mod local_refresh;
pub mod manifest;
pub mod marketplace;
pub mod registry;
pub mod trust;

pub use agent_backend::{
    AgentBackendError, AgentBackendV1, HostPlatform, NativeBackendSource, ResolveContext,
    ResolvedArgv, host_platform_label, normalize_arch, normalize_os, parse_agent_backend,
    parse_target_label, refuse_native_backend_source, resolve_argv, select_target,
    target_matches_host, validate_backends,
};
pub use discovery::{
    DiscoveredPlugin, PluginOrigin, PluginScope,
    content_plugins_exclude_native_backend_registration, discover_plugins, project_plugin_dirs,
    project_plugin_dirs_in, refuse_backend_registration_from_content_plugin,
};
pub use hooks_adapter::parse_plugin_hooks;
pub use install_registry::InstallRegistry;
pub use manifest::PluginManifest;
pub use registry::{LoadedPlugin, PluginRegistry, SharedPluginRegistryHandle};
pub use trust::TrustStore;
