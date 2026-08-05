//! Backend selection: `--backend`, defaults, pin precedence, CLI commands.
//!
//! // allow: SIZE_OK — plan Task 12 freezes selection + backend CLI in one module

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::registry::{BackendDescriptor, BackendKind, BackendRegistry, NATIVE_BACKEND_ID};
use super::session_pin::{PinStore, PinStoreError};
use crate::plugin_host::lifecycle::{ExternalPinState, SessionPinV1};
use crate::plugin_host::receipts::{LogicalDefaultV1, RegistryDocumentV2};

/// Launch surface: interactive may soft-fallback a corrupt default; headless may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    Interactive,
    Headless,
}

/// Why this backend was chosen (precedence evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionOrigin {
    Explicit,
    SessionPin,
    UserDefault,
    NativeBuiltin,
}

/// Parsed `--backend` / set-default selector (logical id, optional version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSelector {
    pub backend_id: String,
    pub version: Option<String>,
}

/// Inputs for one selection decision.
#[derive(Debug)]
pub struct SelectionInput<'a> {
    pub explicit: Option<&'a str>,
    pub resume_host_session_id: Option<&'a str>,
    pub mode: LaunchMode,
    pub registry: &'a BackendRegistry,
    pub registry_doc: Option<&'a RegistryDocumentV2>,
    pub default_path: &'a Path,
    pub pin_store: Option<&'a PinStore>,
}

/// Resolved backend for session create/resume (no process spawn).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBackend {
    pub backend_id: String,
    pub version: Option<String>,
    pub kind: BackendKind,
    pub origin: SelectionOrigin,
    pub receipt_digest: Option<String>,
    pub pin: Option<SessionPinV1>,
    /// Visible one-launch warning (interactive corrupt default only).
    pub warning: Option<String>,
    /// True only when the host will start the native backend.
    pub native_start: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SelectionError {
    #[error("invalid backend selector: {0}")]
    InvalidSelector(String),
    #[error("backend not found: {0}")]
    NotFound(String),
    #[error("backend not selectable: {0}")]
    NotSelectable(String),
    #[error("explicit backend failed: {0}")]
    ExplicitFailed(String),
    #[error("headless default failed: {0}")]
    HeadlessDefaultFailed(String),
    #[error("corrupt preference: {0}")]
    CorruptPreference(String),
    #[error("session pin: {0}")]
    Pin(String),
    #[error("missing receipt for pin: {0}")]
    MissingReceipt(String),
    #[error("stale pin: {0}")]
    StalePin(String),
    #[error("io: {0}")]
    Io(String),
}

impl From<PinStoreError> for SelectionError {
    fn from(e: PinStoreError) -> Self {
        match e {
            PinStoreError::MissingReceipt(s) => Self::MissingReceipt(s),
            PinStoreError::Stale(s) => Self::StalePin(s),
            other => Self::Pin(other.to_string()),
        }
    }
}

/// Parse `id` or `id@version` (version may contain dots; split on first `@`).
pub fn parse_selector(raw: &str) -> Result<BackendSelector, SelectionError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SelectionError::InvalidSelector("empty".into()));
    }
    if raw.contains('/') || raw.contains('\\') || raw.contains("..") {
        return Err(SelectionError::InvalidSelector(raw.into()));
    }
    match raw.split_once('@') {
        None => Ok(BackendSelector {
            backend_id: raw.into(),
            version: None,
        }),
        Some((id, ver)) => {
            if id.is_empty() || ver.is_empty() {
                return Err(SelectionError::InvalidSelector(raw.into()));
            }
            Ok(BackendSelector {
                backend_id: id.into(),
                version: Some(ver.into()),
            })
        }
    }
}

/// Precedence: explicit `--backend` → session pin → user default → native.
pub fn resolve(input: &SelectionInput<'_>) -> Result<ResolvedBackend, SelectionError> {
    if let Some(raw) = input.explicit {
        return resolve_explicit(raw, input);
    }
    if let (Some(sid), Some(store)) = (input.resume_host_session_id, input.pin_store) {
        if let Some(pin) = store.load(sid)? {
            return resolve_pin(pin, input);
        }
    }
    match load_user_default(input.default_path) {
        Ok(Some(def)) => resolve_default(&def, input),
        Ok(None) => Ok(native_resolved(SelectionOrigin::NativeBuiltin, None)),
        Err(e) => match input.mode {
            LaunchMode::Headless => Err(SelectionError::HeadlessDefaultFailed(e.to_string())),
            LaunchMode::Interactive => Ok(native_resolved(
                SelectionOrigin::NativeBuiltin,
                Some(format!("BACKEND_UNAVAILABLE: {e}")),
            )),
        },
    }
}

fn resolve_explicit(
    raw: &str,
    input: &SelectionInput<'_>,
) -> Result<ResolvedBackend, SelectionError> {
    let sel = parse_selector(raw)?;
    match select_from_registry(&sel, input.registry, input.registry_doc) {
        Ok(desc) => Ok(from_descriptor(desc, SelectionOrigin::Explicit, None, None)),
        Err(e) => Err(SelectionError::ExplicitFailed(e.to_string())),
    }
}

fn resolve_pin(
    pin: SessionPinV1,
    input: &SelectionInput<'_>,
) -> Result<ResolvedBackend, SelectionError> {
    match pin {
        SessionPinV1::Native(n) => Ok(ResolvedBackend {
            backend_id: NATIVE_BACKEND_ID.into(),
            version: None,
            kind: BackendKind::Native,
            origin: SelectionOrigin::SessionPin,
            receipt_digest: None,
            pin: Some(SessionPinV1::Native(n)),
            warning: None,
            native_start: true,
        }),
        SessionPinV1::External(e) => {
            // Pin is immutable: exact receipt; never re-resolve activation.
            let desc = input
                .registry
                .list()
                .iter()
                .find(|d| d.receipt_digest.as_deref() == Some(e.install_receipt_digest.as_str()))
                .ok_or_else(|| SelectionError::MissingReceipt(e.install_receipt_digest.clone()))?;
            if !desc.selectable && e.state == ExternalPinState::Creating {
                // Missing/stale selectable still surfaces Creating without native fallback.
                return Err(SelectionError::MissingReceipt(format!(
                    "receipt {} not selectable while Creating",
                    e.install_receipt_digest
                )));
            }
            if desc.backend_id != e.backend_id {
                return Err(SelectionError::StalePin("backend id drift".into()));
            }
            Ok(ResolvedBackend {
                backend_id: e.backend_id.clone(),
                version: desc.version.clone(),
                kind: BackendKind::External,
                origin: SelectionOrigin::SessionPin,
                receipt_digest: Some(e.install_receipt_digest.clone()),
                pin: Some(SessionPinV1::External(e)),
                warning: None,
                native_start: false,
            })
        }
    }
}

fn resolve_default(
    def: &LogicalDefaultV1,
    input: &SelectionInput<'_>,
) -> Result<ResolvedBackend, SelectionError> {
    if def.backend_id == NATIVE_BACKEND_ID {
        return Ok(native_resolved(SelectionOrigin::UserDefault, None));
    }
    let sel = BackendSelector {
        backend_id: def.backend_id.clone(),
        version: None,
    };
    match select_from_registry(&sel, input.registry, input.registry_doc) {
        Ok(desc) => Ok(from_descriptor(
            desc,
            SelectionOrigin::UserDefault,
            None,
            None,
        )),
        Err(e) => match input.mode {
            LaunchMode::Headless => Err(SelectionError::HeadlessDefaultFailed(e.to_string())),
            LaunchMode::Interactive => Ok(native_resolved(
                SelectionOrigin::NativeBuiltin,
                Some(format!("BACKEND_UNAVAILABLE: {e}")),
            )),
        },
    }
}

fn select_from_registry<'a>(
    sel: &BackendSelector,
    registry: &'a BackendRegistry,
    doc: Option<&RegistryDocumentV2>,
) -> Result<&'a BackendDescriptor, SelectionError> {
    if sel.backend_id == NATIVE_BACKEND_ID {
        if sel.version.is_some() {
            return Err(SelectionError::InvalidSelector(
                "native does not take @version".into(),
            ));
        }
        return Ok(registry.native());
    }
    if let Some(ver) = &sel.version {
        let d = registry
            .by_id_version(&sel.backend_id, Some(ver))
            .ok_or_else(|| SelectionError::NotFound(format!("{}@{ver}", sel.backend_id)))?;
        if !d.selectable {
            return Err(SelectionError::NotSelectable(format!(
                "{}@{ver}: {}",
                sel.backend_id,
                d.diagnostic.as_deref().unwrap_or("not selectable")
            )));
        }
        return Ok(d);
    }
    // followActivation: prefer activation pointer receipt when present.
    if let Some(doc) = doc {
        if let Some(act) = doc.activation.get(&sel.backend_id) {
            if let Some(d) = registry
                .list()
                .iter()
                .find(|x| x.receipt_digest.as_deref() == Some(act.install_receipt_digest.as_str()))
            {
                if d.selectable {
                    return Ok(d);
                }
                return Err(SelectionError::NotSelectable(format!(
                    "{} activation not selectable",
                    sel.backend_id
                )));
            }
            return Err(SelectionError::NotFound(format!(
                "{} activation receipt missing",
                sel.backend_id
            )));
        }
    }
    // No activation: single selectable version, else ambiguous.
    let selectable: Vec<_> = registry
        .versions_of(&sel.backend_id)
        .into_iter()
        .filter(|d| d.selectable)
        .collect();
    match selectable.as_slice() {
        [one] => Ok(*one),
        [] => {
            if registry.versions_of(&sel.backend_id).is_empty() {
                Err(SelectionError::NotFound(sel.backend_id.clone()))
            } else {
                Err(SelectionError::NotSelectable(format!(
                    "{} has no selectable version",
                    sel.backend_id
                )))
            }
        }
        _ => Err(SelectionError::NotSelectable(format!(
            "{}: ambiguous version (set activation or use id@version)",
            sel.backend_id
        ))),
    }
}

fn from_descriptor(
    desc: &BackendDescriptor,
    origin: SelectionOrigin,
    pin: Option<SessionPinV1>,
    warning: Option<String>,
) -> ResolvedBackend {
    let native_start = desc.kind == BackendKind::Native;
    ResolvedBackend {
        backend_id: desc.backend_id.clone(),
        version: desc.version.clone(),
        kind: desc.kind,
        origin,
        receipt_digest: desc.receipt_digest.clone(),
        pin,
        warning,
        native_start,
    }
}

fn native_resolved(origin: SelectionOrigin, warning: Option<String>) -> ResolvedBackend {
    ResolvedBackend {
        backend_id: NATIVE_BACKEND_ID.into(),
        version: None,
        kind: BackendKind::Native,
        origin,
        receipt_digest: None,
        pin: None,
        warning,
        native_start: true,
    }
}

/// Load user default from `state/backend-default.json` (LogicalDefaultV1).
pub fn load_user_default(path: &Path) -> Result<Option<LogicalDefaultV1>, SelectionError> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|e| SelectionError::Io(e.to_string()))?;
    let def = LogicalDefaultV1::parse_json(&raw)
        .map_err(|e| SelectionError::CorruptPreference(e.to_string()))?;
    Ok(Some(def))
}

/// Persist logical default only — never a receipt or version.
pub fn set_user_default(path: &Path, backend_id: &str) -> Result<LogicalDefaultV1, SelectionError> {
    let sel = parse_selector(backend_id)?;
    if sel.version.is_some() {
        return Err(SelectionError::InvalidSelector(
            "set-default takes logical id only (no @version)".into(),
        ));
    }
    let def = LogicalDefaultV1 {
        schema_version: 1,
        backend_id: sel.backend_id,
        version_policy: "followActivation".into(),
        default_digest: String::new(),
    }
    .seal()
    .map_err(|e| SelectionError::CorruptPreference(e.to_string()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SelectionError::Io(e.to_string()))?;
    }
    let bytes = serde_json::to_vec_pretty(&def).map_err(|e| SelectionError::Io(e.to_string()))?;
    atomic_write(path, &bytes).map_err(|e| SelectionError::Io(e.to_string()))?;
    Ok(def)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("def")
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

// ── CLI: orca backend list|status|set-default ─────────────────────────

#[derive(Debug, Clone)]
pub struct BackendCliPaths {
    pub registry_path: PathBuf,
    pub default_path: PathBuf,
    pub plugins_root: Option<PathBuf>,
}

/// Run `backend` subcommand. Returns process exit code.
pub fn run_backend_cli(args: &[String], paths: &BackendCliPaths) -> i32 {
    match args.first().map(String::as_str) {
        Some("list") | Some("status") => cmd_list_status(paths, args.get(1..).unwrap_or(&[])),
        Some("set-default") => {
            let id = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("error: backend set-default requires BACKEND_ID");
                    return 2;
                }
            };
            match set_user_default(&paths.default_path, id) {
                Ok(def) => {
                    println!(
                        "defaultBackend id={} versionPolicy={} digest={}",
                        def.backend_id, def.version_policy, def.default_digest
                    );
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        Some(other) => {
            eprintln!("error: unknown backend command: {other}");
            eprintln!("usage: orca backend list|status|set-default <id>");
            2
        }
        None => {
            eprintln!("usage: orca backend list|status|set-default <id>");
            2
        }
    }
}

fn cmd_list_status(paths: &BackendCliPaths, rest: &[String]) -> i32 {
    let json = rest.iter().any(|a| a == "--json");
    let host = xai_grok_agent::plugins::agent_backend::HostPlatform::current();
    let opts = super::registry::DiscoverOpts {
        plugins_root: paths.plugins_root.clone(),
        ..super::registry::DiscoverOpts::default()
    };
    let reg = if paths.registry_path.is_file() {
        match BackendRegistry::load_from_path(&paths.registry_path, &host, &opts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        }
    } else {
        BackendRegistry::native_only()
    };
    let lines = reg.format_status_lines();
    let default = load_user_default(&paths.default_path)
        .ok()
        .flatten()
        .map(|d| d.backend_id)
        .unwrap_or_else(|| NATIVE_BACKEND_ID.into());
    if json {
        match format_list_status_json(&default, &lines) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        }
        return 0;
    }
    println!("default={default}");
    for line in lines {
        println!("{line}");
    }
    0
}

pub fn format_list_status_json(default: &str, lines: &[String]) -> Result<String, String> {
    let backends: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::json!({ "statusLine": line }))
        .collect();
    let payload = serde_json::json!({
        "default": default,
        "backends": backends,
        "statusLines": lines,
    });
    serde_json::to_string(&payload).map_err(|e| e.to_string())
}

/// Pre-clap intercept for `orca backend ...` (avoids full pager startup).
pub fn try_run_from_args<I, S>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if args.first().map(String::as_str) != Some("backend") {
        return None;
    }
    let paths = match backend_cli_paths_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return Some(2);
        }
    };
    Some(run_backend_cli(&args[1..], &paths))
}

fn backend_cli_paths_from_env() -> Result<BackendCliPaths, String> {
    let host = crate::plugin_host::paths::HostPaths::resolve().map_err(|e| e.to_string())?;
    Ok(BackendCliPaths {
        registry_path: host.plugins_registry_path(),
        default_path: host.backend_default_path(),
        plugins_root: Some(host.plugins_dir()),
    })
}


/// Inputs for production backend selection before auth/ACP connect.
#[derive(Debug, Clone, Copy)]
pub struct LaunchBackendRequest<'a> {
    pub explicit_backend: Option<&'a str>,
    pub resume_host_session_id: Option<&'a str>,
    pub mode: LaunchMode,
}

/// Native-allowed launch decision from [`prepare_launch`].
#[derive(Debug, Clone)]
pub struct LaunchBackendDecision {
    pub resolved: ResolvedBackend,
}

/// Resolve backend before native auth/ACP connect. Selection failures and
/// external backends never start native on this path.
pub fn prepare_launch(
    req: &LaunchBackendRequest<'_>,
) -> Result<LaunchBackendDecision, SelectionError> {
    let host_paths = crate::plugin_host::paths::HostPaths::resolve()
        .map_err(|e| SelectionError::Io(e.to_string()))?;
    let host = xai_grok_agent::plugins::agent_backend::HostPlatform::current();
    let opts = super::registry::DiscoverOpts {
        plugins_root: Some(host_paths.plugins_dir()),
        ..super::registry::DiscoverOpts::default()
    };
    let registry_path = host_paths.plugins_registry_path();
    let registry = if registry_path.is_file() {
        match BackendRegistry::load_from_path(&registry_path, &host, &opts) {
            Ok(r) => r,
            Err(e) => {
                if req.explicit_backend.is_some() {
                    return Err(SelectionError::ExplicitFailed(e.to_string()));
                }
                if req.mode == LaunchMode::Headless {
                    return Err(SelectionError::HeadlessDefaultFailed(e.to_string()));
                }
                BackendRegistry::native_only()
            }
        }
    } else {
        BackendRegistry::native_only()
    };
    let doc_owned = if registry_path.is_file() {
        std::fs::read_to_string(&registry_path)
            .ok()
            .and_then(|raw| RegistryDocumentV2::parse_json(&raw).ok())
    } else {
        None
    };
    let pin_store = PinStore::open(host_paths.session_pins_dir())?;
    let default_path = host_paths.backend_default_path();
    let input = SelectionInput {
        explicit: req.explicit_backend,
        resume_host_session_id: req.resume_host_session_id,
        mode: req.mode,
        registry: &registry,
        registry_doc: doc_owned.as_ref(),
        default_path: &default_path,
        pin_store: Some(&pin_store),
    };
    let resolved = resolve(&input)?;
    if !resolved.native_start {
        return Err(SelectionError::ExplicitFailed(format!(
            "backend '{}' is external (receipt={:?}); refusing native start — external connection is not enabled on this launch path",
            resolved.backend_id, resolved.receipt_digest
        )));
    }
    Ok(LaunchBackendDecision { resolved })
}

/// Persist NativeV1 after native session identity exists. Same identity is idempotent.
pub fn persist_native_session_pin(
    host_session_id: &str,
    native_session_identity: &str,
) -> Result<(), SelectionError> {
    let host_paths = crate::plugin_host::paths::HostPaths::resolve()
        .map_err(|e| SelectionError::Io(e.to_string()))?;
    let store = PinStore::open(host_paths.session_pins_dir())?;
    match store.load(host_session_id)? {
        Some(crate::plugin_host::lifecycle::SessionPinV1::Native(n))
            if n.native_session_identity == native_session_identity =>
        {
            Ok(())
        }
        Some(_) => Err(SelectionError::Pin(format!(
            "session {host_session_id} already pinned to a different identity"
        ))),
        None => {
            store.write_native(host_session_id, native_session_identity)?;
            Ok(())
        }
    }
}

/// Best-effort pin write at session-create boundaries (selection still gates launch).
pub fn persist_native_session_pin_best_effort(
    host_session_id: &str,
    native_session_identity: &str,
) {
    if let Err(e) = persist_native_session_pin(host_session_id, native_session_identity) {
        tracing::warn!(
            error = %e,
            session_id = %host_session_id,
            "failed to persist native session pin"
        );
    }
}

#[cfg(test)]
#[path = "selection_test.rs"]
mod selection_test;
