//! Generic `agentBackends` DTOs for manifest v2.
//!
//! Parse-don't-validate at the JSON boundary: typed structs + bounded
//! smart constructors. Launch is always an argv array — never a shell string.
//!
//! // allow: SIZE_OK — plan Task 4 owns single agent_backend.rs for the full DTO surface

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported `agentBackends[*].schemaVersion` major.
pub const AGENT_BACKEND_SCHEMA_VERSION: u32 = 1;

/// Required top-level `manifestVersion` when native backends are present.
pub const MANIFEST_VERSION_V2: u32 = 2;

const MAX_BACKENDS: usize = 16;
const MAX_TARGETS: usize = 8;
const MAX_ARGV: usize = 64;
const MAX_STR: usize = 512;
const MAX_PATH: usize = 1024;
const MAX_CAPABILITIES: usize = 32;
const MAX_PERMISSIONS: usize = 32;
const MAX_EXTENSIONS: usize = 8;
const MAX_FEATURES: usize = 32;
const SHA256_HEX_LEN: usize = 64;

/// Whole-element placeholders legal in argv / cwd.
pub const ALLOWED_PLACEHOLDERS: &[&str] = &[
    "{pluginRoot}",
    "{pluginData}",
    "{runtimeDir}",
    "{bridge}",
    "{daemon}",
    "{cohortId}",
    "{purgeBarrier}",
    "{purgeBarrierParentIdentity}",
    "{purgeBarrierRevision}",
    "{provisionInput}",
];

/// Typed parse/validation failure for agent backends.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AgentBackendError {
    #[error("manifestVersion 2 is required when agentBackends is non-empty")]
    ManifestVersionRequired,
    #[error("unsupported manifestVersion {0}")]
    UnsupportedManifestVersion(u32),
    #[error("too many agentBackends (max {MAX_BACKENDS})")]
    TooManyBackends,
    #[error("duplicate backend id {0:?}")]
    DuplicateBackendId(String),
    #[error("unknown agentBackends schemaVersion {0}")]
    UnknownSchemaVersion(u32),
    #[error("invalid backend id {0:?}: {1}")]
    InvalidBackendId(String, String),
    #[error("invalid displayName: {0}")]
    InvalidDisplayName(String),
    #[error("invalid SemVer version {0:?}")]
    InvalidSemVer(String),
    #[error("invalid SemVer range for {field}: {value:?}")]
    BadSemverRange { field: &'static str, value: String },
    #[error("duplicate target os={os} arch={arch} libc={libc:?}")]
    DuplicateTarget {
        os: String,
        arch: String,
        libc: Option<String>,
    },
    #[error("path escapes plugin root or is absolute: {0}")]
    PathEscape(String),
    #[error("relative executable is ambiguous: {0}")]
    RelativeExecutable(String),
    #[error("bad placeholder token: {0}")]
    BadPlaceholder(String),
    #[error("missing required placeholder {0} in {1}")]
    MissingPlaceholder(&'static str, &'static str),
    #[error("duplicate placeholder {0} in {1}")]
    DuplicatePlaceholder(&'static str, &'static str),
    #[error("placeholder {0} forbidden in {1}")]
    ForbiddenPlaceholder(&'static str, &'static str),
    #[error("missing lifecycle route: {0}")]
    MissingLifecycleRoute(&'static str),
    #[error("shell text / metacharacters forbidden in argv: {0}")]
    ShellText(String),
    #[error("argv must be a non-empty array (never a shell string)")]
    ArgvNotArray,
    #[error("argv exceeds max length {MAX_ARGV}")]
    ArgvTooLong,
    #[error("string exceeds bound: {0}")]
    StringTooLong(String),
    #[error("invalid sha256 hex: {0}")]
    InvalidSha256(String),
    #[error("supervisor required when backgroundWork=survivesClientExit")]
    SupervisorRequired,
    #[error("admin argvPrefix/argvTail shape invalid")]
    AdminArgvShape,
    #[error("unsupported permission id {0:?}")]
    UnsupportedPermission(String),
    #[error("unsupported enum value for {0}: {1}")]
    UnsupportedEnum(&'static str, String),
    #[error("targets must be non-empty")]
    EmptyTargets,
    #[error("json: {0}")]
    Json(String),
}

/// Host-side resolution context for placeholders.
#[derive(Debug, Clone)]
pub struct ResolveContext {
    pub plugin_root: PathBuf,
    pub plugin_data: PathBuf,
    pub runtime_dir: PathBuf,
    pub bridge: PathBuf,
    pub daemon: PathBuf,
    pub cohort_id: String,
    pub purge_barrier: PathBuf,
    pub purge_barrier_parent_identity: String,
    pub purge_barrier_revision: u64,
    pub provision_input: Option<PathBuf>,
}

/// Resolved argv vector (absolute paths substituted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedArgv {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
}

/// Parsed + validated agent backend (schemaVersion 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBackendV1 {
    pub schema_version: u32,
    pub id: String,
    pub display_name: String,
    pub requires: BackendRequires,
    #[serde(default)]
    pub extensions: Vec<BackendExtension>,
    pub capabilities: Vec<String>,
    pub permissions: Vec<BackendPermission>,
    pub daemon: BackendDaemon,
    pub targets: Vec<BackendTarget>,
    pub lifecycle: BackendLifecycle,
    pub fallback: BackendFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendRequires {
    pub orca: String,
    pub acp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendExtension {
    pub namespace: String,
    pub version: String,
    pub features: Vec<String>,
    pub schema_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendPermission {
    pub id: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendDaemon {
    pub mode: String,
    pub background_work: String,
    pub store_schema_major: u32,
    pub control_protocol_major: u32,
    #[serde(default)]
    pub supervisor: Option<SupervisorSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    pub detach_from_bridge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendTarget {
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub libc: Option<String>,
    pub artifact: BackendArtifact,
    pub files: BackendFiles,
    pub entrypoint: EntrypointSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendArtifact {
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub signature: Option<ArtifactRef>,
    #[serde(default)]
    pub provenance: Option<ArtifactRef>,
    #[serde(default)]
    pub sbom: Option<ArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRef {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendFiles {
    pub bridge: String,
    pub daemon: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrypointSpec {
    pub argv: Vec<String>,
    pub cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendLifecycle {
    pub doctor: ArgvOnly,
    pub admin: AdminSpec,
    pub provision: ArgvOnly,
    pub purge_prepare: ArgvOnly,
    pub purge_preflight: ArgvOnly,
    pub restart_required: String,
    pub uninstall_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgvOnly {
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSpec {
    pub argv_prefix: Vec<String>,
    pub argv_tail: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendFallback {
    pub standard_acp: String,
    pub rich_projection: String,
}

/// Parse a single backend object from JSON and validate bounds.
pub fn parse_agent_backend(value: &serde_json::Value) -> Result<AgentBackendV1, AgentBackendError> {
    // Reject shell-string entrypoint before serde (serde would fail opaquely).
    if let Some(targets) = value.get("targets").and_then(|t| t.as_array()) {
        for t in targets {
            if let Some(ep) = t.get("entrypoint") {
                if let Some(argv) = ep.get("argv") {
                    if argv.is_string() {
                        return Err(AgentBackendError::ShellText(argv.as_str().unwrap_or("").into()));
                    }
                    if !argv.is_array() {
                        return Err(AgentBackendError::ArgvNotArray);
                    }
                }
            }
        }
    }
    let backend: AgentBackendV1 =
        serde_json::from_value(value.clone()).map_err(|e| AgentBackendError::Json(e.to_string()))?;
    validate_backend(&backend)?;
    Ok(backend)
}

/// Validate a list of backends (unique IDs, bounds).
pub fn validate_backends(backends: &[AgentBackendV1]) -> Result<(), AgentBackendError> {
    if backends.len() > MAX_BACKENDS {
        return Err(AgentBackendError::TooManyBackends);
    }
    let mut ids = HashSet::new();
    for b in backends {
        validate_backend(b)?;
        if !ids.insert(b.id.clone()) {
            return Err(AgentBackendError::DuplicateBackendId(b.id.clone()));
        }
    }
    Ok(())
}

/// Validate one backend.
pub fn validate_backend(b: &AgentBackendV1) -> Result<(), AgentBackendError> {
    if b.schema_version != AGENT_BACKEND_SCHEMA_VERSION {
        return Err(AgentBackendError::UnknownSchemaVersion(b.schema_version));
    }
    check_id(&b.id)?;
    bound_str("displayName", &b.display_name, MAX_STR)?;
    if b.display_name.trim().is_empty() {
        return Err(AgentBackendError::InvalidDisplayName("empty".into()));
    }
    parse_range("requires.orca", &b.requires.orca)?;
    parse_range("requires.acp", &b.requires.acp)?;
    if b.extensions.len() > MAX_EXTENSIONS {
        return Err(AgentBackendError::StringTooLong("extensions".into()));
    }
    for ext in &b.extensions {
        validate_extension(ext)?;
    }
    if b.capabilities.len() > MAX_CAPABILITIES {
        return Err(AgentBackendError::StringTooLong("capabilities".into()));
    }
    for c in &b.capabilities {
        bound_str("capability", c, MAX_STR)?;
    }
    if b.permissions.len() > MAX_PERMISSIONS {
        return Err(AgentBackendError::StringTooLong("permissions".into()));
    }
    for p in &b.permissions {
        validate_permission(p)?;
    }
    validate_daemon(&b.daemon)?;
    if b.targets.is_empty() {
        return Err(AgentBackendError::EmptyTargets);
    }
    if b.targets.len() > MAX_TARGETS {
        return Err(AgentBackendError::StringTooLong("targets".into()));
    }
    let mut seen = HashSet::new();
    for t in &b.targets {
        let key = (t.os.clone(), t.arch.clone(), t.libc.clone());
        if !seen.insert(key) {
            return Err(AgentBackendError::DuplicateTarget {
                os: t.os.clone(),
                arch: t.arch.clone(),
                libc: t.libc.clone(),
            });
        }
        validate_target(t)?;
    }
    validate_lifecycle(&b.lifecycle)?;
    match b.fallback.standard_acp.as_str() {
        "required" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum(
                "fallback.standardAcp",
                other.into(),
            ));
        }
    }
    match b.fallback.rich_projection.as_str() {
        "optional" | "required" | "absent" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum(
                "fallback.richProjection",
                other.into(),
            ));
        }
    }
    Ok(())
}

fn validate_extension(ext: &BackendExtension) -> Result<(), AgentBackendError> {
    bound_str("extension.namespace", &ext.namespace, MAX_STR)?;
    bound_str("extension.version", &ext.version, MAX_STR)?;
    if ext.features.len() > MAX_FEATURES {
        return Err(AgentBackendError::StringTooLong("features".into()));
    }
    for f in &ext.features {
        bound_str("feature", f, MAX_STR)?;
    }
    contained_rel_path(&ext.schema_path)?;
    check_sha256(&ext.sha256)?;
    Ok(())
}

fn validate_permission(p: &BackendPermission) -> Result<(), AgentBackendError> {
    const ALLOWED: &[&str] = &[
        "native-code",
        "private-daemon",
        "workspace-access",
        "network-egress",
    ];
    if !ALLOWED.contains(&p.id.as_str()) {
        return Err(AgentBackendError::UnsupportedPermission(p.id.clone()));
    }
    Ok(())
}

fn validate_daemon(d: &BackendDaemon) -> Result<(), AgentBackendError> {
    match d.mode.as_str() {
        "sharedPerVersion" | "perSession" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum("daemon.mode", other.into()));
        }
    }
    match d.background_work.as_str() {
        "survivesClientExit" | "endsWithClient" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum(
                "daemon.backgroundWork",
                other.into(),
            ));
        }
    }
    if d.background_work == "survivesClientExit" && d.supervisor.is_none() {
        return Err(AgentBackendError::SupervisorRequired);
    }
    if let Some(sup) = &d.supervisor {
        validate_argv(
            &sup.argv,
            "daemon.supervisor",
            ArgvRules {
                require_plugin_data: true,
                require_runtime_dir: true,
                allow_provision_input: false,
                require_bridge_first: true,
            },
        )?;
        validate_cwd(&sup.cwd)?;
    }
    Ok(())
}

fn validate_target(t: &BackendTarget) -> Result<(), AgentBackendError> {
    bound_str("os", &t.os, 32)?;
    bound_str("arch", &t.arch, 32)?;
    if let Some(libc) = &t.libc {
        bound_str("libc", libc, 32)?;
    }
    bound_str("artifact.url", &t.artifact.url, MAX_PATH)?;
    check_sha256(&t.artifact.sha256)?;
    for r in [
        t.artifact.signature.as_ref(),
        t.artifact.provenance.as_ref(),
        t.artifact.sbom.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(p) = &r.path {
            contained_rel_path(p)?;
        }
        if let Some(h) = &r.sha256 {
            check_sha256(h)?;
        }
        if let Some(id) = &r.identity {
            bound_str("signature.identity", id, MAX_PATH)?;
        }
    }
    contained_rel_path(&t.files.bridge)?;
    contained_rel_path(&t.files.daemon)?;
    validate_argv(
        &t.entrypoint.argv,
        "entrypoint",
        ArgvRules {
            require_plugin_data: true,
            require_runtime_dir: true,
            allow_provision_input: false,
            require_bridge_first: true,
        },
    )?;
    validate_cwd(&t.entrypoint.cwd)?;
    Ok(())
}

fn validate_lifecycle(lc: &BackendLifecycle) -> Result<(), AgentBackendError> {
    validate_argv(
        &lc.doctor.argv,
        "lifecycle.doctor",
        ArgvRules {
            require_plugin_data: true,
            require_runtime_dir: true,
            allow_provision_input: false,
            require_bridge_first: true,
        },
    )?;
    // admin shape: [{bridge},"admin"] + tail with pluginData/runtimeDir
    if lc.admin.argv_prefix.as_slice() != ["{bridge}", "admin"] {
        return Err(AgentBackendError::AdminArgvShape);
    }
    if lc.admin.argv_tail.as_slice()
        != [
            "--plugin-data",
            "{pluginData}",
            "--runtime-dir",
            "{runtimeDir}",
        ]
    {
        return Err(AgentBackendError::AdminArgvShape);
    }
    validate_argv(
        &lc.provision.argv,
        "lifecycle.provision",
        ArgvRules {
            require_plugin_data: true,
            require_runtime_dir: true,
            allow_provision_input: true,
            require_bridge_first: true,
        },
    )?;
    // provisionInput mandatory exactly once in provision
    count_placeholder(&lc.provision.argv, "{provisionInput}")
        .map_err(|_| AgentBackendError::MissingPlaceholder("{provisionInput}", "lifecycle.provision"))?;
    let n = lc
        .provision
        .argv
        .iter()
        .filter(|a| a.as_str() == "{provisionInput}")
        .count();
    if n != 1 {
        return Err(AgentBackendError::MissingPlaceholder(
            "{provisionInput}",
            "lifecycle.provision",
        ));
    }
    validate_argv(
        &lc.purge_prepare.argv,
        "lifecycle.purgePrepare",
        ArgvRules {
            require_plugin_data: true,
            require_runtime_dir: true,
            allow_provision_input: false,
            require_bridge_first: true,
        },
    )?;
    validate_argv(
        &lc.purge_preflight.argv,
        "lifecycle.purgePreflight",
        ArgvRules {
            require_plugin_data: true,
            require_runtime_dir: true,
            allow_provision_input: false,
            require_bridge_first: true,
        },
    )?;
    match lc.restart_required.as_str() {
        "never" | "onMajor" | "always" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum(
                "lifecycle.restartRequired",
                other.into(),
            ));
        }
    }
    match lc.uninstall_data.as_str() {
        "retain" | "purge" => {}
        other => {
            return Err(AgentBackendError::UnsupportedEnum(
                "lifecycle.uninstallData",
                other.into(),
            ));
        }
    }
    Ok(())
}

struct ArgvRules {
    require_plugin_data: bool,
    require_runtime_dir: bool,
    allow_provision_input: bool,
    require_bridge_first: bool,
}

fn validate_argv(
    argv: &[String],
    where_: &'static str,
    rules: ArgvRules,
) -> Result<(), AgentBackendError> {
    if argv.is_empty() {
        return Err(AgentBackendError::ArgvNotArray);
    }
    if argv.len() > MAX_ARGV {
        return Err(AgentBackendError::ArgvTooLong);
    }
    for (i, el) in argv.iter().enumerate() {
        bound_str("argv", el, MAX_PATH)?;
        if el.contains('{') || el.contains('}') {
            if !ALLOWED_PLACEHOLDERS.contains(&el.as_str()) {
                return Err(AgentBackendError::BadPlaceholder(el.clone()));
            }
            if el == "{provisionInput}" && !rules.allow_provision_input {
                return Err(AgentBackendError::ForbiddenPlaceholder(
                    "{provisionInput}",
                    where_,
                ));
            }
        } else if has_shell_meta(el) {
            return Err(AgentBackendError::ShellText(el.clone()));
        } else if i == 0 && rules.require_bridge_first {
            if Path::new(el).is_absolute() {
                // absolute path allowed for already-resolved forms
            } else {
                return Err(AgentBackendError::RelativeExecutable(el.clone()));
            }
        }
    }
    if rules.require_plugin_data {
        require_once(argv, "{pluginData}", where_)?;
    }
    if rules.require_runtime_dir {
        require_once(argv, "{runtimeDir}", where_)?;
    }
    if !rules.allow_provision_input {
        let n = argv.iter().filter(|a| a.as_str() == "{provisionInput}").count();
        if n > 0 {
            return Err(AgentBackendError::ForbiddenPlaceholder(
                "{provisionInput}",
                where_,
            ));
        }
    }
    Ok(())
}

fn require_once(argv: &[String], ph: &'static str, where_: &'static str) -> Result<(), AgentBackendError> {
    let n = argv.iter().filter(|a| a.as_str() == ph).count();
    match n {
        0 => Err(AgentBackendError::MissingPlaceholder(ph, where_)),
        1 => Ok(()),
        _ => Err(AgentBackendError::DuplicatePlaceholder(ph, where_)),
    }
}

fn count_placeholder(argv: &[String], ph: &str) -> Result<usize, ()> {
    Ok(argv.iter().filter(|a| a.as_str() == ph).count())
}

fn validate_cwd(cwd: &str) -> Result<(), AgentBackendError> {
    bound_str("cwd", cwd, MAX_PATH)?;
    if cwd.starts_with('{') {
        if !ALLOWED_PLACEHOLDERS.contains(&cwd) {
            return Err(AgentBackendError::BadPlaceholder(cwd.into()));
        }
        return Ok(());
    }
    contained_rel_path(cwd)
}

fn has_shell_meta(s: &str) -> bool {
    if ALLOWED_PLACEHOLDERS.contains(&s) {
        return false;
    }
    // Partial `{...}` is a placeholder error, not shell text.
    if s.contains('{') || s.contains('}') {
        return false;
    }
    s.bytes().any(|b| {
        matches!(
            b,
            b'|' | b'&'
                | b';'
                | b'<'
                | b'>'
                | b'`'
                | b'$'
                | b'\n'
                | b'\r'
                | b'('
                | b')'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'\''
                | b'"'
                | b'\\'
                | b' '
                | b'\t'
        )
    }) || s.contains("&&")
        || s.contains("||")
}

fn check_id(id: &str) -> Result<(), AgentBackendError> {
    if id.is_empty() || id.len() > 64 {
        return Err(AgentBackendError::InvalidBackendId(
            id.into(),
            "length".into(),
        ));
    }
    let ok = id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    if !ok {
        return Err(AgentBackendError::InvalidBackendId(
            id.into(),
            "kebab-case".into(),
        ));
    }
    Ok(())
}

fn bound_str(field: &str, s: &str, max: usize) -> Result<(), AgentBackendError> {
    if s.len() > max {
        return Err(AgentBackendError::StringTooLong(field.into()));
    }
    Ok(())
}

fn check_sha256(s: &str) -> Result<(), AgentBackendError> {
    if s.len() != SHA256_HEX_LEN || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AgentBackendError::InvalidSha256(s.into()));
    }
    Ok(())
}

fn parse_range(field: &'static str, value: &str) -> Result<(), AgentBackendError> {
    bound_str(field, value, MAX_STR)?;
    // Plan ranges use space-separated comparators (`>=1 <2`); semver wants commas.
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(",");
    normalized
        .parse::<semver::VersionReq>()
        .map(|_| ())
        .map_err(|_| AgentBackendError::BadSemverRange {
            field,
            value: value.into(),
        })
}

/// Relative path, no `..`, no absolute, no empty.
pub fn contained_rel_path(p: &str) -> Result<(), AgentBackendError> {
    bound_str("path", p, MAX_PATH)?;
    if p.is_empty() || p.starts_with('/') || p.contains('\\') {
        return Err(AgentBackendError::PathEscape(p.into()));
    }
    let path = Path::new(p);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    {
        return Err(AgentBackendError::PathEscape(p.into()));
    }
    Ok(())
}

/// Resolve argv placeholders against a host context.
pub fn resolve_argv(
    argv: &[String],
    cwd_template: &str,
    ctx: &ResolveContext,
) -> Result<ResolvedArgv, AgentBackendError> {
    let mut out = Vec::with_capacity(argv.len());
    for el in argv {
        out.push(resolve_token(el, ctx)?);
    }
    let cwd = PathBuf::from(resolve_token(cwd_template, ctx)?);
    // First element must be absolute after resolve.
    if let Some(exe) = out.first() {
        if !Path::new(exe).is_absolute() {
            return Err(AgentBackendError::RelativeExecutable(exe.clone()));
        }
    }
    Ok(ResolvedArgv { argv: out, cwd })
}

fn resolve_token(tok: &str, ctx: &ResolveContext) -> Result<String, AgentBackendError> {
    let abs = |p: &Path| {
        let s = p.to_string_lossy().into_owned();
        if Path::new(&s).is_absolute() {
            Ok(s)
        } else {
            Err(AgentBackendError::RelativeExecutable(s))
        }
    };
    match tok {
        "{pluginRoot}" => abs(&ctx.plugin_root),
        "{pluginData}" => abs(&ctx.plugin_data),
        "{runtimeDir}" => abs(&ctx.runtime_dir),
        "{bridge}" => abs(&ctx.bridge),
        "{daemon}" => abs(&ctx.daemon),
        "{cohortId}" => Ok(ctx.cohort_id.clone()),
        "{purgeBarrier}" => abs(&ctx.purge_barrier),
        "{purgeBarrierParentIdentity}" => Ok(ctx.purge_barrier_parent_identity.clone()),
        "{purgeBarrierRevision}" => Ok(ctx.purge_barrier_revision.to_string()),
        "{provisionInput}" => {
            let p = ctx.provision_input.as_ref().ok_or_else(|| {
                AgentBackendError::MissingPlaceholder("{provisionInput}", "resolve")
            })?;
            abs(p)
        }
        other if other.starts_with('{') && other.ends_with('}') => {
            Err(AgentBackendError::BadPlaceholder(other.into()))
        }
        other => {
            if has_shell_meta(other) {
                return Err(AgentBackendError::ShellText(other.into()));
            }
            Ok(other.to_string())
        }
    }
}

/// Select the unique matching target for host os/arch/libc.
pub fn select_target<'a>(
    backend: &'a AgentBackendV1,
    os: &str,
    arch: &str,
    libc: Option<&str>,
) -> Result<&'a BackendTarget, AgentBackendError> {
    let matches: Vec<_> = backend
        .targets
        .iter()
        .filter(|t| {
            t.os == os
                && t.arch == arch
                && match (&t.libc, libc) {
                    (None, _) => true,
                    (Some(a), Some(b)) => a == b,
                    (Some(_), None) => false,
                }
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(AgentBackendError::Json(format!(
            "no target for {os}/{arch}"
        ))),
        _ => Err(AgentBackendError::DuplicateTarget {
            os: os.into(),
            arch: arch.into(),
            libc: libc.map(str::to_string),
        }),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert!(matches!(
            contained_rel_path("../x"),
            Err(AgentBackendError::PathEscape(_))
        ));
        assert!(matches!(
            contained_rel_path("/abs"),
            Err(AgentBackendError::PathEscape(_))
        ));
        assert!(contained_rel_path("bin/darwin-aarch64/go-orca").is_ok());
    }

    #[test]
    fn rejects_shell_meta_in_argv_element() {
        assert!(has_shell_meta("a;b"));
        assert!(has_shell_meta("a && b"));
        assert!(!has_shell_meta("{bridge}"));
        assert!(!has_shell_meta("--json"));
    }
}
