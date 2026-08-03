//! Installed backend registry: built-in `native` plus validated v2 receipts only.
//!
//! // allow: SIZE_OK — plan Task 11 freezes registry discovery in one module

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::plugin_host::receipts::{
    InstallReceiptV1, ReceiptError, RegistryDocumentV2, TrustState, REGISTRY_SCHEMA_V2,
};
use xai_grok_agent::plugins::agent_backend::{
    host_platform_label, parse_target_label, refuse_native_backend_source, target_matches_host,
    HostPlatform, NativeBackendSource,
};

/// Built-in backend id (D02). Always registered and selectable.
pub const NATIVE_BACKEND_ID: &str = "native";
/// Source-qualified identity for the built-in native descriptor.
pub const NATIVE_SOURCE: &str = "builtin:native";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendRegistryError {
    #[error("json: {0}")]
    Json(String),
    #[error("receipt: {0}")]
    Receipt(String),
    #[error("unsupported registry schemaVersion {0}")]
    UnsupportedSchema(u32),
    #[error("forged registry row: {0}")]
    ForgedRow(String),
    #[error("missing receipt: {0}")]
    MissingReceipt(String),
    #[error("install path owner/root drift: {0}")]
    PathOwner(String),
    #[error("PATH-only executable cannot register a backend: {0}")]
    PathOnlyExecutable(String),
    #[error("project-local native backend refused: {0}")]
    ProjectLocalNative(String),
    #[error("source checkout cannot register a backend: {0}")]
    SourceCheckout(String),
    #[error("v1 manifest cannot register native code: {0}")]
    V1Manifest(String),
    #[error("duplicate backend id {backend_id}: sources {sources:?}")]
    DuplicateBackendId {
        backend_id: String,
        sources: Vec<String>,
    },
    #[error("corrupt registry: {0}")]
    Corrupt(String),
    #[error("native backend source refused: {0}")]
    NativeSourceRefused(String),
}

impl From<ReceiptError> for BackendRegistryError {
    fn from(e: ReceiptError) -> Self {
        match e {
            ReceiptError::Digest(d) => Self::ForgedRow(d),
            ReceiptError::UnsupportedSchema(v) => Self::UnsupportedSchema(v),
            ReceiptError::Json(j) => Self::Json(j),
            other => Self::Receipt(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Native,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enablement {
    Enabled,
    Disabled { reason: String },
    Quarantined { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    Compatible,
    Incompatible { reason: String },
}

/// Health is never probed during discovery (no spawn).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    NotProbed,
}

/// One diagnosable backend version (native or external install receipt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDescriptor {
    pub backend_id: String,
    pub version: Option<String>,
    pub kind: BackendKind,
    pub target: Option<String>,
    pub trust: Option<TrustState>,
    pub enablement: Enablement,
    pub compatibility: Compatibility,
    pub health: HealthStatus,
    pub receipt_digest: Option<String>,
    pub install_root: Option<String>,
    /// Source-qualified identity (`builtin:native`, `receipt:<digest>`).
    pub source: String,
    pub selectable: bool,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendConflict {
    pub backend_id: String,
    pub sources: Vec<String>,
}

/// Options controlling enablement overlays and path binding.
#[derive(Debug, Clone, Default)]
pub struct DiscoverOpts {
    /// Backend ids explicitly disabled by user/config (logical id only).
    pub disabled_backend_ids: BTreeSet<String>,
    /// When set, receipt `installRoot` must resolve under this plugins directory.
    pub plugins_root: Option<PathBuf>,
    /// When set with `plugins_root`, require install tree ownership match (unix uid).
    #[cfg(unix)]
    pub expected_owner_uid: Option<u32>,
}

/// Host registry of installed backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRegistry {
    descriptors: Vec<BackendDescriptor>,
    conflicts: Vec<BackendConflict>,
}

impl BackendRegistry {
    /// Built-in native only (no external receipts).
    pub fn native_only() -> Self {
        Self {
            descriptors: vec![native_descriptor()],
            conflicts: Vec::new(),
        }
    }

    /// Discover backends: always `native`, plus validated v2 receipts only.
    pub fn discover(
        doc: Option<&RegistryDocumentV2>,
        host: &HostPlatform,
        opts: &DiscoverOpts,
    ) -> Result<Self, BackendRegistryError> {
        let mut descriptors = vec![native_descriptor()];
        let mut conflicts = Vec::new();
        // backend_id -> sources seen (for cross-source duplicate detection)
        let mut sources_by_id: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        sources_by_id
            .entry(NATIVE_BACKEND_ID.into())
            .or_default()
            .insert(NATIVE_SOURCE.into());

        if let Some(doc) = doc {
            if doc.schema_version != REGISTRY_SCHEMA_V2 {
                return Err(BackendRegistryError::UnsupportedSchema(doc.schema_version));
            }
            doc.validate()?;
            for receipt in doc.receipts.values() {
                // Content-only receipts (no native code) never enter the backend registry.
                if !receipt.native_code {
                    continue;
                }
                let source = format!("receipt:{}", receipt.receipt_digest);
                let backend_id = receipt.plugin_id.clone();
                if backend_id == NATIVE_BACKEND_ID {
                    // Receipts must not claim the reserved native id.
                    let entry = sources_by_id.entry(backend_id.clone()).or_default();
                    entry.insert(source.clone());
                    conflicts.push(BackendConflict {
                        backend_id: backend_id.clone(),
                        sources: entry.iter().cloned().collect(),
                    });
                    let mut d = descriptor_from_receipt(receipt, host, opts);
                    d.selectable = false;
                    d.diagnostic = Some(format!(
                        "duplicate backend id {NATIVE_BACKEND_ID}: reserved builtin"
                    ));
                    descriptors.push(d);
                    continue;
                }
                if let Some(root) = &opts.plugins_root {
                    bind_install_root(receipt, root, opts)?;
                }
                let desc = descriptor_from_receipt(receipt, host, opts);
                let entry = sources_by_id.entry(backend_id.clone()).or_default();
                // Same backend id from a different receipt source is OK when versions differ;
                // conflict only when the same version identity collides across sources.
                let version_key = format!("{}@{}", backend_id, receipt.version);
                let prior_same_version = descriptors.iter().any(|d| {
                    d.backend_id == backend_id
                        && d.version.as_deref() == Some(receipt.version.as_str())
                        && d.source != source
                });
                entry.insert(source.clone());
                if prior_same_version {
                    conflicts.push(BackendConflict {
                        backend_id: backend_id.clone(),
                        sources: entry.iter().cloned().collect(),
                    });
                    let mut d = desc;
                    d.selectable = false;
                    d.diagnostic =
                        Some(format!("duplicate backend id {backend_id} ({version_key})"));
                    descriptors.push(d);
                    continue;
                }
                descriptors.push(desc);
            }
        }

        // Apply reserved-id / multi-source conflicts: any backend_id that also
        // collides with native is non-selectable.
        for c in &conflicts {
            for d in &mut descriptors {
                if d.backend_id == c.backend_id && d.kind != BackendKind::Native {
                    d.selectable = false;
                    d.diagnostic = Some(format!(
                        "duplicate backend id {}: sources {:?}",
                        c.backend_id, c.sources
                    ));
                }
            }
        }

        Ok(Self {
            descriptors,
            conflicts,
        })
    }

    /// Load and validate a registry-v2 document from disk, then discover.
    pub fn load_from_path(
        path: &Path,
        host: &HostPlatform,
        opts: &DiscoverOpts,
    ) -> Result<Self, BackendRegistryError> {
        if !path.is_file() {
            return Err(BackendRegistryError::MissingReceipt(
                path.display().to_string(),
            ));
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| BackendRegistryError::Corrupt(format!("read {}: {e}", path.display())))?;
        let doc = RegistryDocumentV2::parse_json(&raw)?;
        Self::discover(Some(&doc), host, opts)
    }

    /// Refuse non-receipt native registration attempts (project/PATH/source/v1).
    pub fn refuse_external_source(
        source: NativeBackendSource,
        detail: &str,
    ) -> BackendRegistryError {
        match refuse_native_backend_source(source) {
            Ok(()) => BackendRegistryError::Corrupt(format!(
                "refuse_external_source called for legal receipt source: {detail}"
            )),
            Err(NativeBackendSource::ProjectTree) => {
                BackendRegistryError::ProjectLocalNative(detail.into())
            }
            Err(NativeBackendSource::PathLookup) => {
                BackendRegistryError::PathOnlyExecutable(detail.into())
            }
            Err(NativeBackendSource::SourceCheckout) => {
                BackendRegistryError::SourceCheckout(detail.into())
            }
            Err(NativeBackendSource::ManifestV1) => BackendRegistryError::V1Manifest(detail.into()),
            Err(NativeBackendSource::ContentPluginDiscovery) => {
                BackendRegistryError::NativeSourceRefused(detail.into())
            }
            Err(NativeBackendSource::InstallReceiptV2) => {
                BackendRegistryError::Corrupt(detail.into())
            }
        }
    }

    /// Attempt to register a PATH-resolved executable as a backend — always fails.
    pub fn register_path_executable(exe_name: &str) -> Result<(), BackendRegistryError> {
        Err(Self::refuse_external_source(
            NativeBackendSource::PathLookup,
            exe_name,
        ))
    }

    /// Attempt to register a project-local agentBackends claim — always fails.
    pub fn register_project_native(plugin_path: &str) -> Result<(), BackendRegistryError> {
        Err(Self::refuse_external_source(
            NativeBackendSource::ProjectTree,
            plugin_path,
        ))
    }

    /// Attempt to register from a v1 content manifest — always fails.
    pub fn register_v1_manifest(plugin_id: &str) -> Result<(), BackendRegistryError> {
        Err(Self::refuse_external_source(
            NativeBackendSource::ManifestV1,
            plugin_id,
        ))
    }

    /// Attempt to register from a source checkout — always fails.
    pub fn register_source_checkout(path: &str) -> Result<(), BackendRegistryError> {
        Err(Self::refuse_external_source(
            NativeBackendSource::SourceCheckout,
            path,
        ))
    }

    pub fn list(&self) -> &[BackendDescriptor] {
        &self.descriptors
    }

    pub fn conflicts(&self) -> &[BackendConflict] {
        &self.conflicts
    }

    pub fn selectable(&self) -> impl Iterator<Item = &BackendDescriptor> {
        self.descriptors.iter().filter(|d| d.selectable)
    }

    pub fn native(&self) -> &BackendDescriptor {
        self.descriptors
            .iter()
            .find(|d| d.kind == BackendKind::Native)
            .expect("native is always registered")
    }

    pub fn by_id_version(&self, id: &str, version: Option<&str>) -> Option<&BackendDescriptor> {
        self.descriptors.iter().find(|d| {
            d.backend_id == id
                && match (version, &d.version) {
                    (None, None) => true,
                    (Some(v), Some(dv)) => v == dv,
                    (None, Some(_)) => false,
                    (Some(_), None) => false,
                }
        })
    }

    /// All versions for a backend id (diagnosable, including non-selectable).
    pub fn versions_of(&self, id: &str) -> Vec<&BackendDescriptor> {
        self.descriptors
            .iter()
            .filter(|d| d.backend_id == id)
            .collect()
    }

    /// Normalized list/status lines for host surfaces and ORCA_QA evidence.
    ///
    /// Stable machine-oriented rows (no prose). Sorted by backend_id then version.
    /// Does not spawn processes or probe health.
    pub fn format_status_lines(&self) -> Vec<String> {
        let mut rows: Vec<&BackendDescriptor> = self.descriptors.iter().collect();
        rows.sort_by(|a, b| {
            (
                a.backend_id.as_str(),
                a.version.as_deref().unwrap_or(""),
                a.source.as_str(),
            )
                .cmp(&(
                    b.backend_id.as_str(),
                    b.version.as_deref().unwrap_or(""),
                    b.source.as_str(),
                ))
        });
        rows.into_iter()
            .map(|d| {
                let version = d.version.as_deref().unwrap_or("-");
                let target = d.target.as_deref().unwrap_or("-");
                let trust = match &d.trust {
                    None => "builtin",
                    Some(TrustState::Consented { .. }) => "consented",
                    Some(TrustState::Untrusted) => "untrusted",
                    Some(TrustState::Revoked { .. }) => "revoked",
                };
                let enablement = match &d.enablement {
                    Enablement::Enabled => "enabled",
                    Enablement::Disabled { .. } => "disabled",
                    Enablement::Quarantined { .. } => "quarantined",
                };
                let compatibility = match &d.compatibility {
                    Compatibility::Compatible => "compatible",
                    Compatibility::Incompatible { .. } => "incompatible",
                };
                let selectable = if d.selectable { "yes" } else { "no" };
                let kind = match d.kind {
                    BackendKind::Native => "native",
                    BackendKind::External => "external",
                };
                let health = match d.health {
                    HealthStatus::NotProbed => "not_probed",
                };
                let digest = d.receipt_digest.as_deref().unwrap_or("-");
                format!(
                    "id={id} version={version} kind={kind} target={target} trust={trust} \
                     enablement={enablement} compatibility={compatibility} health={health} \
                     selectable={selectable} source={src} receipt={digest}",
                    id = d.backend_id,
                    src = d.source,
                )
            })
            .collect()
    }
}

fn native_descriptor() -> BackendDescriptor {
    let host = HostPlatform::current();
    BackendDescriptor {
        backend_id: NATIVE_BACKEND_ID.into(),
        version: None,
        kind: BackendKind::Native,
        target: Some(host_platform_label(&host)),
        trust: None,
        enablement: Enablement::Enabled,
        compatibility: Compatibility::Compatible,
        health: HealthStatus::NotProbed,
        receipt_digest: None,
        install_root: None,
        source: NATIVE_SOURCE.into(),
        selectable: true,
        diagnostic: None,
    }
}

fn descriptor_from_receipt(
    receipt: &InstallReceiptV1,
    host: &HostPlatform,
    opts: &DiscoverOpts,
) -> BackendDescriptor {
    let source = format!("receipt:{}", receipt.receipt_digest);
    let compatibility = match parse_target_label(&receipt.target) {
        Ok(t) if target_matches_host(host, &t) => Compatibility::Compatible,
        Ok(_) => Compatibility::Incompatible {
            reason: format!(
                "target {} incompatible with host {}",
                receipt.target,
                host_platform_label(host)
            ),
        },
        Err(e) => Compatibility::Incompatible {
            reason: format!("bad target {}: {e}", receipt.target),
        },
    };

    let enablement = if opts.disabled_backend_ids.contains(&receipt.plugin_id) {
        Enablement::Disabled {
            reason: "user-disabled".into(),
        }
    } else {
        match &receipt.trust {
            TrustState::Revoked { .. } => Enablement::Quarantined {
                reason: "trust-revoked".into(),
            },
            TrustState::Untrusted => Enablement::Disabled {
                reason: "untrusted".into(),
            },
            TrustState::Consented { .. } => Enablement::Enabled,
        }
    };

    let trust_ok = matches!(receipt.trust, TrustState::Consented { .. });
    let enabled = matches!(enablement, Enablement::Enabled);
    let compatible = matches!(compatibility, Compatibility::Compatible);
    let selectable = enabled && compatible && trust_ok;

    let mut diagnostic = None;
    if !selectable {
        diagnostic = Some(match &enablement {
            Enablement::Disabled { reason } => reason.clone(),
            Enablement::Quarantined { reason } => reason.clone(),
            Enablement::Enabled => match &compatibility {
                Compatibility::Incompatible { reason } => reason.clone(),
                Compatibility::Compatible if !trust_ok => "trust-not-consented".into(),
                Compatibility::Compatible => "not-selectable".into(),
            },
        });
    }

    BackendDescriptor {
        backend_id: receipt.plugin_id.clone(),
        version: Some(receipt.version.clone()),
        kind: BackendKind::External,
        target: Some(receipt.target.clone()),
        trust: Some(receipt.trust.clone()),
        enablement,
        compatibility,
        health: HealthStatus::NotProbed,
        receipt_digest: Some(receipt.receipt_digest.clone()),
        install_root: Some(receipt.install_root.clone()),
        source,
        selectable,
        diagnostic,
    }
}

fn bind_install_root(
    receipt: &InstallReceiptV1,
    plugins_root: &Path,
    opts: &DiscoverOpts,
) -> Result<(), BackendRegistryError> {
    let root = Path::new(&receipt.install_root);
    let bound = if root.is_absolute() {
        // Lexical normalize both sides so `plugins_root/../../../etc/passwd`
        // cannot pass a raw Path::starts_with prefix check.
        let root_n = lexical_normalize(root);
        let plugins_n = lexical_normalize(plugins_root);
        if !path_is_under(&root_n, &plugins_n) {
            return Err(BackendRegistryError::PathOwner(format!(
                "installRoot {} escapes plugins root {}",
                receipt.install_root,
                plugins_root.display()
            )));
        }
        root_n
    } else {
        if receipt.install_root.contains("..")
            || receipt.install_root.starts_with('/')
            || receipt.install_root.starts_with('\\')
        {
            return Err(BackendRegistryError::PathOwner(
                receipt.install_root.clone(),
            ));
        }
        lexical_normalize(&plugins_root.join(root))
    };

    #[cfg(unix)]
    if let Some(expected) = opts.expected_owner_uid {
        if bound.exists() {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&bound).map_err(|e| {
                BackendRegistryError::PathOwner(format!("{}: {e}", bound.display()))
            })?;
            if meta.uid() != expected {
                return Err(BackendRegistryError::PathOwner(format!(
                    "uid {} != expected {expected} for {}",
                    meta.uid(),
                    bound.display()
                )));
            }
        }
    }
    let _ = opts;
    Ok(())
}

/// Collapse `.` / `..` without touching the filesystem (receipts need not exist).
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // At root/prefix or empty: stay put (Unix `/..` == `/`).
                _ => {}
            },
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Component-wise containment after both sides are lexically normalized.
///
/// Safe only when `..` has already been collapsed — raw `starts_with` alone
/// accepts `plugins_root/../../../etc/passwd`.
fn path_is_under(child: &Path, parent: &Path) -> bool {
    child.starts_with(parent)
}

#[cfg(test)]
#[path = "registry_test.rs"]
mod registry_test;
