//! Parse the CI-generated `plugin-index.json` component catalog.
//!
//! Directory precedence mirrors `index::load_index`:
//! `.grok-plugin/plugin-index.json` (preferred), then
//! `.claude-plugin/plugin-index.json` — but only one filename is probed per
//! directory, and a present-but-unreadable/unparseable preferred catalog does
//! not fall back to the other directory (never serve possibly-stale data when
//! the authoritative file is broken). The catalog is presentation-layer
//! enrichment only: failures degrade to `None` and never fail a marketplace
//! listing.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use xai_hooks_plugins_types::{
    AgentBackendCatalogItem, AgentBackendTargetSummary, PluginComponents,
};

/// Catalog format version this client understands.
const SUPPORTED_VERSION: u64 = 1;

/// Hard cap on catalog file size (bytes). Oversized indexes isolate the source.
pub const MAX_CATALOG_BYTES: u64 = 2 * 1024 * 1024;

/// Max plugins accepted from one catalog file.
pub const MAX_CATALOG_PLUGINS: usize = 512;

/// Top-level `plugin-index.json` catalog, keyed by index plugin name.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginCatalog {
    pub version: u64,
    #[serde(default)]
    pub plugins: HashMap<String, CatalogEntry>,
}

/// Per-plugin catalog entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    /// Commit the components were extracted from (required for URL-sourced
    /// entries; optional for in-repo plugins).
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub components: PluginComponents,
    /// Native backend summaries — presentation only, never install authority.
    #[serde(default, deserialize_with = "deserialize_agent_backends")]
    pub agent_backends: Vec<AgentBackendCatalogItem>,
}

/// Wire shape accepts nested `requires` / `artifact` objects from fixtures.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBackend {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    requires: Option<RawRequires>,
    #[serde(default)]
    requires_orca: Option<String>,
    #[serde(default)]
    requires_acp: Option<String>,
    #[serde(default)]
    targets: Vec<RawTarget>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    discloses_native_code: bool,
    #[serde(default)]
    install_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRequires {
    #[serde(default)]
    orca: Option<String>,
    #[serde(default)]
    acp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTarget {
    os: String,
    arch: String,
    #[serde(default)]
    libc: Option<String>,
    #[serde(default)]
    artifact: Option<RawArtifact>,
    #[serde(default)]
    artifact_sha256: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    has_signature: bool,
    #[serde(default)]
    has_provenance: bool,
    #[serde(default)]
    has_sbom: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawArtifact {
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    has_signature: bool,
    #[serde(default)]
    has_provenance: bool,
    #[serde(default)]
    has_sbom: bool,
}

fn deserialize_agent_backends<'de, D>(
    deserializer: D,
) -> Result<Vec<AgentBackendCatalogItem>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<RawBackend> = Vec::deserialize(deserializer)?;
    Ok(raw.into_iter().map(raw_backend_to_item).collect())
}

fn raw_backend_to_item(raw: RawBackend) -> AgentBackendCatalogItem {
    let requires_orca = raw
        .requires_orca
        .or_else(|| raw.requires.as_ref().and_then(|r| r.orca.clone()));
    let requires_acp = raw
        .requires_acp
        .or_else(|| raw.requires.as_ref().and_then(|r| r.acp.clone()));
    let targets = raw
        .targets
        .into_iter()
        .map(|t| {
            let (sha, media, sig, prov, sbom) = if let Some(a) = t.artifact {
                (
                    a.sha256.or(t.artifact_sha256),
                    a.media_type.or(t.media_type),
                    a.has_signature || t.has_signature,
                    a.has_provenance || t.has_provenance,
                    a.has_sbom || t.has_sbom,
                )
            } else {
                (
                    t.artifact_sha256,
                    t.media_type,
                    t.has_signature,
                    t.has_provenance,
                    t.has_sbom,
                )
            };
            AgentBackendTargetSummary {
                os: t.os,
                arch: t.arch,
                libc: t.libc,
                artifact_sha256: sha,
                media_type: media,
                has_signature: sig,
                has_provenance: prov,
                has_sbom: sbom,
            }
        })
        .collect();
    AgentBackendCatalogItem {
        id: raw.id,
        display_name: raw.display_name,
        version: raw.version,
        requires_orca,
        requires_acp,
        targets,
        permissions: raw.permissions,
        discloses_native_code: raw.discloses_native_code,
        install_authority: raw.install_authority,
    }
}

/// Why catalog load failed (isolated; listing continues for other sources).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogLoadError {
    Missing,
    Oversized { bytes: u64 },
    Malformed(String),
    UnsupportedVersion(u64),
    Io(String),
}

impl PluginCatalog {
    /// Components for an index entry, gated on the pinned SHA for
    /// URL-sourced entries: when `index_sha` is `Some`, the catalog entry
    /// must carry an equal `sha` or the components are treated as absent.
    pub fn components_for(
        &self,
        index_name: &str,
        index_sha: Option<&str>,
    ) -> Option<&PluginComponents> {
        let entry = self.entry_if_sha_ok(index_name, index_sha)?;
        Some(&entry.components)
    }

    /// Backend catalog summaries for an index entry (never install authority).
    pub fn agent_backends_for(
        &self,
        index_name: &str,
        index_sha: Option<&str>,
    ) -> Option<&[AgentBackendCatalogItem]> {
        let entry = self.entry_if_sha_ok(index_name, index_sha)?;
        if entry.agent_backends.is_empty() {
            None
        } else {
            Some(entry.agent_backends.as_slice())
        }
    }

    fn entry_if_sha_ok(
        &self,
        index_name: &str,
        index_sha: Option<&str>,
    ) -> Option<&CatalogEntry> {
        let entry = self.plugins.get(index_name)?;
        if let Some(expected) = index_sha
            && entry.sha.as_deref() != Some(expected)
        {
            tracing::debug!(
                plugin = index_name,
                catalog_sha = entry.sha.as_deref().unwrap_or(""),
                index_sha = expected,
                "marketplace catalog sha mismatch; hiding components"
            );
            return None;
        }
        Some(entry)
    }
}

/// Load `plugin-index.json` from a marketplace root, or `None` when absent,
/// malformed, or of an unsupported version. A missing file falls through to
/// the next candidate directory; a broken one does not (see module docs).
pub fn load_catalog(marketplace_root: &Path) -> Option<PluginCatalog> {
    match load_catalog_detailed(marketplace_root) {
        Ok(c) => Some(c),
        Err(CatalogLoadError::Missing) => None,
        Err(e) => {
            tracing::warn!("marketplace catalog load failed: {e:?}");
            None
        }
    }
}

/// Load catalog with typed failure reason (oversized / malformed / missing).
pub fn load_catalog_detailed(marketplace_root: &Path) -> Result<PluginCatalog, CatalogLoadError> {
    let candidates = [
        marketplace_root
            .join(".grok-plugin")
            .join("plugin-index.json"),
        marketplace_root
            .join(".claude-plugin")
            .join("plugin-index.json"),
    ];
    for path in &candidates {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(CatalogLoadError::Io(format!("{}: {e}", path.display())));
            }
        };
        let bytes = meta.len();
        if bytes > MAX_CATALOG_BYTES {
            return Err(CatalogLoadError::Oversized { bytes });
        }
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                return Err(CatalogLoadError::Io(format!("{}: {e}", path.display())));
            }
        };
        return parse_catalog_json(&content);
    }
    Err(CatalogLoadError::Missing)
}

/// Parse catalog JSON bytes (used by fixtures and loaders).
pub fn parse_catalog_json(content: &str) -> Result<PluginCatalog, CatalogLoadError> {
    if content.len() as u64 > MAX_CATALOG_BYTES {
        return Err(CatalogLoadError::Oversized {
            bytes: content.len() as u64,
        });
    }
    let mut catalog: PluginCatalog = serde_json::from_str(content)
        .map_err(|e| CatalogLoadError::Malformed(e.to_string()))?;
    if catalog.version != SUPPORTED_VERSION {
        return Err(CatalogLoadError::UnsupportedVersion(catalog.version));
    }
    if catalog.plugins.len() > MAX_CATALOG_PLUGINS {
        return Err(CatalogLoadError::Malformed(format!(
            "too many plugins: {} > {MAX_CATALOG_PLUGINS}",
            catalog.plugins.len()
        )));
    }
    for entry in catalog.plugins.values_mut() {
        entry.components.sanitize();
        entry.agent_backends.truncate(16);
        entry.agent_backends.retain_mut(|b| {
            b.sanitize();
            AgentBackendCatalogItem::is_valid_id(&b.id)
        });
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_catalog(dir: &Path, subdir: &str, content: &str) {
        let d = dir.join(subdir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("plugin-index.json"), content).unwrap();
    }

    const BASIC: &str = r#"{
        "version": 1,
        "plugins": {
            "superpowers": {
                "sha": "61f1903bed7b322c9745f6ba67095bc006de7e63",
                "components": {
                    "skills": [
                        { "name": "brainstorming", "description": "Structured ideation" }
                    ],
                    "commands": [ { "name": "/brainstorm" } ],
                    "hooks": [ { "name": "PreToolUse", "description": "Bash" } ]
                }
            }
        }
    }"#;

    #[test]
    fn load_catalog_parses_grok_plugin_dir() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".grok-plugin", BASIC);
        let catalog = load_catalog(dir.path()).unwrap();
        let components = catalog.components_for("superpowers", None).unwrap();
        assert_eq!(components.skills.len(), 1);
        assert_eq!(components.skills[0].name, "brainstorming");
        assert_eq!(
            components.skills[0].description.as_deref(),
            Some("Structured ideation")
        );
        assert_eq!(components.commands[0].name, "/brainstorm");
        assert_eq!(components.hooks[0].name, "PreToolUse");
        assert!(components.agents.is_empty());
    }

    #[test]
    fn load_catalog_falls_back_to_claude_plugin_dir() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".claude-plugin", BASIC);
        assert!(load_catalog(dir.path()).is_some());
    }

    #[test]
    fn load_catalog_prefers_grok_dir_over_claude_dir() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".grok-plugin", BASIC);
        write_catalog(
            dir.path(),
            ".claude-plugin",
            r#"{"version": 1, "plugins": {"other": {"components": {}}}}"#,
        );
        let catalog = load_catalog(dir.path()).unwrap();
        assert!(catalog.plugins.contains_key("superpowers"));
        assert!(!catalog.plugins.contains_key("other"));
    }

    #[test]
    fn load_catalog_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_catalog(dir.path()).is_none());
    }

    #[test]
    fn load_catalog_malformed_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".grok-plugin", "not json");
        assert!(load_catalog(dir.path()).is_none());
    }

    #[test]
    fn load_catalog_broken_preferred_does_not_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".grok-plugin", "not json");
        write_catalog(dir.path(), ".claude-plugin", BASIC);
        assert!(load_catalog(dir.path()).is_none());
    }

    #[test]
    fn load_catalog_unsupported_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(
            dir.path(),
            ".grok-plugin",
            r#"{"version": 2, "plugins": {}}"#,
        );
        assert!(load_catalog(dir.path()).is_none());
    }

    #[test]
    fn load_catalog_ignores_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(
            dir.path(),
            ".grok-plugin",
            r#"{
                "$schema": "https://x.ai/grok/plugin-index.schema.json",
                "version": 1,
                "generatedAt": "2026-06-09T12:00:00Z",
                "plugins": {
                    "p": { "components": { "skills": [{"name": "s", "extra": 1}] }, "future": true }
                }
            }"#,
        );
        let catalog = load_catalog(dir.path()).unwrap();
        assert_eq!(
            catalog.components_for("p", None).unwrap().skills[0].name,
            "s"
        );
    }

    #[test]
    fn load_catalog_sanitizes_entries() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(
            dir.path(),
            ".grok-plugin",
            r#"{
                "version": 1,
                "plugins": {
                    "p": { "components": { "skills": [{"name": "a\u001b[31mb", "description": "x\u0007y"}] } }
                }
            }"#,
        );
        let catalog = load_catalog(dir.path()).unwrap();
        let components = catalog.components_for("p", None).unwrap();
        assert_eq!(components.skills[0].name, "a[31mb");
        assert_eq!(components.skills[0].description.as_deref(), Some("xy"));
    }

    #[test]
    fn components_for_gates_on_sha() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(dir.path(), ".grok-plugin", BASIC);
        let catalog = load_catalog(dir.path()).unwrap();
        let pinned = "61f1903bed7b322c9745f6ba67095bc006de7e63";
        assert!(
            catalog
                .components_for("superpowers", Some(pinned))
                .is_some()
        );
        assert!(
            catalog
                .components_for("superpowers", Some("deadbeef"))
                .is_none()
        );
        assert!(catalog.components_for("unknown", None).is_none());
    }

    #[test]
    fn components_for_requires_catalog_sha_when_index_pinned() {
        let dir = tempfile::tempdir().unwrap();
        write_catalog(
            dir.path(),
            ".grok-plugin",
            r#"{"version": 1, "plugins": {"p": {"components": {"skills": [{"name": "s"}]}}}}"#,
        );
        let catalog = load_catalog(dir.path()).unwrap();
        assert!(catalog.components_for("p", Some("abc123")).is_none());
        assert!(catalog.components_for("p", None).is_some());
    }
}
