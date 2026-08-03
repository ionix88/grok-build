//! Core types for marketplace browse and install.
//!
//! // allow: SIZE_OK — plan Task 5 owns types.rs for source identity + backend catalog DTOs

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use xai_hooks_plugins_types::AgentBackendCatalogItem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketplacePathError {
    Empty,
    Absolute,
    ParentComponent,
    Prefix,
    CurrentComponent,
    EscapesRoot,
}

impl std::fmt::Display for MarketplacePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("marketplace path is empty"),
            Self::Absolute => f.write_str("marketplace path must be relative"),
            Self::ParentComponent => {
                f.write_str("marketplace path must not contain parent components")
            }
            Self::Prefix => f.write_str("marketplace path must not contain a platform prefix"),
            Self::CurrentComponent => {
                f.write_str("marketplace path must not contain current-directory components")
            }
            Self::EscapesRoot => f.write_str("marketplace path escapes marketplace root"),
        }
    }
}

impl std::error::Error for MarketplacePathError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MarketplaceRelativePath(String);

impl MarketplaceRelativePath {
    pub fn parse(input: &str) -> Result<Self, MarketplacePathError> {
        let stripped = input.strip_prefix("./").unwrap_or(input);
        if stripped.is_empty() {
            return Err(MarketplacePathError::Empty);
        }
        let path = Path::new(stripped);
        if path.is_absolute() {
            return Err(MarketplacePathError::Absolute);
        }

        for segment in stripped.split(['/', '\\']) {
            match segment {
                "" => return Err(MarketplacePathError::Prefix),
                "." => return Err(MarketplacePathError::CurrentComponent),
                ".." => return Err(MarketplacePathError::ParentComponent),
                value if value.contains(':') => return Err(MarketplacePathError::Prefix),
                _ => {}
            }
        }

        let mut normalized = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let part = part.to_str().ok_or(MarketplacePathError::Prefix)?;
                    for split in part.split('\\') {
                        match split {
                            "" => return Err(MarketplacePathError::Prefix),
                            "." => return Err(MarketplacePathError::CurrentComponent),
                            ".." => return Err(MarketplacePathError::ParentComponent),
                            value if value.contains(':') => {
                                return Err(MarketplacePathError::Prefix);
                            }
                            value => normalized.push(value.to_string()),
                        }
                    }
                }
                Component::CurDir => return Err(MarketplacePathError::CurrentComponent),
                Component::ParentDir => return Err(MarketplacePathError::ParentComponent),
                Component::RootDir => return Err(MarketplacePathError::Absolute),
                Component::Prefix(_) => return Err(MarketplacePathError::Prefix),
            }
        }

        if normalized.is_empty() {
            return Err(MarketplacePathError::Empty);
        }

        Ok(Self(normalized.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join_under(&self, root: &Path) -> Result<PathBuf, MarketplacePathError> {
        let candidate = root.join(&self.0);
        let canonical_root =
            dunce::canonicalize(root).map_err(|_| MarketplacePathError::EscapesRoot)?;

        let mut current = candidate.as_path();
        let mut missing_suffix = Vec::new();
        while !current.exists() {
            let Some(name) = current.file_name() else {
                return Err(MarketplacePathError::EscapesRoot);
            };
            missing_suffix.push(name.to_os_string());
            current = current.parent().ok_or(MarketplacePathError::EscapesRoot)?;
        }

        let canonical_existing =
            dunce::canonicalize(current).map_err(|_| MarketplacePathError::EscapesRoot)?;
        // Fail-closed >MAX_PATH caveat: see workspace clippy.toml.
        if !canonical_existing.starts_with(&canonical_root) {
            return Err(MarketplacePathError::EscapesRoot);
        }

        let mut resolved = canonical_existing;
        for component in missing_suffix.iter().rev() {
            resolved.push(component);
        }
        Ok(resolved)
    }
}

/// A configured marketplace source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceSource {
    /// User-facing display name.
    pub name: String,
    /// How to access the marketplace.
    pub kind: SourceKind,
}

/// How to access a marketplace source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceKind {
    /// A local directory containing a `plugins/` subdirectory.
    Local { path: PathBuf },
    /// A git repo. Cloned/pulled to a persistent cache on refresh.
    Git { url: String, branch: Option<String> },
}

/// Canonical source identity — equality key for add/list/remove/dedup.
///
/// Git identities normalize case, trailing `.git`/`/`, and GitHub URL forms.
/// Local identities use the expanded path string (callers canonicalize).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceIdentity(String);

impl SourceIdentity {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn from_source(source: &MarketplaceSource) -> Self {
        match &source.kind {
            SourceKind::Git { url, .. } => Self::from_git_url(url),
            SourceKind::Local { path } => Self(path.display().to_string()),
        }
    }

    pub fn from_git_url(url: &str) -> Self {
        let trimmed = url.trim();
        if let Some(rest) = trimmed
            .strip_prefix("github:")
            .or_else(|| trimmed.strip_prefix("GITHUB:"))
        {
            return Self(format!("github:{}", rest.to_ascii_lowercase()));
        }
        if let Some(owner_repo) = crate::canonical_github_owner_repo(url) {
            return Self(format!("github:{owner_repo}"));
        }
        let s = trimmed.strip_suffix('/').unwrap_or(trimmed);
        let s = s.strip_suffix(".git").unwrap_or(s);
        Self(s.to_ascii_lowercase())
    }

    pub fn from_local_path(path: &Path) -> Self {
        Self(path.display().to_string())
    }

    /// Parse a user-supplied identity string (git URL, github:owner/repo, or path).
    pub fn parse_user_input(input: &str) -> Self {
        let input = input.trim();
        if input.starts_with("github:")
            || input.contains("://")
            || input.starts_with("git@")
        {
            Self::from_git_url(input)
        } else {
            Self::from_local_path(Path::new(input))
        }
    }
}

impl std::fmt::Display for SourceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reachability / parse status for one source during list (no network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Ok,
    Offline,
    Malformed,
    Unreachable,
}

/// One installed plugin that depends on a marketplace source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledDependent {
    pub source_identity: String,
    pub plugin_name: String,
    pub version: Option<String>,
}

/// Bounded catalog listing entry (search/filter/details surface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogListingEntry {
    pub name: String,
    pub source_name: String,
    pub source_identity: String,
    pub qualified_name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub agent_backends: Vec<AgentBackendCatalogItem>,
    pub source_status: SourceStatus,
}

/// Result of listing across sources — per-source errors are isolated.
#[derive(Debug, Clone, Default)]
pub struct CatalogListResult {
    pub entries: Vec<CatalogListingEntry>,
    pub source_errors: Vec<SourceListError>,
}

/// Isolated failure for one source during list/search (others continue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceListError {
    pub source_name: String,
    pub source_identity: String,
    pub status: SourceStatus,
    pub message: String,
}

/// A plugin found by scanning a marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceEntry {
    /// Plugin name (from manifest or index).
    pub name: String,
    /// Version string (from manifest).
    pub version: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Category (from index, e.g., "development", "productivity").
    pub category: Option<String>,
    /// Author name.
    pub author: Option<String>,
    /// Tags/keywords (from index).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Matcher keywords (from index).
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Matcher domains (from index).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Homepage URL (from index).
    pub homepage: Option<String>,
    /// Relative path within marketplace (e.g., "plugins/xai-code-review").
    pub relative_path: String,
    /// Number of skills discovered.
    pub skill_count: usize,
    /// Whether the plugin has hooks.
    pub has_hooks: bool,
    /// Whether the plugin has agents.
    pub has_agents: bool,
    /// Whether the plugin has MCP configuration.
    pub has_mcp: bool,
    /// Remote git URL for URL-sourced plugins (not present for local plugins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    /// Git ref (branch/tag) for remote URL sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_subdir: Option<String>,
    /// Structured inventory from the marketplace catalog (`plugin-index.json`).
    /// `None` = no catalog data for this plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<xai_hooks_plugins_types::PluginComponents>,
    /// Native backend catalog summaries (presentation only; never install authority).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_backends: Vec<AgentBackendCatalogItem>,
}

/// Result of a marketplace scan, with catalog telemetry.
#[derive(Debug, Clone)]
pub struct MarketplaceScan {
    pub entries: Vec<MarketplaceEntry>,
    /// Whether a `plugin-index.json` catalog was loaded for this marketplace.
    pub catalog_loaded: bool,
}
#[cfg(test)]
mod tests {
    use super::{
        MarketplaceEntry, MarketplacePathError, MarketplaceRelativePath, SourceIdentity,
    };

    #[test]
    fn marketplace_relative_path_rejects_absolute_parent_and_prefix() {
        let rejected = [
            "/plugins/foo",
            "plugins/../secret",
            "plugins/foo/.",
            "C:\\plugins\\foo",
            "\\\\server\\share\\plugins\\foo",
        ];
        for path in rejected {
            assert!(
                MarketplaceRelativePath::parse(path).is_err(),
                "path should be rejected: {path}"
            );
        }
        assert_eq!(
            MarketplaceRelativePath::parse("").unwrap_err(),
            MarketplacePathError::Empty
        );
    }

    #[test]
    fn marketplace_relative_path_accepts_normalized_index_path() {
        let path = MarketplaceRelativePath::parse("./plugins/foo").unwrap();
        assert_eq!(path.as_str(), "plugins/foo");
        let windows_style = MarketplaceRelativePath::parse("plugins\\foo").unwrap();
        assert_eq!(windows_style.as_str(), "plugins/foo");
    }

    #[test]
    fn marketplace_relative_path_join_under_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
            let path = MarketplaceRelativePath::parse("escape").unwrap();
            assert_eq!(
                path.join_under(dir.path()).unwrap_err(),
                MarketplacePathError::EscapesRoot
            );
        }
    }

    #[test]
    fn marketplace_relative_path_join_under_rejects_symlink_ancestor_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), dir.path().join("plugins")).unwrap();
            let path = MarketplaceRelativePath::parse("plugins/evil").unwrap();
            assert_eq!(
                path.join_under(dir.path()).unwrap_err(),
                MarketplacePathError::EscapesRoot
            );
        }
    }

    #[test]
    fn discovered_plugin_serde_roundtrip() {
        let plugin = MarketplaceEntry {
            name: "test-plugin".into(),
            version: Some("1.0.0".into()),
            description: Some("A test plugin".into()),
            category: Some("development".into()),
            author: Some("Test Author".into()),
            tags: vec!["test".into(), "example".into()],
            keywords: vec!["notion.so".into()],
            domains: vec!["notion.so".into()],
            homepage: None,
            relative_path: "plugins/test-plugin".into(),
            skill_count: 3,
            has_hooks: true,
            has_agents: false,
            has_mcp: false,
            remote_url: None,
            remote_ref: None,
            remote_sha: None,
            remote_subdir: None,
            components: None,
            agent_backends: Vec::new(),
        };
        let json = serde_json::to_string(&plugin).unwrap();
        let parsed: MarketplaceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test-plugin");
        assert_eq!(parsed.keywords, vec!["notion.so"]);
    }

    #[test]
    fn source_identity_normalizes_github_urls() {
        let a = SourceIdentity::from_git_url(
            "https://github.com/xai-org/plugin-marketplace.git",
        );
        let b = SourceIdentity::from_git_url("git@github.com:XAI-org/plugin-marketplace");
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "github:xai-org/plugin-marketplace");
    }
}
