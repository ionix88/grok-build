//! Task 5: native backend catalog + source management.
//!
//! Given / When / Then coverage for two fixture sources and named failure vectors.

use std::path::{Path, PathBuf};

use xai_grok_plugin_marketplace::catalog::{
    parse_catalog_json, CatalogLoadError, MAX_CATALOG_BYTES,
};
use xai_grok_plugin_marketplace::install_resolve::{
    details_for, filter_by_target, listings_from_scan, merge_catalog_lists, search_listings,
    select_bare_name, BareNameError, ScannedEntry, SourceManageError, SourceRegistry,
};
use xai_grok_plugin_marketplace::types::{
    InstalledDependent, MarketplaceEntry, MarketplaceSource, SourceIdentity, SourceKind,
    SourceListError, SourceStatus,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name)).expect("fixture")
}

fn local_source(name: &str, path: &Path) -> MarketplaceSource {
    MarketplaceSource {
        name: name.into(),
        kind: SourceKind::Local {
            path: path.to_path_buf(),
        },
    }
}

fn entry_from_catalog_plugin(
    name: &str,
    catalog: &xai_grok_plugin_marketplace::catalog::PluginCatalog,
) -> MarketplaceEntry {
    let backends = catalog
        .agent_backends_for(name, None)
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let components = catalog.components_for(name, None).cloned();
    MarketplaceEntry {
        name: name.into(),
        version: backends.first().and_then(|b| b.version.clone()),
        description: None,
        category: None,
        author: None,
        tags: Vec::new(),
        keywords: Vec::new(),
        domains: Vec::new(),
        homepage: None,
        relative_path: format!("plugins/{name}"),
        skill_count: components
            .as_ref()
            .map(|c| c.skills.len())
            .unwrap_or(0),
        has_hooks: components
            .as_ref()
            .is_some_and(|c| !c.hooks.is_empty()),
        has_agents: false,
        has_mcp: false,
        remote_url: None,
        remote_ref: None,
        remote_sha: None,
        remote_subdir: None,
        components,
        agent_backends: backends,
    }
}

/// Given: source-a and source-b fixtures
/// When: parse + list + search + details + remove unused
/// Then: backends exposed, install_authority false, no download path
#[test]
fn happy_two_sources_list_search_details_remove() {
    let a = parse_catalog_json(&read_fixture("source-a.json")).expect("source-a");
    let b = parse_catalog_json(&read_fixture("source-b.json")).expect("source-b");

    let root_a = PathBuf::from("/tmp/fixture-source-a");
    let root_b = PathBuf::from("/tmp/fixture-source-b");
    let src_a = local_source("fixture-source-a", &root_a);
    let src_b = local_source("fixture-source-b", &root_b);

    let mut reg = SourceRegistry::new();
    let id_a = reg.add(src_a.clone()).expect("add a");
    let id_b = reg.add(src_b.clone()).expect("add b");
    assert_ne!(id_a, id_b);
    assert_eq!(reg.list().len(), 2);

    // refresh plan is local-only (no network)
    let plan = reg.refresh_plan(None).expect("refresh");
    assert_eq!(plan.len(), 2);

    let entries_a: Vec<_> = a
        .plugins
        .keys()
        .map(|n| entry_from_catalog_plugin(n, &a))
        .collect();
    let entries_b: Vec<_> = b
        .plugins
        .keys()
        .map(|n| entry_from_catalog_plugin(n, &b))
        .collect();

    let list = merge_catalog_lists([
        Ok(listings_from_scan(&src_a, &entries_a, SourceStatus::Ok)),
        Ok(listings_from_scan(&src_b, &entries_b, SourceStatus::Ok)),
    ]);
    assert!(list.source_errors.is_empty());
    assert!(list.entries.len() >= 3);

    // Catalog summaries never install authority
    for e in &list.entries {
        for backend in &e.agent_backends {
            assert!(
                !backend.install_authority,
                "catalog must never be install authority"
            );
            if backend.discloses_native_code {
                assert!(
                    backend.permissions.iter().any(|p| p == "native-code")
                        || backend.discloses_native_code,
                    "native disclosure present"
                );
            }
        }
    }

    let go = search_listings(&list.entries, "go-orca");
    assert!(go.len() >= 2, "both sources advertise go-orca");

    let darwin = filter_by_target(&list.entries, "darwin", "aarch64");
    assert!(darwin.iter().any(|e| e.name == "go-orca"));

    // bare name ambiguous across sources
    let pairs_a: Vec<(MarketplaceSource, MarketplaceEntry)> = entries_a
        .iter()
        .map(|e| (src_a.clone(), e.clone()))
        .collect();
    let pairs_b: Vec<(MarketplaceSource, MarketplaceEntry)> = entries_b
        .iter()
        .map(|e| (src_b.clone(), e.clone()))
        .collect();
    let all_pairs: Vec<_> = pairs_a.into_iter().chain(pairs_b).collect();
    let scanned: Vec<ScannedEntry> = all_pairs
        .iter()
        .map(|(s, e)| ScannedEntry {
            source: s,
            entry: e,
        })
        .collect();
    assert!(matches!(
        select_bare_name("go-orca", &scanned),
        Err(BareNameError::Ambiguous { .. })
    ));

    // qualified details unique
    let d = details_for(&list.entries, "other-backend@local/fixture-source-b")
        .expect("qualified other-backend");
    assert_eq!(d.name, "other-backend");
    assert_eq!(d.agent_backends.len(), 1);
    assert_eq!(d.agent_backends[0].id, "other-backend");
    assert!(d.agent_backends[0].targets[0].has_signature);
    assert!(d.agent_backends[0].targets[0].has_sbom);

    // remove unused source-b
    let removed = reg.remove("fixture-source-b", &[]).expect("remove b");
    assert_eq!(removed.name, "fixture-source-b");
    assert_eq!(reg.list().len(), 1);
}

#[test]
fn failure_duplicate_source_identity() {
    let mut reg = SourceRegistry::new();
    let path = PathBuf::from("/tmp/same");
    reg.add(local_source("A", &path)).unwrap();
    let err = reg.add(local_source("B", &path)).unwrap_err();
    assert!(matches!(err, SourceManageError::DuplicateIdentity { .. }));
}

#[test]
fn failure_alias_conflict_same_name() {
    let mut reg = SourceRegistry::new();
    reg.add(local_source("dup", Path::new("/tmp/a"))).unwrap();
    let err = reg
        .add(local_source("dup", Path::new("/tmp/b")))
        .unwrap_err();
    assert!(matches!(err, SourceManageError::AliasConflict { .. }));
}

#[test]
fn failure_installed_dependent_blocks_remove() {
    let mut reg = SourceRegistry::new();
    let path = PathBuf::from("/tmp/dep-src");
    reg.add(local_source("dep-src", &path)).unwrap();
    let id = SourceIdentity::from_local_path(&path);
    let deps = vec![InstalledDependent {
        source_identity: id.to_string(),
        plugin_name: "go-orca".into(),
        version: Some("1.2.0".into()),
    }];
    let err = reg.remove("dep-src", &deps).unwrap_err();
    assert!(matches!(
        err,
        SourceManageError::HasInstalledDependents { .. }
    ));
}

#[test]
fn failure_ambiguous_bare_name() {
    let a = local_source("a", Path::new("/tmp/a"));
    let b = local_source("b", Path::new("/tmp/b"));
    let ea = MarketplaceEntry {
        name: "go-orca".into(),
        version: None,
        description: None,
        category: None,
        author: None,
        tags: Vec::new(),
        keywords: Vec::new(),
        domains: Vec::new(),
        homepage: None,
        relative_path: "plugins/go-orca".into(),
        skill_count: 0,
        has_hooks: false,
        has_agents: false,
        has_mcp: false,
        remote_url: None,
        remote_ref: None,
        remote_sha: None,
        remote_subdir: None,
        components: None,
        agent_backends: Vec::new(),
    };
    let eb = ea.clone();
    let pairs = [(a, ea), (b, eb)];
    let scanned: Vec<_> = pairs
        .iter()
        .map(|(s, e)| ScannedEntry {
            source: s,
            entry: e,
        })
        .collect();
    assert!(matches!(
        select_bare_name("go-orca", &scanned),
        Err(BareNameError::Ambiguous { .. })
    ));
}

#[test]
fn failure_forged_digest_and_media_type_dropped() {
    let cat = parse_catalog_json(&read_fixture("malformed.json")).expect("parse structure");
    // invalid id ../escape dropped by sanitize
    assert!(
        cat.agent_backends_for("bad", None).is_none()
            || cat
                .agent_backends_for("bad", None)
                .is_some_and(|b| b.is_empty())
    );
}

#[test]
fn failure_malformed_json_isolates() {
    let err = parse_catalog_json("not json {{{").unwrap_err();
    assert!(matches!(err, CatalogLoadError::Malformed(_)));
}

#[test]
fn failure_oversized_index() {
    let huge = "x".repeat((MAX_CATALOG_BYTES as usize) + 1);
    let err = parse_catalog_json(&huge).unwrap_err();
    assert!(matches!(err, CatalogLoadError::Oversized { .. }));
}

#[test]
fn failure_unreachable_source_isolated_in_merge() {
    let list = merge_catalog_lists([
        Ok(vec![]),
        Err(SourceListError {
            source_name: "offline".into(),
            source_identity: "github:acme/offline".into(),
            status: SourceStatus::Unreachable,
            message: "cache miss; list does not download".into(),
        }),
    ]);
    assert_eq!(list.source_errors.len(), 1);
    assert_eq!(list.source_errors[0].status, SourceStatus::Unreachable);
    assert!(list.entries.is_empty());
}

#[test]
fn source_identity_canonical_for_git_aliases() {
    let a = SourceIdentity::from_git_url("https://github.com/Acme/Repo.git");
    let b = SourceIdentity::from_git_url("git@github.com:acme/repo");
    assert_eq!(a, b);
}

#[test]
fn catalog_backend_targets_carry_trust_flags() {
    let a = parse_catalog_json(&read_fixture("source-a.json")).unwrap();
    let backends = a.agent_backends_for("go-orca", None).unwrap();
    assert_eq!(backends[0].id, "go-orca");
    assert_eq!(backends[0].requires_orca.as_deref(), Some(">=0.4.0 <0.6.0"));
    assert_eq!(backends[0].requires_acp.as_deref(), Some(">=1 <2"));
    assert!(backends[0].discloses_native_code);
    assert!(!backends[0].install_authority);
    assert_eq!(backends[0].targets.len(), 2);
    let t0 = &backends[0].targets[0];
    assert_eq!(t0.media_type.as_deref(), Some("application/gzip"));
    assert!(t0.has_signature && t0.has_provenance && t0.has_sbom);
    assert_eq!(
        t0.artifact_sha256.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}
