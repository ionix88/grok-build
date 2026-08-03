use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ACP_SCHEMA_SHA256: &str =
    "92c1dfcda10dd47e99127500a3763da2b471f9ac61e12b9bf0430c32cf953796";
const ACP_SCHEMA_BYTES: u64 = 198_609;
const ACP_META_SHA256: &str =
    "e0bf36f8123b2544b499174197fdc371ec49a1b4572a35114513d56492741599";
const ACP_META_BYTES: u64 = 1_059;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionFixture {
    schema_version: u32,
    mode: String,
    session_id: String,
    extension: Option<ExtensionMeta>,
    fallback: Option<String>,
    ndjson_digest: String,
    acp_schema_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionMeta {
    namespace: String,
    version: String,
    schema_digest: String,
    features: Vec<String>,
}

fn orca_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/codegen/xai-grok-pager -> repo root
    for _ in 0..3 {
        dir.pop();
    }
    dir
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/app/acp_handler/go_orca/fixtures")
}

fn sha256_file(path: &std::path::Path) -> (u64, String) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut h = Sha256::new();
    h.update(&bytes);
    let dig = h.finalize();
    let mut s = String::with_capacity(dig.len() * 2);
    for b in dig {
        s.push_str(&format!("{b:02x}"));
    }
    (bytes.len() as u64, s)
}

#[test]
fn acp_release_pin_matches() {
    let root = orca_root();
    let schema = root.join("release/contracts/acp-v1/schema.json");
    let meta = root.join("release/contracts/acp-v1/meta.json");
    let (sz, dig) = sha256_file(&schema);
    assert_eq!(sz, ACP_SCHEMA_BYTES);
    assert_eq!(dig, ACP_SCHEMA_SHA256);
    let (msz, mdig) = sha256_file(&meta);
    assert_eq!(msz, ACP_META_BYTES);
    assert_eq!(mdig, ACP_META_SHA256);
    let meta_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(meta).unwrap()).unwrap();
    assert_eq!(meta_json["version"], 1);
}

#[test]
fn standard_fixture_has_no_extension() {
    let raw = std::fs::read(fixture_dir().join("standard.json")).unwrap();
    let f: ProjectionFixture = serde_json::from_slice(&raw).unwrap();
    assert_eq!(f.schema_version, 1);
    assert_eq!(f.mode, "standard-only");
    assert!(f.extension.is_none());
    assert_eq!(f.acp_schema_digest, ACP_SCHEMA_SHA256);
    assert!(!f.session_id.is_empty());
    assert_eq!(f.ndjson_digest.len(), 64);
}

#[test]
fn rich_fixture_binds_extension_digest() {
    let raw = std::fs::read(fixture_dir().join("rich.json")).unwrap();
    let f: ProjectionFixture = serde_json::from_slice(&raw).unwrap();
    assert_eq!(f.mode, "rich");
    let ext = f.extension.expect("rich extension");
    assert_eq!(ext.namespace, "_go-orca.dev");
    assert_eq!(ext.version, "1");
    assert_eq!(ext.schema_digest.len(), 64);
    assert!(!ext.features.is_empty());
}

#[test]
fn unknown_rich_major_falls_back_to_standard() {
    let raw = std::fs::read(fixture_dir().join("unknown-version.json")).unwrap();
    let f: ProjectionFixture = serde_json::from_slice(&raw).unwrap();
    assert_eq!(f.mode, "unknown-rich-major");
    let ext = f.extension.expect("extension present");
    assert_eq!(ext.version, "99");
    assert_eq!(f.fallback.as_deref(), Some("standard-acp-v1"));
}

#[test]
fn shared_diagnostics_byte_identical_to_go() {
    let orca = orca_root().join("release/contracts/plugin-diagnostics-v1");
    let go = orca_root()
        .parent()
        .unwrap()
        .join("go-orca/schema/plugin-diagnostics/v1");
    if !go.is_dir() {
        // Independent Orca checkout without sibling Go root: skip cross-root compare.
        return;
    }
    for name in [
        "schema.json",
        "healthy.json",
        "degraded.json",
        "unavailable.json",
        "invalid.json",
        "MANIFEST.sha256",
    ] {
        let a = std::fs::read(orca.join(name)).unwrap();
        let b = std::fs::read(go.join(name)).unwrap();
        assert_eq!(a, b, "diagnostics diverge on {name}");
    }
}

#[test]
fn authority_diagnostics_fixture_is_marked_invalid() {
    let raw = std::fs::read(
        orca_root().join("release/contracts/plugin-diagnostics-v1/invalid.json"),
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(
        v.get("authority").is_some() || v.get("executablePath").is_some(),
        "invalid fixture must carry authority-bearing fields for negative tests"
    );
}

#[test]
fn agent_backend_v2_release_present() {
    let dir = orca_root().join("release/contracts/agent-backend-v2");
    for name in ["schema.json", "standard.json", "rich.json", "MANIFEST.sha256"] {
        assert!(dir.join(name).is_file(), "missing {name}");
    }
    let rich: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("rich.json")).unwrap()).unwrap();
    let ext = &rich["agentBackends"][0]["extensions"][0];
    assert_eq!(ext["namespace"], "_go-orca.dev");
    let sha = ext["sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert_ne!(sha, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}
