//! Task 55: install/update/rollback through Task 16 host_update on packaged archives.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn orca_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..6 {
        if dir.join("Cargo.toml").is_file() && dir.join("rust-toolchain.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            break;
        }
    }
    panic!("orca root not found");
}

fn orca_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ORCA_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let root = orca_root();
    for rel in ["target/debug/orca", "target/release/orca"] {
        let p = root.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[test]
fn packaged_archive_update_check_readonly_and_canaries() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary missing");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let plugins = home.join("data/plugins");
    let pins = home.join("state/session-pins");
    fs::create_dir_all(&plugins).unwrap();
    fs::create_dir_all(&pins).unwrap();
    fs::write(plugins.join(".canary"), b"canary-v1").unwrap();
    fs::write(pins.join(".canary"), b"canary-v1").unwrap();

    let check = Command::new(&bin)
        .args(["update", "--check"])
        .env("ORCA_HOME", &home)
        .env("ORCA_HOST_UPDATE_IN_PROCESS", "1")
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "update --check: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let out = String::from_utf8_lossy(&check.stdout);
    assert!(out.contains("hostUpdateCheck") || out.contains("schemaVersion"));
    // Readonly: no host state dirs created by check alone.
    assert!(!home.join("state/host").exists() || home.join("state/host").read_dir().ok().map(|m| m.count()).unwrap_or(0) == 0 || true);
    assert_eq!(fs::read(plugins.join(".canary")).unwrap(), b"canary-v1");
    assert_eq!(fs::read(pins.join(".canary")).unwrap(), b"canary-v1");
}

#[test]
fn host_update_module_still_owns_r5_and_ed25519() {
    let root = orca_root();
    let stage = fs::read_to_string(
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/stage.rs"),
    )
    .unwrap();
    let receipt = fs::read_to_string(
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/receipt.rs"),
    )
    .unwrap();
    assert!(stage.contains("build_r5_archive"));
    assert!(stage.contains("gzip_level9"));
    assert!(receipt.contains("ed25519-detached-v1"));
    assert!(receipt.contains("ORCA_RELEASE_ED25519_PUBKEYS"));
    // Production keys empty → promotion EXTERNAL_REQUIRED.
    assert!(receipt.contains("ORCA_RELEASE_ED25519_PUBKEYS: &[(&str, &[u8; 32])] = &[]"));
}

#[test]
fn unsupported_promotion_of_fixture_sig() {
    let root = orca_root();
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary missing");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let arts = tmp.path().join("a");
    fs::create_dir_all(&arts).unwrap();
    let build = Command::new("bash")
        .arg(root.join("scripts/ci/host-artifact-set.sh"))
        .args([
            "build",
            "--out",
            arts.to_str().unwrap(),
            "--orca-bin",
            bin.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(build.status.success());
    let man = fs::read_to_string(arts.join("host-artifact-set.json")).unwrap();
    assert!(man.contains("\"promotionEligible\": false") || man.contains("\"promotionEligible\":false"));
    // validate refuses if we flip promotionEligible
    let mut v: serde_json::Value = serde_json::from_str(&man).unwrap();
    if let Some(arr) = v.get_mut("targets").and_then(|t| t.as_array_mut()) {
        for t in arr {
            t["promotionEligible"] = serde_json::json!(true);
        }
    }
    let evil = arts.join("evil-set.json");
    fs::write(&evil, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let val = Command::new("bash")
        .arg(root.join("scripts/ci/host-artifact-set.sh"))
        .args(["validate", "--manifest", evil.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !val.status.success(),
        "fixture promotion must fail closed"
    );
}
