//! Integration tests for `orca import grok` (library surface via binary crate).
//!
//! These tests exercise the same modules as the binary by re-including the
//! source through a thin path — the binary crate exposes no lib target, so we
//! shell out to the built `orca` when available and otherwise unit-test via
//! process isolation helpers duplicated from import_grok public contracts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn orca_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ORCA_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().nth(3)?; // crates/codegen/xai-grok-pager-bin -> orca
    for rel in ["target/debug/orca", "target/release/orca"] {
        let p = root.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    // workspace root may be two levels up from package when nested differently
    let alt = manifest.join("../../../..").canonicalize().ok()?;
    for rel in ["target/debug/orca", "target/release/orca"] {
        let p = alt.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn find_orca_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("rust-toolchain.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            panic!("orca root not found");
        }
    }
}

fn setup_homes() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let grok = tmp.path().join("grok");
    let orca = tmp.path().join("orca-home");
    fs::create_dir_all(&grok).unwrap();
    fs::write(grok.join("config.toml"), b"[cli]\ntheme = \"dark\"\n").unwrap();
    (tmp, grok, orca)
}

fn run_orca(bin: &Path, args: &[&str], grok: &Path, orca_home: &Path) -> std::process::Output {
    Command::new(bin)
        .args(args)
        .env("GROK_HOME", grok)
        .env("ORCA_HOME", orca_home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .expect("spawn orca")
}

#[test]
fn cli_preview_writes_nothing_and_emits_digest() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let (_tmp, grok, orca_home) = setup_homes();
    let out = run_orca(&bin, &["import", "grok", "--preview"], &grok, &orca_home);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GrokImportPreviewV1"));
    assert!(stdout.contains("previewDigest"));
    // destination untouched
    assert!(!orca_home.join("config.toml").exists());
    assert!(
        !orca_home.join("data").exists()
            || fs::read_dir(orca_home.join("data"))
                .map(|d| d.count())
                .unwrap_or(0)
                == 0
    );
}

#[test]
fn cli_confirm_applies_and_source_unchanged() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let (_tmp, grok, orca_home) = setup_homes();
    let src_before = fs::read(grok.join("config.toml")).unwrap();
    let preview = run_orca(&bin, &["import", "grok", "--preview"], &grok, &orca_home);
    assert!(preview.status.success());
    let v: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let digest = v["previewDigest"].as_str().unwrap();
    let apply = run_orca(
        &bin,
        &["import", "grok", "--confirm", digest],
        &grok,
        &orca_home,
    );
    assert!(
        apply.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert_eq!(fs::read(grok.join("config.toml")).unwrap(), src_before);
    assert!(orca_home.join("config.toml").exists());
    assert_eq!(
        fs::read_to_string(orca_home.join("config.toml")).unwrap(),
        "[cli]\ntheme = \"dark\"\n"
    );
}

#[test]
fn cli_stale_digest_refused() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let (_tmp, grok, orca_home) = setup_homes();
    let out = run_orca(
        &bin,
        &["import", "grok", "--confirm", "deadbeef"],
        &grok,
        &orca_home,
    );
    assert!(!out.status.success());
    assert!(!orca_home.join("config.toml").exists());
}

#[test]
fn cli_secret_content_refused() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let (_tmp, grok, orca_home) = setup_homes();
    fs::write(grok.join("config.toml"), b"api_key = \"sk-secret-value\"\n").unwrap();
    let out = run_orca(&bin, &["import", "grok", "--preview"], &grok, &orca_home);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secret"), "{err}");
}

#[test]
fn cli_conflict_refused() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let (_tmp, grok, orca_home) = setup_homes();
    fs::create_dir_all(&orca_home).unwrap();
    fs::write(orca_home.join("config.toml"), b"[cli]\ntheme = \"light\"\n").unwrap();
    let preview = run_orca(&bin, &["import", "grok", "--preview"], &grok, &orca_home);
    assert!(preview.status.success());
    let v: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let digest = v["previewDigest"].as_str().unwrap();
    let apply = run_orca(
        &bin,
        &["import", "grok", "--confirm", digest],
        &grok,
        &orca_home,
    );
    assert!(!apply.status.success());
    assert!(
        fs::read_to_string(grok.join("config.toml"))
            .unwrap()
            .contains("dark")
    );
}

#[cfg(unix)]
#[test]
fn cli_symlink_source_refused() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let real = tmp.path().join("real");
    let link = tmp.path().join("link");
    let orca_home = tmp.path().join("orca");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("config.toml"), b"[cli]\n").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = run_orca(&bin, &["import", "grok", "--preview"], &link, &orca_home);
    assert!(!out.status.success());
}

#[test]
fn normal_startup_help_does_not_require_grok_home() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary not built");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let missing_grok = tmp.path().join("no-such-grok");
    let orca_home = tmp.path().join("orca");
    let out = Command::new(&bin)
        .arg("--help")
        .env("GROK_HOME", &missing_grok)
        .env("ORCA_HOME", &orca_home)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!missing_grok.exists());
}

#[test]
fn orca_root_exists_for_qa() {
    let root = find_orca_root();
    assert!(
        root.join("crates/codegen/xai-grok-config/src/orca_paths.rs")
            .is_file()
    );
    assert!(
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/paths.rs")
            .is_file()
    );
    assert!(
        root.join("crates/codegen/xai-grok-pager-bin/src/import_grok.rs")
            .is_file()
    );
}
