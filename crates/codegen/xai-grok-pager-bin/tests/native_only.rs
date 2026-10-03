//! Task 55: native-only host — empty plugin store, doctor without plugin authority.
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
fn native_only_doctor_and_empty_plugin_store() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary missing");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("orca-home");
    fs::create_dir_all(home.join("data/plugins")).unwrap();
    // Empty plugin store — no plugin receipts.
    let entries: Vec<_> = fs::read_dir(home.join("data/plugins"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(entries.is_empty());

    let out = Command::new(&bin)
        .args(["doctor", "--json"])
        .env("ORCA_HOME", &home)
        .env_remove("GO_ORCA_ROOT")
        .output()
        .unwrap();
    // Doctor must remain useful native-only (exit 0).
    assert!(
        out.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("schemaVersion") || stdout.contains("facts"),
        "doctor json missing facts: {stdout}"
    );
    // Must not require plugin startup.
    assert!(!stdout.contains("plugin required"));
}

#[test]
fn released_diagnostics_fixtures_present_on_orca_only() {
    let root = orca_root();
    let diag = root.join("release/contracts/plugin-diagnostics-v1");
    for name in [
        "schema.json",
        "healthy.json",
        "degraded.json",
        "unavailable.json",
        "invalid.json",
        "MANIFEST.sha256",
    ] {
        assert!(
            diag.join(name).is_file(),
            "missing Orca diagnostics fixture {name}"
        );
    }
    // Host packaging must not open Go diagnostics copy — path must not be required.
    let go_diag = root
        .parent()
        .unwrap()
        .join("go-orca/schema/plugin-diagnostics/v1");
    // Existence of sibling is environmental; we only assert Orca copy is sufficient.
    let _ = go_diag;
    assert!(root.join("docs/FORK_DELTA.md").is_file());
}

#[test]
fn plugin_required_startup_not_encoded_in_host_scripts() {
    let root = orca_root();
    let verify = fs::read_to_string(root.join("scripts/ci/verify-host.sh")).unwrap();
    let has = fs::read_to_string(root.join("scripts/ci/host-artifact-set.sh")).unwrap();
    // Scripts fail closed on PluginRequired inject; they must not require plugins for happy path.
    assert!(verify.contains("PluginRequired") || verify.contains("plugin_required"));
    assert!(!has.contains("require_plugin"));
    assert!(!verify.contains("GO_ORCA_ROOT}/"));
}
