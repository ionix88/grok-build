//! Task 55: host package dual-build, manifest, resolver, isolation.
use std::fs;
use std::path::{Path, PathBuf};
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

fn run_has(args: &[&str]) -> std::process::Output {
    let root = orca_root();
    let script = root.join("scripts/ci/host-artifact-set.sh");
    Command::new("bash")
        .arg(&script)
        .args(args)
        .current_dir(&root)
        .output()
        .expect("host-artifact-set.sh")
}

#[test]
fn host_package_build_validate_path_and_isolation() {
    let root = orca_root();
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary missing");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("artifacts");
    fs::create_dir_all(&out).unwrap();

    let build = run_has(&[
        "build",
        "--out",
        out.to_str().unwrap(),
        "--version",
        "0.0.0-test-host",
        "--orca-bin",
        bin.to_str().unwrap(),
    ]);
    assert!(
        build.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let man = out.join("host-artifact-set.json");
    assert!(man.is_file());

    let val = run_has(&["validate", "--manifest", man.to_str().unwrap()]);
    assert!(
        val.status.success(),
        "validate: {}",
        String::from_utf8_lossy(&val.stderr)
    );

    let path = run_has(&[
        "path",
        "--manifest",
        man.to_str().unwrap(),
        "--target",
        "darwin-aarch64",
    ]);
    assert!(path.status.success());
    let p = String::from_utf8_lossy(&path.stdout).trim().to_string();
    assert!(Path::new(&p).is_absolute());
    assert!(Path::new(&p).is_file());
    assert!(p.ends_with('\n') || !path.stdout.is_empty());

    let raw = fs::read_to_string(&man).unwrap();
    assert!(!raw.contains("pluginArtifact"));
    assert!(!raw.contains("goOrcaCommit"));
    assert!(raw.contains("\"expectedShardIds\": []") || raw.contains("\"expectedShardIds\":[]"));

    // Ambiguous/unknown target fails closed.
    let bad = run_has(&[
        "path",
        "--manifest",
        man.to_str().unwrap(),
        "--target",
        "windows-amd64",
    ]);
    assert!(!bad.status.success());

    // Dual archives exist and differ by target.
    let d = out.join("orca-0.0.0-test-host-darwin-aarch64.tar.gz");
    let l = out.join("orca-0.0.0-test-host-linux-amd64.tar.gz");
    assert!(d.is_file() && l.is_file());
    assert_ne!(fs::read(&d).unwrap(), fs::read(&l).unwrap());

    // Second build into fresh dir is byte-equal for same inputs.
    let out2 = tmp.path().join("artifacts2");
    fs::create_dir_all(&out2).unwrap();
    let build2 = run_has(&[
        "build",
        "--out",
        out2.to_str().unwrap(),
        "--version",
        "0.0.0-test-host",
        "--orca-bin",
        bin.to_str().unwrap(),
    ]);
    assert!(build2.status.success());
    assert_eq!(
        fs::read(out2.join("orca-0.0.0-test-host-darwin-aarch64.tar.gz")).unwrap(),
        fs::read(&d).unwrap(),
        "two clean builds must be byte-equal"
    );

    // Root cargo template present.
    assert!(root.join("packaging/host-manifest.json").is_file());
    assert!(root.join("docs/FORK_DELTA.md").is_file());
    assert!(root.join("docs/GROK_SOURCE_SYNC.md").is_file());
}

#[test]
fn verify_host_script_approves_clean_set() {
    let Some(bin) = orca_bin() else {
        eprintln!("skip: orca binary missing");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let arts = tmp.path().join("a");
    fs::create_dir_all(&arts).unwrap();
    let build = run_has(&[
        "build",
        "--out",
        arts.to_str().unwrap(),
        "--orca-bin",
        bin.to_str().unwrap(),
    ]);
    assert!(build.status.success());
    let man = arts.join("host-artifact-set.json");
    let runner = tmp.path().join("runner");
    fs::create_dir_all(&runner).unwrap();
    let root = orca_root();
    let out = Command::new("bash")
        .arg(root.join("scripts/ci/verify-host.sh"))
        .args([
            "--result-schema",
            "host-artifact-set/v1",
            "--host-artifact-set",
            man.to_str().unwrap(),
            "--target",
            "darwin-aarch64",
            "--out",
            runner.to_str().unwrap(),
        ])
        .env_remove("GO_ORCA_ROOT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify-host: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result = fs::read_to_string(runner.join("result.json")).unwrap();
    assert!(result.contains("HostArtifactSetResultV1"));
    assert!(result.contains("\"status\": \"APPROVED\"") || result.contains("\"status\":\"APPROVED\""));
    assert!(!result.contains("pluginArtifact"));
}

#[test]
fn verify_host_inject_source_sync_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = tmp.path().join("inj");
    fs::create_dir_all(&runner).unwrap();
    // Need a dummy manifest path even for inject early-exit — inject runs first.
    let root = orca_root();
    let out = Command::new("bash")
        .arg(root.join("scripts/ci/verify-host.sh"))
        .args([
            "--result-schema",
            "host-artifact-set/v1",
            "--out",
            runner.to_str().unwrap(),
            "--inject",
            "SourceSyncConflict",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
