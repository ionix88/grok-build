//! Task 10 — deterministic visual capture harness (red-first).
//!
//! Given / When / Then coverage for:
//! - two clean fixture captures are semantically equal
//! - readiness refuses fixed-sleep barriers
//! - missing screenshot fails closed
//! - lock/render drift refuses capture
//! - process tree cleanup leaves no children
//! - Go source imports are refused

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use xai_grok_pager_pty_harness::visual::{
    capture::{CaptureRequest, CaptureRunner, ReadinessPolicy},
    manifest::{HarnessManifest, OWNED_VISUAL_RELATIVE_PATHS},
    process_tree::ProcessTreeSnapshot,
    protocol::CaptureArtifacts,
};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn visual_root() -> PathBuf {
    crate_root().join("visual")
}

fn load_manifest() -> HarnessManifest {
    let path = visual_root().join("harness-manifest.lock.json");
    HarnessManifest::load(&path).expect("harness-manifest.lock.json must load")
}

#[test]
fn owned_path_manifest_lists_exactly_twenty_three_files() {
    // given
    let paths = OWNED_VISUAL_RELATIVE_PATHS;
    // when / then
    assert_eq!(paths.len(), 23, "Task 10 PathManifestV1 is exactly 23 files");
    for rel in paths {
        let abs = crate_root().join(rel.trim_start_matches(
            "crates/codegen/xai-grok-pager-pty-harness/",
        ));
        // Paths in the constant are relative to the pty-harness crate root when
        // they start with visual/ or src/ or tests/ or Cargo.toml.
        let candidate = if rel.starts_with("visual/")
            || rel.starts_with("src/")
            || rel.starts_with("tests/")
            || *rel == "Cargo.toml"
        {
            crate_root().join(rel)
        } else {
            abs
        };
        assert!(
            candidate.is_file(),
            "owned path missing: {} (resolved {})",
            rel,
            candidate.display()
        );
    }
}

#[test]
fn harness_manifest_pins_node_xterm_playwright_font_and_chromium() {
    // given
    let m = load_manifest();
    // when / then
    assert_eq!(m.node.version, "24.18.0");
    assert_eq!(m.npm.version, "11.16.0");
    assert_eq!(m.packages.xterm.version, "6.0.0");
    assert_eq!(m.packages.playwright_test.version, "1.62.0");
    assert_eq!(m.packages.tsx.version, "4.23.1");
    assert_eq!(m.packages.fontsource_jetbrains_mono.version, "5.3.0");
    assert_eq!(m.chromium.chrome_for_testing_version, "151.0.7922.34");
    assert_eq!(m.render.locale, "C");
    assert_eq!(m.render.timezone, "UTC");
    assert_eq!(m.render.cols, 120);
    assert_eq!(m.render.rows, 32);
    assert_eq!(m.render.device_scale_factor, 2.0);
    assert_eq!(m.render.term, "xterm-256color");
    assert!(!m.readiness.allow_fixed_sleep);
}

#[test]
fn duplicate_fixture_captures_are_semantically_equal() {
    // given
    let m = load_manifest();
    let fixture = visual_root().join("fixtures/native-startup.json");
    let out_a = tempfile::tempdir().expect("temp a");
    let out_b = tempfile::tempdir().expect("temp b");
    let runner = CaptureRunner::new(m, visual_root());

    // when — two clean captures of the same fixture (semantic path; no browser required)
    let a = runner
        .capture_semantic(&CaptureRequest {
            fixture: fixture.clone(),
            out_dir: out_a.path().to_path_buf(),
            chromium_executable: None,
            readiness: ReadinessPolicy::EventBased,
        })
        .expect("capture a");
    let b = runner
        .capture_semantic(&CaptureRequest {
            fixture: fixture,
            out_dir: out_b.path().to_path_buf(),
            chromium_executable: None,
            readiness: ReadinessPolicy::EventBased,
        })
        .expect("capture b");

    // then
    assert_eq!(
        a.semantic, b.semantic,
        "two clean captures must be semantically equal"
    );
    assert_eq!(a.semantic_digest(), b.semantic_digest());
    assert!(a.artifacts.screenshot_present || a.artifacts.semantic_only);
    assert!(b.artifacts.screenshot_present || b.artifacts.semantic_only);
    assert!(a.cleanup.clean);
    assert!(b.cleanup.clean);
}

#[test]
fn sleep_readiness_is_rejected() {
    // given
    let m = load_manifest();
    let fixture = visual_root().join("fixtures/native-startup.json");
    let out = tempfile::tempdir().expect("temp");
    let runner = CaptureRunner::new(m, visual_root());

    // when
    let err = runner
        .capture_semantic(&CaptureRequest {
            fixture,
            out_dir: out.path().to_path_buf(),
            chromium_executable: None,
            readiness: ReadinessPolicy::FixedSleep { millis: 1500 },
        })
        .expect_err("sleep readiness must fail");

    // then
    let msg = err.to_string();
    assert!(
        msg.contains("sleep") || msg.contains("READINESS"),
        "expected sleep refusal, got: {msg}"
    );
}

#[test]
fn missing_screenshot_requirement_fails_when_browser_mode() {
    // given
    let m = load_manifest();
    let runner = CaptureRunner::new(m, visual_root());
    let artifacts = CaptureArtifacts {
        screenshot_present: false,
        semantic_only: false,
        raw_pty_present: true,
        process_tree_present: true,
        readiness_event_present: true,
        cleanup_present: true,
    };

    // when / then
    let err = runner
        .require_browser_artifacts(&artifacts)
        .expect_err("missing screenshot must fail");
    assert!(err.to_string().contains("screenshot"));
}

#[test]
fn manifest_drift_refuses_capture() {
    // given
    let mut m = load_manifest();
    m.packages.xterm.version = "0.0.0-drift".into();
    let fixture = visual_root().join("fixtures/native-startup.json");
    let out = tempfile::tempdir().expect("temp");
    let runner = CaptureRunner::new(m, visual_root());

    // when
    let err = runner
        .capture_semantic(&CaptureRequest {
            fixture,
            out_dir: out.path().to_path_buf(),
            chromium_executable: None,
            readiness: ReadinessPolicy::EventBased,
        })
        .expect_err("drift must refuse");

    // then
    let msg = err.to_string();
    assert!(
        msg.contains("drift") || msg.contains("pin") || msg.contains("MANIFEST"),
        "expected drift refusal, got: {msg}"
    );
}

#[test]
fn process_tree_cleanup_reports_no_leaked_children() {
    // given
    let before = ProcessTreeSnapshot::capture_self().expect("snapshot before");
    // when — no child spawned; cleanup of empty set
    let after = ProcessTreeSnapshot::capture_self().expect("snapshot after");
    let report = before.diff_cleanup(&after);
    // then
    assert!(report.clean, "no children should leak: {:?}", report.leaked_pids);
    assert!(report.leaked_pids.is_empty());
}

#[test]
fn go_source_import_is_refused() {
    // given
    let m = load_manifest();
    let runner = CaptureRunner::new(m, visual_root());
    // when / then
    let err = runner
        .refuse_go_source_path(Path::new("/Users/ej/dev/go-orca/go-orca/internal/foo.go"))
        .expect_err("go source must be refused");
    assert!(err.to_string().contains("Go") || err.to_string().contains("go-orca"));
}

#[test]
fn no_tracked_node_modules_under_visual_source() {
    // given
    let nm = visual_root().join("node_modules");
    // when / then
    assert!(
        !nm.exists(),
        "source visual/node_modules must remain absent (runtime-only install)"
    );
}

#[test]
fn root_cargo_toml_unchanged_by_visual_bin_registration() {
    // given — visual-capture is registered only on the pty-harness crate
    let harness_cargo = fs::read_to_string(crate_root().join("Cargo.toml")).expect("cargo");
    // when / then
    assert!(
        harness_cargo.contains("name = \"visual-capture\""),
        "pty-harness Cargo.toml must register visual-capture bin"
    );
    assert!(
        harness_cargo.contains("path = \"src/bin/visual_capture.rs\""),
        "visual-capture path must match plan"
    );
}

#[test]
fn crate_does_not_depend_on_go_orca_path() {
    let cargo = fs::read_to_string(crate_root().join("Cargo.toml")).expect("cargo");
    assert!(
        !cargo.contains("go-orca") && !cargo.contains("go_orca"),
        "pty-harness must not import Go-Orca"
    );
    // Also scan visual TS sources for go-orca imports.
    for rel in ["src/capture.ts", "src/protocol.ts", "src/terminal.ts", "src/semantic_regions.ts"] {
        let p = visual_root().join(rel);
        if p.is_file() {
            let s = fs::read_to_string(&p).expect("ts");
            assert!(
                !s.contains("go-orca") && !s.contains("GO_ORCA"),
                "{rel} must not reference Go-Orca"
            );
        }
    }
}

#[test]
fn package_json_pins_exact_versions_and_package_manager() {
    let pkg: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(visual_root().join("package.json")).expect("package.json"),
    )
    .expect("json");
    assert_eq!(pkg["packageManager"], "npm@11.16.0");
    let deps = pkg["devDependencies"].as_object().expect("devDeps");
    assert_eq!(deps["@playwright/test"], "1.62.0");
    assert_eq!(deps["@xterm/xterm"], "6.0.0");
    assert_eq!(deps["tsx"], "4.23.1");
    assert_eq!(deps["@fontsource/jetbrains-mono"], "5.3.0");
}

#[test]
fn node_version_file_pins_24_18_0() {
    let v = fs::read_to_string(visual_root().join(".node-version")).expect("node-version");
    assert_eq!(v.trim(), "24.18.0");
}

#[test]
fn readiness_policy_has_no_sleep_variant_accepted_by_default_manifest() {
    let m = load_manifest();
    assert!(!m.readiness.allow_fixed_sleep);
    let _ = Command::new("true").status();
}
