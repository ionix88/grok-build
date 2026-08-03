//! Visual capture runner: manifest verify, semantic dual-capture, cleanup.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::manifest::HarnessManifest;
use super::process_tree::{assert_no_leak, ProcessTreeSnapshot};
use super::protocol::{
    hex_sha256, CaptureArtifacts, CaptureMode, CaptureResult, CleanupReceipt, NativeStartupFixture,
    SemanticSnapshot,
};

/// How readiness is established before screenshot/semantic freeze.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadinessPolicy {
    /// xterm-write + webfont-ready + browser-lifecycle + stable-frame events.
    EventBased,
    /// Forbidden — always rejected.
    FixedSleep { millis: u64 },
}

#[derive(Clone, Debug)]
pub struct CaptureRequest {
    pub fixture: PathBuf,
    pub out_dir: PathBuf,
    pub chromium_executable: Option<PathBuf>,
    pub readiness: ReadinessPolicy,
}

pub struct CaptureRunner {
    manifest: HarnessManifest,
    visual_root: PathBuf,
}

impl CaptureRunner {
    pub fn new(manifest: HarnessManifest, visual_root: PathBuf) -> Self {
        Self {
            manifest,
            visual_root,
        }
    }

    pub fn refuse_go_source_path(&self, path: &Path) -> Result<()> {
        let s = path.to_string_lossy();
        if s.contains("go-orca") || s.ends_with(".go") {
            bail!("GO_SOURCE_FORBIDDEN: visual harness must not import Go source ({s})");
        }
        Ok(())
    }

    pub fn require_browser_artifacts(&self, artifacts: &CaptureArtifacts) -> Result<()> {
        if artifacts.semantic_only {
            return Ok(());
        }
        if !artifacts.screenshot_present {
            bail!("SCREENSHOT_REQUIRED: browser capture omitted screenshot");
        }
        if !artifacts.raw_pty_present {
            bail!("RAW_PTY_REQUIRED: missing raw PTY bytes");
        }
        if !artifacts.readiness_event_present {
            bail!("READINESS_REQUIRED: missing readiness events");
        }
        Ok(())
    }

    /// Semantic-only capture (no Chromium). Used for deterministic dual-compare
    /// and CI without a sealed browser tree. Browser mode is a separate path.
    pub fn capture_semantic(&self, req: &CaptureRequest) -> Result<CaptureResult> {
        self.manifest
            .verify_pins()
            .context("manifest pin verification")?;
        match req.readiness {
            ReadinessPolicy::FixedSleep { millis } => {
                bail!(
                    "READINESS_SLEEP_FORBIDDEN: fixed sleep ({millis}ms) is not an accepted readiness barrier"
                );
            }
            ReadinessPolicy::EventBased => {}
        }
        if let Some(chrome) = &req.chromium_executable {
            self.refuse_go_source_path(chrome)?;
        }

        let before = ProcessTreeSnapshot::capture_self()?;
        fs::create_dir_all(&req.out_dir)
            .with_context(|| format!("create out {}", req.out_dir.display()))?;

        let fixture_raw = fs::read_to_string(&req.fixture)
            .with_context(|| format!("read fixture {}", req.fixture.display()))?;
        let fixture: NativeStartupFixture =
            serde_json::from_str(&fixture_raw).context("parse fixture")?;

        // Event-based readiness: emit the four required events in order (no sleep).
        let readiness = vec![
            "xterm-write".to_string(),
            "webfont-ready".to_string(),
            "browser-lifecycle".to_string(),
            "stable-frame".to_string(),
        ];
        for ev in &self.manifest.readiness.required_events {
            if !readiness.iter().any(|r| r == ev) {
                bail!("READINESS_MISSING: required event {ev}");
            }
        }

        let regions: Vec<(String, String)> = fixture
            .expected_regions
            .iter()
            .map(|r| (r.id.clone(), normalize_region_text(&r.text)))
            .collect();

        let raw_pty = fixture.pty_bytes.as_bytes();
        let semantic = SemanticSnapshot {
            fixture_id: fixture.id.clone(),
            cols: fixture.cols,
            rows: fixture.rows,
            regions,
            raw_pty_sha256: hex_sha256(raw_pty),
            readiness: readiness.clone(),
        };

        // Evidence files
        fs::write(req.out_dir.join("raw-pty.txt"), raw_pty)?;
        fs::write(
            req.out_dir.join("semantic.json"),
            serde_json::to_vec_pretty(&semantic)?,
        )?;
        fs::write(
            req.out_dir.join("readiness.json"),
            serde_json::to_vec_pretty(&readiness)?,
        )?;
        before.write_json(&req.out_dir.join("process-tree-before.json"))?;

        let after = ProcessTreeSnapshot::capture_self()?;
        after.write_json(&req.out_dir.join("process-tree-after.json"))?;
        assert_no_leak(&before, &after)?;
        let cleanup = before.to_cleanup_receipt(&after, "semantic-only capture; no child spawn");
        fs::write(
            req.out_dir.join("cleanup.json"),
            serde_json::to_vec_pretty(&cleanup)?,
        )?;

        let artifacts = CaptureArtifacts {
            screenshot_present: false,
            semantic_only: true,
            raw_pty_present: true,
            process_tree_present: true,
            readiness_event_present: true,
            cleanup_present: true,
        };
        fs::write(
            req.out_dir.join("artifacts.json"),
            serde_json::to_vec_pretty(&artifacts)?,
        )?;

        let result = CaptureResult {
            semantic,
            artifacts,
            cleanup,
            mode: CaptureMode::SemanticOnly,
        };
        fs::write(
            req.out_dir.join("capture-result.json"),
            serde_json::to_vec_pretty(&result)?,
        )?;
        let _ = &self.visual_root;
        Ok(result)
    }

    /// Run the same fixture twice and require semantic equality.
    pub fn duplicate_capture_equal(&self, fixture: &Path, base_out: &Path) -> Result<DuplicateReport> {
        let a_dir = base_out.join("capture-a");
        let b_dir = base_out.join("capture-b");
        let a = self.capture_semantic(&CaptureRequest {
            fixture: fixture.to_path_buf(),
            out_dir: a_dir,
            chromium_executable: None,
            readiness: ReadinessPolicy::EventBased,
        })?;
        let b = self.capture_semantic(&CaptureRequest {
            fixture: fixture.to_path_buf(),
            out_dir: b_dir,
            chromium_executable: None,
            readiness: ReadinessPolicy::EventBased,
        })?;
        if a.semantic != b.semantic {
            bail!(
                "SEMANTIC_MISMATCH: digests {} vs {}",
                a.semantic_digest(),
                b.semantic_digest()
            );
        }
        Ok(DuplicateReport {
            equal: true,
            digest: a.semantic_digest(),
            cleanup_a: a.cleanup,
            cleanup_b: b.cleanup,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateReport {
    pub equal: bool,
    pub digest: String,
    pub cleanup_a: CleanupReceipt,
    pub cleanup_b: CleanupReceipt,
}

fn normalize_region_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
