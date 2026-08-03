//! `visual-capture` — deterministic Orca visual harness entrypoint (Task 10).
//!
//! Verifies the locked manifest, runs semantic (and optional browser) capture,
//! and writes screenshot/raw-PTY/process-tree/readiness/cleanup evidence.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;
use xai_grok_pager_pty_harness::visual::{
    capture::{CaptureRequest, CaptureRunner, ReadinessPolicy},
    manifest::HarnessManifest,
};

#[derive(Parser, Debug)]
#[command(
    name = "visual-capture",
    about = "Pin-verified Orca visual capture (PTY → xterm.js → Chromium)"
)]
struct Cli {
    /// Absolute path to harness-manifest.lock.json
    #[arg(long)]
    manifest: PathBuf,

    /// Fixture JSON (e.g. native-startup.json)
    #[arg(long)]
    fixture: PathBuf,

    /// Output directory (must be empty or creatable)
    #[arg(long)]
    out: PathBuf,

    /// Optional sealed Chromium executable (browser mode)
    #[arg(long)]
    chromium_executable: Option<PathBuf>,

    /// Run two captures and require semantic equality
    #[arg(long, default_value_t = false)]
    duplicate: bool,

    /// Visual package root (contains src/, fixtures/)
    #[arg(long)]
    visual_root: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("visual-capture: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let manifest = HarnessManifest::load(&cli.manifest)?;
    manifest.verify_pins()?;

    let visual_root = match cli.visual_root {
        Some(p) => p,
        None => cli
            .manifest
            .parent()
            .map(PathBuf::from)
            .context("manifest parent")?,
    };

    let runner = CaptureRunner::new(manifest, visual_root);

    if cli.duplicate {
        let report = runner.duplicate_capture_equal(&cli.fixture, &cli.out)?;
        let path = cli.out.join("duplicate-report.json");
        std::fs::create_dir_all(&cli.out)?;
        std::fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
        if !report.equal {
            bail!("duplicate captures not equal");
        }
        println!("duplicate-ok digest={}", report.digest);
        return Ok(());
    }

    let result = runner.capture_semantic(&CaptureRequest {
        fixture: cli.fixture,
        out_dir: cli.out,
        chromium_executable: cli.chromium_executable,
        readiness: ReadinessPolicy::EventBased,
    })?;
    println!(
        "capture-ok mode={:?} digest={}",
        result.mode,
        result.semantic_digest()
    );
    Ok(())
}
