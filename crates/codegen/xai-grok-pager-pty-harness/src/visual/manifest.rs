//! Locked visual harness manifest (Node/npm/xterm/Chromium/font/render pins).

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Exactly the 23 Task-10 owned paths relative to the pty-harness crate root.
pub const OWNED_VISUAL_RELATIVE_PATHS: &[&str] = &[
    "Cargo.toml",
    "src/lib.rs",
    "src/bin/visual_capture.rs",
    "src/visual/mod.rs",
    "src/visual/capture.rs",
    "src/visual/manifest.rs",
    "src/visual/process_tree.rs",
    "src/visual/protocol.rs",
    "tests/visual_capture.rs",
    "visual/.node-version",
    "visual/package.json",
    "visual/package-lock.json",
    "visual/tsconfig.json",
    "visual/playwright.config.ts",
    "visual/harness-manifest.lock.json",
    "visual/src/capture.ts",
    "visual/src/protocol.ts",
    "visual/src/semantic_regions.ts",
    "visual/src/terminal.ts",
    "visual/src/index.html",
    "visual/src/terminal.css",
    "visual/tests/capture.spec.ts",
    "visual/fixtures/native-startup.json",
];

const PINNED_NODE: &str = "24.18.0";
const PINNED_NPM: &str = "11.16.0";
const PINNED_XTERM: &str = "6.0.0";
const PINNED_PLAYWRIGHT: &str = "1.62.0";
const PINNED_TSX: &str = "4.23.1";
const PINNED_FONT: &str = "5.3.0";
const PINNED_CFT: &str = "151.0.7922.34";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessManifest {
    pub schema_version: u32,
    pub schema: String,
    pub node: ToolPin,
    pub npm: ToolPin,
    pub packages: PackagePins,
    pub chromium: ChromiumPin,
    pub font: FontPin,
    pub render: RenderPin,
    pub readiness: ReadinessPin,
    pub shell: ShellPin,
    /// Digests of owned source files (path → sha256).
    pub source_digests: Vec<SourceDigest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolPin {
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackagePins {
    pub xterm: PackagePin,
    pub playwright_test: PackagePin,
    pub tsx: PackagePin,
    pub fontsource_jetbrains_mono: PackagePin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackagePin {
    pub name: String,
    pub version: String,
    pub integrity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChromiumPin {
    pub playwright_version: String,
    pub chrome_for_testing_version: String,
    pub revision_label: String,
    pub platforms: Vec<ChromiumPlatform>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChromiumPlatform {
    pub target: String,
    pub archive_url: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub executable_relpath: String,
    pub executable_sha256: String,
    pub executable_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FontPin {
    pub package: String,
    pub version: String,
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
    pub license: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenderPin {
    pub locale: String,
    pub timezone: String,
    pub color_scheme: String,
    pub color_profile: String,
    pub cols: u16,
    pub rows: u16,
    pub device_scale_factor: f64,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub font_size: u32,
    pub term: String,
    pub colorterm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessPin {
    pub allow_fixed_sleep: bool,
    pub required_events: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShellPin {
    pub argv: Vec<String>,
    pub env_allowlist: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceDigest {
    pub path: String,
    pub sha256: String,
}

impl HarnessManifest {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read manifest {}", path.display()))?;
        let m: Self = serde_json::from_str(&raw).context("parse harness-manifest.lock.json")?;
        Ok(m)
    }

    /// Verify pins match the Task-10 locked contract.
    pub fn verify_pins(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("MANIFEST_DRIFT: schema_version");
        }
        if self.node.version != PINNED_NODE {
            bail!("MANIFEST_DRIFT: node {}", self.node.version);
        }
        if self.npm.version != PINNED_NPM {
            bail!("MANIFEST_DRIFT: npm {}", self.npm.version);
        }
        if self.packages.xterm.version != PINNED_XTERM {
            bail!("MANIFEST_DRIFT: @xterm/xterm pin");
        }
        if self.packages.playwright_test.version != PINNED_PLAYWRIGHT {
            bail!("MANIFEST_DRIFT: @playwright/test pin");
        }
        if self.packages.tsx.version != PINNED_TSX {
            bail!("MANIFEST_DRIFT: tsx pin");
        }
        if self.packages.fontsource_jetbrains_mono.version != PINNED_FONT {
            bail!("MANIFEST_DRIFT: font pin");
        }
        if self.chromium.chrome_for_testing_version != PINNED_CFT {
            bail!("MANIFEST_DRIFT: chromium CFT version");
        }
        if self.readiness.allow_fixed_sleep {
            bail!("MANIFEST_DRIFT: fixed sleep readiness forbidden");
        }
        for ev in ["xterm-write", "webfont-ready", "browser-lifecycle", "stable-frame"] {
            if !self.readiness.required_events.iter().any(|e| e == ev) {
                bail!("MANIFEST_DRIFT: missing readiness event {ev}");
            }
        }
        if self.render.locale != "C" || self.render.timezone != "UTC" {
            bail!("MANIFEST_DRIFT: locale/timezone");
        }
        if self.render.cols != 120 || self.render.rows != 32 {
            bail!("MANIFEST_DRIFT: terminal dimensions");
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
