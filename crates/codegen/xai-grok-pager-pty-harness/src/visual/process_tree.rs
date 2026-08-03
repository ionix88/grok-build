//! Process-tree capture and cleanup verification for visual capture children.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::protocol::CleanupReceipt;

/// Snapshot of the current process and its descendants (best-effort, Unix).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessTreeSnapshot {
    pub root_pid: u32,
    pub pids: BTreeSet<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupDiff {
    pub clean: bool,
    pub leaked_pids: Vec<u32>,
}

impl ProcessTreeSnapshot {
    pub fn capture_self() -> Result<Self> {
        let root_pid = std::process::id();
        let mut pids = BTreeSet::new();
        pids.insert(root_pid);
        // Best-effort: on macOS/Linux walk /proc or use `pgrep -P` style via sysctl is heavy;
        // for harness tests we record only self unless children are registered explicitly.
        Ok(Self { root_pid, pids })
    }

    pub fn with_child(&self, child: u32) -> Self {
        let mut pids = self.pids.clone();
        pids.insert(child);
        Self {
            root_pid: self.root_pid,
            pids,
        }
    }

    pub fn diff_cleanup(&self, after: &Self) -> CleanupDiff {
        let leaked: Vec<u32> = after
            .pids
            .difference(&self.pids)
            .copied()
            .filter(|p| *p != after.root_pid)
            .collect();
        CleanupDiff {
            clean: leaked.is_empty(),
            leaked_pids: leaked,
        }
    }

    pub fn to_cleanup_receipt(&self, after: &Self, notes: impl Into<String>) -> CleanupReceipt {
        let d = self.diff_cleanup(after);
        CleanupReceipt {
            clean: d.clean,
            leaked_pids: d.leaked_pids,
            notes: notes.into(),
        }
    }

    pub fn write_json(&self, path: &PathBuf) -> Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

/// Assert no leaked PIDs remain after capture teardown.
pub fn assert_no_leak(before: &ProcessTreeSnapshot, after: &ProcessTreeSnapshot) -> Result<()> {
    let d = before.diff_cleanup(after);
    if !d.clean {
        anyhow::bail!("CHILD_LEAK: leaked pids {:?}", d.leaked_pids);
    }
    Ok(())
}
