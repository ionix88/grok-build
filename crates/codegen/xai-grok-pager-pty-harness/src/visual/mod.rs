//! Deterministic PTY → xterm.js → Chromium visual capture (Task 10).
//!
//! Rust owns typed launch/IPC, manifest verification, process-tree capture,
//! and teardown. The locked `visual/` package owns the isolated browser
//! renderer and Playwright assertions.

pub mod capture;
pub mod manifest;
pub mod process_tree;
pub mod protocol;
