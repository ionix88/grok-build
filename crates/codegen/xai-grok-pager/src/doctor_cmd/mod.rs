use std::io::{IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::diagnostics::{DiagnosticReport, FixActivation, FixPlan, ShellKind};

mod human;
mod json;

pub const SCHEMA_VERSION: &str = "1";

/// Relative path (from Orca root) to the Task-7 released diagnostics contract pack.
pub const ORCA_DIAGNOSTICS_CONTRACT_REL: &str = "release/contracts/plugin-diagnostics-v1";

/// Forbidden authority-bearing keys in plugin diagnostics (schema `not` clause).
const FORBIDDEN_DIAG_AUTHORITY_KEYS: &[&str] = &[
    "grant",
    "command",
    "executable",
    "executablePath",
    "secret",
    "authority",
    "hostDecision",
];

#[derive(Clone, Debug, Default, Eq, PartialEq, clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct DoctorArgs {
    /// Print the diagnostic report as JSON.
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<DoctorCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq, clap::Subcommand)]
pub enum DoctorCommand {
    /// Apply an automatic fix.
    Fix(FixArgs),
}

#[derive(Clone, Debug, Eq, PartialEq, clap::Args)]
pub struct FixArgs {
    /// Named fix to apply. Omit it to list available automatic fixes.
    pub id: Option<String>,
    /// Apply the displayed changes without confirmation.
    #[arg(long, requires = "id")]
    pub yes: bool,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    match args.command {
        None => run_report(args.json, &mut std::io::stdout().lock()),
        Some(DoctorCommand::Fix(fix)) => run_fix(
            fix,
            std::io::stdin().is_terminal(),
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        ),
    }
}

pub fn run_with_writer(args: DoctorArgs, writer: &mut impl Write) -> Result<()> {
    match args.command {
        None => run_report(args.json, writer),
        Some(_) => anyhow::bail!("Doctor fixes require interactive input and output."),
    }
}

fn run_report(json_output: bool, writer: &mut impl Write) -> Result<()> {
    let report = collect_report();
    write_report(&report, json_output, writer)
}

pub fn collect_report() -> DiagnosticReport {
    let terminal = crate::terminal::standalone_terminal_context();
    let report = collect_report_with(crate::diagnostics::probes::collect_standalone(&terminal));
    configured_report_for_terminal(report, &terminal)
}

fn configured_report_for_terminal(
    report: DiagnosticReport,
    terminal: &crate::terminal::TerminalContext,
) -> DiagnosticReport {
    if terminal.is_ssh || terminal.is_official_vscode_remote {
        return report;
    }
    let configured = shell_home_and_kind().is_some_and(|(home, shell)| {
        crate::diagnostics::managed_alias_configured(&shell.config_path(&home), shell)
    });
    crate::diagnostics::configured_report(report, configured)
}

fn collect_report_with(
    snapshot: crate::diagnostics::probes::StandaloneDiagnosticSnapshot<'_>,
) -> DiagnosticReport {
    let mut report = crate::diagnostics::view(snapshot.into());
    crate::diagnostics::apply_voice_probe(&mut report, true);
    report
}

fn write_report(
    report: &DiagnosticReport,
    json_output: bool,
    writer: &mut impl Write,
) -> Result<()> {
    if json_output {
        json::write(report, writer)
    } else {
        write!(writer, "{}", human::format(report))?;
        Ok(())
    }
}

fn run_fix(
    args: FixArgs,
    stdin_is_terminal: bool,
    input: &mut impl std::io::BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    let terminal = crate::terminal::standalone_terminal_context();
    let Some(value) = args.id.as_deref() else {
        let report = configured_report_for_terminal(
            collect_report_with(crate::diagnostics::probes::collect_standalone_fix(
                &terminal, None,
            )),
            &terminal,
        );
        write!(
            writer,
            "{}",
            crate::diagnostics::format_applicable_automatic_fixes(&report, &terminal)
        )?;
        return Ok(());
    };
    let id = crate::diagnostics::resolve_fix_id(value)?;
    let report = configured_report_for_terminal(
        collect_report_with(crate::diagnostics::probes::collect_standalone_fix(
            &terminal,
            Some(id),
        )),
        &terminal,
    );
    let request = crate::diagnostics::FixRequest::from_environment(id)?;
    let plan = crate::diagnostics::plan_fix(request, &report, &terminal)?;
    apply_fix_plan(args, stdin_is_terminal, input, writer, &terminal, plan)
}

fn apply_fix_plan(
    args: FixArgs,
    stdin_is_terminal: bool,
    input: &mut impl std::io::BufRead,
    writer: &mut impl Write,
    terminal: &crate::terminal::TerminalContext,
    plan: FixPlan,
) -> Result<()> {
    write_fix_preview(&plan, writer)?;

    if !args.yes {
        if !stdin_is_terminal {
            anyhow::bail!(
                "Cannot apply this fix without confirmation. Run it in an interactive terminal or add `--yes`."
            );
        }
        write!(writer, "\nApply this fix? [y/N] ")?;
        writer.flush()?;
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(writer, "Fix cancelled.")?;
            return Ok(());
        }
    }

    let outcome = crate::diagnostics::apply_fix(plan)?;
    if outcome.activation() == FixActivation::SatisfiedNow {
        // Use the shell stored on the outcome (from planning), not `$SHELL`.
        // `$SHELL` may be missing or no longer match the shell the plan targeted.
        let post_report = crate::diagnostics::configured_report(
            collect_report_with(crate::diagnostics::probes::collect_standalone(terminal)),
            outcome.managed_alias_is_configured(),
        );
        if post_report
            .findings
            .iter()
            .any(|finding| finding.id == outcome.id())
        {
            anyhow::bail!(
                "The change was applied, but Doctor still reports `{}`.",
                outcome.id()
            );
        }
    } else if !crate::diagnostics::verify_persistent_fix(&outcome) {
        anyhow::bail!(
            "The change was applied, but Doctor could not verify `{}` in persistent configuration.",
            outcome.id()
        );
    }

    writeln!(
        writer,
        "\n{}",
        crate::diagnostics::format_fix_success(&outcome)
    )?;
    Ok(())
}

fn write_fix_preview(plan: &FixPlan, writer: &mut impl Write) -> std::io::Result<()> {
    write!(writer, "{}", crate::diagnostics::format_fix_preview(plan))
}

fn shell_home_and_kind() -> Option<(std::path::PathBuf, ShellKind)> {
    #[allow(deprecated)]
    let home = std::env::home_dir()?;
    let shell = std::env::var_os("SHELL")?;
    let kind = ShellKind::from_shell_path(Path::new(&shell))?;
    Some((home, kind))
}

/// Outcome of validating an optional plugin-diagnostics fixture against the
/// Orca-released contract copy only (never the Go tree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginDiagnosticsView {
    /// No plugin diagnostics supplied — native doctor remains useful.
    Absent,
    /// Fixture parsed and authority-safe.
    Accepted { status: String, backend_id: String },
    /// Present but unusable; native diagnosis continues.
    Reported {
        kind: PluginDiagnosticsIssue,
        detail: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginDiagnosticsIssue {
    Missing,
    Malformed,
    UnauthorizedField,
    Incompatible,
}

/// Validate plugin diagnostics JSON against Orca's released schema constraints.
///
/// Does **not** grant install/execution authority. Missing or bad optional
/// plugin diagnostics never block native doctor output.
pub fn validate_plugin_diagnostics_fixture(raw: &[u8]) -> PluginDiagnosticsView {
    let value: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(e) => {
            return PluginDiagnosticsView::Reported {
                kind: PluginDiagnosticsIssue::Malformed,
                detail: format!("json: {e}"),
            };
        }
    };
    let Some(obj) = value.as_object() else {
        return PluginDiagnosticsView::Reported {
            kind: PluginDiagnosticsIssue::Malformed,
            detail: "root must be object".into(),
        };
    };
    for key in FORBIDDEN_DIAG_AUTHORITY_KEYS {
        if obj.contains_key(*key) {
            return PluginDiagnosticsView::Reported {
                kind: PluginDiagnosticsIssue::UnauthorizedField,
                detail: (*key).to_string(),
            };
        }
    }
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let backend_id = obj
        .get("backendId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if status.is_empty() || backend_id.is_empty() {
        return PluginDiagnosticsView::Reported {
            kind: PluginDiagnosticsIssue::Incompatible,
            detail: "status and backendId required".into(),
        };
    }
    if !matches!(
        status.as_str(),
        "healthy" | "degraded" | "unavailable" | "invalid"
    ) {
        // Still render without authority; mark incompatible for callers.
        return PluginDiagnosticsView::Reported {
            kind: PluginDiagnosticsIssue::Incompatible,
            detail: format!("status={status}"),
        };
    }
    PluginDiagnosticsView::Accepted {
        status,
        backend_id,
    }
}

/// Load a named fixture from the Orca-released diagnostics contract directory.
pub fn load_released_diagnostics_fixture(
    orca_root: &Path,
    name: &str,
) -> Result<(Vec<u8>, PluginDiagnosticsView)> {
    let path = orca_root
        .join(ORCA_DIAGNOSTICS_CONTRACT_REL)
        .join(name);
    if !path.is_file() {
        return Ok((
            Vec::new(),
            PluginDiagnosticsView::Reported {
                kind: PluginDiagnosticsIssue::Missing,
                detail: path.display().to_string(),
            },
        ));
    }
    let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let view = validate_plugin_diagnostics_fixture(&raw);
    Ok((raw, view))
}

/// Render optional plugin diagnostics into the human doctor report section.
pub fn format_plugin_diagnostics_section(view: &PluginDiagnosticsView) -> String {
    human::format_plugin_diagnostics(view)
}

/// Resolve Orca root by walking parents for Cargo.toml + rust-toolchain.toml.
pub fn find_orca_root_from(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("rust-toolchain.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!("orca root not found from {}", start.display());
        }
    }
}

#[cfg(test)]
mod tests;
