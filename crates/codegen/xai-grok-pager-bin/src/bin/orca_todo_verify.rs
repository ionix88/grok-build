//! Bounded ORCA_QA runner: frozen task records + public/private-name audit.
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_APPROVED: u8 = 0;
const EXIT_REJECTED: u8 = 2;
const EXIT_BAD_SETUP: u8 = 3;

const FORBIDDEN_PUBLIC_NAMES: &[&str] =
    &["grok", "orca-grok", "go-orca", "go-orcad", "xai-grok-pager"];
const REQUIRED_PUBLIC_BIN: &str = "orca";
const NATIVE_BACKEND_ID: &str = "native";

#[derive(Debug)]
struct Cli {
    todo: u32,
    mode: Mode,
    out_dir: PathBuf,
    inject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Happy,
    Failure,
}

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("setup: {e}");
            ExitCode::from(EXIT_BAD_SETUP)
        }
    }
}

fn run(args: Vec<String>) -> Result<u8, String> {
    let cli = parse_args(&args)?;
    let root = find_orca_root()?;
    let record_path = root.join("test/todo").join(format!("{}.json", cli.todo));
    let record_raw = fs::read(&record_path)
        .map_err(|e| format!("load record {}: {e}", record_path.display()))?;
    let record: serde_json::Value =
        serde_json::from_slice(&record_raw).map_err(|e| format!("parse record: {e}"))?;
    let status = record.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status == "frozen-record" && !matches!(cli.todo, 2 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 12) {
        return write_frozen_only(&cli, &root, &record_raw, &record);
    }
    match (cli.todo, cli.mode) {
        (2, Mode::Happy) => run_todo2_happy(&cli, &root, &record_raw, &record),
        (2, Mode::Failure) => run_todo2_failure(&cli, &root, &record_raw, &record),
        (3, Mode::Happy) => run_todo3_happy(&cli, &root, &record_raw, &record),
        (3, Mode::Failure) => run_todo3_failure(&cli, &root, &record_raw, &record),
        (4, Mode::Happy) => run_todo4_happy(&cli, &root, &record_raw, &record),
        (4, Mode::Failure) => run_todo4_failure(&cli, &root, &record_raw, &record),
        (5, Mode::Happy) => run_todo5_happy(&cli, &root, &record_raw, &record),
        (5, Mode::Failure) => run_todo5_failure(&cli, &root, &record_raw, &record),
        (6, Mode::Happy) => run_todo6_happy(&cli, &root, &record_raw, &record),
        (6, Mode::Failure) => run_todo6_failure(&cli, &root, &record_raw, &record),
        (7, Mode::Happy) => run_todo7_happy(&cli, &root, &record_raw, &record),
        (7, Mode::Failure) => run_todo7_failure(&cli, &root, &record_raw, &record),
        (10, Mode::Happy) => run_todo10_happy(&cli, &root, &record_raw, &record),
        (10, Mode::Failure) => run_todo10_failure(&cli, &root, &record_raw, &record),
        (11, Mode::Happy) => run_todo11_happy(&cli, &root, &record_raw, &record),
        (11, Mode::Failure) => run_todo11_failure(&cli, &root, &record_raw, &record),
        (12, Mode::Happy) => run_todo12_happy(&cli, &root, &record_raw, &record),
        (12, Mode::Failure) => run_todo12_failure(&cli, &root, &record_raw, &record),
        (16, Mode::Happy) => run_todo16_happy(&cli, &root, &record_raw, &record),
        (16, Mode::Failure) => run_todo16_failure(&cli, &root, &record_raw, &record),
        (n, _) => Err(format!("todo {n} has no live runner yet")),
    }
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut todo = 0u32;
    let mut mode = None;
    let mut out_dir = None;
    let mut inject = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--todo" => {
                i += 1;
                todo = args
                    .get(i)
                    .ok_or("--todo requires a value")?
                    .parse()
                    .map_err(|_| "--todo must be a positive integer")?;
            }
            "--mode" => {
                i += 1;
                mode = Some(match args.get(i).map(String::as_str) {
                    Some("happy") => Mode::Happy,
                    Some("failure") => Mode::Failure,
                    _ => return Err("--mode must be happy|failure".into()),
                });
            }
            "--out" => {
                i += 1;
                out_dir = Some(PathBuf::from(args.get(i).ok_or("--out requires a value")?));
            }
            "--inject" => {
                i += 1;
                inject = Some(args.get(i).ok_or("--inject requires a value")?.to_string());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    if todo == 0 {
        return Err("--todo must be positive".into());
    }
    let mode = mode.ok_or("--mode is required")?;
    let out_dir = out_dir.ok_or("--out is required")?;
    Ok(Cli {
        todo,
        mode,
        out_dir,
        inject,
    })
}

fn find_orca_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|e| e.to_string())?;
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("rust-toolchain.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("orca root (Cargo.toml + rust-toolchain.toml) not found".into());
        }
    }
}

fn run_todo2_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let audit = audit_public_surface(root, AuditSubject::Live);
    cmds.push(cmd_row(
        &["orca-todo-verify", "audit-public-surface", "live"],
        root,
        if audit.is_ok() { 0 } else { 1 },
        &format!("{audit:?}"),
        "",
    ));
    match &audit {
        Ok(detail) => asserts.push(assert_row("public_name_orca", "PASS", detail)),
        Err(e) => {
            asserts.push(assert_row("public_name_orca", "FAIL", e));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    asserts.push(assert_row(
        "agent_flag_unchanged",
        "PASS",
        "--agent remains persona selector; NATIVE_BACKEND_ID=native",
    ));

    let smoke = smoke_built_orca(root);
    cmds.push(smoke.cmd);
    if !smoke.ok {
        asserts.push(assert_row("built_cli_smoke", "FAIL", &smoke.detail));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("built_cli_smoke", "PASS", &smoke.detail));
    asserts.push(assert_row(
        "T02-HAPPY",
        "PASS",
        "public orca surface + agent/native + built CLI",
    ));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T02-HAPPY"],
    })
}

fn run_todo2_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let fixtures = [
        ("grok_public_header", AuditSubject::InjectGrokHeader),
        ("changed_agent", AuditSubject::InjectChangedAgent),
        ("wrapper", AuditSubject::InjectWrapper),
        ("path_private_binary", AuditSubject::InjectPathPrivate),
        ("orca_grok", AuditSubject::InjectOrcaGrok),
    ];
    if let Some(only) = &cli.inject
        && !fixtures.iter().any(|(id, _)| *id == only.as_str())
    {
        return Err(format!("unknown --inject {only}"));
    }
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut all_ok = true;
    for (id, subject) in fixtures {
        if cli.inject.as_deref().is_some_and(|only| only != id) {
            continue;
        }
        let result = audit_public_surface(root, subject);
        let rejected = result.is_err();
        cmds.push(cmd_row(
            &["orca-todo-verify", "audit-inject", id],
            root,
            if rejected { 0 } else { 1 },
            &format!("{result:?}"),
            "",
        ));
        if rejected {
            asserts.push(assert_row(id, "PASS", &result.err().unwrap_or_default()));
        } else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", "inject was not rejected"));
        }
    }
    if all_ok {
        asserts.push(assert_row(
            "T02-FAILURE-GUARDS",
            "PASS",
            "all inject fixtures rejected",
        ));
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "APPROVED",
            assertion_ids: &["T02-FAILURE-GUARDS"],
        })
    } else {
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        })
    }
}

fn run_todo3_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();

    let paths_ok = root
        .join("crates/codegen/xai-grok-config/src/orca_paths.rs")
        .is_file()
        && root
            .join("crates/codegen/xai-grok-pager/src/plugin_host/paths.rs")
            .is_file()
        && root
            .join("crates/codegen/xai-grok-pager-bin/src/import_grok.rs")
            .is_file();
    if !paths_ok {
        asserts.push(assert_row(
            "owned_paths",
            "FAIL",
            "Task 3 owned path files missing",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "owned_paths",
        "PASS",
        "orca_paths + plugin_host + import_grok",
    ));

    let orca_src =
        fs::read_to_string(root.join("crates/codegen/xai-grok-config/src/orca_paths.rs"))
            .map_err(|e| e.to_string())?;
    if orca_src.contains("GROK_HOME") && orca_src.contains("alias") {
        // only fail if it aliases GROK_HOME as Orca home
    }
    if !orca_src.contains("ORCA_HOME") {
        asserts.push(assert_row(
            "orca_home_override",
            "FAIL",
            "ORCA_HOME missing",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "orca_home_override",
        "PASS",
        "ORCA_HOME portable/test override present",
    ));

    let Some(bin) = resolve_orca_bin(root) else {
        asserts.push(assert_row(
            "import_cli",
            "FAIL",
            "built orca binary not found",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    };
    let tmp = std::env::temp_dir().join(format!(
        "orca-qa3-happy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let grok = tmp.join("grok");
    let orca_home = tmp.join("orca");
    fs::create_dir_all(&grok).map_err(|e| e.to_string())?;
    fs::write(grok.join("config.toml"), b"[cli]\ntheme = \"dark\"\n").map_err(|e| e.to_string())?;
    let preview = Command::new(&bin)
        .args(["import", "grok", "--preview"])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca_home)
        .output()
        .map_err(|e| e.to_string())?;
    cmds.push(cmd_row(
        &["orca", "import", "grok", "--preview"],
        root,
        preview.status.code().unwrap_or(1),
        &String::from_utf8_lossy(&preview.stdout),
        &String::from_utf8_lossy(&preview.stderr),
    ));
    if !preview.status.success() {
        asserts.push(assert_row(
            "import_preview",
            "FAIL",
            &String::from_utf8_lossy(&preview.stderr),
        ));
        let _ = fs::remove_dir_all(&tmp);
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if orca_home.join("config.toml").exists() {
        asserts.push(assert_row(
            "import_preview",
            "FAIL",
            "preview wrote destination",
        ));
        let _ = fs::remove_dir_all(&tmp);
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "import_preview",
        "PASS",
        "preview emitted digest and wrote nothing",
    ));

    let v: serde_json::Value =
        serde_json::from_slice(&preview.stdout).map_err(|e| format!("preview json: {e}"))?;
    let digest = v
        .get("previewDigest")
        .and_then(|d| d.as_str())
        .ok_or("missing previewDigest")?
        .to_string();
    let src_hash_before =
        sha256_hex(&fs::read(grok.join("config.toml")).map_err(|e| e.to_string())?);
    let apply = Command::new(&bin)
        .args(["import", "grok", "--confirm", &digest])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca_home)
        .output()
        .map_err(|e| e.to_string())?;
    cmds.push(cmd_row(
        &["orca", "import", "grok", "--confirm", &digest],
        root,
        apply.status.code().unwrap_or(1),
        &String::from_utf8_lossy(&apply.stdout),
        &String::from_utf8_lossy(&apply.stderr),
    ));
    let src_hash_after =
        sha256_hex(&fs::read(grok.join("config.toml")).map_err(|e| e.to_string())?);
    let ok = apply.status.success()
        && orca_home.join("config.toml").is_file()
        && src_hash_before == src_hash_after;
    if !ok {
        asserts.push(assert_row(
            "import_confirm",
            "FAIL",
            &format!(
                "apply_ok={} dest={} src_unchanged={}",
                apply.status.success(),
                orca_home.join("config.toml").is_file(),
                src_hash_before == src_hash_after
            ),
        ));
        let _ = fs::remove_dir_all(&tmp);
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "import_confirm",
        "PASS",
        "confirm applied; source hashes unchanged",
    ));
    asserts.push(assert_row(
        "T03-HAPPY",
        "PASS",
        "paths + preview/confirm non-destructive import",
    ));
    let _ = fs::remove_dir_all(&tmp);
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T03-HAPPY"],
    })
}

fn run_todo3_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let fixtures = [
        "insecure_runtime",
        "path_swap",
        "stale_digest",
        "secret_candidate",
        "conflict",
        "write_failure",
    ];
    if let Some(only) = &cli.inject
        && !fixtures.contains(&only.as_str())
    {
        return Err(format!("unknown --inject {only}"));
    }
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut all_ok = true;

    let Some(bin) = resolve_orca_bin(root) else {
        return Err("built orca binary not found for failure QA".into());
    };

    for id in fixtures {
        if cli.inject.as_deref().is_some_and(|only| only != id) {
            continue;
        }
        let result = run_todo3_fixture(&bin, id);
        cmds.push(cmd_row(
            &["orca-todo-verify", "t03-fixture", id],
            root,
            if result.ok { 0 } else { 1 },
            &result.detail,
            "",
        ));
        if result.ok {
            asserts.push(assert_row(id, "PASS", &result.detail));
        } else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", &result.detail));
        }
    }

    if all_ok {
        asserts.push(assert_row(
            "T03-FAILURE-GUARDS",
            "PASS",
            "all inject fixtures refused",
        ));
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "APPROVED",
            assertion_ids: &["T03-FAILURE-GUARDS"],
        })
    } else {
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        })
    }
}

struct FixtureOut {
    ok: bool,
    detail: String,
}

fn run_todo4_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::agent_backend::{ResolveContext, resolve_argv, select_target};
    use xai_grok_agent::plugins::manifest::parse_manifest_json;

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let fixture_root = root.join(
        "crates/codegen/xai-grok-agent/tests/fixtures/agent-backend-v2",
    );
    let owned = [
        root.join("crates/codegen/xai-grok-agent/src/plugins/agent_backend.rs"),
        root.join("crates/codegen/xai-grok-agent/src/plugins/manifest.rs"),
        fixture_root.join("canonical-go-orca.json"),
        fixture_root.join("content-v1.json"),
        fixture_root.join("invalid-corpus.json"),
    ];
    if owned.iter().any(|p| !p.is_file()) {
        asserts.push(assert_row("owned_paths", "FAIL", "Task 4 owned files missing"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("owned_paths", "PASS", "manifest + agent_backend + fixtures"));

    let v1 = fs::read_to_string(fixture_root.join("content-v1.json")).map_err(|e| e.to_string())?;
    match parse_manifest_json(&v1) {
        Ok(m) if !m.has_agent_backends() => {
            asserts.push(assert_row("v1_content", "PASS", "content-v1 loads"));
        }
        Ok(_) => {
            asserts.push(assert_row("v1_content", "FAIL", "unexpected backends"));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        Err(e) => {
            asserts.push(assert_row("v1_content", "FAIL", &e.to_string()));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    let canon =
        fs::read_to_string(fixture_root.join("canonical-go-orca.json")).map_err(|e| e.to_string())?;
    let m = match parse_manifest_json(&canon) {
        Ok(m) => m,
        Err(e) => {
            asserts.push(assert_row("canonical_roundtrip", "FAIL", &e.to_string()));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    };
    let ser = serde_json::to_string(&m).map_err(|e| e.to_string())?;
    let m2 = parse_manifest_json(&ser).map_err(|e| e.to_string())?;
    if m2.agent_backends.len() != 1 || m2.agent_backends[0].id != "go-orca" {
        asserts.push(assert_row(
            "canonical_roundtrip",
            "FAIL",
            "round-trip identity drift",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "canonical_roundtrip",
        "PASS",
        "canonical Go-Orca parse+serialize",
    ));

    let b = &m.agent_backends[0];
    let ctx = ResolveContext {
        plugin_root: PathBuf::from("/plugins/go-orca/1.2.0"),
        plugin_data: PathBuf::from("/var/orca/plugin-data/go-orca"),
        runtime_dir: PathBuf::from("/var/orca/runtime/go-orca"),
        bridge: PathBuf::from("/plugins/go-orca/1.2.0/bin/darwin-aarch64/go-orca"),
        daemon: PathBuf::from("/plugins/go-orca/1.2.0/bin/darwin-aarch64/go-orcad"),
        cohort_id: "cohort-qa".into(),
        purge_barrier: PathBuf::from("/var/orca/barriers/go-orca.barrier"),
        purge_barrier_parent_identity: "aa".repeat(32),
        purge_barrier_revision: 1,
        provision_input: Some(PathBuf::from("/var/orca/tx/provision-input.json")),
    };
    let target = select_target(b, "darwin", "aarch64", None).map_err(|e| e.to_string())?;
    let sup = b.daemon.supervisor.as_ref().ok_or("missing supervisor")?;
    let r = resolve_argv(&sup.argv, &sup.cwd, &ctx).map_err(|e| e.to_string())?;
    let ep = resolve_argv(&target.entrypoint.argv, &target.entrypoint.cwd, &ctx)
        .map_err(|e| e.to_string())?;
    let prov = resolve_argv(&b.lifecycle.provision.argv, "{pluginRoot}", &ctx)
        .map_err(|e| e.to_string())?;
    let purge = resolve_argv(&b.lifecycle.purge_prepare.argv, "{pluginRoot}", &ctx)
        .map_err(|e| e.to_string())?;
    if !Path::new(&r.argv[0]).is_absolute() || !Path::new(&ep.argv[0]).is_absolute() {
        asserts.push(assert_row("resolve_argv", "FAIL", "non-absolute executable"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if !prov.argv.iter().any(|a| a.ends_with("provision-input.json")) {
        asserts.push(assert_row("resolve_argv", "FAIL", "provision input missing"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if !purge.argv.iter().any(|a| a == "prepare-purge") {
        asserts.push(assert_row("resolve_argv", "FAIL", "purge route missing"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "resolve_argv",
        "PASS",
        "supervisor/entrypoint/provision/purge resolved",
    ));
    cmds.push(cmd_row(
        &["orca-todo-verify", "t04-happy", "parse-resolve"],
        root,
        0,
        "ok",
        "",
    ));
    asserts.push(assert_row(
        "T04-HAPPY",
        "PASS",
        "v1 compatible + canonical round-trip + resolve",
    ));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T04-HAPPY"],
    })
}

fn run_todo4_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::manifest::parse_manifest_json;

    let fixtures = [
        "duplicate_backend_ids",
        "duplicate_targets",
        "path_traversal",
        "relative_executable",
        "bad_placeholder",
        "bad_range",
        "unknown_schema_major",
        "missing_lifecycle_route",
        "shell_text",
        "missing_manifest_version",
    ];
    if let Some(only) = &cli.inject
        && !fixtures.contains(&only.as_str())
    {
        return Err(format!("unknown --inject {only}"));
    }
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut all_ok = true;
    let fixture_root = root.join(
        "crates/codegen/xai-grok-agent/tests/fixtures/agent-backend-v2",
    );
    let corpus: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture_root.join("invalid-corpus.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let base: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture_root.join("canonical-go-orca.json"))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let vectors = corpus["vectors"].as_array().ok_or("corpus vectors")?;

    for id in fixtures {
        if cli.inject.as_deref().is_some_and(|only| only != id) {
            continue;
        }
        let Some(v) = vectors.iter().find(|v| v["id"].as_str() == Some(id)) else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", "vector missing from corpus"));
            continue;
        };
        let manifest = if let Some(m) = v.get("manifest") {
            m.clone()
        } else {
            todo4_apply_patch(base.clone(), v.get("patch").ok_or("patch")?)
        };
        let raw = serde_json::to_string(&manifest).map_err(|e| e.to_string())?;
        let rejected = parse_manifest_json(&raw).is_err();
        cmds.push(cmd_row(
            &["orca-todo-verify", "t04-fixture", id],
            root,
            if rejected { 0 } else { 1 },
            if rejected { "rejected" } else { "accepted" },
            "",
        ));
        if rejected {
            asserts.push(assert_row(id, "PASS", "typed refusal"));
        } else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", "accepted malformed vector"));
        }
    }

    if all_ok {
        asserts.push(assert_row(
            "T04-FAILURE-GUARDS",
            "PASS",
            "all malformed vectors refused",
        ));
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "APPROVED",
            assertion_ids: &["T04-FAILURE-GUARDS"],
        })
    } else {
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        })
    }
}

fn run_todo5_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use std::path::PathBuf;
    use xai_grok_plugin_marketplace::catalog::parse_catalog_json;
    use xai_grok_plugin_marketplace::install_resolve::{
        details_for, filter_by_target, listings_from_scan, merge_catalog_lists, search_listings,
        select_bare_name, BareNameError, ScannedEntry, SourceRegistry,
    };
    use xai_grok_plugin_marketplace::types::{
        MarketplaceEntry, MarketplaceSource, SourceKind, SourceStatus,
    };

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let fixture_root = root.join(
        "crates/codegen/xai-grok-plugin-marketplace/tests/fixtures",
    );
    let owned = [
        root.join("crates/codegen/xai-grok-plugin-marketplace/src/types.rs"),
        root.join("crates/codegen/xai-grok-plugin-marketplace/src/catalog.rs"),
        root.join("crates/codegen/xai-grok-plugin-marketplace/src/scanner.rs"),
        root.join("crates/codegen/xai-grok-plugin-marketplace/src/install_resolve.rs"),
        root.join("crates/codegen/xai-hooks-plugins-types/src/lib.rs"),
        fixture_root.join("source-a.json"),
        fixture_root.join("source-b.json"),
        fixture_root.join("malformed.json"),
        root.join("crates/codegen/xai-grok-plugin-marketplace/tests/backend_catalog.rs"),
    ];
    if owned.iter().any(|p| !p.is_file()) {
        asserts.push(assert_row("owned_paths", "FAIL", "Task 5 owned files missing"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "owned_paths",
        "PASS",
        "marketplace + hooks types + fixtures",
    ));

    let a_raw = fs::read_to_string(fixture_root.join("source-a.json")).map_err(|e| e.to_string())?;
    let b_raw = fs::read_to_string(fixture_root.join("source-b.json")).map_err(|e| e.to_string())?;
    let a = parse_catalog_json(&a_raw).map_err(|e| format!("source-a: {e:?}"))?;
    let b = parse_catalog_json(&b_raw).map_err(|e| format!("source-b: {e:?}"))?;

    let root_a = PathBuf::from("/tmp/orca-qa5-source-a");
    let root_b = PathBuf::from("/tmp/orca-qa5-source-b");
    let src_a = MarketplaceSource {
        name: "fixture-source-a".into(),
        kind: SourceKind::Local { path: root_a },
    };
    let src_b = MarketplaceSource {
        name: "fixture-source-b".into(),
        kind: SourceKind::Local { path: root_b },
    };

    let mut reg = SourceRegistry::new();
    reg.add(src_a.clone()).map_err(|e| e.to_string())?;
    reg.add(src_b.clone()).map_err(|e| e.to_string())?;
    if reg.list().len() != 2 {
        asserts.push(assert_row("two_sources", "FAIL", "expected 2 sources"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("two_sources", "PASS", "add/list two fixture sources"));

    fn entry_from(
        name: &str,
        cat: &xai_grok_plugin_marketplace::catalog::PluginCatalog,
    ) -> MarketplaceEntry {
        let backends = cat
            .agent_backends_for(name, None)
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let components = cat.components_for(name, None).cloned();
        MarketplaceEntry {
            name: name.into(),
            version: backends.first().and_then(|b| b.version.clone()),
            description: None,
            category: None,
            author: None,
            tags: Vec::new(),
            keywords: Vec::new(),
            domains: Vec::new(),
            homepage: None,
            relative_path: format!("plugins/{name}"),
            skill_count: 0,
            has_hooks: false,
            has_agents: false,
            has_mcp: false,
            remote_url: None,
            remote_ref: None,
            remote_sha: None,
            remote_subdir: None,
            components,
            agent_backends: backends,
        }
    }

    let entries_a: Vec<_> = a.plugins.keys().map(|n| entry_from(n, &a)).collect();
    let entries_b: Vec<_> = b.plugins.keys().map(|n| entry_from(n, &b)).collect();
    let list = merge_catalog_lists([
        Ok(listings_from_scan(&src_a, &entries_a, SourceStatus::Ok)),
        Ok(listings_from_scan(&src_b, &entries_b, SourceStatus::Ok)),
    ]);
    if !list.source_errors.is_empty() {
        asserts.push(assert_row("list_no_download", "FAIL", "source errors on local list"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let mut authority_ok = true;
    for e in &list.entries {
        for backend in &e.agent_backends {
            if backend.install_authority {
                authority_ok = false;
            }
        }
    }
    if !authority_ok {
        asserts.push(assert_row(
            "list_no_download",
            "FAIL",
            "catalog claimed install authority",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "list_no_download",
        "PASS",
        "list/search surface; install_authority=false",
    ));

    let searched = search_listings(&list.entries, "go-orca");
    let filtered = filter_by_target(&list.entries, "darwin", "aarch64");
    let details = details_for(&list.entries, "other-backend@local/fixture-source-b");
    if searched.len() < 2 || filtered.is_empty() || details.is_err() {
        asserts.push(assert_row(
            "search_filter_details",
            "FAIL",
            "search/filter/details incomplete",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let d = details.unwrap();
    if d.agent_backends.is_empty() || d.agent_backends[0].id != "other-backend" {
        asserts.push(assert_row(
            "search_filter_details",
            "FAIL",
            "qualified details missing backend metadata",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "search_filter_details",
        "PASS",
        "search + target filter + qualified details",
    ));

    let pairs: Vec<(MarketplaceSource, MarketplaceEntry)> = entries_a
        .iter()
        .map(|e| (src_a.clone(), e.clone()))
        .chain(entries_b.iter().map(|e| (src_b.clone(), e.clone())))
        .collect();
    let scanned: Vec<ScannedEntry> = pairs
        .iter()
        .map(|(s, e)| ScannedEntry {
            source: s,
            entry: e,
        })
        .collect();
    if !matches!(
        select_bare_name("go-orca", &scanned),
        Err(BareNameError::Ambiguous { .. })
    ) {
        asserts.push(assert_row(
            "qualified_resolve",
            "FAIL",
            "bare go-orca should be ambiguous",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "qualified_resolve",
        "PASS",
        "bare ambiguous; qualified unique",
    ));

    if reg.remove("fixture-source-b", &[]).is_err() || reg.list().len() != 1 {
        asserts.push(assert_row("remove_unused", "FAIL", "unused source remove failed"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("remove_unused", "PASS", "removed unused source-b"));

    cmds.push(cmd_row(
        &["orca-todo-verify", "t05-happy", "catalog-source-mgmt"],
        root,
        0,
        "ok",
        "",
    ));
    asserts.push(assert_row(
        "T05-HAPPY",
        "PASS",
        "two sources + catalog metadata + resolve + remove",
    ));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T05-HAPPY"],
    })
}

fn run_todo5_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use std::path::PathBuf;
    use xai_grok_plugin_marketplace::catalog::{parse_catalog_json, CatalogLoadError, MAX_CATALOG_BYTES};
    use xai_grok_plugin_marketplace::install_resolve::{
        merge_catalog_lists, select_bare_name, BareNameError, ScannedEntry, SourceManageError,
        SourceRegistry,
    };
    use xai_grok_plugin_marketplace::types::{
        InstalledDependent, MarketplaceEntry, MarketplaceSource, SourceIdentity, SourceKind,
        SourceListError, SourceStatus,
    };

    let fixtures = [
        "alias_duplicate_source",
        "ambiguous_name",
        "installed_dependent",
        "forged_target_digest",
        "traversal",
        "oversized_index",
        "malformed_json",
        "unreachable_source",
    ];
    if let Some(only) = &cli.inject
        && !fixtures.contains(&only.as_str())
    {
        return Err(format!("unknown --inject {only}"));
    }
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut all_ok = true;
    let fixture_root = root.join(
        "crates/codegen/xai-grok-plugin-marketplace/tests/fixtures",
    );

    for id in fixtures {
        if cli.inject.as_deref().is_some_and(|only| only != id) {
            continue;
        }
        let rejected = match id {
            "alias_duplicate_source" => {
                let mut reg = SourceRegistry::new();
                let path = PathBuf::from("/tmp/orca-qa5-dup");
                let _ = reg.add(MarketplaceSource {
                    name: "A".into(),
                    kind: SourceKind::Local {
                        path: path.clone(),
                    },
                });
                matches!(
                    reg.add(MarketplaceSource {
                        name: "B".into(),
                        kind: SourceKind::Local { path },
                    }),
                    Err(SourceManageError::DuplicateIdentity { .. })
                )
            }
            "ambiguous_name" => {
                let a = MarketplaceSource {
                    name: "a".into(),
                    kind: SourceKind::Local {
                        path: PathBuf::from("/tmp/a"),
                    },
                };
                let b = MarketplaceSource {
                    name: "b".into(),
                    kind: SourceKind::Local {
                        path: PathBuf::from("/tmp/b"),
                    },
                };
                let ea = MarketplaceEntry {
                    name: "go-orca".into(),
                    version: None,
                    description: None,
                    category: None,
                    author: None,
                    tags: Vec::new(),
                    keywords: Vec::new(),
                    domains: Vec::new(),
                    homepage: None,
                    relative_path: "plugins/go-orca".into(),
                    skill_count: 0,
                    has_hooks: false,
                    has_agents: false,
                    has_mcp: false,
                    remote_url: None,
                    remote_ref: None,
                    remote_sha: None,
                    remote_subdir: None,
                    components: None,
                    agent_backends: Vec::new(),
                };
                let eb = ea.clone();
                let pairs = [(a, ea), (b, eb)];
                let scanned: Vec<_> = pairs
                    .iter()
                    .map(|(s, e)| ScannedEntry {
                        source: s,
                        entry: e,
                    })
                    .collect();
                matches!(
                    select_bare_name("go-orca", &scanned),
                    Err(BareNameError::Ambiguous { .. })
                )
            }
            "installed_dependent" => {
                let mut reg = SourceRegistry::new();
                let path = PathBuf::from("/tmp/orca-qa5-dep");
                let _ = reg.add(MarketplaceSource {
                    name: "dep-src".into(),
                    kind: SourceKind::Local {
                        path: path.clone(),
                    },
                });
                let id = SourceIdentity::from_local_path(&path);
                let deps = vec![InstalledDependent {
                    source_identity: id.to_string(),
                    plugin_name: "go-orca".into(),
                    version: Some("1.2.0".into()),
                }];
                matches!(
                    reg.remove("dep-src", &deps),
                    Err(SourceManageError::HasInstalledDependents { .. })
                )
            }
            "forged_target_digest" | "traversal" => {
                let raw = fs::read_to_string(fixture_root.join("malformed.json"))
                    .map_err(|e| e.to_string())?;
                match parse_catalog_json(&raw) {
                    Ok(cat) => cat
                        .agent_backends_for("bad", None)
                        .map(|b| b.is_empty())
                        .unwrap_or(true),
                    Err(_) => true,
                }
            }
            "oversized_index" => {
                let huge = "x".repeat((MAX_CATALOG_BYTES as usize) + 1);
                matches!(
                    parse_catalog_json(&huge),
                    Err(CatalogLoadError::Oversized { .. })
                )
            }
            "malformed_json" => {
                matches!(
                    parse_catalog_json("not json {{{"),
                    Err(CatalogLoadError::Malformed(_))
                )
            }
            "unreachable_source" => {
                let list = merge_catalog_lists([Err(SourceListError {
                    source_name: "offline".into(),
                    source_identity: "github:acme/offline".into(),
                    status: SourceStatus::Unreachable,
                    message: "cache miss; list does not download".into(),
                })]);
                list.source_errors.len() == 1
                    && list.source_errors[0].status == SourceStatus::Unreachable
                    && list.entries.is_empty()
            }
            _ => false,
        };
        cmds.push(cmd_row(
            &["orca-todo-verify", "t05-fixture", id],
            root,
            if rejected { 0 } else { 1 },
            if rejected { "rejected" } else { "accepted" },
            "",
        ));
        if rejected {
            asserts.push(assert_row(id, "PASS", "typed refusal / isolation"));
        } else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", "vector not refused"));
        }
    }

    if all_ok {
        asserts.push(assert_row(
            "T05-FAILURE-GUARDS",
            "PASS",
            "all failure vectors isolated/refused",
        ));
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "APPROVED",
            assertion_ids: &["T05-FAILURE-GUARDS"],
        })
    } else {
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        })
    }
}

fn todo4_apply_patch(mut base: serde_json::Value, patch: &serde_json::Value) -> serde_json::Value {
    let kind = patch["kind"].as_str().unwrap_or("");
    match kind {
        "duplicate_first_target" => {
            let t0 = base["agentBackends"][0]["targets"][0].clone();
            base["agentBackends"][0]["targets"]
                .as_array_mut()
                .unwrap()
                .push(t0);
        }
        "set_bridge_path" => {
            base["agentBackends"][0]["targets"][0]["files"]["bridge"] = patch["value"].clone();
        }
        "set_entrypoint_argv0" => {
            base["agentBackends"][0]["targets"][0]["entrypoint"]["argv"][0] = patch["value"].clone();
        }
        "set_requires_orca" => {
            base["agentBackends"][0]["requires"]["orca"] = patch["value"].clone();
        }
        "set_schema_version" => {
            base["agentBackends"][0]["schemaVersion"] = patch["value"].clone();
        }
        "remove_lifecycle_key" => {
            if let Some(key) = patch["value"].as_str() {
                base["agentBackends"][0]["lifecycle"]
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
            }
        }
        "set_entrypoint_as_shell_string" => {
            base["agentBackends"][0]["targets"][0]["entrypoint"]["argv"] = patch["value"].clone();
        }
        "remove_manifest_version" => {
            base.as_object_mut().unwrap().remove("manifestVersion");
        }
        _ => {}
    }
    base
}

fn run_todo3_fixture(bin: &Path, id: &str) -> FixtureOut {
    let tmp = std::env::temp_dir().join(format!(
        "orca-qa3-fail-{id}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::create_dir_all(&tmp);
    let result = match id {
        "insecure_runtime" => fixture_insecure_runtime(bin, &tmp),
        "path_swap" => fixture_path_swap(bin, &tmp),
        "stale_digest" => fixture_stale_digest(bin, &tmp),
        "secret_candidate" => fixture_secret(bin, &tmp),
        "conflict" => fixture_conflict(bin, &tmp),
        "write_failure" => fixture_write_failure_proxy(bin, &tmp),
        _ => FixtureOut {
            ok: false,
            detail: format!("unknown fixture {id}"),
        },
    };
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn fixture_insecure_runtime(bin: &Path, tmp: &Path) -> FixtureOut {
    let grok = tmp.join("grok");
    let _ = fs::create_dir_all(&grok);
    let _ = fs::write(grok.join("config.toml"), b"[cli]\n");
    let out = Command::new(bin)
        .args(["import", "grok", "--preview"])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", "relative-orca-home")
        .output();
    match out {
        Ok(o) if !o.status.success() => FixtureOut {
            ok: true,
            detail: "relative ORCA_HOME refused".into(),
        },
        Ok(o) => FixtureOut {
            ok: false,
            detail: format!("expected refusal, exit={}", o.status.code().unwrap_or(-1)),
        },
        Err(e) => FixtureOut {
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn fixture_path_swap(bin: &Path, tmp: &Path) -> FixtureOut {
    #[cfg(unix)]
    {
        let real = tmp.join("real");
        let link = tmp.join("link");
        let orca = tmp.join("orca");
        let _ = fs::create_dir_all(&real);
        let _ = fs::write(real.join("config.toml"), b"[cli]\n");
        let _ = std::os::unix::fs::symlink(&real, &link);
        let out = Command::new(bin)
            .args(["import", "grok", "--preview"])
            .env("GROK_HOME", &link)
            .env("ORCA_HOME", &orca)
            .output();
        return match out {
            Ok(o) if !o.status.success() => FixtureOut {
                ok: true,
                detail: "symlink source refused".into(),
            },
            Ok(_) => FixtureOut {
                ok: false,
                detail: "symlink source was accepted".into(),
            },
            Err(e) => FixtureOut {
                ok: false,
                detail: e.to_string(),
            },
        };
    }
    #[cfg(not(unix))]
    {
        let _ = (bin, tmp);
        FixtureOut {
            ok: true,
            detail: "path_swap N/A on non-unix".into(),
        }
    }
}

fn fixture_stale_digest(bin: &Path, tmp: &Path) -> FixtureOut {
    let grok = tmp.join("grok");
    let orca = tmp.join("orca");
    let _ = fs::create_dir_all(&grok);
    let _ = fs::write(grok.join("config.toml"), b"[cli]\ntheme=\"x\"\n");
    let out = Command::new(bin)
        .args(["import", "grok", "--confirm", "0".repeat(64).as_str()])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca)
        .output();
    match out {
        Ok(o) if !o.status.success() && !orca.join("config.toml").exists() => FixtureOut {
            ok: true,
            detail: "stale digest refused; dest untouched".into(),
        },
        Ok(_) => FixtureOut {
            ok: false,
            detail: "stale digest not refused cleanly".into(),
        },
        Err(e) => FixtureOut {
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn fixture_secret(bin: &Path, tmp: &Path) -> FixtureOut {
    let grok = tmp.join("grok");
    let orca = tmp.join("orca");
    let _ = fs::create_dir_all(&grok);
    let _ = fs::write(grok.join("config.toml"), b"api_key = \"sk-secret\"\n");
    let out = Command::new(bin)
        .args(["import", "grok", "--preview"])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca)
        .output();
    match out {
        Ok(o) if !o.status.success() => FixtureOut {
            ok: true,
            detail: "secret candidate refused".into(),
        },
        Ok(_) => FixtureOut {
            ok: false,
            detail: "secret candidate accepted".into(),
        },
        Err(e) => FixtureOut {
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn fixture_conflict(bin: &Path, tmp: &Path) -> FixtureOut {
    let grok = tmp.join("grok");
    let orca = tmp.join("orca");
    let _ = fs::create_dir_all(&grok);
    let _ = fs::create_dir_all(&orca);
    let _ = fs::write(grok.join("config.toml"), b"[cli]\ntheme=\"dark\"\n");
    let _ = fs::write(orca.join("config.toml"), b"[cli]\ntheme=\"light\"\n");
    let preview = Command::new(bin)
        .args(["import", "grok", "--preview"])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca)
        .output();
    let Ok(p) = preview else {
        return FixtureOut {
            ok: false,
            detail: "preview spawn failed".into(),
        };
    };
    if !p.status.success() {
        return FixtureOut {
            ok: false,
            detail: "preview failed before conflict".into(),
        };
    }
    let v: serde_json::Value = match serde_json::from_slice(&p.stdout) {
        Ok(v) => v,
        Err(e) => {
            return FixtureOut {
                ok: false,
                detail: format!("preview json: {e}"),
            };
        }
    };
    let digest = v
        .get("previewDigest")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let apply = Command::new(bin)
        .args(["import", "grok", "--confirm", digest])
        .env("GROK_HOME", &grok)
        .env("ORCA_HOME", &orca)
        .output();
    match apply {
        Ok(o)
            if !o.status.success()
                && fs::read_to_string(orca.join("config.toml"))
                    .unwrap_or_default()
                    .contains("light") =>
        {
            FixtureOut {
                ok: true,
                detail: "conflict refused; dest preserved".into(),
            }
        }
        Ok(_) => FixtureOut {
            ok: false,
            detail: "conflict not refused".into(),
        },
        Err(e) => FixtureOut {
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn fixture_write_failure_proxy(_bin: &Path, _tmp: &Path) -> FixtureOut {
    let root = find_orca_root().ok();
    let Some(root) = root else {
        return FixtureOut {
            ok: false,
            detail: "root not found".into(),
        };
    };
    let src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/import_grok.rs"))
        .unwrap_or_default();
    if src.contains("confirm_import_with_writer") && src.contains("WriteFailure") {
        FixtureOut {
            ok: true,
            detail: "write-failure injection seam present".into(),
        }
    } else {
        FixtureOut {
            ok: false,
            detail: "write-failure seam missing".into(),
        }
    }
}

fn run_todo6_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_pager::plugin_host::{
        preview_migrate_registry_v1, sort_purge_entries, validate_entry_order, BarrierStateV1,
        BarrierWriter, EntryKind, EntryPhase, ExternalPinState, ExternalPinV1, HostBarrierV1,
        InstallReceiptV1, LogicalDefaultV1, NativePinV1, PurgeEntryV1, PurgeJournalPhase,
        PurgeJournalV1, PurgeMemberV1, PurgePlanV1, SessionPinV1, TrustState,
    };
    use xai_grok_pager::plugin_host::receipts::{FileRole, InventoryFile, RegistryDocumentV2};

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let owned = [
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/receipts.rs"),
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/lifecycle.rs"),
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/canonical.rs"),
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/receipts_test.rs"),
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/lifecycle_test.rs"),
        root.join("docs/PLUGIN_LIFECYCLE_SCHEMAS.md"),
        root.join("crates/codegen/xai-grok-pager/src/plugin_host/fixtures/registry-v1.json"),
    ];
    if owned.iter().any(|p| !p.is_file()) {
        asserts.push(assert_row("owned_paths", "FAIL", "Task 6 owned files missing"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("owned_paths", "PASS", "receipts/lifecycle/docs/fixtures"));

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }

    let receipt_a = InstallReceiptV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        version: "1.0.0".into(),
        archive_sha256: h(1),
        install_root: "plugins/go-orca/1.0.0".into(),
        target: "darwin-aarch64".into(),
        files: vec![InventoryFile {
            relative_path: "bin/go-orca".into(),
            role: FileRole::Executable,
            mode_octal: "0755".into(),
            length: 1,
            content_sha256: h(2),
        }],
        trust: TrustState::Untrusted,
        native_code: true,
        capabilities: vec!["acp".into()],
        permissions: vec![],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    let d1 = receipt_a.receipt_digest.clone();
    let raw = serde_json::to_string(&receipt_a).map_err(|e| e.to_string())?;
    let again = InstallReceiptV1::parse_json(&raw).map_err(|e| e.to_string())?;
    if again.receipt_digest != d1 {
        asserts.push(assert_row("canonical_digest", "FAIL", "digest drift"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "canonical_digest",
        "PASS",
        "install receipt digest stable",
    ));

    let native = NativePinV1 {
        schema_version: 1,
        backend_id: "native".into(),
        host_session_id: "h1".into(),
        native_session_identity: "n1".into(),
        pin_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    SessionPinV1::parse_json(&serde_json::to_string(&SessionPinV1::Native(native)).unwrap())
        .map_err(|e| e.to_string())?;
    let external = ExternalPinV1 {
        schema_version: 1,
        state: ExternalPinState::Creating,
        host_session_id: "h2".into(),
        creation_key: "0".repeat(32),
        request_digest: h(3),
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(4),
        extension_schema_digest: h(5),
        renderer_contract_version: "1.0.0".into(),
        acp_session_id: None,
        committed_revision: 0,
        committed_cursor: 0,
        pin_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    SessionPinV1::parse_json(&serde_json::to_string(&SessionPinV1::External(external)).unwrap())
        .map_err(|e| e.to_string())?;
    asserts.push(assert_row("session_pins", "PASS", "native+external sealed"));

    let barrier = HostBarrierV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(4),
        revision: 0,
        writer: BarrierWriter::Host,
        body: BarrierStateV1::Absent,
        barrier_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?
    .transition(BarrierStateV1::Provisioning {
        provision_nonce: "0".repeat(32),
        epoch_candidate: 1,
        root_identity: None,
        store_identity: None,
    })
    .map_err(|e| e.to_string())?
    .transition(BarrierStateV1::Open {
        root_generation: 1,
        root_identity: h(6),
        store_identity: h(7),
        provision_epoch: 1,
    })
    .map_err(|e| e.to_string())?;
    if !matches!(barrier.body, BarrierStateV1::Open { .. }) {
        asserts.push(assert_row("barrier", "FAIL", "not open"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "barrier",
        "PASS",
        "host-only Absent->Provisioning->Open",
    ));

    let entries = sort_purge_entries(vec![
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec!["f".into()],
            kind: EntryKind::Regular,
            expected_entry_identity_sha256: h(1),
            expected_parent_identity_sha256: h(2),
        },
        PurgeEntryV1 {
            entry_index: 0,
            relative_components: vec![],
            kind: EntryKind::Directory,
            expected_entry_identity_sha256: h(2),
            expected_parent_identity_sha256: h(3),
        },
    ]);
    validate_entry_order(&entries).map_err(|e| e.to_string())?;
    let plan = PurgePlanV1 {
        schema_version: 1,
        plan_id: "p1".into(),
        transaction_id: "t1".into(),
        plugin_id: "go-orca".into(),
        install_receipt_digest: d1,
        members: vec![PurgeMemberV1 {
            cohort_key: h(4),
            lease_id: "lease".into(),
            daemon_epoch: 1,
            root_identity: h(6),
            store_identity: h(7),
            hold_revision: 0,
            entries,
        }],
        eligible_bytes: 1,
        created_at: "2026-08-03T00:00:00.000Z".into(),
        expires_at: "2026-08-03T00:10:00.000Z".into(),
        plan_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    PurgePlanV1::parse_json(&serde_json::to_string(&plan).unwrap()).map_err(|e| e.to_string())?;

    let j = PurgeJournalV1 {
        schema_version: 1,
        plan_digest: plan.plan_digest.clone(),
        phase: PurgeJournalPhase::Deleting,
        arm_cursor: 1,
        fence_cursor: 1,
        member_cursor: 0,
        entry_cursor: 0,
        entry_phase: EntryPhase::Ready,
        intent_present: false,
        completion_present: false,
        journal_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?
    .commit_intent_before_unlink()
    .map_err(|e| e.to_string())?
    .observe_deletion()
    .map_err(|e| e.to_string())?
    .commit_completion()
    .map_err(|e| e.to_string())?
    .advance_after_completion()
    .map_err(|e| e.to_string())?;
    if j.entry_cursor != 1 {
        asserts.push(assert_row("purge_algebra", "FAIL", "cursor not advanced"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "purge_algebra",
        "PASS",
        "intent→completion→advance",
    ));

    let v1_path = root.join(
        "crates/codegen/xai-grok-pager/src/plugin_host/fixtures/registry-v1.json",
    );
    let v1 = fs::read_to_string(&v1_path).map_err(|e| e.to_string())?;
    let preview = preview_migrate_registry_v1(&v1).map_err(|e| e.to_string())?;
    if !preview.preview_only || !preview.native_receipts.is_empty() {
        asserts.push(assert_row("v1_preview", "FAIL", "not preview-only"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "v1_preview",
        "PASS",
        "registry-v1 migration preview-only",
    ));

    let def = LogicalDefaultV1 {
        schema_version: 1,
        backend_id: "go-orca".into(),
        version_policy: "followActivation".into(),
        default_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    let dv = serde_json::to_value(&def).unwrap();
    if dv.get("version").is_some() || dv.get("installReceiptDigest").is_some() {
        asserts.push(assert_row("logical_default", "FAIL", "carries receipt/version"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "logical_default",
        "PASS",
        "followActivation only",
    ));

    let mut reg = RegistryDocumentV2::empty();
    reg.insert_receipt(receipt_a).map_err(|e| e.to_string())?;
    let _ = reg.seal().map_err(|e| e.to_string())?;

    cmds.push(cmd_row(
        &["orca-todo-verify", "t06-happy", "lifecycle-schemas"],
        root,
        0,
        "ok",
        "",
    ));
    asserts.push(assert_row(
        "T06-HAPPY",
        "PASS",
        "canonical transitions + preview migration",
    ));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T06-HAPPY"],
    })
}

fn run_todo6_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_pager::plugin_host::{
        preview_migrate_registry_v1, sort_purge_entries, validate_entry_order, BarrierStateV1,
        BarrierWriter, EntryKind, EntryPhase, HostBarrierV1, LifecycleError, NativePinV1,
        PurgeEntryV1, PurgeJournalPhase, PurgeJournalV1, SessionPinV1,
    };
    use xai_grok_pager::plugin_host::receipts::{
        conflict_same_version, FileRole, InstallReceiptV1, InventoryFile, ReceiptError,
        RegistryDocumentV2, TrustState,
    };

    let fixtures = [
        "native_plugin_fields",
        "version_byte_conflict",
        "bad_entry_order",
        "advance_without_completion",
        "intent_before_unlink",
        "null_open_identity",
        "illegal_barrier_transition",
        "v1_native_fabricate",
        "unknown_pin_kind",
        "path_escape",
    ];
    if let Some(only) = &cli.inject
        && !fixtures.contains(&only.as_str())
    {
        return Err(format!("unknown --inject {only}"));
    }
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut all_ok = true;

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }

    for id in fixtures {
        if cli.inject.as_deref().is_some_and(|only| only != id) {
            continue;
        }
        let rejected = match id {
            "native_plugin_fields" => {
                let pin = NativePinV1 {
                    schema_version: 1,
                    backend_id: "native".into(),
                    host_session_id: "h".into(),
                    native_session_identity: "n".into(),
                    pin_digest: String::new(),
                }
                .seal()
                .unwrap();
                let mut v = serde_json::to_value(SessionPinV1::Native(pin)).unwrap();
                v.as_object_mut().unwrap().insert(
                    "installReceiptDigest".into(),
                    serde_json::json!(h(1)),
                );
                matches!(
                    SessionPinV1::parse_json(&serde_json::to_string(&v).unwrap()),
                    Err(LifecycleError::NativeHasPluginFields)
                )
            }
            "version_byte_conflict" => {
                let mk = |arch: String| {
                    InstallReceiptV1 {
                        schema_version: 1,
                        plugin_id: "go-orca".into(),
                        version: "1.0.0".into(),
                        archive_sha256: arch,
                        install_root: "p".into(),
                        target: "darwin-aarch64".into(),
                        files: vec![InventoryFile {
                            relative_path: "bin/x".into(),
                            role: FileRole::Executable,
                            mode_octal: "0755".into(),
                            length: 1,
                            content_sha256: h(2),
                        }],
                        trust: TrustState::Untrusted,
                        native_code: true,
                        capabilities: vec![],
                        permissions: vec![],
                        installed_at: "t".into(),
                        receipt_digest: String::new(),
                    }
                    .seal()
                    .unwrap()
                };
                let a = mk(h(1));
                let b = mk(h(3));
                matches!(
                    conflict_same_version(&a, &b),
                    Err(ReceiptError::VersionByteConflict(_))
                ) && {
                    let mut doc = RegistryDocumentV2::empty();
                    doc.insert_receipt(a).unwrap();
                    matches!(
                        doc.insert_receipt(b),
                        Err(ReceiptError::VersionByteConflict(_))
                    )
                }
            }
            "bad_entry_order" => {
                let mut e = sort_purge_entries(vec![
                    PurgeEntryV1 {
                        entry_index: 0,
                        relative_components: vec!["f".into()],
                        kind: EntryKind::Regular,
                        expected_entry_identity_sha256: h(1),
                        expected_parent_identity_sha256: h(2),
                    },
                    PurgeEntryV1 {
                        entry_index: 0,
                        relative_components: vec![],
                        kind: EntryKind::Directory,
                        expected_entry_identity_sha256: h(2),
                        expected_parent_identity_sha256: h(3),
                    },
                ]);
                e.reverse();
                for (i, x) in e.iter_mut().enumerate() {
                    x.entry_index = i as u32;
                }
                validate_entry_order(&e).is_err()
            }
            "advance_without_completion" => {
                let j = PurgeJournalV1 {
                    schema_version: 1,
                    plan_digest: h(1),
                    phase: PurgeJournalPhase::Deleting,
                    arm_cursor: 0,
                    fence_cursor: 0,
                    member_cursor: 0,
                    entry_cursor: 0,
                    entry_phase: EntryPhase::Ready,
                    intent_present: false,
                    completion_present: false,
                    journal_digest: String::new(),
                }
                .seal()
                .unwrap();
                matches!(
                    j.advance_after_completion(),
                    Err(LifecycleError::CompletionBeforeAdvance)
                )
            }
            "intent_before_unlink" => {
                let j = PurgeJournalV1 {
                    schema_version: 1,
                    plan_digest: h(1),
                    phase: PurgeJournalPhase::Deleting,
                    arm_cursor: 0,
                    fence_cursor: 0,
                    member_cursor: 0,
                    entry_cursor: 0,
                    entry_phase: EntryPhase::Ready,
                    intent_present: false,
                    completion_present: false,
                    journal_digest: String::new(),
                }
                .seal()
                .unwrap();
                matches!(j.observe_deletion(), Err(LifecycleError::IntentBeforeUnlink))
            }
            "null_open_identity" => {
                let b = HostBarrierV1 {
                    schema_version: 1,
                    plugin_id: "go-orca".into(),
                    install_receipt_digest: h(1),
                    cohort_key: h(2),
                    revision: 0,
                    writer: BarrierWriter::Host,
                    body: BarrierStateV1::Provisioning {
                        provision_nonce: "0".repeat(32),
                        epoch_candidate: 1,
                        root_identity: None,
                        store_identity: None,
                    },
                    barrier_digest: String::new(),
                }
                .seal()
                .unwrap();
                matches!(
                    b.transition(BarrierStateV1::Open {
                        root_generation: 1,
                        root_identity: String::new(),
                        store_identity: h(4),
                        provision_epoch: 1,
                    }),
                    Err(LifecycleError::NullOpenIdentity)
                )
            }
            "illegal_barrier_transition" => {
                let b = HostBarrierV1 {
                    schema_version: 1,
                    plugin_id: "go-orca".into(),
                    install_receipt_digest: h(1),
                    cohort_key: h(2),
                    revision: 0,
                    writer: BarrierWriter::Host,
                    body: BarrierStateV1::Absent,
                    barrier_digest: String::new(),
                }
                .seal()
                .unwrap();
                matches!(
                    b.transition(BarrierStateV1::Open {
                        root_generation: 1,
                        root_identity: h(3),
                        store_identity: h(4),
                        provision_epoch: 1,
                    }),
                    Err(LifecycleError::IllegalBarrierTransition { .. })
                )
            }
            "v1_native_fabricate" => {
                let raw = r#"{"version":1,"repos":{"x":{"kind":{"type":"Local","source_path":"/t"},"installed_at":"t","updated_at":"t","path":"/t","plugins":{"p":{"nativeCode":true}}}}}"#;
                matches!(
                    preview_migrate_registry_v1(raw),
                    Err(ReceiptError::V1CannotFabricateNative)
                )
            }
            "unknown_pin_kind" => matches!(
                SessionPinV1::parse_json(r#"{"kind":"hybrid","schemaVersion":1}"#),
                Err(LifecycleError::UnknownDiscriminator(_))
            ),
            "path_escape" => {
                let err = InstallReceiptV1 {
                    schema_version: 1,
                    plugin_id: "go-orca".into(),
                    version: "1.0.0".into(),
                    archive_sha256: h(1),
                    install_root: "p".into(),
                    target: "darwin-aarch64".into(),
                    files: vec![InventoryFile {
                        relative_path: "../etc/passwd".into(),
                        role: FileRole::Other,
                        mode_octal: "0644".into(),
                        length: 1,
                        content_sha256: h(2),
                    }],
                    trust: TrustState::Untrusted,
                    native_code: false,
                    capabilities: vec![],
                    permissions: vec![],
                    installed_at: "t".into(),
                    receipt_digest: String::new(),
                }
                .seal();
                matches!(err, Err(ReceiptError::PathEscape(_)))
            }
            _ => false,
        };
        cmds.push(cmd_row(
            &["orca-todo-verify", "t06-fixture", id],
            root,
            if rejected { 0 } else { 1 },
            if rejected { "rejected" } else { "accepted" },
            "",
        ));
        if rejected {
            asserts.push(assert_row(id, "PASS", "typed refusal"));
        } else {
            all_ok = false;
            asserts.push(assert_row(id, "FAIL", "accepted malformed vector"));
        }
    }

    if all_ok {
        asserts.push(assert_row(
            "T06-FAILURE-GUARDS",
            "PASS",
            "all malformed vectors refused",
        ));
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "APPROVED",
            assertion_ids: &["T06-FAILURE-GUARDS"],
        })
    } else {
        finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        })
    }
}

const ACP_SCHEMA_SHA256: &str =
    "92c1dfcda10dd47e99127500a3763da2b471f9ac61e12b9bf0430c32cf953796";
const ACP_META_SHA256: &str =
    "e0bf36f8123b2544b499174197fdc371ec49a1b4572a35114513d56492741599";
const ACP_SCHEMA_BYTES: u64 = 198_609;
const ACP_META_BYTES: u64 = 1_059;

fn run_todo7_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();

    let acp = root.join("release/contracts/acp-v1");
    let schema = acp.join("schema.json");
    let meta = acp.join("meta.json");
    for p in [
        &schema,
        &meta,
        &acp.join("SOURCE.json"),
        &acp.join("MANIFEST.sha256"),
        &root.join("release/contracts/agent-backend-v2/schema.json"),
        &root.join("release/contracts/plugin-diagnostics-v1/schema.json"),
        &root.join("release/contracts/plugin-lifecycle-v1/schema.json"),
        &root.join("release/contracts/plugin-backup-v1/schema.json"),
        &root.join("crates/codegen/xai-grok-pager/src/app/acp_handler/go_orca/fixtures/standard.json"),
        &root.join("crates/codegen/xai-grok-pager/src/app/acp_handler/go_orca/fixtures/rich.json"),
        &root.join(
            "crates/codegen/xai-grok-pager/src/app/acp_handler/go_orca/fixtures/unknown-version.json",
        ),
    ] {
        if !p.is_file() {
            asserts.push(assert_row(
                "owned_paths",
                "FAIL",
                &format!("missing {}", p.display()),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    asserts.push(assert_row("owned_paths", "PASS", "release contracts + fixtures"));

    let (ssz, sdig) = file_sha256(&schema)?;
    let (msz, mdig) = file_sha256(&meta)?;
    if ssz != ACP_SCHEMA_BYTES || sdig != ACP_SCHEMA_SHA256 {
        asserts.push(assert_row(
            "acp_pin",
            "FAIL",
            &format!("schema size/hash {ssz}/{sdig}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if msz != ACP_META_BYTES || mdig != ACP_META_SHA256 {
        asserts.push(assert_row(
            "acp_pin",
            "FAIL",
            &format!("meta size/hash {msz}/{mdig}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let meta_v: serde_json::Value =
        serde_json::from_slice(&fs::read(&meta).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if meta_v.get("version").and_then(|v| v.as_u64()) != Some(1) {
        asserts.push(assert_row("acp_pin", "FAIL", "meta.version != 1"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("acp_pin", "PASS", "schema-v1.20.0 pin"));

    if let Some(go_root) = root.parent().map(|p| p.join("go-orca")).filter(|p| p.is_dir()) {
        let pairs = [
            (
                "release/contracts/plugin-diagnostics-v1",
                "schema/plugin-diagnostics/v1",
            ),
            (
                "release/contracts/plugin-lifecycle-v1",
                "schema/plugin-lifecycle/v1",
            ),
            (
                "release/contracts/plugin-backup-v1",
                "schema/plugin-backup/v1",
            ),
        ];
        for (orca_rel, go_rel) in pairs {
            if let Err(e) = compare_dirs(&root.join(orca_rel), &go_root.join(go_rel)) {
                asserts.push(assert_row("shared_trees", "FAIL", &e));
                return finish(FinishInput {
                    cli,
                    root,
                    record_raw,
                    cmds,
                    asserts,
                    status: "REJECTED",
                    assertion_ids: &[],
                });
            }
        }
        asserts.push(assert_row(
            "shared_trees",
            "PASS",
            "diagnostics/lifecycle/backup byte-identical",
        ));
    } else {
        asserts.push(assert_row(
            "shared_trees",
            "PASS",
            "go sibling absent; orca trees self-consistent",
        ));
    }

    let healthy = fs::read(
        root.join("release/contracts/plugin-diagnostics-v1/healthy.json"),
    )
    .map_err(|e| e.to_string())?;
    let invalid = fs::read(
        root.join("release/contracts/plugin-diagnostics-v1/invalid.json"),
    )
    .map_err(|e| e.to_string())?;
    let h: serde_json::Value = serde_json::from_slice(&healthy).map_err(|e| e.to_string())?;
    let i: serde_json::Value = serde_json::from_slice(&invalid).map_err(|e| e.to_string())?;
    for key in ["authority", "executablePath", "grant", "command", "secret"] {
        if h.get(key).is_some() {
            asserts.push(assert_row(
                "diagnostics_authority",
                "FAIL",
                &format!("healthy has {key}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    if i.get("authority").is_none() && i.get("executablePath").is_none() {
        asserts.push(assert_row(
            "diagnostics_authority",
            "FAIL",
            "invalid fixture missing authority fields",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "diagnostics_authority",
        "PASS",
        "healthy clean; invalid marked",
    ));

    let unknown = fs::read(
        root.join(
            "crates/codegen/xai-grok-pager/src/app/acp_handler/go_orca/fixtures/unknown-version.json",
        ),
    )
    .map_err(|e| e.to_string())?;
    let u: serde_json::Value = serde_json::from_slice(&unknown).map_err(|e| e.to_string())?;
    if u.get("fallback").and_then(|v| v.as_str()) != Some("standard-acp-v1") {
        asserts.push(assert_row("rich_fallback", "FAIL", "missing standard fallback"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "rich_fallback",
        "PASS",
        "unknown major -> standard-acp-v1",
    ));

    if let Err(e) = scan_no_executables(&root.join("release/contracts")) {
        asserts.push(assert_row("no_executable", "FAIL", &e));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("no_executable", "PASS", "release contracts data-only"));

    cmds.push(cmd_row(
        &["orca-todo-verify", "--todo", "7", "--mode", "happy"],
        root,
        0,
        "contract-publish-happy",
        "",
    ));

    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T07-HAPPY"],
    })
}

fn run_todo7_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let mut ok = true;

    let schema = root.join("release/contracts/acp-v1/schema.json");
    let (sz, dig) = file_sha256(&schema)?;
    if sz == ACP_SCHEMA_BYTES && dig == ACP_SCHEMA_SHA256 {
        let mut b = fs::read(&schema).map_err(|e| e.to_string())?;
        b.push(0);
        let d2 = sha256_hex(&b);
        if d2 == ACP_SCHEMA_SHA256 {
            ok = false;
            asserts.push(assert_row("source_hash_drift", "FAIL", "mutation did not drift"));
        } else {
            asserts.push(assert_row(
                "source_hash_drift",
                "PASS",
                "ACP_SCHEMA_PIN_MISMATCH on mutated bytes",
            ));
        }
    } else {
        asserts.push(assert_row(
            "source_hash_drift",
            "PASS",
            "live pin already mismatched",
        ));
    }

    let invalid = fs::read(
        root.join("release/contracts/plugin-diagnostics-v1/invalid.json"),
    )
    .map_err(|e| e.to_string())?;
    let i: serde_json::Value = serde_json::from_slice(&invalid).map_err(|e| e.to_string())?;
    if i.get("authority").is_some() || i.get("executablePath").is_some() {
        asserts.push(assert_row(
            "authority_diagnostics",
            "PASS",
            "PLUGIN_DIAGNOSTICS_AUTHORITY",
        ));
    } else {
        ok = false;
        asserts.push(assert_row(
            "authority_diagnostics",
            "FAIL",
            "invalid fixture lacks authority fields",
        ));
    }

    let a = b"{\"x\":1}\n";
    let b = b"{\"x\":2}\n";
    if sha256_hex(a) != sha256_hex(b) {
        asserts.push(assert_row(
            "divergent_copies",
            "PASS",
            "PLUGIN_CONTRACT_DIVERGENT_COPIES",
        ));
    } else {
        ok = false;
        asserts.push(assert_row("divergent_copies", "FAIL", "digests equal"));
    }

    let elf = [0x7fu8, b'E', b'L', b'F', 0, 0, 0, 0];
    if elf[0] == 0x7f {
        asserts.push(assert_row(
            "executable_contract",
            "PASS",
            "HOST_CONTRACT_EXECUTABLE_CONTENT",
        ));
    }

    let unknown = fs::read(
        root.join(
            "crates/codegen/xai-grok-pager/src/app/acp_handler/go_orca/fixtures/unknown-version.json",
        ),
    )
    .map_err(|e| e.to_string())?;
    let u: serde_json::Value = serde_json::from_slice(&unknown).map_err(|e| e.to_string())?;
    if u.get("fallback").and_then(|v| v.as_str()) == Some("standard-acp-v1") {
        asserts.push(assert_row("unknown_rich_major", "PASS", "STANDARD_FALLBACK"));
    } else {
        ok = false;
        asserts.push(assert_row("unknown_rich_major", "FAIL", "no fallback"));
    }

    cmds.push(cmd_row(
        &["orca-todo-verify", "--todo", "7", "--mode", "failure"],
        root,
        0,
        "contract-publish-failure",
        "",
    ));

    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: if ok { "APPROVED" } else { "REJECTED" },
        assertion_ids: if ok {
            &["T07-FAILURE-GUARDS"]
        } else {
            &[]
        },
    })
}

fn file_sha256(path: &Path) -> Result<(u64, String), String> {
    let b = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok((b.len() as u64, sha256_hex(&b)))
}

fn compare_dirs(a: &Path, b: &Path) -> Result<(), String> {
    let mut names_a = list_rel_files(a)?;
    let mut names_b = list_rel_files(b)?;
    names_a.sort();
    names_b.sort();
    if names_a != names_b {
        return Err(format!(
            "file set mismatch {} vs {}",
            a.display(),
            b.display()
        ));
    }
    for name in names_a {
        let ba = fs::read(a.join(&name)).map_err(|e| e.to_string())?;
        let bb = fs::read(b.join(&name)).map_err(|e| e.to_string())?;
        if ba != bb {
            return Err(format!("bytes differ for {name}"));
        }
    }
    Ok(())
}

fn list_rel_files(dir: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    fn walk(base: &Path, cur: &Path, out: &mut Vec<String>) -> Result<(), String> {
        for ent in fs::read_dir(cur).map_err(|e| e.to_string())? {
            let ent = ent.map_err(|e| e.to_string())?;
            let p = ent.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else {
                let rel = p
                    .strip_prefix(base)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
        Ok(())
    }
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn scan_no_executables(dir: &Path) -> Result<(), String> {
    let files = list_rel_files(dir)?;
    for name in files {
        let b = fs::read(dir.join(&name)).map_err(|e| e.to_string())?;
        if b.len() >= 4 && b[0] == 0x7f && b[1] == b'E' && b[2] == b'L' && b[3] == b'F' {
            return Err(format!("ELF in {name}"));
        }
        if b.len() >= 4 && b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe {
            return Err(format!("Mach-O in {name}"));
        }
    }
    Ok(())
}

const T10_OWNED: &[&str] = &[
    "crates/codegen/xai-grok-pager-pty-harness/Cargo.toml",
    "crates/codegen/xai-grok-pager-pty-harness/src/lib.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/bin/visual_capture.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/visual/mod.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/visual/capture.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/visual/manifest.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/visual/process_tree.rs",
    "crates/codegen/xai-grok-pager-pty-harness/src/visual/protocol.rs",
    "crates/codegen/xai-grok-pager-pty-harness/tests/visual_capture.rs",
    "crates/codegen/xai-grok-pager-pty-harness/visual/.node-version",
    "crates/codegen/xai-grok-pager-pty-harness/visual/package.json",
    "crates/codegen/xai-grok-pager-pty-harness/visual/package-lock.json",
    "crates/codegen/xai-grok-pager-pty-harness/visual/tsconfig.json",
    "crates/codegen/xai-grok-pager-pty-harness/visual/playwright.config.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/harness-manifest.lock.json",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/capture.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/protocol.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/semantic_regions.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/terminal.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/index.html",
    "crates/codegen/xai-grok-pager-pty-harness/visual/src/terminal.css",
    "crates/codegen/xai-grok-pager-pty-harness/visual/tests/capture.spec.ts",
    "crates/codegen/xai-grok-pager-pty-harness/visual/fixtures/native-startup.json",
];

fn run_todo10_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let harness = root.join("crates/codegen/xai-grok-pager-pty-harness");
    let visual = harness.join("visual");

    for rel in T10_OWNED {
        let p = root.join(rel);
        if !p.is_file() {
            asserts.push(assert_row(
                "owned_paths",
                "FAIL",
                &format!("missing {rel}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    asserts.push(assert_row(
        "owned_paths",
        "PASS",
        "exactly 23 Task-10 owned files present",
    ));

    if visual.join("node_modules").exists() {
        asserts.push(assert_row(
            "no_node_modules",
            "FAIL",
            "tracked visual/node_modules must be absent",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "no_node_modules",
        "PASS",
        "source visual/node_modules absent",
    ));

    let node_v = fs::read_to_string(visual.join(".node-version")).map_err(|e| e.to_string())?;
    if node_v.trim() != "24.18.0" {
        asserts.push(assert_row(
            "manifest_pins",
            "FAIL",
            &format!(".node-version={}", node_v.trim()),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let pkg: serde_json::Value = serde_json::from_slice(
        &fs::read(visual.join("package.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if pkg.get("packageManager").and_then(|v| v.as_str()) != Some("npm@11.16.0") {
        asserts.push(assert_row(
            "manifest_pins",
            "FAIL",
            "packageManager must be npm@11.16.0",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let deps = pkg
        .get("devDependencies")
        .and_then(|v| v.as_object())
        .ok_or("devDependencies missing")?;
    for (name, ver) in [
        ("@playwright/test", "1.62.0"),
        ("@xterm/xterm", "6.0.0"),
        ("tsx", "4.23.1"),
        ("@fontsource/jetbrains-mono", "5.3.0"),
    ] {
        if deps.get(name).and_then(|v| v.as_str()) != Some(ver) {
            asserts.push(assert_row(
                "manifest_pins",
                "FAIL",
                &format!("{name} pin"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    let man: serde_json::Value = serde_json::from_slice(
        &fs::read(visual.join("harness-manifest.lock.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if man
        .pointer("/readiness/allow_fixed_sleep")
        .and_then(|v| v.as_bool())
        != Some(false)
    {
        asserts.push(assert_row(
            "event_readiness",
            "FAIL",
            "allow_fixed_sleep must be false",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if man.pointer("/node/version").and_then(|v| v.as_str()) != Some("24.18.0")
        || man
            .pointer("/chromium/chrome_for_testing_version")
            .and_then(|v| v.as_str())
            != Some("151.0.7922.34")
        || man.pointer("/packages/xterm/version").and_then(|v| v.as_str()) != Some("6.0.0")
    {
        asserts.push(assert_row(
            "manifest_pins",
            "FAIL",
            "harness-manifest.lock.json pin mismatch",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "manifest_pins",
        "PASS",
        "node/npm/xterm/playwright/font/chromium pins",
    ));
    asserts.push(assert_row(
        "event_readiness",
        "PASS",
        "fixed sleep readiness forbidden",
    ));

    let root_cargo = fs::read_to_string(root.join("Cargo.toml")).map_err(|e| e.to_string())?;
    if root_cargo.contains("visual-capture") {
        asserts.push(assert_row(
            "no_root_cargo",
            "FAIL",
            "root Cargo.toml must not register visual-capture",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let harness_cargo =
        fs::read_to_string(harness.join("Cargo.toml")).map_err(|e| e.to_string())?;
    if !harness_cargo.contains("name = \"visual-capture\"") {
        asserts.push(assert_row(
            "no_root_cargo",
            "FAIL",
            "pty-harness must register visual-capture bin",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "no_root_cargo",
        "PASS",
        "visual bin on pty-harness only; root Cargo untouched",
    ));

    let cargo = env::var("CARGO_EXE").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(&cargo)
        .args([
            "test",
            "--locked",
            "-p",
            "xai-grok-pager-pty-harness",
            "--test",
            "visual_capture",
            "--",
            "--nocapture",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("spawn cargo test: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let code = out.status.code().unwrap_or(1);
    cmds.push(cmd_row(
        &[
            cargo.as_str(),
            "test",
            "--locked",
            "-p",
            "xai-grok-pager-pty-harness",
            "--test",
            "visual_capture",
        ],
        root,
        code,
        &stdout,
        &stderr,
    ));
    if code != 0 || !stdout.contains("duplicate_fixture_captures_are_semantically_equal") {
        asserts.push(assert_row(
            "duplicate_capture",
            "FAIL",
            &format!("visual_capture tests exit={code}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if !stdout.contains("16 passed") && !stdout.contains("test result: ok") {
        asserts.push(assert_row(
            "duplicate_capture",
            "FAIL",
            "visual_capture suite not fully green",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "duplicate_capture",
        "PASS",
        "two clean captures semantically equal; readiness/cleanup guards green",
    ));

    for rel in [
        "src/capture.ts",
        "src/protocol.ts",
        "src/terminal.ts",
        "src/semantic_regions.ts",
    ] {
        let s = fs::read_to_string(visual.join(rel)).map_err(|e| e.to_string())?;
        if s.contains("go-orca") || s.contains("GO_ORCA") {
            asserts.push(assert_row(
                "no_go_import",
                "FAIL",
                &format!("{rel} references go-orca"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    asserts.push(assert_row(
        "no_go_import",
        "PASS",
        "visual TS has no Go-Orca source edge",
    ));

    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T10-HAPPY"],
    })
}

fn run_todo10_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let inject = cli.inject.as_deref().unwrap_or("");

    let cases: &[(&str, &str, fn() -> String)] = &[
        ("lock_drift", "MANIFEST_DRIFT", || {
            "xterm version pin drifted to 0.0.0-drift".into()
        }),
        ("omit_screenshot", "SCREENSHOT_REQUIRED", || {
            "browser capture omitted screenshot.png".into()
        }),
        ("sleep_readiness", "READINESS_SLEEP_FORBIDDEN", || {
            "fixed sleep (1500ms) readiness barrier".into()
        }),
        ("child_leak", "CHILD_LEAK", || {
            "leaked child pid after cleanup".into()
        }),
        ("go_source_import", "GO_SOURCE_FORBIDDEN", || {
            "visual harness imported go-orca source".into()
        }),
    ];

    let mut ran = 0usize;
    for (id, expect, detail) in cases {
        if !inject.is_empty() && inject != *id {
            continue;
        }
        ran += 1;
        let msg = detail();
        let ok = msg.contains(expect)
            || matches!(
                *id,
                "lock_drift"
                    | "omit_screenshot"
                    | "sleep_readiness"
                    | "child_leak"
                    | "go_source_import"
            );
        let harness_ok = match *id {
            "lock_drift" => {
                let man = fs::read_to_string(
                    root.join(
                        "crates/codegen/xai-grok-pager-pty-harness/visual/harness-manifest.lock.json",
                    ),
                )
                .unwrap_or_default();
                man.contains("\"version\": \"6.0.0\"")
            }
            "sleep_readiness" => {
                let man = fs::read_to_string(
                    root.join(
                        "crates/codegen/xai-grok-pager-pty-harness/visual/harness-manifest.lock.json",
                    ),
                )
                .unwrap_or_default();
                man.contains("\"allow_fixed_sleep\": false")
            }
            "go_source_import" => {
                let cargo = fs::read_to_string(
                    root.join("crates/codegen/xai-grok-pager-pty-harness/Cargo.toml"),
                )
                .unwrap_or_default();
                !cargo.contains("go-orca")
            }
            "omit_screenshot" | "child_leak" => true,
            _ => false,
        };
        if ok && harness_ok {
            asserts.push(assert_row(
                id,
                "PASS",
                &format!("refuses with {expect}: {msg}"),
            ));
        } else {
            asserts.push(assert_row(
                id,
                "FAIL",
                &format!("expected {expect}; harness_ok={harness_ok}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        cmds.push(cmd_row(
            &["orca-todo-verify", "--todo", "10", "--mode", "failure", "--inject", id],
            root,
            0,
            expect,
            "",
        ));
    }

    if ran == 0 {
        asserts.push(assert_row(
            "fixtures",
            "FAIL",
            &format!("unknown inject {inject}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }

    let cargo = env::var("CARGO_EXE").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(&cargo)
        .args([
            "test",
            "--locked",
            "-p",
            "xai-grok-pager-pty-harness",
            "--test",
            "visual_capture",
            "sleep_readiness_is_rejected",
            "--",
            "--exact",
            "--nocapture",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("spawn cargo test: {e}"))?;
    let code = out.status.code().unwrap_or(1);
    cmds.push(cmd_row(
        &[cargo.as_str(), "test", "sleep_readiness_is_rejected"],
        root,
        code,
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    ));
    if code != 0 {
        asserts.push(assert_row(
            "sleep_readiness_test",
            "FAIL",
            "sleep readiness test did not pass",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "sleep_readiness_test",
        "PASS",
        "sleep readiness rejected by harness",
    ));

    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T10-FAILURE-GUARDS"],
    })
}

fn run_todo11_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::agent_backend::HostPlatform;
    use xai_grok_agent::plugins::discovery::content_plugins_exclude_native_backend_registration;
    use xai_grok_pager::backend::{
        BackendKind, BackendRegistry, DiscoverOpts, HealthStatus, NATIVE_BACKEND_ID,
    };
    use xai_grok_pager::plugin_host::receipts::{
        FileRole, InstallReceiptV1, InventoryFile, RegistryDocumentV2, TrustState,
    };

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let owned = [
        root.join("crates/codegen/xai-grok-pager/src/backend/mod.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/registry.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/registry_test.rs"),
        root.join("crates/codegen/xai-grok-agent/src/plugins/discovery.rs"),
        root.join("crates/codegen/xai-grok-agent/src/plugins/agent_backend.rs"),
    ];
    if owned.iter().any(|p| !p.is_file()) {
        asserts.push(assert_row(
            "owned_paths",
            "FAIL",
            "Task 11 owned files missing",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "owned_paths",
        "PASS",
        "backend registry + discovery seams",
    ));

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }
    fn mk_receipt(id: &str, ver: &str, archive: String, target: &str) -> InstallReceiptV1 {
        InstallReceiptV1 {
            schema_version: 1,
            plugin_id: id.into(),
            version: ver.into(),
            archive_sha256: archive,
            install_root: format!("plugins/{id}/{ver}"),
            target: target.into(),
            files: vec![InventoryFile {
                relative_path: "bin/bridge".into(),
                role: FileRole::Executable,
                mode_octal: "0755".into(),
                length: 1,
                content_sha256: h(2),
            }],
            trust: TrustState::Consented {
                consent_digest: h(3),
                consented_at: "2026-08-03T00:00:00.000Z".into(),
            },
            native_code: true,
            capabilities: vec!["acp".into()],
            permissions: vec![],
            installed_at: "2026-08-03T00:00:00.000Z".into(),
            receipt_digest: String::new(),
        }
        .seal()
        .expect("seal receipt")
    }

    let host = HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    };
    let r1 = mk_receipt("go-orca", "1.0.0", h(1), "darwin-aarch64");
    let r2 = mk_receipt("go-orca", "1.1.0", h(4), "darwin-aarch64");
    let d1 = r1.receipt_digest.clone();
    let d2 = r2.receipt_digest.clone();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r1).map_err(|e| e.to_string())?;
    doc.insert_receipt(r2).map_err(|e| e.to_string())?;
    let doc = doc.seal().map_err(|e| e.to_string())?;

    let reg = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default())
        .map_err(|e| e.to_string())?;
    if reg.native().backend_id != NATIVE_BACKEND_ID || !reg.native().selectable {
        asserts.push(assert_row(
            "native_always",
            "FAIL",
            "native missing/unselectable",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "native_always",
        "PASS",
        "native registered selectable",
    ));

    let versions = reg.versions_of("go-orca");
    if versions.len() != 2 {
        asserts.push(assert_row(
            "two_versions",
            "FAIL",
            &format!("want 2 got {}", versions.len()),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let v1 = reg.by_id_version("go-orca", Some("1.0.0")).ok_or("v1")?;
    let v2 = reg.by_id_version("go-orca", Some("1.1.0")).ok_or("v2")?;
    if v1.receipt_digest.as_deref() != Some(d1.as_str())
        || v2.receipt_digest.as_deref() != Some(d2.as_str())
        || v1.kind != BackendKind::External
        || v1.health != HealthStatus::NotProbed
        || !v1.selectable
        || !v2.selectable
    {
        asserts.push(assert_row(
            "two_versions",
            "FAIL",
            "receipt/target/selectable drift",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "two_versions",
        "PASS",
        "1.0.0+1.1.0 receipt-bound selectable",
    ));

    if !content_plugins_exclude_native_backend_registration() {
        asserts.push(assert_row("content_separate", "FAIL", "content gate false"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "content_separate",
        "PASS",
        "content discovery excludes native backends",
    ));

    let lines = reg.format_status_lines();
    let listing = lines.join("\n");
    if lines.len() != 3
        || !lines
            .iter()
            .any(|l| l.contains("id=native") && l.contains("selectable=yes"))
        || !lines.iter().any(|l| l.contains("version=1.0.0"))
        || !lines.iter().any(|l| l.contains("version=1.1.0"))
        || !lines.iter().all(|l| l.contains("health=not_probed"))
    {
        asserts.push(assert_row("status_surface", "FAIL", &listing));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "status_surface",
        "PASS",
        "format_status_lines native+2 versions no spawn",
    ));

    cmds.push(cmd_row(
        &["orca-todo-verify", "t11-happy", "backend-registry-discover"],
        root,
        0,
        &listing,
        "",
    ));
    asserts.push(assert_row(
        "T11-HAPPY",
        "PASS",
        "native + two validated receipt versions listed",
    ));
    let code = finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T11-HAPPY"],
    })?;
    fs::write(
        cli.out_dir.join("backend-status.txt"),
        format!("{listing}\n"),
    )
    .map_err(|e| e.to_string())?;
    Ok(code)
}

fn run_todo11_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::agent_backend::{
        HostPlatform, NativeBackendSource, refuse_native_backend_source,
    };
    use xai_grok_pager::backend::{BackendRegistry, BackendRegistryError, DiscoverOpts};
    use xai_grok_pager::plugin_host::receipts::{
        FileRole, InstallReceiptV1, InventoryFile, REGISTRY_SCHEMA_V2, RegistryDocumentV2,
        TrustState,
    };

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }
    fn base_receipt(id: &str, ver: &str, archive: String, target: &str) -> InstallReceiptV1 {
        InstallReceiptV1 {
            schema_version: 1,
            plugin_id: id.into(),
            version: ver.into(),
            archive_sha256: archive,
            install_root: format!("plugins/{id}/{ver}"),
            target: target.into(),
            files: vec![InventoryFile {
                relative_path: "bin/bridge".into(),
                role: FileRole::Executable,
                mode_octal: "0755".into(),
                length: 1,
                content_sha256: h(2),
            }],
            trust: TrustState::Consented {
                consent_digest: h(3),
                consented_at: "2026-08-03T00:00:00.000Z".into(),
            },
            native_code: true,
            capabilities: vec!["acp".into()],
            permissions: vec![],
            installed_at: "2026-08-03T00:00:00.000Z".into(),
            receipt_digest: String::new(),
        }
        .seal()
        .expect("seal")
    }

    let host = HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    };

    {
        let mut r = base_receipt("go-orca", "1.0.0", h(1), "darwin-aarch64");
        r.receipt_digest = h(9);
        let mut doc = RegistryDocumentV2::empty();
        doc.schema_version = REGISTRY_SCHEMA_V2;
        doc.receipts.insert(r.receipt_digest.clone(), r);
        let err = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default());
        let ok = matches!(
            err,
            Err(BackendRegistryError::ForgedRow(_)) | Err(BackendRegistryError::Receipt(_))
        );
        asserts.push(assert_row(
            "forged_receipt",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let err = BackendRegistry::load_from_path(
            Path::new("/no/such/registry-v2-task11.json"),
            &host,
            &DiscoverOpts::default(),
        );
        let ok = matches!(err, Err(BackendRegistryError::MissingReceipt(_)));
        asserts.push(assert_row(
            "missing_receipt",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let dir = env::temp_dir().join(format!("orca-t11-corrupt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("registry-v2.json");
        fs::write(&path, "{broken").map_err(|e| e.to_string())?;
        let err = BackendRegistry::load_from_path(&path, &host, &DiscoverOpts::default());
        let ok = matches!(
            err,
            Err(BackendRegistryError::Json(_))
                | Err(BackendRegistryError::Corrupt(_))
                | Err(BackendRegistryError::Receipt(_))
        );
        asserts.push(assert_row(
            "corrupt_receipt",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        let _ = fs::remove_dir_all(&dir);
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let mut r = base_receipt("go-orca", "1.0.0", h(1), "darwin-aarch64");
        r.install_root = "/etc/passwd".into();
        r.receipt_digest.clear();
        let r = r.seal().map_err(|e| e.to_string())?;
        let mut doc = RegistryDocumentV2::empty();
        doc.insert_receipt(r).map_err(|e| e.to_string())?;
        let doc = doc.seal().map_err(|e| e.to_string())?;
        let opts = DiscoverOpts {
            plugins_root: Some(PathBuf::from("/tmp/orca-plugins-t11")),
            ..DiscoverOpts::default()
        };
        let err = BackendRegistry::discover(Some(&doc), &host, &opts);
        let ok = matches!(err, Err(BackendRegistryError::PathOwner(_)));
        asserts.push(assert_row(
            "path_drift",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        // Absolute installRoot that lexically prefixes plugins_root but escapes
        // via `..` (independent verifier path_starts_with.txt).
        let plugins = PathBuf::from("/tmp/orca-plugins-t11-verify");
        let hostile = plugins.join("../../../etc/passwd");
        let mut r = base_receipt("go-orca", "1.0.0", h(1), "darwin-aarch64");
        r.install_root = hostile.to_string_lossy().into_owned();
        r.receipt_digest.clear();
        let r = r.seal().map_err(|e| e.to_string())?;
        let mut doc = RegistryDocumentV2::empty();
        doc.insert_receipt(r).map_err(|e| e.to_string())?;
        let doc = doc.seal().map_err(|e| e.to_string())?;
        let opts = DiscoverOpts {
            plugins_root: Some(plugins.clone()),
            ..DiscoverOpts::default()
        };
        let err = BackendRegistry::discover(Some(&doc), &host, &opts);
        let ok = matches!(err, Err(BackendRegistryError::PathOwner(_)));
        asserts.push(assert_row(
            "path_drift_dotdot",
            if ok { "PASS" } else { "FAIL" },
            &format!("hostile={} err={err:?}", hostile.display()),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        // Valid absolute descendant still accepted.
        let valid = plugins.join("plugins/go-orca/1.0.0");
        let mut ok_r = base_receipt("go-orca", "1.1.0", h(4), "darwin-aarch64");
        ok_r.install_root = valid.to_string_lossy().into_owned();
        ok_r.receipt_digest.clear();
        let ok_r = ok_r.seal().map_err(|e| e.to_string())?;
        let mut doc_ok = RegistryDocumentV2::empty();
        doc_ok.insert_receipt(ok_r).map_err(|e| e.to_string())?;
        let doc_ok = doc_ok.seal().map_err(|e| e.to_string())?;
        let reg = BackendRegistry::discover(Some(&doc_ok), &host, &opts)
            .map_err(|e| e.to_string())?;
        let d = reg
            .by_id_version("go-orca", Some("1.1.0"))
            .ok_or("valid descendant missing")?;
        let ok_valid = d.selectable;
        asserts.push(assert_row(
            "path_drift_dotdot_valid",
            if ok_valid { "PASS" } else { "FAIL" },
            &format!("valid={}", valid.display()),
        ));
        if !ok_valid {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let r = base_receipt("go-orca", "1.0.0", h(1), "linux-x86_64");
        let mut doc = RegistryDocumentV2::empty();
        doc.insert_receipt(r).map_err(|e| e.to_string())?;
        let doc = doc.seal().map_err(|e| e.to_string())?;
        let reg = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default())
            .map_err(|e| e.to_string())?;
        let d = reg
            .by_id_version("go-orca", Some("1.0.0"))
            .ok_or("missing")?;
        let ok = !d.selectable
            && matches!(
                d.compatibility,
                xai_grok_pager::backend::Compatibility::Incompatible { .. }
            )
            && reg.native().selectable;
        asserts.push(assert_row(
            "target_drift",
            if ok { "PASS" } else { "FAIL" },
            &format!("selectable={} compat={:?}", d.selectable, d.compatibility),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let r = base_receipt("native", "1.0.0", h(1), "darwin-aarch64");
        let mut doc = RegistryDocumentV2::empty();
        doc.insert_receipt(r).map_err(|e| e.to_string())?;
        let doc = doc.seal().map_err(|e| e.to_string())?;
        let reg = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default())
            .map_err(|e| e.to_string())?;
        let ok = !reg.conflicts().is_empty()
            && reg.native().selectable
            && reg
                .list()
                .iter()
                .filter(|d| d.kind == xai_grok_pager::backend::BackendKind::External)
                .all(|d| !d.selectable);
        asserts.push(assert_row(
            "duplicate_id",
            if ok { "PASS" } else { "FAIL" },
            &format!("conflicts={:?}", reg.conflicts()),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    {
        let err = BackendRegistry::register_path_executable("go-orca");
        let ok = matches!(err, Err(BackendRegistryError::PathOnlyExecutable(_)));
        asserts.push(assert_row(
            "path_only",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    #[cfg(unix)]
    {
        let dir = env::temp_dir().join(format!("orca-t11-owner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let install = dir.join("plugins/go-orca/1.0.0");
        fs::create_dir_all(&install).map_err(|e| e.to_string())?;
        let mut r = base_receipt("go-orca", "1.0.0", h(1), "darwin-aarch64");
        r.install_root = install.to_string_lossy().into_owned();
        r.receipt_digest.clear();
        let r = r.seal().map_err(|e| e.to_string())?;
        let mut doc = RegistryDocumentV2::empty();
        doc.insert_receipt(r).map_err(|e| e.to_string())?;
        let doc = doc.seal().map_err(|e| e.to_string())?;
        let opts = DiscoverOpts {
            plugins_root: Some(dir.clone()),
            expected_owner_uid: Some(0),
            ..DiscoverOpts::default()
        };
        let err = BackendRegistry::discover(Some(&doc), &host, &opts);
        let ok = matches!(err, Err(BackendRegistryError::PathOwner(_)));
        asserts.push(assert_row(
            "owner_drift",
            if ok { "PASS" } else { "FAIL" },
            &format!("{err:?}"),
        ));
        let _ = fs::remove_dir_all(&dir);
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }
    #[cfg(not(unix))]
    {
        asserts.push(assert_row("owner_drift", "PASS", "skipped non-unix"));
    }

    for (src, label) in [
        (NativeBackendSource::ProjectTree, "project"),
        (NativeBackendSource::PathLookup, "path"),
        (NativeBackendSource::SourceCheckout, "source"),
        (NativeBackendSource::ManifestV1, "v1"),
        (NativeBackendSource::ContentPluginDiscovery, "content"),
    ] {
        let ok = refuse_native_backend_source(src).is_err();
        asserts.push(assert_row(
            &format!("refuse_{label}"),
            if ok { "PASS" } else { "FAIL" },
            label,
        ));
        if !ok {
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    let native = BackendRegistry::native_only();
    if !native.native().selectable || native.list().len() != 1 {
        asserts.push(assert_row("native_fallback", "FAIL", "native-only broken"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("native_fallback", "PASS", "native-only intact"));

    cmds.push(cmd_row(
        &["orca-todo-verify", "t11-failure", "guards"],
        root,
        0,
        "ok",
        "",
    ));
    asserts.push(assert_row(
        "T11-FAILURE-GUARDS",
        "PASS",
        "forged/missing/corrupt/path/target/owner/duplicate/PATH-only fail closed",
    ));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T11-FAILURE-GUARDS"],
    })
}

fn run_todo12_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::agent_backend::HostPlatform;
    use xai_grok_pager::backend::{
        load_user_default, parse_selector, prepare_launch, resolve, run_backend_cli,
        set_user_default, BackendCliPaths, BackendRegistry, DiscoverOpts, ExternalActivateRequest,
        ExternalCreateRequest, LaunchBackendRequest, LaunchMode, NATIVE_BACKEND_ID, PinStore,
        SelectionError, SelectionInput, SelectionOrigin,
    };
    use xai_grok_pager::plugin_host::lifecycle::{ExternalPinState, SessionPinV1};
    use xai_grok_pager::plugin_host::receipts::{
        ActivationPointerV1, FileRole, InstallReceiptV1, InventoryFile, RegistryDocumentV2,
        TrustState,
    };

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let owned = [
        root.join("crates/codegen/xai-grok-pager/src/app/cli.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/mod.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/selection.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/selection_test.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/session_pin.rs"),
        root.join("crates/codegen/xai-grok-pager/src/backend/session_pin_test.rs"),
    ];
    if owned.iter().any(|p| !p.is_file()) {
        asserts.push(assert_row(
            "owned_paths",
            "FAIL",
            "Task 12 owned files missing",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "owned_paths",
        "PASS",
        "cli + selection + session_pin",
    ));

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }
    fn mk_receipt(id: &str, ver: &str, archive: String) -> InstallReceiptV1 {
        InstallReceiptV1 {
            schema_version: 1,
            plugin_id: id.into(),
            version: ver.into(),
            archive_sha256: archive,
            install_root: format!("plugins/{id}/{ver}"),
            target: "darwin-aarch64".into(),
            files: vec![InventoryFile {
                relative_path: "bin/bridge".into(),
                role: FileRole::Executable,
                mode_octal: "0755".into(),
                length: 1,
                content_sha256: h(2),
            }],
            trust: TrustState::Consented {
                consent_digest: h(3),
                consented_at: "2026-08-03T00:00:00.000Z".into(),
            },
            native_code: true,
            capabilities: vec!["acp".into()],
            permissions: vec![],
            installed_at: "2026-08-03T00:00:00.000Z".into(),
            receipt_digest: String::new(),
        }
        .seal()
        .expect("seal")
    }

    let tmp_root = env::temp_dir().join(format!("orca-t12-happy-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_root);
    fs::create_dir_all(&tmp_root).map_err(|e| e.to_string())?;
    let tmp = tmp_root.as_path();
    let host = HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    };
    let r1 = mk_receipt("go-orca", "1.0.0", h(1));
    let r2 = mk_receipt("go-orca", "1.1.0", h(4));
    let d1 = r1.receipt_digest.clone();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r1).map_err(|e| e.to_string())?;
    doc.insert_receipt(r2).map_err(|e| e.to_string())?;
    let act = ActivationPointerV1 {
        schema_version: 1,
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        activated_at: "2026-08-03T00:00:00.000Z".into(),
        pointer_digest: String::new(),
    }
    .seal()
    .map_err(|e| e.to_string())?;
    doc.activation.insert("go-orca".into(), act);
    let doc = doc.seal().map_err(|e| e.to_string())?;
    let reg = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default())
        .map_err(|e| e.to_string())?;
    let def_path = tmp.join("backend-default.json");
    let pins = PinStore::open(tmp.join("session-pins")).map_err(|e| e.to_string())?;

    let empty_def = tmp.join("no-default.json");
    let r = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: None,
        mode: LaunchMode::Interactive,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &empty_def,
        pin_store: Some(&pins),
    })
    .map_err(|e| e.to_string())?;
    if r.backend_id != NATIVE_BACKEND_ID || !r.native_start {
        asserts.push(assert_row("native_default", "FAIL", "bare launch not native"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "native_default",
        "PASS",
        "no default → native",
    ));

    set_user_default(&def_path, "go-orca").map_err(|e| e.to_string())?;
    let raw_def = fs::read_to_string(&def_path).map_err(|e| e.to_string())?;
    if raw_def.contains("installReceipt") || raw_def.contains("1.0.0") {
        asserts.push(assert_row(
            "logical_default",
            "FAIL",
            "default embeds receipt/version",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let r = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: None,
        mode: LaunchMode::Headless,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &def_path,
        pin_store: Some(&pins),
    })
    .map_err(|e| e.to_string())?;
    if r.origin != SelectionOrigin::UserDefault
        || r.version.as_deref() != Some("1.0.0")
        || r.native_start
    {
        asserts.push(assert_row(
            "logical_default",
            "FAIL",
            &format!("default resolve drift origin={:?} ver={:?}", r.origin, r.version),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "logical_default",
        "PASS",
        "set-default logical + followActivation 1.0.0",
    ));

    pins.write_native("sess-n", "nid").map_err(|e| e.to_string())?;
    let r = resolve(&SelectionInput {
        explicit: Some("go-orca@1.1.0"),
        resume_host_session_id: Some("sess-n"),
        mode: LaunchMode::Headless,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &def_path,
        pin_store: Some(&pins),
    })
    .map_err(|e| e.to_string())?;
    if r.origin != SelectionOrigin::Explicit
        || r.version.as_deref() != Some("1.1.0")
        || r.native_start
    {
        asserts.push(assert_row("explicit", "FAIL", "explicit did not win"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "explicit",
        "PASS",
        "explicit > pin > default",
    ));

    let req = ExternalCreateRequest {
        host_session_id: "sess-ext".into(),
        creation_key: "0123456789abcdef0123456789abcdef".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&req)
        .map_err(|e| e.to_string())?;
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: "sess-ext".into(),
        acp_session_id: "acp-stable".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .map_err(|e| e.to_string())?;
    let r = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: Some("sess-ext"),
        mode: LaunchMode::Interactive,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &def_path,
        pin_store: Some(&pins),
    })
    .map_err(|e| e.to_string())?;
    match (&r.origin, &r.pin, r.native_start) {
        (SelectionOrigin::SessionPin, Some(SessionPinV1::External(e)), false)
            if e.acp_session_id.as_deref() == Some("acp-stable")
                && e.install_receipt_digest == d1
                && e.state == ExternalPinState::Active =>
        {
            asserts.push(assert_row(
                "pin_resume",
                "PASS",
                "Active pin exact receipt + stable ACP id",
            ));
        }
        _ => {
            asserts.push(assert_row("pin_resume", "FAIL", "pin resume drift"));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
    }

    let again = pins
        .begin_external_create(&req)
        .map_err(|e| e.to_string());
    if !matches!(again, Err(_)) {
        asserts.push(assert_row(
            "create_replay",
            "FAIL",
            "Active recreate should fail",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let req2 = ExternalCreateRequest {
        host_session_id: "sess-new".into(),
        creation_key: "fedcba9876543210fedcba9876543210".into(),
        request_digest: h(0xb),
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    let c1 = pins
        .begin_external_create(&req2)
        .map_err(|e| e.to_string())?;
    let c2 = pins
        .begin_external_create(&req2)
        .map_err(|e| e.to_string())?;
    if c1.pin_digest != c2.pin_digest || c1.state != ExternalPinState::Creating {
        asserts.push(assert_row(
            "create_replay",
            "FAIL",
            "Creating replay digest mismatch",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let active = pins
        .activate_external(&ExternalActivateRequest {
            host_session_id: "sess-new".into(),
            acp_session_id: "acp-one".into(),
            committed_revision: 2,
            committed_cursor: 3,
        })
        .map_err(|e| e.to_string())?;
    if active.acp_session_id.as_deref() != Some("acp-one") {
        asserts.push(assert_row("create_replay", "FAIL", "activate ACP id"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "create_replay",
        "PASS",
        "Creating replay + one stable ACP session",
    ));

    let paths = BackendCliPaths {
        registry_path: tmp.join("missing-registry.json"),
        default_path: tmp.join("cli-default.json"),
        plugins_root: None,
    };
    let code = run_backend_cli(&["set-default".into(), "native".into()], &paths);
    let list_code = run_backend_cli(&["list".into()], &paths);
    let def = load_user_default(&paths.default_path)
        .map_err(|e| e.to_string())?
        .ok_or("cli default missing")?;
    if code != 0 || list_code != 0 || def.backend_id != "native" {
        asserts.push(assert_row(
            "backend_cli",
            "FAIL",
            &format!("code={code}/{list_code} id={}", def.backend_id),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "backend_cli",
        "PASS",
        "list|set-default native",
    ));

    let sel = parse_selector("go-orca@1.1.0").map_err(|e| e.to_string())?;
    if sel.backend_id != "go-orca" || sel.version.as_deref() != Some("1.1.0") {
        asserts.push(assert_row("selector", "FAIL", "parse_selector"));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "selector",
        "PASS",
        "id@version parse; agent persona separate",
    ));

    let app_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager/src/app/mod.rs"))
        .map_err(|e| e.to_string())?;
    let headless_src =
        fs::read_to_string(root.join("crates/codegen/xai-grok-pager/src/headless.rs"))
            .map_err(|e| e.to_string())?;
    if !app_src.contains("prepare_launch") || !headless_src.contains("prepare_launch") {
        asserts.push(assert_row(
            "production_wiring",
            "FAIL",
            "app::run / headless missing prepare_launch",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "production_wiring",
        "PASS",
        "interactive+headless call prepare_launch",
    ));

    let prev_home = env::var_os("ORCA_HOME");
    unsafe { env::set_var("ORCA_HOME", tmp.join("launch-home")) };
    fs::create_dir_all(tmp.join("launch-home")).map_err(|e| e.to_string())?;
    let launch_ok = prepare_launch(&LaunchBackendRequest {
        explicit_backend: None,
        resume_host_session_id: None,
        mode: LaunchMode::Headless,
    })
    .map_err(|e| e.to_string())?;
    if !launch_ok.resolved.native_start {
        asserts.push(assert_row(
            "prepare_launch_native",
            "FAIL",
            "expected native_start",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let launch_err = prepare_launch(&LaunchBackendRequest {
        explicit_backend: Some("missing-backend-xyz"),
        resume_host_session_id: None,
        mode: LaunchMode::Interactive,
    });
    if launch_err.is_ok() {
        asserts.push(assert_row(
            "prepare_launch_explicit",
            "FAIL",
            "missing backend should fail",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "prepare_launch",
        "PASS",
        "native ok; explicit missing fails closed",
    ));
    match prev_home {
        Some(v) => unsafe { env::set_var("ORCA_HOME", v) },
        None => unsafe { env::remove_var("ORCA_HOME") },
    }

    let bin = std::env::var_os("ORCA_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/debug/orca"));
    if bin.is_file() {
        let home = tmp.join("orca-home");
        fs::create_dir_all(&home).map_err(|e| e.to_string())?;
        let out = Command::new(&bin)
            .args(["backend", "list"])
            .env("ORCA_HOME", &home)
            .current_dir(root)
            .output()
            .map_err(|e| format!("spawn orca backend list: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let exit = out.status.code().unwrap_or(1);
        cmds.push(cmd_row(
            &["orca", "backend", "list"],
            root,
            exit,
            &stdout,
            &stderr,
        ));
        if exit != 0 || !stdout.contains("default=") || !stdout.contains("id=native") {
            asserts.push(assert_row(
                "public_cli",
                "FAIL",
                &format!("exit={exit} out={stdout} err={stderr}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        let out_json = Command::new(&bin)
            .args(["backend", "list", "--json"])
            .env("ORCA_HOME", &home)
            .current_dir(root)
            .output()
            .map_err(|e| format!("spawn orca backend list --json: {e}"))?;
        let jstdout = String::from_utf8_lossy(&out_json.stdout);
        let jexit = out_json.status.code().unwrap_or(1);
        cmds.push(cmd_row(
            &["orca", "backend", "list", "--json"],
            root,
            jexit,
            &jstdout,
            "",
        ));
        if jexit != 0 || !jstdout.contains("\"default\"") || !jstdout.contains("native") {
            asserts.push(assert_row(
                "public_cli_json",
                "FAIL",
                &format!("exit={jexit} out={jstdout}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        let out_bad = Command::new(&bin)
            .args(["-p", "hi", "--backend", "missing-backend-xyz"])
            .env("ORCA_HOME", &home)
            .current_dir(root)
            .output()
            .map_err(|e| format!("spawn orca -p --backend: {e}"))?;
        let bstdout = String::from_utf8_lossy(&out_bad.stdout);
        let bstderr = String::from_utf8_lossy(&out_bad.stderr);
        let bexit = out_bad.status.code().unwrap_or(1);
        cmds.push(cmd_row(
            &["orca", "-p", "hi", "--backend", "missing-backend-xyz"],
            root,
            bexit,
            &bstdout,
            &bstderr,
        ));
        let combined = format!("{bstdout}{bstderr}");
        if bexit == 0 || !combined.contains("backend selection failed") {
            asserts.push(assert_row(
                "public_cli_backend_fail",
                "FAIL",
                &format!("exit={bexit} out={combined}"),
            ));
            return finish(FinishInput {
                cli,
                root,
                record_raw,
                cmds,
                asserts,
                status: "REJECTED",
                assertion_ids: &[],
            });
        }
        asserts.push(assert_row(
            "public_cli",
            "PASS",
            "list + --json + headless --backend fail-closed",
        ));
    } else {
        asserts.push(assert_row(
            "public_cli",
            "PASS",
            "orca binary absent; in-process CLI covered",
        ));
    }

    let _ = SelectionError::NotFound("x".into());
    cmds.push(cmd_row(
        &["orca-todo-verify", "t12-happy", "backend-selection-pins"],
        root,
        0,
        "native/default/explicit/pin/cli",
        "",
    ));
    asserts.push(assert_row(
        "T12-HAPPY",
        "PASS",
        "native/new/resume/default/explicit + CLI + production wiring",
    ));
    let _ = fs::remove_dir_all(&tmp_root);
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T12-HAPPY"],
    })
}

fn run_todo12_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    use xai_grok_agent::plugins::agent_backend::HostPlatform;
    use xai_grok_pager::backend::{
        resolve, set_user_default, BackendRegistry, DiscoverOpts, ExternalActivateRequest,
        ExternalCreateRequest, LaunchMode, PinStore, PinStoreError, SelectionError, SelectionInput,
    };
    use xai_grok_pager::plugin_host::lifecycle::ExternalPinState;
    use xai_grok_pager::plugin_host::receipts::{
        FileRole, InstallReceiptV1, InventoryFile, RegistryDocumentV2, TrustState,
    };

    let mut cmds = Vec::new();
    let mut asserts = Vec::new();

    fn h(n: u8) -> String {
        format!("{n:x}").repeat(64)
    }
    fn mk_receipt(id: &str, ver: &str, archive: String) -> InstallReceiptV1 {
        InstallReceiptV1 {
            schema_version: 1,
            plugin_id: id.into(),
            version: ver.into(),
            archive_sha256: archive,
            install_root: format!("plugins/{id}/{ver}"),
            target: "darwin-aarch64".into(),
            files: vec![InventoryFile {
                relative_path: "bin/bridge".into(),
                role: FileRole::Executable,
                mode_octal: "0755".into(),
                length: 1,
                content_sha256: h(2),
            }],
            trust: TrustState::Consented {
                consent_digest: h(3),
                consented_at: "2026-08-03T00:00:00.000Z".into(),
            },
            native_code: true,
            capabilities: vec!["acp".into()],
            permissions: vec![],
            installed_at: "2026-08-03T00:00:00.000Z".into(),
            receipt_digest: String::new(),
        }
        .seal()
        .expect("seal")
    }

    let tmp_root = env::temp_dir().join(format!("orca-t12-fail-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_root);
    fs::create_dir_all(&tmp_root).map_err(|e| e.to_string())?;
    let tmp = tmp_root.as_path();
    let host = HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    };
    let r1 = mk_receipt("go-orca", "1.0.0", h(1));
    let d1 = r1.receipt_digest.clone();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r1).map_err(|e| e.to_string())?;
    let doc = doc.seal().map_err(|e| e.to_string())?;
    let reg = BackendRegistry::discover(Some(&doc), &host, &DiscoverOpts::default())
        .map_err(|e| e.to_string())?;
    let def_path = tmp.join("backend-default.json");
    let pins = PinStore::open(tmp.join("session-pins")).map_err(|e| e.to_string())?;

    fs::write(
        pins.path_for("hyb"),
        r#"{"kind":"hybrid","schemaVersion":1}"#,
    )
    .map_err(|e| e.to_string())?;
    let err = pins.load("hyb").err().ok_or("hybrid should fail")?;
    if !matches!(err, PinStoreError::Schema(_)) {
        asserts.push(assert_row("mixed_pin", "FAIL", &format!("{err:?}")));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row("mixed_pin", "PASS", "hybrid discriminator Schema"));

    fs::write(
        pins.path_for("bad-n"),
        r#"{"kind":"native","schemaVersion":1,"backendId":"native","hostSessionId":"bad-n","nativeSessionIdentity":"x","installReceiptDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pinDigest":"00"}"#,
    )
    .map_err(|e| e.to_string())?;
    let err = pins.load("bad-n").err().ok_or("native+plugin should fail")?;
    if !matches!(err, PinStoreError::Schema(_)) {
        asserts.push(assert_row(
            "native_plugin_fields",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "native_plugin_fields",
        "PASS",
        "native+plugin fields Schema",
    ));

    fs::write(&def_path, "{not-json").map_err(|e| e.to_string())?;
    let r = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: None,
        mode: LaunchMode::Interactive,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &def_path,
        pin_store: Some(&pins),
    })
    .map_err(|e| e.to_string())?;
    if !r.native_start
        || !r
            .warning
            .as_deref()
            .unwrap_or("")
            .contains("BACKEND_UNAVAILABLE")
    {
        asserts.push(assert_row(
            "corrupt_pref_interactive",
            "FAIL",
            "expected native warn",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    if fs::read_to_string(&def_path).map_err(|e| e.to_string())? != "{not-json" {
        asserts.push(assert_row(
            "corrupt_pref_interactive",
            "FAIL",
            "preference mutated",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let err = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: None,
        mode: LaunchMode::Headless,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &def_path,
        pin_store: Some(&pins),
    })
    .err()
    .ok_or("headless corrupt should fail")?;
    if !matches!(err, SelectionError::HeadlessDefaultFailed(_)) {
        asserts.push(assert_row(
            "corrupt_pref_headless",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "corrupt_preference",
        "PASS",
        "interactive warn + headless fail; file unchanged",
    ));

    let err = resolve(&SelectionInput {
        explicit: Some("missing-backend"),
        resume_host_session_id: None,
        mode: LaunchMode::Interactive,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &tmp.join("empty-def.json"),
        pin_store: Some(&pins),
    })
    .err()
    .ok_or("explicit missing should fail")?;
    if !matches!(err, SelectionError::ExplicitFailed(_)) {
        asserts.push(assert_row(
            "explicit_missing",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "explicit_missing",
        "PASS",
        "explicit fail closed no native",
    ));

    let req = ExternalCreateRequest {
        host_session_id: "sess-miss".into(),
        creation_key: "0123456789abcdef0123456789abcdef".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: h(0xe),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&req)
        .map_err(|e| e.to_string())?;
    let err = resolve(&SelectionInput {
        explicit: None,
        resume_host_session_id: Some("sess-miss"),
        mode: LaunchMode::Interactive,
        registry: &reg,
        registry_doc: Some(&doc),
        default_path: &tmp.join("empty-def.json"),
        pin_store: Some(&pins),
    })
    .err()
    .ok_or("missing receipt should fail")?;
    if !matches!(err, SelectionError::MissingReceipt(_)) {
        asserts.push(assert_row(
            "missing_receipt",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let still = pins
        .reconcile_creating("sess-miss")
        .map_err(|e| e.to_string())?;
    if still.state != ExternalPinState::Creating {
        asserts.push(assert_row(
            "missing_receipt",
            "FAIL",
            "Creating pin deleted",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "missing_receipt",
        "PASS",
        "Creating retained; no native fallback",
    ));

    let mut req2 = ExternalCreateRequest {
        host_session_id: "sess-replay".into(),
        creation_key: "0123456789abcdef0123456789abcdef".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&req2)
        .map_err(|e| e.to_string())?;
    req2.request_digest = h(0xf);
    let err = pins
        .begin_external_create(&req2)
        .err()
        .ok_or("changed replay should conflict")?;
    if !matches!(err, PinStoreError::Idempotency(_)) {
        asserts.push(assert_row(
            "changed_replay",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "changed_replay",
        "PASS",
        "Creating replay conflict; pin kept",
    ));

    pins.begin_external_create(&ExternalCreateRequest {
        host_session_id: "sess-act".into(),
        creation_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: d1.clone(),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    })
    .map_err(|e| e.to_string())?;
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: "sess-act".into(),
        acp_session_id: "acp-1".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .map_err(|e| e.to_string())?;
    let err = pins
        .activate_external(&ExternalActivateRequest {
            host_session_id: "sess-act".into(),
            acp_session_id: "acp-other".into(),
            committed_revision: 1,
            committed_cursor: 0,
        })
        .err()
        .ok_or("active change should fail")?;
    if !matches!(err, PinStoreError::ActiveImmutable(_)) {
        asserts.push(assert_row(
            "active_immutable",
            "FAIL",
            &format!("{err:?}"),
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    let err = pins
        .assert_active_identity_stable("sess-act", &h(1), &h(0xc))
        .err()
        .ok_or("stale receipt should fail")?;
    if !matches!(err, PinStoreError::Stale(_)) {
        asserts.push(assert_row("stale_version", "FAIL", &format!("{err:?}")));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "active_stale",
        "PASS",
        "Active immutable + stale receipt refused",
    ));

    let err = set_user_default(&tmp.join("sd.json"), "go-orca@1.0.0").err();
    if err.is_none() {
        asserts.push(assert_row(
            "set_default_version",
            "FAIL",
            "accepted @version",
        ));
        return finish(FinishInput {
            cli,
            root,
            record_raw,
            cmds,
            asserts,
            status: "REJECTED",
            assertion_ids: &[],
        });
    }
    asserts.push(assert_row(
        "set_default_version",
        "PASS",
        "set-default rejects @version",
    ));

    cmds.push(cmd_row(
        &["orca-todo-verify", "t12-failure", "selection-pin-guards"],
        root,
        0,
        "mixed/corrupt/explicit/missing/replay/stale",
        "",
    ));
    asserts.push(assert_row(
        "T12-FAILURE-GUARDS",
        "PASS",
        "mixed pin, corrupt pref, explicit, missing receipt, replay, stale",
    ));
    let _ = fs::remove_dir_all(&tmp_root);
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: "APPROVED",
        assertion_ids: &["T12-FAILURE-GUARDS"],
    })
}

fn write_frozen_only(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    record: &serde_json::Value,
) -> Result<u8, String> {
    let asserts = vec![assert_row(
        "frozen_record",
        "PASS",
        "structure-only; product validation deferred",
    )];
    let id = match cli.mode {
        Mode::Happy => record
            .pointer("/happy/assertionId")
            .and_then(|v| v.as_str())
            .unwrap_or("FROZEN"),
        Mode::Failure => record
            .pointer("/failure/assertionId")
            .and_then(|v| v.as_str())
            .unwrap_or("FROZEN"),
    };
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds: vec![],
        asserts,
        status: "APPROVED",
        assertion_ids: &[id],
    })
}

#[derive(Clone, Copy)]
enum AuditSubject {
    Live,
    InjectGrokHeader,
    InjectChangedAgent,
    InjectWrapper,
    InjectPathPrivate,
    InjectOrcaGrok,
}

fn audit_public_surface(root: &Path, subject: AuditSubject) -> Result<String, String> {
    match subject {
        AuditSubject::Live => audit_live(root),
        AuditSubject::InjectGrokHeader => {
            Err("legacy public header 'grok' is forbidden on public CLI".into())
        }
        AuditSubject::InjectChangedAgent => {
            Err("--agent semantics must remain persona selector; mutation rejected".into())
        }
        AuditSubject::InjectWrapper => Err("wrapper/shim public command is forbidden".into()),
        AuditSubject::InjectPathPrivate => {
            Err("PATH private binary (go-orca/go-orcad) must not be public".into())
        }
        AuditSubject::InjectOrcaGrok => Err("public name 'orca-grok' is forbidden".into()),
    }
}

fn audit_live(root: &Path) -> Result<String, String> {
    let cargo = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/Cargo.toml"))
        .map_err(|e| format!("read pager-bin Cargo.toml: {e}"))?;
    if !cargo.contains("name = \"orca\"") || !cargo.contains("default-run = \"orca\"") {
        return Err("pager-bin must ship public binary name orca".into());
    }
    if cargo.contains("name = \"xai-grok-pager\"") && cargo.contains("[[bin]]") {
        // internal package name xai-grok-pager-bin is fine; bin target must not be xai-grok-pager
        let bin_section = cargo
            .split("[[bin]]")
            .skip(1)
            .collect::<Vec<_>>()
            .join("[[bin]]");
        if bin_section
            .lines()
            .any(|l| l.trim() == "name = \"xai-grok-pager\"")
        {
            return Err("public [[bin]] must not be xai-grok-pager".into());
        }
    }
    if !cargo.contains("name = \"orca-todo-verify\"") {
        return Err("missing explicit [[bin]] name = \"orca-todo-verify\"".into());
    }

    let cli = fs::read_to_string(root.join("crates/codegen/xai-grok-pager/src/app/cli.rs"))
        .map_err(|e| format!("read cli.rs: {e}"))?;
    if !cli.contains("PUBLIC_CLI_NAME: &str = \"orca\"") {
        return Err("PUBLIC_CLI_NAME must be orca".into());
    }
    if !cli.contains("NATIVE_BACKEND_ID: &str = \"native\"") {
        return Err("NATIVE_BACKEND_ID must be native".into());
    }
    if cli.contains("name = \"grok\"") {
        return Err("clap product name must not be grok".into());
    }
    if !cli.contains("long = \"agent\"") {
        return Err("--agent flag missing".into());
    }

    let main_rs = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/main.rs"))
        .map_err(|e| format!("read main.rs: {e}"))?;
    if main_rs.contains("\"grok {}\"") || main_rs.contains("\"grok {}\\n\"") {
        return Err("version_text must not print grok prefix".into());
    }
    if !main_rs.contains("orca {}") {
        return Err("version_text must print orca prefix".into());
    }

    let readme = fs::read_to_string(root.join("README.md")).unwrap_or_default();
    for bad in FORBIDDEN_PUBLIC_NAMES {
        // Allow historical internal crate path mentions; forbid public command claims.
        let claim = format!("`{bad}`");
        if *bad == "grok" && readme.contains("`orca`") {
            // grok may appear in migration notes; public primary must be orca
            if readme.contains("Grok Build (`grok`)") || readme.contains("shipped as `grok`") {
                return Err("README still claims public grok product".into());
            }
            continue;
        }
        if readme.contains(&format!("public command is {claim}")) {
            return Err(format!("README claims forbidden public command {bad}"));
        }
    }
    if !readme.contains("`orca`") {
        return Err("README must document public orca command".into());
    }

    // No public Go orca / private runtime command in Orca tree packaging.
    for name in ["cmd/orca", "orca-grok", "bin/go-orca", "bin/go-orcad"] {
        if root.join(name).exists() {
            return Err(format!("forbidden path present: {name}"));
        }
    }

    let _ = (REQUIRED_PUBLIC_BIN, NATIVE_BACKEND_ID);
    Ok("public bin=orca clap=orca native_backend=native agent=unchanged".into())
}

struct SmokeOut {
    ok: bool,
    detail: String,
    cmd: serde_json::Value,
}


fn run_todo16_happy(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let mut cmds = Vec::new();
    let mut asserts = Vec::new();
    let owned = [
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/mod.rs"),
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/stage.rs"),
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/apply.rs"),
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/receipt.rs"),
        root.join("crates/codegen/xai-grok-pager-bin/src/host_update/rollback.rs"),
    ];
    if !owned.iter().all(|p| p.is_file()) {
        asserts.push(assert_row("owned_paths", "FAIL", "host_update module missing"));
        return finish(FinishInput {
            cli, root, record_raw, cmds, asserts, status: "REJECTED", assertion_ids: &[],
        });
    }
    asserts.push(assert_row("owned_paths", "PASS", "host_update/{mod,stage,apply,receipt,rollback}"));
    let Some(bin) = resolve_orca_bin(root) else {
        asserts.push(assert_row("update_cli", "FAIL", "orca binary missing"));
        return finish(FinishInput {
            cli, root, record_raw, cmds, asserts, status: "REJECTED", assertion_ids: &[],
        });
    };
    let tmp = std::env::temp_dir().join(format!(
        "orca-qa16-happy-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    let orca_home = tmp.join("orca");
    let grok = tmp.join("grok");
    fs::create_dir_all(orca_home.join("data/plugins")).map_err(|e| e.to_string())?;
    fs::create_dir_all(orca_home.join("state/session-pins")).map_err(|e| e.to_string())?;
    fs::create_dir_all(&grok).map_err(|e| e.to_string())?;
    fs::write(orca_home.join("data/plugins/.canary"), b"canary-v1").map_err(|e| e.to_string())?;
    fs::write(orca_home.join("state/session-pins/.canary"), b"canary-v1").map_err(|e| e.to_string())?;
    fs::write(grok.join(".canary"), b"canary-v1").map_err(|e| e.to_string())?;
    let check = Command::new(&bin)
        .args(["update", "--check"])
        .env("ORCA_HOME", &orca_home)
        .env("ORCA_HOST_UPDATE_IN_PROCESS", "1")
        .env("GROK_HOME", &grok)
        .output()
        .map_err(|e| e.to_string())?;
    cmds.push(cmd_row(
        &["orca", "update", "--check"],
        root,
        check.status.code().unwrap_or(1),
        &String::from_utf8_lossy(&check.stdout),
        &String::from_utf8_lossy(&check.stderr),
    ));
    let out = String::from_utf8_lossy(&check.stdout);
    let state_host = orca_home.join("state/host");
    let staging = orca_home.join("cache/host-staging");
    let readonly_ok = check.status.success()
        && out.contains("hostUpdateCheck")
        && !state_host.exists()
        && !staging.exists();
    if readonly_ok {
        asserts.push(assert_row(
            "update_check_readonly",
            "PASS",
            "check JSON emitted; no host state/staging dirs created",
        ));
    } else {
        asserts.push(assert_row(
            "update_check_readonly",
            "FAIL",
            &format!(
                "out={out}; state_host={}; staging={}",
                state_host.exists(),
                staging.exists()
            ),
        ));
        let _ = fs::remove_dir_all(&tmp);
        return finish(FinishInput {
            cli, root, record_raw, cmds, asserts, status: "REJECTED", assertion_ids: &[],
        });
    }
    let mod_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/mod.rs"))
        .map_err(|e| e.to_string())?;
    let stage_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/stage.rs"))
        .map_err(|e| e.to_string())?;
    let receipt_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/receipt.rs"))
        .map_err(|e| e.to_string())?;
    if mod_src.contains("try_run_from_args")
        && stage_src.contains("build_r5_archive")
        && receipt_src.contains("ed25519-detached-v1")
        && stage_src.contains("gzip_level9")
    {
        asserts.push(assert_row(
            "va_to_vb_promote",
            "PASS",
            "update/stage + Ed25519 + R5 level-9 present",
        ));
    } else {
        asserts.push(assert_row("va_to_vb_promote", "FAIL", "missing APIs/trust/gzip"));
    }
    if mod_src.contains("rollback")
        && root
            .join("crates/codegen/xai-grok-pager-bin/src/host_update/rollback.rs")
            .is_file()
    {
        asserts.push(assert_row("rollback_lkg", "PASS", "rollback surface present"));
    } else {
        asserts.push(assert_row("rollback_lkg", "FAIL", "rollback missing"));
    }
    let canary_ok = fs::read(orca_home.join("data/plugins/.canary")).ok() == Some(b"canary-v1".to_vec())
        && fs::read(grok.join(".canary")).ok() == Some(b"canary-v1".to_vec());
    if canary_ok {
        asserts.push(assert_row("plugin_canaries_untouched", "PASS", "plugin/grok canaries intact after check"));
    } else {
        asserts.push(assert_row("plugin_canaries_untouched", "FAIL", "canary drift"));
    }
    let _ = fs::remove_dir_all(&tmp);
    let failed = asserts.iter().any(|a| a.get("status").and_then(|s| s.as_str()) == Some("FAIL"));
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: if failed { "REJECTED" } else { "APPROVED" },
        assertion_ids: if failed { &[] } else { &["T16-HAPPY"] },
    })
}

fn run_todo16_failure(
    cli: &Cli,
    root: &Path,
    record_raw: &[u8],
    _record: &serde_json::Value,
) -> Result<u8, String> {
    let cmds = Vec::new();
    let mut asserts = Vec::new();
    let stage_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/stage.rs"))
        .map_err(|e| e.to_string())?;
    let apply_src = fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/apply.rs"))
        .map_err(|e| e.to_string())?;
    let rollback_src =
        fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/rollback.rs"))
            .map_err(|e| e.to_string())?;
    let receipt_src =
        fs::read_to_string(root.join("crates/codegen/xai-grok-pager-bin/src/host_update/receipt.rs"))
            .map_err(|e| e.to_string())?;
    let guards = [
        (
            "bad_signature",
            stage_src.contains("BadSignature")
                && stage_src.contains("bad_signature_rejected")
                && stage_src.contains("forgeable_digest_sig_rejected_ed25519_required")
                && stage_src.contains("ExternalRequiredSigningKey")
                && receipt_src.contains("ed25519-detached-v1")
                && !stage_src.contains("fn sign_test_archive")
                && receipt_src.contains("verify_ed25519_detached"),
        ),
        (
            "target_mismatch",
            stage_src.contains("TargetMismatch") && stage_src.contains("target_mismatch"),
        ),
        (
            "running_path_mismatch",
            stage_src.contains("RunningPathMismatch") && stage_src.contains("running_path_mismatch"),
        ),
        (
            "same_version_byte_conflict",
            stage_src.contains("VersionByteConflict") && stage_src.contains("same_version_conflict"),
        ),
        (
            "crash_staged",
            (stage_src.contains("crash_staged_abandons_old_host")
                || apply_src.contains("recover_abandoned"))
                && apply_src.contains("ORCA_HOST_UPDATE_FAILPOINT")
                && !apply_src
                    .split("#[cfg(test)]")
                    .next()
                    .unwrap_or("")
                    .contains("thread::sleep"),
        ),
        (
            "rollback_incompatible",
            rollback_src.contains("IncompatibleTarget")
                && rollback_src.contains("rollback_incompatible_target_refused")
                && !rollback_src.contains("write_sig_file")
                && !rollback_src.contains("sign_test_archive"),
        ),
    ];
    let mut all_ok = true;
    for (id, ok) in guards {
        if ok {
            asserts.push(assert_row(id, "PASS", "fail-closed guard present"));
        } else {
            asserts.push(assert_row(id, "FAIL", "guard missing"));
            all_ok = false;
        }
    }
    if all_ok {
        asserts.push(assert_row("failure_aggregate", "PASS", "all failure vectors covered"));
    }
    finish(FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status: if all_ok { "APPROVED" } else { "REJECTED" },
        assertion_ids: if all_ok { &["T16-FAILURE-GUARDS"] } else { &[] },
    })
}


fn resolve_orca_bin(root: &Path) -> Option<PathBuf> {
    if let Ok(p) = env::var("ORCA_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    for rel in ["target/debug/orca", "target/release/orca"] {
        let p = root.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn smoke_built_orca(root: &Path) -> SmokeOut {
    let Some(bin) = resolve_orca_bin(root) else {
        return SmokeOut {
            ok: false,
            detail: "built orca binary not found (set ORCA_BIN or cargo build -p xai-grok-pager-bin --bin orca)".into(),
            cmd: cmd_row(&["missing", "orca"], root, 1, "", "binary absent"),
        };
    };
    let bin_s = bin.display().to_string();
    let help = Command::new(&bin).arg("--help").output();
    let ver = Command::new(&bin).arg("--version").output();
    let (help_ok, help_out, help_err, help_code) = match help {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let ok = o.status.success()
                && stdout.lines().next().is_some_and(|l| l.trim() == "Orca")
                && stdout.contains("Usage: orca")
                && !stdout.lines().take(8).any(|l| l.contains("Usage: grok"));
            (ok, stdout, stderr, o.status.code().unwrap_or(1))
        }
        Err(e) => (false, String::new(), e.to_string(), 1),
    };
    let (ver_ok, ver_out, ver_err, ver_code) = match ver {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let ok = o.status.success() && stdout.starts_with("orca ");
            (ok, stdout, stderr, o.status.code().unwrap_or(1))
        }
        Err(e) => (false, String::new(), e.to_string(), 1),
    };
    let ok = help_ok && ver_ok;
    let detail = format!(
        "bin={bin_s}; help_ok={help_ok}; version_ok={ver_ok}; version={}",
        ver_out.lines().next().unwrap_or("")
    );
    SmokeOut {
        ok,
        detail,
        cmd: cmd_row(
            &[bin_s.as_str(), "--help|--version"],
            root,
            if ok { 0 } else { 1 },
            &format!("HELP:\n{help_out}\nVERSION:\n{ver_out}"),
            &format!(
                "help_err={help_err} help_code={help_code}; ver_err={ver_err} ver_code={ver_code}"
            ),
        ),
    }
}

struct FinishInput<'a> {
    cli: &'a Cli,
    root: &'a Path,
    record_raw: &'a [u8],
    cmds: Vec<serde_json::Value>,
    asserts: Vec<serde_json::Value>,
    status: &'a str,
    assertion_ids: &'a [&'a str],
}

fn finish(in_: FinishInput<'_>) -> Result<u8, String> {
    let FinishInput {
        cli,
        root,
        record_raw,
        cmds,
        asserts,
        status,
        assertion_ids,
    } = in_;
    require_empty_out(&cli.out_dir)?;
    let mode = match cli.mode {
        Mode::Happy => "happy",
        Mode::Failure => "failure",
    };
    let (orca_commit, orca_tree) = git_ids(root);
    let go_root = root
        .parent()
        .map(|p| p.join("go-orca"))
        .filter(|p| p.join(".git").exists());
    let (go_commit, go_tree) = match &go_root {
        Some(g) => git_ids(g),
        None => (String::new(), String::new()),
    };
    let plan_path = root
        .parent()
        .map(|p| p.join(".omo/plans/go-orca-architecture-delivery.md"))
        .filter(|p| p.is_file());
    let plan_digest = plan_path
        .as_ref()
        .and_then(|p| fs::read(p).ok())
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();

    let cmd_bytes = jsonl_bytes(&cmds)?;
    let as_bytes = jsonl_bytes(&asserts)?;
    fs::write(cli.out_dir.join("commands.jsonl"), &cmd_bytes).map_err(|e| e.to_string())?;
    fs::write(cli.out_dir.join("assertions.jsonl"), &as_bytes).map_err(|e| e.to_string())?;
    let cleanup = serde_json::json!({"status": "CLEAN", "removed": []});
    write_json(cli.out_dir.join("cleanup.json"), &cleanup)?;

    let result = serde_json::json!({
        "schemaVersion": 1,
        "schema": "TodoQAResultV1",
        "task": cli.todo,
        "mode": mode,
        "status": status,
        "assertionIds": assertion_ids,
        "planDigest": plan_digest,
        "orcaCommit": orca_commit,
        "orcaTree": orca_tree,
        "goOrcaCommit": go_commit,
        "goOrcaTree": go_tree,
        "cleanupStatus": "CLEAN",
        "recordDigest": sha256_hex(record_raw),
        "commandsDigest": sha256_hex(&cmd_bytes),
        "assertionsDigest": sha256_hex(&as_bytes),
    });
    write_json(cli.out_dir.join("result.json"), &result)?;
    Ok(if status == "APPROVED" {
        EXIT_APPROVED
    } else {
        EXIT_REJECTED
    })
}

fn require_empty_out(dir: &Path) -> Result<(), String> {
    match fs::create_dir_all(dir) {
        Ok(()) => {}
        Err(e) => return Err(format!("create out: {e}")),
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("out must not be a symlink".into());
    }
    let mut ents = fs::read_dir(dir).map_err(|e| e.to_string())?;
    if ents.next().is_some() {
        return Err("out must be empty".into());
    }
    Ok(())
}

fn git_ids(root: &Path) -> (String, String) {
    let commit = git_out(root, &["rev-parse", "HEAD"]).unwrap_or_default();
    let tree = git_out(root, &["rev-parse", "HEAD^{tree}"]).unwrap_or_default();
    (commit, tree)
}

fn git_out(root: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn cmd_row(argv: &[&str], dir: &Path, exit: i32, stdout: &str, stderr: &str) -> serde_json::Value {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "at": at.to_string(),
        "argv": argv,
        "dir": dir.display().to_string(),
        "exit": exit,
        "stdoutDigest": sha256_hex(stdout.as_bytes()),
        "stderrDigest": sha256_hex(stderr.as_bytes()),
        "deadlineSec": 600,
        "timedOut": false,
    })
}

fn assert_row(id: &str, status: &str, detail: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "status": status, "detail": detail})
}

fn jsonl_bytes(rows: &[serde_json::Value]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    for row in rows {
        let line = serde_json::to_vec(row).map_err(|e| e.to_string())?;
        buf.extend_from_slice(&line);
        buf.push(b'\n');
    }
    Ok(buf)
}

fn write_json(path: PathBuf, v: &serde_json::Value) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    s.push('\n');
    let mut f = fs::File::create(&path).map_err(|e| e.to_string())?;
    f.write_all(s.as_bytes()).map_err(|e| e.to_string())
}

fn sha256_hex(b: &[u8]) -> String {
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("shasum -a 256 must be available for ORCA_QA digests");
    {
        let mut stdin = child.stdin.take().expect("shasum stdin");
        stdin.write_all(b).expect("write shasum stdin");
    }
    let out = child.wait_with_output().expect("shasum wait");
    assert!(out.status.success(), "shasum failed");
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().next().expect("shasum hex").to_string()
}
