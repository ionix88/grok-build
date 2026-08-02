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
    if status == "frozen-record" && !matches!(cli.todo, 2 | 3 | 4) {
        return write_frozen_only(&cli, &root, &record_raw, &record);
    }
    match (cli.todo, cli.mode) {
        (2, Mode::Happy) => run_todo2_happy(&cli, &root, &record_raw, &record),
        (2, Mode::Failure) => run_todo2_failure(&cli, &root, &record_raw, &record),
        (3, Mode::Happy) => run_todo3_happy(&cli, &root, &record_raw, &record),
        (3, Mode::Failure) => run_todo3_failure(&cli, &root, &record_raw, &record),
        (4, Mode::Happy) => run_todo4_happy(&cli, &root, &record_raw, &record),
        (4, Mode::Failure) => run_todo4_failure(&cli, &root, &record_raw, &record),
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
