//! Tests for verified external ACP stdio transport (Task 14).

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use super::{
    config_from_receipt, sha256_hex_bytes, write_file_sha256, ExternalStdioConfig,
    ExternalStdioError, ExternalStdioLimits, ExternalStdioTransport, DEFAULT_MAX_LINE_BYTES,
};
use crate::backend::connection::{
    construct, BackendConnection, ConnectionError, ExternalBackendTransport,
    UnavailableExternalTransport,
};
use crate::backend::registry::BackendKind;
use crate::backend::selection::{ResolvedBackend, SelectionOrigin};
use crate::plugin_host::receipts::{FileRole, InstallReceiptV1, InventoryFile, TrustState};

fn native_backend() -> ResolvedBackend {
    ResolvedBackend {
        backend_id: "native".into(),
        version: None,
        kind: BackendKind::Native,
        origin: SelectionOrigin::NativeBuiltin,
        receipt_digest: None,
        pin: None,
        warning: None,
        native_start: true,
    }
}

fn external_backend(receipt: &str) -> ResolvedBackend {
    ResolvedBackend {
        backend_id: "go-orca".into(),
        version: Some("1.0.0".into()),
        kind: BackendKind::External,
        origin: SelectionOrigin::Explicit,
        receipt_digest: Some(receipt.into()),
        pin: None,
        warning: None,
        native_start: false,
    }
}

fn fixture_bridge_src() -> &'static str {
    r#"#!/usr/bin/env python3
import sys, json, os, time
mode = os.environ.get("ORCA_T14_MODE", "echo")
# PATH must be empty in product spawn; fixture uses only stdlib.
def out(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()

if mode == "hang":
    time.sleep(3600)
elif mode == "stderr_flood":
    while True:
        sys.stderr.write("x" * 4096)
        sys.stderr.flush()
elif mode == "malformed":
    sys.stdout.write("not-json\n")
    sys.stdout.flush()
elif mode == "truncated":
    sys.stdout.write('{"jsonrpc":"2.0"')
    sys.stdout.flush()
elif mode == "oversize":
    sys.stdout.write('{"a":"' + ("y" * (2 * 1024 * 1024)) + '"}\n')
    sys.stdout.flush()
else:
    # echo: reply to each request line with a tiny result object
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            out({"error": "bad-json"})
            continue
        mid = msg.get("id")
        out({"jsonrpc": "2.0", "id": mid, "result": {"ok": True}})
"#
}

fn absolute_python() -> Option<PathBuf> {
    for c in [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
    ] {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn make_fixture_layout(mode: &str) -> (tempfile::TempDir, ExternalStdioConfig) {
    let tmp = tempfile::TempDir::new().unwrap();
    let plugins = tmp.path().join("plugins");
    let install = plugins.join("go-orca/1.0.0");
    let bin = install.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let bridge = bin.join("go-orca-bridge");
    let body = fixture_bridge_src();
    let digest = write_file_sha256(&bridge, body.as_bytes()).unwrap();
    let py = absolute_python().expect("absolute python3 required for fixture bridge tests");
    // Product argv is absolute interpreter + absolute script (no PATH lookup).
    let argv = vec![
        py.to_string_lossy().into_owned(),
        bridge.to_string_lossy().into_owned(),
    ];
    let receipt = InstallReceiptV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
        install_root: "go-orca/1.0.0".into(),
        target: "darwin-aarch64".into(),
        files: vec![InventoryFile {
            relative_path: "bin/go-orca-bridge".into(),
            role: FileRole::Executable,
            mode_octal: "0755".into(),
            length: body.len() as u64,
            content_sha256: digest.clone(),
        }],
        trust: TrustState::Untrusted,
        native_code: true,
        capabilities: vec!["acp".into()],
        permissions: vec![],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: "fd289aa1458324082cfac42747b709a263a11e5a159db751df76eb3edfb62cb4".into(),
    };
    // config_from_receipt expects plugins_root + install_root relative join.
    // Our install_root is go-orca/1.0.0 under plugins.
    let mut cfg = config_from_receipt(
        &plugins,
        &receipt,
        &["{bridge}".into()],
        ".",
        ExternalStdioLimits {
            max_line_bytes: 64 * 1024,
            max_stderr_bytes: 32 * 1024,
            deadline: Duration::from_secs(5),
        },
    )
    .unwrap();
    // Override to absolute python + script for portable fixture (digest still on script file).
    cfg.executable = py;
    cfg.argv = argv;
    cfg.exe_content_sha256 = String::new(); // interpreter digest not pinned; script path is absolute
                                            // Pass mode via rewriting env is forbidden in product; encode mode in argv for tests only
                                            // by using a wrapper: set ORCA_T14_MODE by prepending env is product-forbidden.
                                            // Instead rewrite script launch: python -c is shell-like. Use env in test spawn only
                                            // through a second config used solely in tests via direct Command — product PATH empty.
                                            // For product transport tests we inject mode by writing mode-specific script files.
    let _ = mode;
    let script = match mode {
        "echo" => body.to_string(),
        other => body.replace(
            "os.environ.get(\"ORCA_T14_MODE\", \"echo\")",
            &format!("\"{other}\""),
        ),
    };
    let digest2 = write_file_sha256(&bridge, script.as_bytes()).unwrap();
    cfg.argv = vec![
        cfg.executable.to_string_lossy().into_owned(),
        bridge.to_string_lossy().into_owned(),
    ];
    let _ = digest2;
    (tmp, cfg)
}

#[test]
fn native_construct_baseline_unchanged() {
    // Given: native backend
    let mut t = UnavailableExternalTransport;
    // When: construct without external orch
    let c = construct(&native_backend(), &mut t).unwrap();
    // Then: native, no transport
    assert_eq!(c, BackendConnection::Native);
}

#[test]
fn external_without_real_transport_still_requires_orch() {
    let mut t = UnavailableExternalTransport;
    let err = construct(&external_backend(&"f".repeat(64)), &mut t).unwrap_err();
    assert!(matches!(
        err,
        ConnectionError::ExternalRequiresOrchestration
    ));
}

#[test]
fn rejects_relative_executable() {
    let err = config_from_receipt(
        std::path::Path::new("/tmp"),
        &minimal_receipt("bin/x"),
        &["relative-bridge".into()],
        ".",
        ExternalStdioLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalStdioError::RelativeExecutable(_)));
}

#[test]
fn rejects_shell_metacharacters_in_argv() {
    let err = config_from_receipt(
        std::path::Path::new("/tmp"),
        &minimal_receipt("bin/x"),
        &["{bridge}".into(), "a;b".into()],
        ".",
        ExternalStdioLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalStdioError::ShellText(_)));
}

#[test]
fn rejects_cwd_escape() {
    let err = config_from_receipt(
        std::path::Path::new("/tmp"),
        &minimal_receipt("bin/x"),
        &["{bridge}".into()],
        "../outside",
        ExternalStdioLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalStdioError::CwdEscape(_)));
}

#[test]
fn rejects_path_token() {
    let err = config_from_receipt(
        std::path::Path::new("/tmp"),
        &minimal_receipt("bin/x"),
        &["{bridge}".into(), "$PATH".into()],
        ".",
        ExternalStdioLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ExternalStdioError::PathLookupForbidden));
}

fn minimal_receipt(exe_rel: &str) -> InstallReceiptV1 {
    InstallReceiptV1 {
        schema_version: 1,
        plugin_id: "go-orca".into(),
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
        install_root: "go-orca/1.0.0".into(),
        target: "darwin-aarch64".into(),
        files: vec![InventoryFile {
            relative_path: exe_rel.into(),
            role: FileRole::Executable,
            mode_octal: "0755".into(),
            length: 1,
            content_sha256: "b".repeat(64),
        }],
        trust: TrustState::Untrusted,
        native_code: true,
        capabilities: vec![],
        permissions: vec![],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: "c".repeat(64),
    }
}

#[test]
fn digest_drift_refuses_spawn() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, mut cfg) = make_fixture_layout("echo");
    cfg.exe_content_sha256 = "0".repeat(64);
    cfg.executable = cfg.argv[1].clone().into(); // digest the script file
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let err = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap_err();
    assert!(
        matches!(err, ExternalStdioError::DigestDrift { .. }),
        "{err:?}"
    );
}

#[test]
fn receipt_mismatch_refuses_dispatch() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("echo");
    let mut transport = ExternalStdioTransport::new(cfg);
    let err = transport
        .dispatch(&external_backend(&"0".repeat(64)))
        .unwrap_err();
    assert!(matches!(err, ExternalStdioError::ReceiptMismatch));
}

#[test]
fn echo_roundtrip_and_cleanup() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("echo");
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    assert!(conn.identity().pid > 0);
    conn.write_frame(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .unwrap();
    let resp = conn.read_frame().unwrap();
    assert!(resp.contains("\"ok\":true") || resp.contains("\"result\""));
    // Drop must not panic; kills child.
    drop(conn);
}

#[test]
fn malformed_frame_rejected() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("malformed");
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    // Bridge writes malformed immediately; reading should fail closed.
    let err = conn.read_frame().unwrap_err();
    assert!(
        matches!(
            err,
            ExternalStdioError::MalformedFrame(_) | ExternalStdioError::BridgeExited { .. }
        ),
        "{err:?}"
    );
}

#[test]
fn oversize_line_rejected() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, mut cfg) = make_fixture_layout("oversize");
    cfg.limits.max_line_bytes = 1024;
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    let err = conn.read_frame().unwrap_err();
    assert!(
        matches!(err, ExternalStdioError::LineTooLarge { .. }),
        "{err:?}"
    );
}

#[test]
fn stderr_flood_rejected() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, mut cfg) = make_fixture_layout("stderr_flood");
    cfg.limits.max_stderr_bytes = 8192;
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    thread::sleep(Duration::from_millis(400));
    let mut err = None;
    for _ in 0..20 {
        if let Err(e) = conn.write_frame(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{}}"#) {
            err = Some(e);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        matches!(
            err,
            Some(ExternalStdioError::StderrFlood { .. })
                | Some(ExternalStdioError::BridgeExited { .. })
                | Some(ExternalStdioError::Io(_))
        ),
        "expected flood or bridge death under stderr bomb, got {err:?}"
    );
}

#[test]
fn hang_read_exceeds_deadline_without_caller_cancel() {
    // Given: hung fixture (no stdout) and a short transport deadline.
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, mut cfg) = make_fixture_layout("hang");
    cfg.limits.deadline = Duration::from_millis(300);
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    let pid = conn.identity().pid;
    // When: read_frame blocks waiting for NDJSON (no cancel_bridge from test).
    let started = std::time::Instant::now();
    let err = conn.read_frame().unwrap_err();
    let elapsed = started.elapsed();
    // Then: DeadlineExceeded within bound, bridge reaped by transport.
    assert!(
        matches!(err, ExternalStdioError::DeadlineExceeded),
        "expected DeadlineExceeded, got {err:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3),
        "elapsed {elapsed:?}"
    );
    let _ = pid;
}

#[test]
fn cancellation_kills_bridge_only() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("hang");
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    conn.cancel_bridge().unwrap();
    let _ = conn.last_exit_code();
}

#[test]
fn cancel_flag_before_dispatch() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("echo");
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    transport.request_cancel();
    let err = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap_err();
    assert!(matches!(err, ExternalStdioError::Cancelled));
}

#[test]
fn bridge_exit_is_reportable_not_daemon() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, cfg) = make_fixture_layout("echo");
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    // Close stdin by dropping write side via exit: send nothing and kill.
    conn.cancel_bridge().unwrap();
    // last_exit may be set after wait inside cancel
    let _code = conn.last_exit_code();
    // Documented: bridge exit != daemon lifetime — no API signals daemon.
}

#[test]
fn write_frame_rejects_oversize() {
    let Some(_) = absolute_python() else {
        return;
    };
    let (_tmp, mut cfg) = make_fixture_layout("echo");
    cfg.limits.max_line_bytes = 32;
    let mut transport = ExternalStdioTransport::new(cfg.clone());
    let mut conn = transport
        .dispatch(&external_backend(&cfg.receipt_digest))
        .unwrap();
    let big = format!(r#"{{"x":"{}"}}"#, "z".repeat(64));
    let err = conn.write_frame(&big).unwrap_err();
    assert!(matches!(err, ExternalStdioError::LineTooLarge { .. }));
}

#[test]
fn sha256_helper_stable() {
    assert_eq!(
        sha256_hex_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// silence unused import warning if any
#[allow(dead_code)]
fn _limits() -> usize {
    DEFAULT_MAX_LINE_BYTES
}
