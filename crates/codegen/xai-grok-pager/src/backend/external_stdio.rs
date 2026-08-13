//! Verified external ACP stdio transport (Task 14).
//!
//! Launches a receipt-bound absolute argv with a closed child environment,
//! bounded NDJSON line IO, deadline, cancellation, and deterministic cleanup.
//! Does not own Task-13 pin/barrier ordering — callers must only `dispatch`
//! after a sealed Open barrier. Bridge exit is reportable and never treated as
//! durable daemon lifetime.
//!
//! // allow: SIZE_OK — plan freezes external stdio transport in one module

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::connection::ExternalBackendTransport;
use crate::backend::selection::ResolvedBackend;
use crate::plugin_host::receipts::{FileRole, InstallReceiptV1};

/// Default max NDJSON line size (1 MiB) — tighter than acp-lib's 64 MiB for host bombs.
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;
/// Default cumulative stderr capture before flood reject.
pub const DEFAULT_MAX_STDERR_BYTES: usize = 256 * 1024;
/// Default launch/readiness deadline.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// Closed child environment keys (exact set; no ambient HOME/proxy/credentials).
const CHILD_ENV: &[(&str, &str)] = &[("LANG", "C"), ("LC_ALL", "C"), ("TZ", "UTC")];

/// IO / process bounds for an external bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalStdioLimits {
    pub max_line_bytes: usize,
    pub max_stderr_bytes: usize,
    pub deadline: Duration,
}

impl Default for ExternalStdioLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            deadline: DEFAULT_DEADLINE,
        }
    }
}

/// Receipt-bound launch configuration (all paths absolute after construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalStdioConfig {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub exe_content_sha256: String,
    pub receipt_digest: String,
    pub backend_id: String,
    pub limits: ExternalStdioLimits,
}

/// Stable identity of a live bridge process (not a durable daemon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProcessIdentity {
    pub pid: u32,
    pub executable: PathBuf,
    pub receipt_digest: String,
    pub backend_id: String,
}

#[derive(Debug, Error)]
pub enum ExternalStdioError {
    #[error("executable path must be absolute: {0}")]
    RelativeExecutable(String),
    #[error("cwd path must be absolute: {0}")]
    RelativeCwd(String),
    #[error("cwd escapes install root: {0}")]
    CwdEscape(String),
    #[error("shell metacharacters forbidden in argv: {0}")]
    ShellText(String),
    #[error("argv empty or missing executable")]
    EmptyArgv,
    #[error("PATH lookup forbidden for external bridge")]
    PathLookupForbidden,
    #[error("executable content digest mismatch: expected {expected}, got {actual}")]
    DigestDrift { expected: String, actual: String },
    #[error("receipt digest mismatch for selected backend")]
    ReceiptMismatch,
    #[error("backend is not external")]
    NotExternal,
    #[error("missing executable on disk: {0}")]
    MissingExecutable(String),
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("io: {0}")]
    Io(String),
    #[error("NDJSON line exceeds max {max} bytes")]
    LineTooLarge { max: usize },
    #[error("stderr flood exceeds max {max} bytes")]
    StderrFlood { max: usize },
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("cancelled")]
    Cancelled,
    #[error("bridge exited: code={code:?}")]
    BridgeExited { code: Option<i32> },
    #[error("malformed NDJSON frame: {0}")]
    MalformedFrame(String),
    #[error("truncated NDJSON stream")]
    TruncatedFrame,
}

impl From<io::Error> for ExternalStdioError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Build config from a sealed install receipt + absolute install tree.
///
/// `entrypoint_argv` uses `{bridge}` for the receipt executable path (first element
/// after resolve must be absolute). `cwd_rel` is relative to install root, or `"."`.
pub fn config_from_receipt(
    plugins_root: &Path,
    receipt: &InstallReceiptV1,
    entrypoint_argv: &[String],
    cwd_rel: &str,
    limits: ExternalStdioLimits,
) -> Result<ExternalStdioConfig, ExternalStdioError> {
    if entrypoint_argv.is_empty() {
        return Err(ExternalStdioError::EmptyArgv);
    }
    let install_abs = absolute_join(plugins_root, &receipt.install_root)?;
    let bridge_rel = receipt
        .files
        .iter()
        .find(|f| f.role == FileRole::Executable)
        .map(|f| f.relative_path.as_str())
        .ok_or_else(|| ExternalStdioError::MissingExecutable("no executable role".into()))?;
    let bridge_abs = absolute_join(&install_abs, bridge_rel)?;
    let exe_digest = receipt
        .files
        .iter()
        .find(|f| f.role == FileRole::Executable)
        .map(|f| f.content_sha256.clone())
        .unwrap_or_default();

    let mut argv = Vec::with_capacity(entrypoint_argv.len());
    for (i, tok) in entrypoint_argv.iter().enumerate() {
        if tok == "PATH"
            || tok.eq_ignore_ascii_case("$PATH")
            || tok.contains("$PATH")
            || tok.contains("${PATH}")
        {
            return Err(ExternalStdioError::PathLookupForbidden);
        }
        if has_shell_meta(tok) {
            return Err(ExternalStdioError::ShellText(tok.clone()));
        }
        if tok.contains('/') && i == 0 && tok != "{bridge}" && !Path::new(tok).is_absolute() {
            return Err(ExternalStdioError::RelativeExecutable(tok.clone()));
        }
        let resolved = match tok.as_str() {
            "{bridge}" => bridge_abs.to_string_lossy().into_owned(),
            other => other.to_string(),
        };
        if i == 0 && !Path::new(&resolved).is_absolute() {
            return Err(ExternalStdioError::RelativeExecutable(resolved));
        }
        argv.push(resolved);
    }

    if cwd_rel.contains("..") || cwd_rel.starts_with('/') || cwd_rel.starts_with('\\') {
        return Err(ExternalStdioError::CwdEscape(cwd_rel.into()));
    }
    let cwd = if cwd_rel.is_empty() || cwd_rel == "." {
        install_abs.clone()
    } else {
        absolute_join(&install_abs, cwd_rel)?
    };
    if !cwd.starts_with(&install_abs) {
        return Err(ExternalStdioError::CwdEscape(cwd.display().to_string()));
    }

    Ok(ExternalStdioConfig {
        executable: PathBuf::from(&argv[0]),
        argv,
        cwd,
        exe_content_sha256: exe_digest,
        receipt_digest: receipt.receipt_digest.clone(),
        backend_id: receipt.plugin_id.clone(),
        limits,
    })
}

/// Transport holding a pre-validated launch config.
#[derive(Debug, Clone)]
pub struct ExternalStdioTransport {
    pub config: ExternalStdioConfig,
    /// When set, cancel in-flight reads/writes and kill the child.
    pub cancel: Arc<AtomicBool>,
}

impl ExternalStdioTransport {
    pub fn new(config: ExternalStdioConfig) -> Self {
        Self {
            config,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

impl ExternalBackendTransport for ExternalStdioTransport {
    type Connection = ExternalStdioConnection;
    type Error = ExternalStdioError;

    fn dispatch(&mut self, backend: &ResolvedBackend) -> Result<Self::Connection, Self::Error> {
        if backend.kind != crate::backend::registry::BackendKind::External {
            return Err(ExternalStdioError::NotExternal);
        }
        match backend.receipt_digest.as_deref() {
            Some(d) if d == self.config.receipt_digest => {}
            _ => return Err(ExternalStdioError::ReceiptMismatch),
        }
        if backend.backend_id != self.config.backend_id {
            return Err(ExternalStdioError::ReceiptMismatch);
        }
        spawn_bridge(&self.config, Arc::clone(&self.cancel))
    }
}

/// Live external bridge with bounded NDJSON IO and Drop cleanup.
pub struct ExternalStdioConnection {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    stdout_rx: Receiver<StdoutEvent>,
    stderr_rx: Receiver<StderrEvent>,
    _stdout_thread: JoinHandle<()>,
    _stderr_thread: JoinHandle<()>,
    identity: BridgeProcessIdentity,
    limits: ExternalStdioLimits,
    cancel: Arc<AtomicBool>,
    stderr_total: Arc<Mutex<usize>>,
    /// True once wait() collected the exit — Drop will not kill again.
    reaped: bool,
    last_exit_code: Option<i32>,
}

enum StdoutEvent {
    Line(Vec<u8>),
    LineTooLarge { max: usize },
    Io(String),
    Eof,
}

impl std::fmt::Debug for ExternalStdioConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalStdioConnection")
            .field("identity", &self.identity)
            .field("reaped", &self.reaped)
            .field("last_exit_code", &self.last_exit_code)
            .finish_non_exhaustive()
    }
}

enum StderrEvent {
    Chunk,
    Flood,
    Done,
}

impl ExternalStdioConnection {
    pub fn identity(&self) -> &BridgeProcessIdentity {
        &self.identity
    }

    pub fn last_exit_code(&self) -> Option<i32> {
        self.last_exit_code
    }

    /// Write one NDJSON line (appends `\n` if missing).
    ///
    /// Blocks at most `limits.deadline` (including flush). On expiry kills/reaps
    /// only this bridge child and returns [`ExternalStdioError::DeadlineExceeded`].
    pub fn write_frame(&mut self, frame: &str) -> Result<(), ExternalStdioError> {
        self.check_cancel()?;
        self.drain_stderr_events()?;
        let mut line = frame.as_bytes().to_vec();
        if !line.ends_with(b"\n") {
            line.push(b'\n');
        }
        if line.len() > self.limits.max_line_bytes {
            return Err(ExternalStdioError::LineTooLarge {
                max: self.limits.max_line_bytes,
            });
        }

        let deadline = Instant::now() + self.limits.deadline;
        let stdin = Arc::clone(&self.stdin);
        let (tx, rx) = mpsc::channel();
        let writer = thread::Builder::new()
            .name("ext-stdio-write".into())
            .spawn(move || {
                let mut guard = match stdin.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let res = guard
                    .write_all(&line)
                    .and_then(|_| guard.flush())
                    .map_err(|e| e.to_string());
                let _ = tx.send(res);
            })
            .map_err(|e| ExternalStdioError::Spawn(e.to_string()))?;

        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Ok(())) => {
                let _ = writer.join();
                Ok(())
            }
            Ok(Err(msg)) => {
                let _ = writer.join();
                if self.child_exited() {
                    Err(ExternalStdioError::BridgeExited {
                        code: self.try_exit_code(),
                    })
                } else {
                    Err(ExternalStdioError::Io(msg))
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.kill_bridge_only();
                let _ = writer.join();
                Err(ExternalStdioError::DeadlineExceeded)
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = writer.join();
                if self.child_exited() {
                    Err(ExternalStdioError::BridgeExited {
                        code: self.try_exit_code(),
                    })
                } else {
                    Err(ExternalStdioError::Io("write worker disconnected".into()))
                }
            }
        }
    }

    /// Read one NDJSON line (without trailing newline).
    ///
    /// Blocks at most `limits.deadline`. On expiry kills/reaps only this bridge
    /// child and returns [`ExternalStdioError::DeadlineExceeded`].
    pub fn read_frame(&mut self) -> Result<String, ExternalStdioError> {
        let deadline = Instant::now() + self.limits.deadline;
        loop {
            self.check_cancel()?;
            self.drain_stderr_events()?;
            let now = Instant::now();
            if now >= deadline {
                return self.fail_deadline();
            }
            let wait = deadline.saturating_duration_since(now);
            match self.stdout_rx.recv_timeout(wait) {
                Ok(StdoutEvent::Line(mut buf)) => {
                    if buf.ends_with(b"\n") {
                        buf.pop();
                        if buf.ends_with(b"\r") {
                            buf.pop();
                        }
                    }
                    let s = String::from_utf8(buf)
                        .map_err(|e| ExternalStdioError::MalformedFrame(e.to_string()))?;
                    if s.trim().is_empty() {
                        continue;
                    }
                    let v: serde_json::Value = serde_json::from_str(&s)
                        .map_err(|e| ExternalStdioError::MalformedFrame(e.to_string()))?;
                    if !v.is_object() {
                        return Err(ExternalStdioError::MalformedFrame(
                            "frame root must be object".into(),
                        ));
                    }
                    return Ok(s);
                }
                Ok(StdoutEvent::LineTooLarge { max }) => {
                    let _ = self.kill_bridge_only();
                    return Err(ExternalStdioError::LineTooLarge { max });
                }
                Ok(StdoutEvent::Io(msg)) => {
                    if self.child_exited() {
                        return Err(ExternalStdioError::BridgeExited {
                            code: self.try_exit_code(),
                        });
                    }
                    return Err(ExternalStdioError::Io(msg));
                }
                Ok(StdoutEvent::Eof) => {
                    if self.child_exited() {
                        return Err(ExternalStdioError::BridgeExited {
                            code: self.try_exit_code(),
                        });
                    }
                    return Err(ExternalStdioError::TruncatedFrame);
                }
                Err(RecvTimeoutError::Timeout) => {
                    return self.fail_deadline();
                }
                Err(RecvTimeoutError::Disconnected) => {
                    if self.child_exited() {
                        return Err(ExternalStdioError::BridgeExited {
                            code: self.try_exit_code(),
                        });
                    }
                    return Err(ExternalStdioError::TruncatedFrame);
                }
            }
        }
    }

    fn fail_deadline(&mut self) -> Result<String, ExternalStdioError> {
        let _ = self.kill_bridge_only();
        Err(ExternalStdioError::DeadlineExceeded)
    }

    fn kill_bridge_only(&mut self) -> Result<(), ExternalStdioError> {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        Ok(())
    }

    /// Wait for child exit without treating it as daemon death — returns code.
    pub fn wait_bridge_exit(&mut self) -> Result<Option<i32>, ExternalStdioError> {
        let status = self
            .child
            .wait()
            .map_err(|e| ExternalStdioError::Io(e.to_string()))?;
        self.reaped = true;
        let code = status.code();
        self.last_exit_code = code;
        Ok(code)
    }

    /// Explicit cancel: set flag and kill the bridge process only.
    pub fn cancel_bridge(&mut self) -> Result<(), ExternalStdioError> {
        self.cancel.store(true, Ordering::SeqCst);
        self.kill_bridge_only()
    }

    fn check_cancel(&self) -> Result<(), ExternalStdioError> {
        if self.cancel.load(Ordering::SeqCst) {
            Err(ExternalStdioError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn drain_stderr_events(&self) -> Result<(), ExternalStdioError> {
        loop {
            match self.stderr_rx.try_recv() {
                Ok(StderrEvent::Flood) => {
                    return Err(ExternalStdioError::StderrFlood {
                        max: self.limits.max_stderr_bytes,
                    });
                }
                Ok(StderrEvent::Chunk) | Ok(StderrEvent::Done) => {}
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if let Ok(n) = self.stderr_total.lock() {
            if *n > self.limits.max_stderr_bytes {
                return Err(ExternalStdioError::StderrFlood {
                    max: self.limits.max_stderr_bytes,
                });
            }
        }
        Ok(())
    }

    fn child_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    fn try_exit_code(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(st)) => {
                self.reaped = true;
                let c = st.code();
                self.last_exit_code = c;
                c
            }
            _ => self.last_exit_code,
        }
    }
}

impl Drop for ExternalStdioConnection {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

fn spawn_bridge(
    config: &ExternalStdioConfig,
    cancel: Arc<AtomicBool>,
) -> Result<ExternalStdioConnection, ExternalStdioError> {
    if cancel.load(Ordering::SeqCst) {
        return Err(ExternalStdioError::Cancelled);
    }
    if !config.executable.is_absolute() {
        return Err(ExternalStdioError::RelativeExecutable(
            config.executable.display().to_string(),
        ));
    }
    if !config.cwd.is_absolute() {
        return Err(ExternalStdioError::RelativeCwd(
            config.cwd.display().to_string(),
        ));
    }
    if !config.executable.is_file() {
        return Err(ExternalStdioError::MissingExecutable(
            config.executable.display().to_string(),
        ));
    }
    // Digest check before spawn.
    if !config.exe_content_sha256.is_empty() {
        let actual = file_sha256_hex(&config.executable)?;
        if !actual.eq_ignore_ascii_case(&config.exe_content_sha256) {
            return Err(ExternalStdioError::DigestDrift {
                expected: config.exe_content_sha256.clone(),
                actual,
            });
        }
    }

    let mut cmd = Command::new(&config.executable);
    // argv[0] is executable; pass remaining as args.
    if config.argv.len() > 1 {
        cmd.args(&config.argv[1..]);
    }
    cmd.current_dir(&config.cwd);
    cmd.env_clear();
    for (k, v) in CHILD_ENV {
        cmd.env(k, v);
    }
    // Empty PATH — no lookup of ambient tools.
    cmd.env("PATH", "");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| ExternalStdioError::Spawn(e.to_string()))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ExternalStdioError::Spawn("stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExternalStdioError::Spawn("stdout".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExternalStdioError::Spawn("stderr".into()))?;

    let pid = child.id();
    let stderr_total = Arc::new(Mutex::new(0usize));
    let (err_tx, err_rx) = mpsc::channel();
    let max_err = config.limits.max_stderr_bytes;
    let total_c = Arc::clone(&stderr_total);
    let stderr_thread = thread::Builder::new()
        .name("ext-stdio-stderr".into())
        .spawn(move || pump_stderr(stderr, max_err, total_c, err_tx))
        .map_err(|e| ExternalStdioError::Spawn(e.to_string()))?;

    let (out_tx, out_rx) = mpsc::channel();
    let max_line = config.limits.max_line_bytes;
    let stdout_thread = thread::Builder::new()
        .name("ext-stdio-stdout".into())
        .spawn(move || pump_stdout(stdout, max_line, out_tx))
        .map_err(|e| ExternalStdioError::Spawn(e.to_string()))?;

    Ok(ExternalStdioConnection {
        child,
        stdin: Arc::new(Mutex::new(stdin)),
        stdout_rx: out_rx,
        stderr_rx: err_rx,
        _stdout_thread: stdout_thread,
        _stderr_thread: stderr_thread,
        identity: BridgeProcessIdentity {
            pid,
            executable: config.executable.clone(),
            receipt_digest: config.receipt_digest.clone(),
            backend_id: config.backend_id.clone(),
        },
        limits: config.limits.clone(),
        cancel,
        stderr_total,
        reaped: false,
        last_exit_code: None,
    })
}

fn pump_stdout(stdout: ChildStdout, max_line: usize, tx: Sender<StdoutEvent>) {
    let mut reader = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match read_line_capped(&mut reader, max_line, &mut buf) {
            Ok(0) => {
                let _ = tx.send(StdoutEvent::Eof);
                break;
            }
            Ok(_) => {
                if tx
                    .send(StdoutEvent::Line(std::mem::take(&mut buf)))
                    .is_err()
                {
                    break;
                }
            }
            Err(ExternalStdioError::LineTooLarge { max }) => {
                let _ = tx.send(StdoutEvent::LineTooLarge { max });
                break;
            }
            Err(e) => {
                let _ = tx.send(StdoutEvent::Io(e.to_string()));
                break;
            }
        }
    }
}

fn pump_stderr(
    mut stderr: ChildStderr,
    max: usize,
    total: Arc<Mutex<usize>>,
    tx: Sender<StderrEvent>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match stderr.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send(StderrEvent::Done);
                break;
            }
            Ok(n) => {
                let flooded = {
                    let mut t = total.lock().unwrap_or_else(|e| e.into_inner());
                    *t = t.saturating_add(n);
                    *t > max
                };
                if flooded {
                    let _ = tx.send(StderrEvent::Flood);
                    break;
                }
                let _ = tx.send(StderrEvent::Chunk);
            }
            Err(_) => {
                let _ = tx.send(StderrEvent::Done);
                break;
            }
        }
    }
}

fn read_line_capped<R: BufRead>(
    reader: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> Result<usize, ExternalStdioError> {
    buf.clear();
    loop {
        let mut chunk = [0u8; 1];
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(buf.len());
        }
        buf.push(chunk[0]);
        if buf.len() > max {
            return Err(ExternalStdioError::LineTooLarge { max });
        }
        if chunk[0] == b'\n' {
            return Ok(buf.len());
        }
    }
}

fn absolute_join(root: &Path, rel: &str) -> Result<PathBuf, ExternalStdioError> {
    if !root.is_absolute() {
        return Err(ExternalStdioError::RelativeCwd(root.display().to_string()));
    }
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    if Path::new(rel).is_absolute() {
        return Err(ExternalStdioError::CwdEscape(rel.into()));
    }
    if rel.split(['/', '\\']).any(|p| p == "..") {
        return Err(ExternalStdioError::CwdEscape(rel.into()));
    }
    Ok(root.join(rel))
}

fn has_shell_meta(s: &str) -> bool {
    if s == "{bridge}" {
        return false;
    }
    s.bytes().any(|b| {
        matches!(
            b,
            b'|' | b'&'
                | b';'
                | b'<'
                | b'>'
                | b'`'
                | b'$'
                | b'\n'
                | b'\r'
                | b'('
                | b')'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'!'
                | b'#'
        )
    })
}

fn file_sha256_hex(path: &Path) -> Result<String, ExternalStdioError> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Hex sha256 of bytes (tests / callers).
pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Write bytes to `path` and return content sha256 hex.
pub fn write_file_sha256(path: &Path, bytes: &[u8]) -> Result<String, ExternalStdioError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(sha256_hex_bytes(bytes))
}

#[cfg(test)]
#[path = "external_stdio_test.rs"]
mod external_stdio_test;
