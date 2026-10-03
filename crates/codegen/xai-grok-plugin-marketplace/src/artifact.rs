// allow: SIZE_OK — plan Task 17 owns R5 acquisition/preflight/stage/verify in one module
//! Bounded native-backend artifact acquisition, R5 expansion, and target verification.
//!
//! Stages a verified tree under an absent staging root. **Never promotes** (Task 18).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use xai_grok_agent::plugins::agent_backend::{
    BackendTarget, EntrypointSpec, HostPlatform, host_platform_label, normalize_arch, normalize_os,
    target_matches_host,
};

/// R5 format id shared with host update (Task 16).
pub const ARCHIVE_FORMAT_ID: &str = "tar-gzip-rfc1952-ustar-v1";
/// Detached Ed25519 signature algorithm id.
pub const SIG_ALG_ED25519: &str = "ed25519-detached-v1";

// Workspace `tar` edge is required by the Task 17 crate contract; R5 parsing is
// hand-rolled (USTAR-only). Keep the crate linked so --locked graphs stay stable.
const _TAR_CRATE_LINK: fn() -> tar::Header = tar::Header::new_ustar;

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_PATH_LEN: usize = 512;
const MAX_PATH_DEPTH: usize = 32;
const MAX_REDIRECTS_DEFAULT: u32 = 3;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Compression bomb: expanded/compressed ratio ceiling (when compressed ≥ 1 KiB).
const MAX_COMPRESSION_RATIO: u64 = 200;

/// Errors from bounded acquisition / expansion / verification.
#[derive(Debug, Error)]
pub enum AcquireError {
    #[error("egress not authorized")]
    EgressDenied,
    #[error("URL scheme not https: {0}")]
    SchemeDenied(String),
    #[error("host not on egress allowlist: {0}")]
    HostDenied(String),
    #[error("redirect not approved: {0}")]
    RedirectDenied(String),
    #[error("download exceeded size limit")]
    DownloadTooLarge,
    #[error("download timeout")]
    Timeout,
    #[error("digest mismatch: want {want}, got {got}")]
    DigestMismatch { want: String, got: String },
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("EXTERNAL_REQUIRED(signing-key)")]
    ExternalRequiredSigningKey,
    #[error("bad archive: {0}")]
    BadArchive(String),
    #[error("target mismatch: want {want}, got {got}")]
    TargetMismatch { want: String, got: String },
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("file role drift: {0}")]
    RoleDrift(String),
    #[error("entrypoint invalid: {0}")]
    EntrypointInvalid(String),
    #[error("staging root must be absent: {0}")]
    StagingExists(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("cancelled")]
    Cancelled,
}

/// Explicit host egress grant required before any network fetch.
#[derive(Debug, Clone)]
pub struct EgressGrant {
    /// When false, all network acquisition is refused.
    pub authorized: bool,
    /// Exact HTTPS hostnames permitted (lowercase). Empty + authorized still denies.
    pub allowed_hosts: Vec<String>,
    pub max_redirects: u32,
    pub timeout: Duration,
    pub max_download_bytes: u64,
}

impl Default for EgressGrant {
    fn default() -> Self {
        Self {
            authorized: false,
            allowed_hosts: Vec::new(),
            max_redirects: MAX_REDIRECTS_DEFAULT,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_download_bytes: MAX_ARCHIVE_BYTES,
        }
    }
}

impl EgressGrant {
    /// Test/fixture grant for a single host.
    pub fn allow_host(host: &str) -> Self {
        Self {
            authorized: true,
            allowed_hosts: vec![host.to_ascii_lowercase()],
            max_redirects: MAX_REDIRECTS_DEFAULT,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_download_bytes: MAX_ARCHIVE_BYTES,
        }
    }
}

/// Trusted Ed25519 public keys for detached archive signatures (key_id → 32-byte pk).
#[derive(Debug, Clone, Default)]
pub struct SignatureTrust {
    pub keys: Vec<(String, [u8; 32])>,
    /// When true, missing/invalid signature fails closed. When false, signature is optional.
    pub require_signature: bool,
}

/// Request to acquire and stage one exact backend target.
#[derive(Debug, Clone)]
pub struct AcquisitionRequest {
    pub plugin_id: String,
    pub version: String,
    pub target: BackendTarget,
    /// Optional pre-resolved archive bytes (local/fixture path). When set, URL is not fetched.
    pub local_archive: Option<PathBuf>,
    /// Optional detached signature bytes path (`.sig`).
    pub local_signature: Option<PathBuf>,
}

/// One verified file under the staging root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFile {
    pub relative_path: String,
    pub role: StagedFileRole,
    pub mode_octal: String,
    pub length: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StagedFileRole {
    Executable,
    Library,
    Manifest,
    Config,
    Notice,
    Other,
}

/// Result of successful acquisition + expansion + verification. Not installed.
#[derive(Debug, Clone)]
pub struct StagedArtifact {
    pub staging_root: PathBuf,
    pub archive_sha256: String,
    pub archive_format: String,
    pub plugin_id: String,
    pub version: String,
    pub target_label: String,
    pub files: Vec<StagedFile>,
    pub bridge_rel: String,
    pub daemon_rel: String,
    pub bridge_abs: PathBuf,
    pub daemon_abs: PathBuf,
    /// Absolute path of entrypoint argv[0] after `{bridge}` resolution.
    pub entrypoint_abs: PathBuf,
    pub signature_key_id: Option<String>,
}

/// In-archive manifest (must not embed archiveSha256 — chicken-egg).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactManifestV1 {
    pub schema_version: u32,
    pub product: String,
    pub plugin_id: String,
    pub version: String,
    pub target: String,
    pub entries: Vec<ArtifactManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactManifestEntry {
    pub relative_path: String,
    pub mode_octal: String,
    pub length: u64,
    pub content_sha256: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Clone)]
struct TarEntry {
    path: String,
    data: Vec<u8>,
    mode: u32,
    is_dir: bool,
}

/// Acquire from local archive bytes/path or HTTPS URL under egress grant.
/// On any failure after creating staging, the staging tree is removed.
pub fn acquire_and_stage(
    req: &AcquisitionRequest,
    egress: &EgressGrant,
    trust: &SignatureTrust,
    staging_root: &Path,
) -> Result<StagedArtifact, AcquireError> {
    if staging_root.exists() {
        return Err(AcquireError::StagingExists(
            staging_root.display().to_string(),
        ));
    }

    let (archive_bytes, source_hint) = load_archive_bytes(req, egress)?;
    if archive_bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(AcquireError::DownloadTooLarge);
    }
    let archive_sha256 = sha256_hex(&archive_bytes);
    if !eq_hex(&archive_sha256, &req.target.artifact.sha256) {
        return Err(AcquireError::DigestMismatch {
            want: req.target.artifact.sha256.clone(),
            got: archive_sha256,
        });
    }

    let sig_key_id = verify_signature(&archive_bytes, req, trust, source_hint.as_deref())?;

    let result = (|| {
        let entries = extract_ustar_gz(&archive_bytes)?;
        let manifest = parse_manifest(&entries)?;
        verify_manifest_identity(&manifest, req)?;
        verify_entries_match_manifest(&entries, &manifest)?;
        check_case_and_duplicate(&entries)?;

        // Materialize into absent staging root (descriptor-relative, no links).
        fs::create_dir_all(staging_root)?;
        write_entries_to_staging(staging_root, &entries)?;

        let files = build_staged_inventory(&entries, &manifest, req)?;
        verify_executable_roles(&files, req)?;
        let (bridge_abs, daemon_abs, entrypoint_abs) =
            verify_entrypoint_and_abs_paths(staging_root, req)?;

        Ok(StagedArtifact {
            staging_root: staging_root.to_path_buf(),
            archive_sha256,
            archive_format: ARCHIVE_FORMAT_ID.into(),
            plugin_id: req.plugin_id.clone(),
            version: req.version.clone(),
            target_label: manifest.target,
            files,
            bridge_rel: req.target.files.bridge.clone(),
            daemon_rel: req.target.files.daemon.clone(),
            bridge_abs,
            daemon_abs,
            entrypoint_abs,
            signature_key_id: sig_key_id,
        })
    })();

    match result {
        Ok(staged) => Ok(staged),
        Err(e) => {
            // Partial staging never becomes installed — wipe attempt tree.
            if staging_root.exists() {
                let _ = fs::remove_dir_all(staging_root);
            }
            Err(e)
        }
    }
}

/// Select exactly one target for the host platform from a backend target list.
pub fn select_exact_target<'a>(
    targets: &'a [BackendTarget],
    host: &HostPlatform,
) -> Result<&'a BackendTarget, AcquireError> {
    let matches: Vec<_> = targets
        .iter()
        .filter(|t| {
            let tplat = HostPlatform {
                os: normalize_os(&t.os),
                arch: normalize_arch(&t.arch),
                libc: t.libc.clone(),
            };
            target_matches_host(host, &tplat)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(AcquireError::TargetMismatch {
            want: host_platform_label(host),
            got: "none".into(),
        }),
        _ => Err(AcquireError::TargetMismatch {
            want: host_platform_label(host),
            got: format!("{} matches", matches.len()),
        }),
    }
}

/// Build target label `os-arch` or `os-arch-libc`.
pub fn target_label_of(t: &BackendTarget) -> String {
    let os = normalize_os(&t.os);
    let arch = normalize_arch(&t.arch);
    match &t.libc {
        Some(l) if !l.is_empty() => format!("{os}-{arch}-{l}"),
        _ => format!("{os}-{arch}"),
    }
}

fn load_archive_bytes(
    req: &AcquisitionRequest,
    egress: &EgressGrant,
) -> Result<(Vec<u8>, Option<String>), AcquireError> {
    if let Some(path) = &req.local_archive {
        let bytes = fs::read(path)?;
        return Ok((bytes, Some(path.display().to_string())));
    }
    let url = req.target.artifact.url.as_str();
    let bytes = fetch_https_bounded(url, egress)?;
    Ok((bytes, Some(url.to_string())))
}

/// Bounded HTTPS GET with allowlisted hosts and approved redirects only.
pub fn fetch_https_bounded(url: &str, egress: &EgressGrant) -> Result<Vec<u8>, AcquireError> {
    if !egress.authorized {
        return Err(AcquireError::EgressDenied);
    }
    if egress.allowed_hosts.is_empty() {
        return Err(AcquireError::EgressDenied);
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(egress.timeout)
        .https_only(true)
        .no_proxy()
        .build()
        .map_err(|e| AcquireError::Http(e.to_string()))?;

    let mut current = url.to_string();
    let mut redirects = 0u32;
    loop {
        let parsed = parse_https_url(&current)?;
        let host = parsed.host.clone();
        if !host_allowed(&host, &egress.allowed_hosts) {
            return Err(AcquireError::HostDenied(host));
        }

        let resp = client
            .get(&current)
            .send()
            .map_err(|e| classify_reqwest(e))?;

        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AcquireError::RedirectDenied("missing Location".into()))?
                .to_string();
            redirects += 1;
            if redirects > egress.max_redirects {
                return Err(AcquireError::RedirectDenied("too many redirects".into()));
            }
            let next = resolve_redirect(&current, &loc)?;
            // Re-validate scheme/host on every hop.
            let next_parsed = parse_https_url(&next)?;
            if !host_allowed(&next_parsed.host, &egress.allowed_hosts) {
                return Err(AcquireError::RedirectDenied(format!(
                    "host {}",
                    next_parsed.host
                )));
            }
            current = next;
            continue;
        }

        if !status.is_success() {
            return Err(AcquireError::Http(format!("status {status}")));
        }

        // Bound body read.
        let mut body = Vec::new();
        let mut reader = resp;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| AcquireError::Http(e.to_string()))?;
            if n == 0 {
                break;
            }
            if (body.len() + n) as u64 > egress.max_download_bytes {
                return Err(AcquireError::DownloadTooLarge);
            }
            body.extend_from_slice(&buf[..n]);
        }
        return Ok(body);
    }
}

struct ParsedHttps {
    host: String,
}

fn parse_https_url(url: &str) -> Result<ParsedHttps, AcquireError> {
    let url = url.trim();
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| AcquireError::SchemeDenied(scheme_of(url)))?;
    if rest.starts_with('/') {
        return Err(AcquireError::HostDenied(String::new()));
    }
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.split('@').next_back().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() || host.contains("..") {
        return Err(AcquireError::HostDenied(host.to_string()));
    }
    // Block literal IPv4/IPv6 and localhost-style names unless explicitly listed
    // (allowlist still required; this only normalizes host string).
    Ok(ParsedHttps {
        host: host.to_ascii_lowercase(),
    })
}

fn scheme_of(url: &str) -> String {
    match url.split_once("://") {
        Some((s, _)) => s.to_string(),
        None => "none".into(),
    }
}

fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    allowed.iter().any(|a| a == &h)
}

fn resolve_redirect(base: &str, loc: &str) -> Result<String, AcquireError> {
    let loc = loc.trim();
    if loc.starts_with("https://") {
        return Ok(loc.to_string());
    }
    if loc.starts_with("http://") {
        return Err(AcquireError::RedirectDenied("http downgrade".into()));
    }
    if loc.starts_with("//") {
        return Ok(format!("https:{}", loc));
    }
    // Relative redirect — resolve against base HTTPS URL path.
    let base = base
        .strip_prefix("https://")
        .ok_or_else(|| AcquireError::RedirectDenied("base not https".into()))?;
    let (host_part, path_part) = match base.find('/') {
        Some(i) => (&base[..i], &base[i..]),
        None => (base, "/"),
    };
    if loc.starts_with('/') {
        return Ok(format!("https://{host_part}{loc}"));
    }
    let dir = match path_part.rfind('/') {
        Some(i) => &path_part[..=i],
        None => "/",
    };
    Ok(format!("https://{host_part}{dir}{loc}"))
}

fn classify_reqwest(e: reqwest::Error) -> AcquireError {
    if e.is_timeout() {
        AcquireError::Timeout
    } else {
        AcquireError::Http(e.to_string())
    }
}

fn verify_signature(
    archive_bytes: &[u8],
    req: &AcquisitionRequest,
    trust: &SignatureTrust,
    _source_hint: Option<&str>,
) -> Result<Option<String>, AcquireError> {
    let sig_bytes = if let Some(p) = &req.local_signature {
        if p.is_file() {
            Some(fs::read(p)?)
        } else {
            None
        }
    } else {
        None
    };

    match (sig_bytes, trust.require_signature, trust.keys.is_empty()) {
        (None, true, _) => Err(AcquireError::BadSignature("missing .sig".into())),
        (None, false, _) => Ok(None),
        (Some(_), _, true) if trust.require_signature => {
            Err(AcquireError::ExternalRequiredSigningKey)
        }
        (Some(_), false, true) => Ok(None),
        (Some(sig), _, _) => {
            if sig.len() != 64 {
                return Err(AcquireError::BadSignature(
                    "signature must be 64 bytes".into(),
                ));
            }
            for (kid, pk) in &trust.keys {
                if verify_ed25519(archive_bytes, &sig, pk) {
                    return Ok(Some(kid.clone()));
                }
            }
            Err(AcquireError::BadSignature(
                "detached Ed25519 signature mismatch".into(),
            ))
        }
    }
}

fn verify_ed25519(msg: &[u8], sig: &[u8], pk: &[u8; 32]) -> bool {
    use ring::signature::{self, UnparsedPublicKey};
    let key = UnparsedPublicKey::new(&signature::ED25519, pk);
    key.verify(msg, sig).is_ok()
}

// --- R5 ustar + gzip level 9 ---

fn extract_ustar_gz(archive: &[u8]) -> Result<Vec<TarEntry>, AcquireError> {
    let tar = gunzip_r5(archive)?;
    if !tar.is_empty() && (archive.len() as u64) >= 1024 {
        let ratio = (tar.len() as u64) / (archive.len() as u64).max(1);
        if ratio > MAX_COMPRESSION_RATIO {
            return Err(AcquireError::BadArchive(format!(
                "compression ratio {ratio} exceeds {MAX_COMPRESSION_RATIO}"
            )));
        }
    }
    if tar.len() as u64 > MAX_EXPANDED_BYTES {
        return Err(AcquireError::BadArchive("expanded tar too large".into()));
    }
    parse_ustar(&tar)
}

/// Accept R5 single-member gzip (level-9 deflate or stored), FLG=0 MTIME=0 OS=255.
fn gunzip_r5(gz: &[u8]) -> Result<Vec<u8>, AcquireError> {
    if gz.len() < 18 {
        return Err(AcquireError::BadArchive("gzip too short".into()));
    }
    if gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8 {
        return Err(AcquireError::BadArchive("not gzip/deflate".into()));
    }
    let flg = gz[3];
    if flg != 0 {
        return Err(AcquireError::BadArchive(format!("gzip FLG={flg} want 0")));
    }
    if gz[4..8] != [0, 0, 0, 0] {
        return Err(AcquireError::BadArchive("gzip MTIME must be 0".into()));
    }
    let xfl = gz[8];
    if xfl != 2 && xfl != 0 && xfl != 4 {
        return Err(AcquireError::BadArchive(format!(
            "gzip XFL={xfl} unsupported"
        )));
    }
    if gz[9] != 255 {
        return Err(AcquireError::BadArchive(format!(
            "gzip OS={} want 255",
            gz[9]
        )));
    }

    use flate2::read::GzDecoder;
    let mut out = Vec::new();
    {
        let mut dec = GzDecoder::new(gz);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = dec
                .read(&mut buf)
                .map_err(|e| AcquireError::BadArchive(format!("gzip inflate: {e}")))?;
            if n == 0 {
                break;
            }
            if (out.len() + n) as u64 > MAX_EXPANDED_BYTES {
                return Err(AcquireError::BadArchive("expanded too large".into()));
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    // Single-member R5: last 8 bytes must be this member's CRC32+ISIZE. Trailing
    // junk or a second member shifts the trailer and fails closed.
    let trailer = &gz[gz.len() - 8..];
    let crc_stored = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if isize as u64 != (out.len() as u64 & 0xffff_ffff) {
        return Err(AcquireError::BadArchive("trailing bytes after gzip".into()));
    }
    let mut crc = flate2::Crc::new();
    crc.update(&out);
    if crc.sum() != crc_stored {
        return Err(AcquireError::BadArchive("gzip CRC mismatch".into()));
    }
    Ok(out)
}

fn parse_ustar(tar: &[u8]) -> Result<Vec<TarEntry>, AcquireError> {
    if tar.len() < 1024 {
        return Err(AcquireError::BadArchive("tar too short".into()));
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut expanded: u64 = 0;
    let mut saw_header = false;
    while i + 512 <= tar.len() {
        let hdr = &tar[i..i + 512];
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        saw_header = true;
        let name = cstr(&hdr[0..100]);
        let size = parse_octal(&hdr[124..136])?;
        let typeflag = hdr[156];
        if matches!(typeflag, b'1' | b'2' | b'3' | b'4' | b'6') {
            return Err(AcquireError::BadArchive(format!(
                "forbidden typeflag {}",
                typeflag as char
            )));
        }
        let magic = &hdr[257..262];
        if magic != b"ustar" {
            return Err(AcquireError::BadArchive("not ustar".into()));
        }
        // Reject GNU/PAX long-name and extended headers.
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
            return Err(AcquireError::BadArchive(format!(
                "pax/gnu typeflag {}",
                typeflag as char
            )));
        }
        i += 512;
        let data_end = i.saturating_add(size as usize);
        if data_end > tar.len() || data_end < i {
            return Err(AcquireError::BadArchive("tar entry OOB".into()));
        }
        let data = tar[i..data_end].to_vec();
        let pad = (512 - (size as usize % 512)) % 512;
        i = data_end + pad;

        if typeflag == b'5' {
            validate_rel_path(&name, true)?;
            continue;
        }
        if typeflag != b'0' && typeflag != 0 {
            return Err(AcquireError::BadArchive(format!(
                "unsupported typeflag {}",
                typeflag as char
            )));
        }
        validate_rel_path(&name, false)?;
        if out.len() >= MAX_ENTRIES {
            return Err(AcquireError::BadArchive("too many entries".into()));
        }
        if size > MAX_FILE_BYTES {
            return Err(AcquireError::BadArchive("file too large".into()));
        }
        expanded = expanded.saturating_add(size);
        if expanded > MAX_EXPANDED_BYTES {
            return Err(AcquireError::BadArchive("expanded bytes limit".into()));
        }
        let mode = parse_octal(&hdr[100..108]).unwrap_or(0o644) as u32;
        out.push(TarEntry {
            path: name,
            data,
            mode,
            is_dir: false,
        });
    }
    if !saw_header {
        return Err(AcquireError::BadArchive("empty or non-ustar tar".into()));
    }
    Ok(out)
}

fn validate_rel_path(name: &str, _is_dir: bool) -> Result<(), AcquireError> {
    if name.is_empty() {
        return Err(AcquireError::BadArchive("empty path".into()));
    }
    if name.len() > MAX_PATH_LEN {
        return Err(AcquireError::BadArchive("path too long".into()));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(AcquireError::BadArchive(format!("absolute path {name}")));
    }
    if name.contains('\0') {
        return Err(AcquireError::BadArchive("NUL in path".into()));
    }
    // Windows device / drive
    if name.contains(':') {
        return Err(AcquireError::BadArchive(format!("device/drive path {name}")));
    }
    let p = Path::new(name);
    let mut depth = 0usize;
    for c in p.components() {
        match c {
            Component::Normal(s) => {
                let s = s.to_string_lossy();
                if s == ".." || s == "." {
                    return Err(AcquireError::BadArchive(format!("bad component {s}")));
                }
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(AcquireError::BadArchive("path too deep".into()));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(AcquireError::BadArchive(format!("bad path {name}")));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(AcquireError::BadArchive(format!("absolute path {name}")));
            }
        }
    }
    if name.contains("..") {
        return Err(AcquireError::BadArchive(format!("traversal {name}")));
    }
    Ok(())
}

fn check_case_and_duplicate(entries: &[TarEntry]) -> Result<(), AcquireError> {
    let mut seen = HashSet::new();
    let mut seen_lower = HashSet::new();
    for e in entries {
        if !seen.insert(e.path.clone()) {
            return Err(AcquireError::BadArchive(format!(
                "duplicate path {}",
                e.path
            )));
        }
        let lower = e.path.to_ascii_lowercase();
        if !seen_lower.insert(lower) {
            return Err(AcquireError::BadArchive(format!(
                "case collision {}",
                e.path
            )));
        }
    }
    Ok(())
}

fn parse_manifest(entries: &[TarEntry]) -> Result<ArtifactManifestV1, AcquireError> {
    let m = entries
        .iter()
        .find(|e| e.path == "artifact-manifest.json")
        .ok_or_else(|| AcquireError::Manifest("missing artifact-manifest.json".into()))?;
    let man: ArtifactManifestV1 =
        serde_json::from_slice(&m.data).map_err(|e| AcquireError::Manifest(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&m.data).map_err(|e| AcquireError::Manifest(e.to_string()))?;
    if v.get("archiveSha256").is_some() {
        return Err(AcquireError::Manifest(
            "artifact-manifest must not embed archiveSha256".into(),
        ));
    }
    if man.schema_version != 1 {
        return Err(AcquireError::Manifest(format!(
            "schemaVersion {}",
            man.schema_version
        )));
    }
    if man.product != "plugin" {
        return Err(AcquireError::Manifest(format!("product {}", man.product)));
    }
    Ok(man)
}

fn verify_manifest_identity(
    man: &ArtifactManifestV1,
    req: &AcquisitionRequest,
) -> Result<(), AcquireError> {
    if man.plugin_id != req.plugin_id {
        return Err(AcquireError::Manifest(format!(
            "pluginId {} != {}",
            man.plugin_id, req.plugin_id
        )));
    }
    if man.version != req.version {
        return Err(AcquireError::Manifest(format!(
            "version {} != {}",
            man.version, req.version
        )));
    }
    let want = target_label_of(&req.target);
    if man.target != want {
        return Err(AcquireError::TargetMismatch {
            want,
            got: man.target.clone(),
        });
    }
    // Cross-check host match for selected target fields.
    let host = HostPlatform {
        os: normalize_os(&req.target.os),
        arch: normalize_arch(&req.target.arch),
        libc: req.target.libc.clone(),
    };
    let tplat = HostPlatform {
        os: normalize_os(&req.target.os),
        arch: normalize_arch(&req.target.arch),
        libc: req.target.libc.clone(),
    };
    if !target_matches_host(&host, &tplat) {
        return Err(AcquireError::TargetMismatch {
            want: host_platform_label(&host),
            got: want,
        });
    }
    Ok(())
}

fn verify_entries_match_manifest(
    entries: &[TarEntry],
    manifest: &ArtifactManifestV1,
) -> Result<(), AcquireError> {
    let by_path: BTreeMap<&str, &TarEntry> =
        entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut man_paths = BTreeSet::new();
    for me in &manifest.entries {
        if me.relative_path == "artifact-manifest.json" {
            continue;
        }
        validate_rel_path(&me.relative_path, false)?;
        if !man_paths.insert(me.relative_path.as_str()) {
            return Err(AcquireError::Manifest(format!(
                "duplicate manifest path {}",
                me.relative_path
            )));
        }
        let e = by_path.get(me.relative_path.as_str()).ok_or_else(|| {
            AcquireError::Manifest(format!("missing {}", me.relative_path))
        })?;
        if e.data.len() as u64 != me.length {
            return Err(AcquireError::Manifest(format!(
                "length mismatch {}",
                me.relative_path
            )));
        }
        let h = sha256_hex(&e.data);
        if !eq_hex(&h, &me.content_sha256) {
            return Err(AcquireError::Manifest(format!(
                "hash mismatch {}",
                me.relative_path
            )));
        }
    }
    // Every tar file except the manifest itself must appear in the manifest.
    for e in entries {
        if e.path == "artifact-manifest.json" {
            continue;
        }
        if !man_paths.contains(e.path.as_str()) {
            return Err(AcquireError::Manifest(format!(
                "undeclared entry {}",
                e.path
            )));
        }
    }
    Ok(())
}

fn write_entries_to_staging(root: &Path, entries: &[TarEntry]) -> Result<(), AcquireError> {
    for e in entries {
        validate_rel_path(&e.path, false)?;
        let dest = root.join(&e.path);
        // Ensure dest stays under root (no symlink follow — we never create links).
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // Refuse if path somehow escaped.
        let canon_root = dunce::canonicalize(root)?;
        let parent_for_check = dest.parent().unwrap_or(root);
        let canon_parent = if parent_for_check.exists() {
            dunce::canonicalize(parent_for_check)?
        } else {
            // Walk up to existing ancestor.
            let mut cur = parent_for_check.to_path_buf();
            while !cur.exists() {
                if !cur.pop() {
                    break;
                }
            }
            dunce::canonicalize(&cur).unwrap_or(canon_root.clone())
        };
        if !canon_parent.starts_with(&canon_root) {
            return Err(AcquireError::BadArchive(format!(
                "escape {}",
                e.path
            )));
        }
        if dest.exists() {
            return Err(AcquireError::BadArchive(format!(
                "duplicate materialize {}",
                e.path
            )));
        }
        fs::write(&dest, &e.data)?;
        set_mode(&dest, e.mode)?;
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), AcquireError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = (path, mode);
    Ok(())
}

fn build_staged_inventory(
    entries: &[TarEntry],
    manifest: &ArtifactManifestV1,
    req: &AcquisitionRequest,
) -> Result<Vec<StagedFile>, AcquireError> {
    let mut files = Vec::new();
    for me in &manifest.entries {
        if me.relative_path == "artifact-manifest.json" {
            continue;
        }
        let e = entries
            .iter()
            .find(|e| e.path == me.relative_path)
            .ok_or_else(|| AcquireError::Manifest(format!("missing {}", me.relative_path)))?;
        let role = classify_role(&me.relative_path, me.role.as_deref(), req);
        let mode_octal = if me.mode_octal.is_empty() {
            format!("{:04o}", e.mode & 0o7777)
        } else {
            me.mode_octal.clone()
        };
        // Enforce R5 mode policy: executables 0755, others 0644.
        match role {
            StagedFileRole::Executable => {
                if mode_octal != "0755" && mode_octal != "755" {
                    return Err(AcquireError::RoleDrift(format!(
                        "{} mode {mode_octal} want 0755",
                        me.relative_path
                    )));
                }
            }
            _ => {
                if mode_octal != "0644" && mode_octal != "644" && role != StagedFileRole::Manifest {
                    // allow 0644 only for non-exec; manifest may be 0644
                    if mode_octal != "0755" && mode_octal != "755" {
                        // ok 0644
                    }
                }
            }
        }
        files.push(StagedFile {
            relative_path: me.relative_path.clone(),
            role,
            mode_octal: if mode_octal.len() == 3 {
                format!("0{mode_octal}")
            } else {
                mode_octal
            },
            length: me.length,
            content_sha256: me.content_sha256.to_ascii_lowercase(),
        });
    }
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(files)
}

fn classify_role(path: &str, declared: Option<&str>, req: &AcquisitionRequest) -> StagedFileRole {
    if path == "artifact-manifest.json" {
        return StagedFileRole::Manifest;
    }
    if path == req.target.files.bridge || path == req.target.files.daemon {
        return StagedFileRole::Executable;
    }
    if let Some(d) = declared {
        return match d.to_ascii_lowercase().as_str() {
            "executable" => StagedFileRole::Executable,
            "library" => StagedFileRole::Library,
            "manifest" => StagedFileRole::Manifest,
            "config" => StagedFileRole::Config,
            "notice" => StagedFileRole::Notice,
            _ => StagedFileRole::Other,
        };
    }
    if path.ends_with(".so") || path.ends_with(".dylib") || path.ends_with(".dll") {
        StagedFileRole::Library
    } else if path.contains("NOTICE") || path.contains("LICENSE") {
        StagedFileRole::Notice
    } else if path.ends_with(".json") || path.ends_with(".toml") {
        StagedFileRole::Config
    } else {
        StagedFileRole::Other
    }
}

fn verify_executable_roles(
    files: &[StagedFile],
    req: &AcquisitionRequest,
) -> Result<(), AcquireError> {
    let bridge = files
        .iter()
        .find(|f| f.relative_path == req.target.files.bridge)
        .ok_or_else(|| {
            AcquireError::RoleDrift(format!("missing bridge {}", req.target.files.bridge))
        })?;
    let daemon = files
        .iter()
        .find(|f| f.relative_path == req.target.files.daemon)
        .ok_or_else(|| {
            AcquireError::RoleDrift(format!("missing daemon {}", req.target.files.daemon))
        })?;
    if bridge.role != StagedFileRole::Executable {
        return Err(AcquireError::RoleDrift(format!(
            "bridge role {:?}",
            bridge.role
        )));
    }
    if daemon.role != StagedFileRole::Executable {
        return Err(AcquireError::RoleDrift(format!(
            "daemon role {:?}",
            daemon.role
        )));
    }
    if bridge.mode_octal != "0755" {
        return Err(AcquireError::RoleDrift(format!(
            "bridge mode {}",
            bridge.mode_octal
        )));
    }
    if daemon.mode_octal != "0755" {
        return Err(AcquireError::RoleDrift(format!(
            "daemon mode {}",
            daemon.mode_octal
        )));
    }
    Ok(())
}

fn verify_entrypoint_and_abs_paths(
    staging_root: &Path,
    req: &AcquisitionRequest,
) -> Result<(PathBuf, PathBuf, PathBuf), AcquireError> {
    let ep: &EntrypointSpec = &req.target.entrypoint;
    if ep.argv.is_empty() {
        return Err(AcquireError::EntrypointInvalid("empty argv".into()));
    }
    if ep.argv[0] != "{bridge}" {
        return Err(AcquireError::EntrypointInvalid(
            "argv[0] must be {bridge}".into(),
        ));
    }
    // cwd must be plugin root placeholder.
    if ep.cwd != "{pluginRoot}" && ep.cwd != "." {
        // Allow only closed placeholders — absolute cwd refused.
        if Path::new(&ep.cwd).is_absolute() {
            return Err(AcquireError::EntrypointInvalid(
                "entrypoint cwd must not be absolute".into(),
            ));
        }
    }

    let bridge_abs = join_under_staging(staging_root, &req.target.files.bridge)?;
    let daemon_abs = join_under_staging(staging_root, &req.target.files.daemon)?;
    if !bridge_abs.is_file() {
        return Err(AcquireError::EntrypointInvalid(format!(
            "bridge missing at {}",
            bridge_abs.display()
        )));
    }
    if !daemon_abs.is_file() {
        return Err(AcquireError::EntrypointInvalid(format!(
            "daemon missing at {}",
            daemon_abs.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(&bridge_abs)?.permissions().mode() & 0o111;
        if m == 0 {
            return Err(AcquireError::RoleDrift("bridge not executable on disk".into()));
        }
    }
    // Never PATH-lookup — entrypoint is the absolute bridge path.
    Ok((bridge_abs.clone(), daemon_abs, bridge_abs))
}

fn join_under_staging(root: &Path, rel: &str) -> Result<PathBuf, AcquireError> {
    validate_rel_path(rel, false)?;
    let candidate = root.join(rel);
    let canon_root = dunce::canonicalize(root)?;
    if let Some(parent) = candidate.parent() {
        if parent.exists() {
            let cp = dunce::canonicalize(parent)?;
            if !cp.starts_with(&canon_root) {
                return Err(AcquireError::BadArchive(format!("escape {rel}")));
            }
        }
    }
    Ok(candidate)
}

// --- builders / digests (fixture + production helpers) ---

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_of(&h.finalize())
}

fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn eq_hex(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn parse_octal(bytes: &[u8]) -> Result<u64, AcquireError> {
    let s = cstr(bytes);
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| AcquireError::BadArchive(format!("bad octal {s}")))
}

/// Build a deterministic R5 plugin archive (USTAR + gzip level 9).
pub fn build_r5_plugin_archive(
    plugin_id: &str,
    version: &str,
    target_label: &str,
    files: &[(&str, &[u8], u32)],
) -> Result<Vec<u8>, AcquireError> {
    let mut entries_meta = Vec::new();
    let mut tar_entries = Vec::new();
    for (path, data, mode) in files {
        validate_rel_path(path, false)?;
        entries_meta.push(ArtifactManifestEntry {
            relative_path: (*path).into(),
            mode_octal: format!("{:04o}", mode & 0o7777),
            length: data.len() as u64,
            content_sha256: sha256_hex(data),
            role: None,
        });
        tar_entries.push(TarEntry {
            path: (*path).into(),
            data: data.to_vec(),
            mode: *mode,
            is_dir: false,
        });
    }
    let manifest = ArtifactManifestV1 {
        schema_version: 1,
        product: "plugin".into(),
        plugin_id: plugin_id.into(),
        version: version.into(),
        target: target_label.into(),
        entries: entries_meta,
    };
    let man_json =
        serde_json::to_vec_pretty(&manifest).map_err(|e| AcquireError::Manifest(e.to_string()))?;
    tar_entries.push(TarEntry {
        path: "artifact-manifest.json".into(),
        data: man_json,
        mode: 0o644,
        is_dir: false,
    });
    tar_entries.sort_by(|a, b| a.path.cmp(&b.path));
    let tar = write_ustar(&tar_entries)?;
    gzip_level9(&tar)
}

fn write_ustar(entries: &[TarEntry]) -> Result<Vec<u8>, AcquireError> {
    let mut out = Vec::new();
    for e in entries {
        let mut hdr = [0u8; 512];
        let name = e.path.as_bytes();
        if name.len() > 100 {
            return Err(AcquireError::BadArchive("path too long for ustar".into()));
        }
        hdr[..name.len()].copy_from_slice(name);
        write_octal(&mut hdr[100..108], u64::from(e.mode), 7);
        write_octal(&mut hdr[108..116], 0, 7);
        write_octal(&mut hdr[116..124], 0, 7);
        write_octal(&mut hdr[124..136], e.data.len() as u64, 11);
        write_octal(&mut hdr[136..148], 0, 11);
        for b in &mut hdr[148..156] {
            *b = b' ';
        }
        hdr[156] = if e.is_dir { b'5' } else { b'0' };
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        let mut sum: u32 = 0;
        for b in &hdr {
            sum += u32::from(*b);
        }
        let cstr = format!("{sum:06o}");
        hdr[148..154].copy_from_slice(cstr.as_bytes());
        hdr[154] = 0;
        hdr[155] = b' ';
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&e.data);
        let pad = (512 - (e.data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    Ok(out)
}

fn write_octal(dst: &mut [u8], val: u64, digits: usize) {
    let s = format!("{val:0digits$o}");
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&bytes[..n]);
    if n < dst.len() {
        dst[n] = 0;
    }
}

fn gzip_level9(data: &[u8]) -> Result<Vec<u8>, AcquireError> {
    use flate2::write::GzEncoder;
    use flate2::{Compression, GzBuilder};
    let enc = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::new(9));
    let mut enc: GzEncoder<Vec<u8>> = enc;
    enc.write_all(data)
        .map_err(|e| AcquireError::BadArchive(format!("gzip encode: {e}")))?;
    let mut out = enc
        .finish()
        .map_err(|e| AcquireError::BadArchive(format!("gzip finish: {e}")))?;
    if out.len() >= 10 {
        out[8] = 2; // XFL=2 max compression
    }
    Ok(out)
}

/// Deterministic fixture keypair seed (test-only).
pub const FIXTURE_SEED: [u8; 32] = *b"orca-plugin-acq-test-seed-v1!!!!";

pub fn fixture_keypair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&FIXTURE_SEED)
        .expect("fixture seed is valid ed25519 seed")
}

pub fn fixture_pubkey() -> [u8; 32] {
    use ring::signature::KeyPair;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(fixture_keypair().public_key().as_ref());
    pk
}

pub fn fixture_key_id() -> String {
    format!("sha256:{}", sha256_hex(&fixture_pubkey()))
}

pub fn sign_archive_ed25519(archive_bytes: &[u8]) -> [u8; 64] {
    let sig = fixture_keypair().sign(archive_bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

pub fn fixture_trust_required() -> SignatureTrust {
    SignatureTrust {
        keys: vec![(fixture_key_id(), fixture_pubkey())],
        require_signature: true,
    }
}

pub fn fixture_trust_optional() -> SignatureTrust {
    SignatureTrust {
        keys: vec![(fixture_key_id(), fixture_pubkey())],
        require_signature: false,
    }
}

/// Low-level hostile archive builders for tests (typeflag injection etc.).
pub fn test_write_ustar_raw(entries: &[(String, Vec<u8>, u32, u8)]) -> Result<Vec<u8>, AcquireError> {
    let mut out = Vec::new();
    for (path, data, mode, typeflag) in entries {
        let mut hdr = [0u8; 512];
        let name = path.as_bytes();
        if name.len() > 100 {
            return Err(AcquireError::BadArchive("path too long".into()));
        }
        hdr[..name.len()].copy_from_slice(name);
        write_octal(&mut hdr[100..108], u64::from(*mode), 7);
        write_octal(&mut hdr[108..116], 0, 7);
        write_octal(&mut hdr[116..124], 0, 7);
        write_octal(&mut hdr[124..136], data.len() as u64, 11);
        write_octal(&mut hdr[136..148], 0, 11);
        for b in &mut hdr[148..156] {
            *b = b' ';
        }
        hdr[156] = *typeflag;
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        let mut sum: u32 = 0;
        for b in &hdr {
            sum += u32::from(*b);
        }
        let cstr = format!("{sum:06o}");
        hdr[148..154].copy_from_slice(cstr.as_bytes());
        hdr[154] = 0;
        hdr[155] = b' ';
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    gzip_level9(&out)
}

pub fn test_gunzip_preflight(bytes: &[u8]) -> Result<Vec<u8>, AcquireError> {
    gunzip_r5(bytes)
}

pub fn test_parse_ustar(tar: &[u8]) -> Result<Vec<String>, AcquireError> {
    let e = parse_ustar(tar)?;
    Ok(e.into_iter().map(|x| x.path).collect())
}

pub fn test_extract_ustar_gz(bytes: &[u8]) -> Result<Vec<String>, AcquireError> {
    let e = extract_ustar_gz(bytes)?;
    Ok(e.into_iter().map(|x| x.path).collect())
}

#[cfg(test)]
#[path = "artifact_test.rs"]
mod artifact_test;
