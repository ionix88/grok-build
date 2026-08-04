// allow: SIZE_OK — plan Task 16 owns R5 archive stage/verify + fixture builders.
//! Stage and verify R5 host archives (ustar+gzip level-9). Never promotes.

use super::receipt::{
    self, check_version_byte_conflict, host_bin_name, host_target_triple, now_rfc3339,
    release_keys_provisioned, sha256_hex, trusted_release_keys, verify_ed25519_detached,
    HostFileEntry, HostLayout, HostUpdateReceiptV1, HostUpdateTransactionV1, TxnPhase,
    ARCHIVE_FORMAT_ID, RECEIPT_SCHEMA, SIG_ALG_ED25519, TXN_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_ENTRIES: usize = 64;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 300 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StageError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("receipt: {0}")]
    Receipt(receipt::ReceiptError),
    #[error("bad archive: {0}")]
    BadArchive(String),
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("EXTERNAL_REQUIRED(signing-key)")]
    ExternalRequiredSigningKey,
    #[error("target mismatch: want {want}, got {got}")]
    TargetMismatch { want: String, got: String },
    #[error("running path mismatch: exe={exe}, managed={managed}")]
    RunningPathMismatch { exe: String, managed: String },
    #[error("version byte conflict: {0}")]
    VersionByteConflict(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl From<receipt::ReceiptError> for StageError {
    fn from(e: receipt::ReceiptError) -> Self {
        match e {
            receipt::ReceiptError::ExternalRequiredSigningKey => {
                StageError::ExternalRequiredSigningKey
            }
            receipt::ReceiptError::Signature(m) => StageError::BadSignature(m),
            other => StageError::Receipt(other),
        }
    }
}

/// Host-manifest.json inside the archive. Do NOT embed archiveSha256 (chicken-egg).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostManifestV1 {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub target: String,
    pub entries: Vec<HostManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostManifestEntry {
    pub relative_path: String,
    pub mode_octal: String,
    pub length: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone)]
pub struct StagedUpdate {
    pub transaction: HostUpdateTransactionV1,
    pub receipt: HostUpdateReceiptV1,
    pub staged_bin: PathBuf,
    pub archive_sha256: String,
    pub txn_path: PathBuf,
    pub signature_key_id: String,
}

/// Stage a verified R5 archive for promotion. Leaves phase=Staged; does not replace install_root.
pub fn stage_archive(
    layout: &HostLayout,
    archive_path: &Path,
    sig_path: Option<&Path>,
    enforce_running_path: bool,
) -> Result<StagedUpdate, StageError> {
    layout.ensure_dirs()?;
    if enforce_running_path {
        check_running_path(layout)?;
    }

    let archive_bytes = fs::read(archive_path)?;
    if archive_bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(StageError::BadArchive("archive too large".into()));
    }
    let archive_sha256 = sha256_hex(&archive_bytes);

    let (sig_bytes, key_id) = verify_detached_sig(&archive_bytes, archive_path, sig_path)?;

    let entries = extract_ustar_gz(&archive_bytes)?;
    let manifest = parse_manifest(&entries)?;
    if manifest.product != "orca" {
        return Err(StageError::Manifest(format!(
            "product {}",
            manifest.product
        )));
    }
    if !target_compatible(&manifest.target) {
        return Err(StageError::TargetMismatch {
            want: host_target_triple(),
            got: manifest.target,
        });
    }

    match check_version_byte_conflict(layout, &manifest.version, &archive_sha256) {
        Ok(()) => {}
        Err(receipt::ReceiptError::VersionByteConflict(m)) => {
            return Err(StageError::VersionByteConflict(m));
        }
        Err(e) => return Err(StageError::Receipt(e)),
    }

    verify_entries_match_manifest(&entries, &manifest)?;

    let bin_name = host_bin_name();
    let _bin_entry = entries
        .iter()
        .find(|e| e.path == "orca" || e.path == bin_name)
        .ok_or_else(|| StageError::BadArchive("missing orca binary entry".into()))?;

    let txn_id = format!("{}-{}", now_rfc3339(), &archive_sha256[..12]);
    let staged_root = layout.staging_dir.join(&txn_id);
    if staged_root.exists() {
        fs::remove_dir_all(&staged_root)?;
    }
    fs::create_dir_all(&staged_root)?;

    for e in &entries {
        if e.path == "host-manifest.json" {
            let p = staged_root.join("host-manifest.json");
            fs::write(&p, &e.data)?;
            continue;
        }
        let rel = if e.path == "orca" {
            bin_name.to_string()
        } else {
            e.path.clone()
        };
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(StageError::BadArchive(format!("bad path {rel}")));
        }
        let dest = staged_root.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &e.data)?;
        set_mode(&dest, &mode_for_path(&rel, &manifest))?;
    }

    // Retain archive + detached signature under state/host/archives.
    let retained = layout.archive_path(&archive_sha256);
    if !retained.exists() {
        fs::write(&retained, &archive_bytes)?;
    }
    let retained_sig = layout.archive_sig_path(&archive_sha256);
    if !retained_sig.exists() {
        fs::write(&retained_sig, &sig_bytes)?;
    }

    let files: Vec<HostFileEntry> = manifest
        .entries
        .iter()
        .filter(|e| e.relative_path != "host-manifest.json")
        .map(|e| HostFileEntry {
            relative_path: if e.relative_path == "orca" {
                bin_name.to_string()
            } else {
                e.relative_path.clone()
            },
            mode_octal: e.mode_octal.clone(),
            length: e.length,
            content_sha256: e.content_sha256.clone(),
        })
        .collect();

    let sig_hex = sha256_hex(&sig_bytes);
    let receipt = HostUpdateReceiptV1 {
        schema_version: RECEIPT_SCHEMA,
        product: "orca".into(),
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        archive_sha256: archive_sha256.clone(),
        archive_format: ARCHIVE_FORMAT_ID.into(),
        signature_algorithm: SIG_ALG_ED25519.into(),
        signature_key_id: key_id.clone(),
        signature_sha256: sig_hex,
        install_root: layout.install_root.display().to_string(),
        files,
        installed_at: now_rfc3339(),
        receipt_digest: String::new(),
    }
    .seal()?;

    let prior = if layout.current_path.is_file() {
        CurrentOptional::load(&layout.current_path)
    } else {
        None
    };

    let mut txn = HostUpdateTransactionV1 {
        schema_version: TXN_SCHEMA,
        transaction_id: txn_id.clone(),
        phase: TxnPhase::Prepared,
        target_version: manifest.version.clone(),
        archive_sha256: archive_sha256.clone(),
        staged_root: staged_root.display().to_string(),
        install_root: layout.install_root.display().to_string(),
        prior_receipt_digest: prior,
        candidate_receipt_digest: Some(receipt.receipt_digest.clone()),
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
        error: None,
    };
    txn.set_phase(TxnPhase::Staged);
    let txn_path = layout.txn_path(&txn_id);
    txn.write_atomic(&txn_path)?;

    let staged_bin = staged_root.join(bin_name);
    Ok(StagedUpdate {
        transaction: txn,
        receipt,
        staged_bin,
        archive_sha256,
        txn_path,
        signature_key_id: key_id,
    })
}

/// Host target match: exact triple, `any`, empty, or `test-*` fixture targets.
pub fn target_compatible(target: &str) -> bool {
    let want = host_target_triple();
    target == want || target == "any" || target.is_empty() || target.starts_with("test-")
}

struct CurrentOptional;
impl CurrentOptional {
    fn load(path: &Path) -> Option<String> {
        receipt::CurrentHostV1::load(path)
            .ok()
            .map(|c| c.receipt_digest)
    }
}

fn mode_for_path(rel: &str, manifest: &HostManifestV1) -> String {
    for e in &manifest.entries {
        let m = if e.relative_path == "orca" {
            host_bin_name()
        } else {
            e.relative_path.as_str()
        };
        if m == rel {
            return e.mode_octal.clone();
        }
    }
    if rel == host_bin_name() || rel == "orca" {
        "0755".into()
    } else {
        "0644".into()
    }
}

fn set_mode(path: &Path, mode_octal: &str) -> Result<(), StageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = u32::from_str_radix(mode_octal, 8).unwrap_or(0o644);
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = (path, mode_octal);
    Ok(())
}

pub fn check_running_path(layout: &HostLayout) -> Result<(), StageError> {
    if !layout.managed_bin.exists() {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(StageError::Io)?;
    let exe_c = dunce::canonicalize(&exe).unwrap_or(exe);
    let managed_c = dunce::canonicalize(&layout.managed_bin).unwrap_or(layout.managed_bin.clone());
    if exe_c != managed_c {
        return Err(StageError::RunningPathMismatch {
            exe: exe_c.display().to_string(),
            managed: managed_c.display().to_string(),
        });
    }
    Ok(())
}

/// Verify detached Ed25519 `.sig` against pinned release keys (or test override).
/// Returns `(signature_bytes, key_id)`.
fn verify_detached_sig(
    archive_bytes: &[u8],
    archive_path: &Path,
    sig_path: Option<&Path>,
) -> Result<(Vec<u8>, String), StageError> {
    if !release_keys_provisioned() {
        return Err(StageError::ExternalRequiredSigningKey);
    }
    let default_sig = {
        let mut p = archive_path.as_os_str().to_os_string();
        p.push(".sig");
        PathBuf::from(p)
    };
    let path = sig_path
        .map(Path::to_path_buf)
        .filter(|p| p.exists())
        .unwrap_or(default_sig);
    if !path.exists() {
        return Err(StageError::BadSignature("missing .sig".into()));
    }
    let sig = fs::read(&path)?;
    if sig.len() != 64 {
        return Err(StageError::BadSignature(
            "signature must be 64 bytes".into(),
        ));
    }
    // Prefer companion key-id file; else try each trusted key.
    let kid_path = {
        let mut p = path.as_os_str().to_os_string();
        p.push(".keyid");
        PathBuf::from(p)
    };
    if kid_path.is_file() {
        let key_id = fs::read_to_string(&kid_path)?.trim().to_string();
        verify_ed25519_detached(archive_bytes, &sig, &key_id)?;
        return Ok((sig, key_id));
    }
    let keys = trusted_release_keys();
    for (id, _) in &keys {
        if verify_ed25519_detached(archive_bytes, &sig, id).is_ok() {
            return Ok((sig, id.clone()));
        }
    }
    Err(StageError::BadSignature(
        "detached Ed25519 signature mismatch".into(),
    ))
}

/// Write raw 64-byte Ed25519 signature (+ optional key id sidecar).
pub fn write_sig_file(
    archive_path: &Path,
    signature: &[u8],
    key_id: &str,
) -> Result<PathBuf, StageError> {
    if signature.len() != 64 {
        return Err(StageError::BadSignature(
            "signature must be 64 bytes".into(),
        ));
    }
    let mut p = archive_path.as_os_str().to_os_string();
    p.push(".sig");
    let path = PathBuf::from(p);
    fs::write(&path, signature)?;
    let mut kid = path.as_os_str().to_os_string();
    kid.push(".keyid");
    fs::write(PathBuf::from(kid), key_id.as_bytes())?;
    Ok(path)
}

/// Sign archive bytes with an Ed25519 keypair (test/fixture helper; never production keys).
pub fn sign_archive_ed25519(
    archive_bytes: &[u8],
    keypair: &ring::signature::Ed25519KeyPair,
) -> [u8; 64] {
    let sig = keypair.sign(archive_bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

/// Deterministic fixture keypair seed (test-only; never a production pin).
pub const FIXTURE_SEED: [u8; 32] = *b"orca-host-upd-test-seed-v1!!!!!!";

pub fn fixture_keypair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&FIXTURE_SEED)
        .expect("fixture seed is valid ed25519 seed")
}

pub fn fixture_pubkey_hex() -> String {
    use ring::signature::KeyPair;
    hex_of(fixture_keypair().public_key().as_ref())
}

pub fn fixture_key_id() -> String {
    use ring::signature::KeyPair;
    format!(
        "sha256:{}",
        sha256_hex(fixture_keypair().public_key().as_ref())
    )
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

/// Install fixture pubkey into process env for the duration of tests.
pub fn install_fixture_trust_env() {
    unsafe { std::env::set_var("ORCA_HOST_UPDATE_TEST_PUBKEY_HEX", fixture_pubkey_hex()) };
    unsafe { std::env::set_var("ORCA_HOST_UPDATE_TEST_KEY_ID", fixture_key_id()) };
}

pub fn clear_fixture_trust_env() {
    unsafe { std::env::remove_var("ORCA_HOST_UPDATE_TEST_PUBKEY_HEX") };
    unsafe { std::env::remove_var("ORCA_HOST_UPDATE_TEST_KEY_ID") };
}

// --- R5 ustar + gzip level 9 ---

#[derive(Clone)]
struct TarEntry {
    path: String,
    data: Vec<u8>,
    mode: u32,
    is_dir: bool,
}

/// Build a deterministic R5 archive (USTAR + gzip level 9, FLG=0 MTIME=0 XFL=2 OS=255).
pub fn build_r5_archive(
    version: &str,
    target: &str,
    orca_bytes: &[u8],
) -> Result<Vec<u8>, StageError> {
    let mut manifest = HostManifestV1 {
        schema_version: 1,
        product: "orca".into(),
        version: version.into(),
        target: target.into(),
        entries: vec![HostManifestEntry {
            relative_path: "orca".into(),
            mode_octal: "0755".into(),
            length: orca_bytes.len() as u64,
            content_sha256: sha256_hex(orca_bytes),
        }],
    };
    let _ = &mut manifest;
    let man_json =
        serde_json::to_vec_pretty(&manifest).map_err(|e| StageError::Manifest(e.to_string()))?;

    let mut tar_entries = vec![
        TarEntry {
            path: "host-manifest.json".into(),
            data: man_json,
            mode: 0o644,
            is_dir: false,
        },
        TarEntry {
            path: "orca".into(),
            data: orca_bytes.to_vec(),
            mode: 0o755,
            is_dir: false,
        },
    ];
    tar_entries.sort_by(|a, b| a.path.cmp(&b.path));
    let tar = write_ustar(&tar_entries)?;
    gzip_level9(&tar)
}

/// Sign + write `.sig` for a fixture archive using the deterministic fixture key.
pub fn sign_and_write_fixture_sig(
    archive_path: &Path,
    archive_bytes: &[u8],
) -> Result<PathBuf, StageError> {
    install_fixture_trust_env();
    let kp = fixture_keypair();
    let sig = sign_archive_ed25519(archive_bytes, &kp);
    write_sig_file(archive_path, &sig, &fixture_key_id())
}

fn write_ustar(entries: &[TarEntry]) -> Result<Vec<u8>, StageError> {
    let mut out = Vec::new();
    for e in entries {
        let mut hdr = [0u8; 512];
        let name = e.path.as_bytes();
        if name.len() > 100 {
            return Err(StageError::BadArchive("path too long for ustar".into()));
        }
        hdr[..name.len()].copy_from_slice(name);
        let mode = e.mode;
        write_octal(&mut hdr[100..108], u64::from(mode), 7);
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

/// Gzip one member at level 9: FLG=0, MTIME=0, XFL=2, OS=255.
fn gzip_level9(data: &[u8]) -> Result<Vec<u8>, StageError> {
    use flate2::write::GzEncoder;
    use flate2::{Compression, GzBuilder};
    let enc = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::new(9));
    let mut enc: GzEncoder<Vec<u8>> = enc;
    enc.write_all(data)
        .map_err(|e| StageError::BadArchive(format!("gzip encode: {e}")))?;
    let mut out = enc
        .finish()
        .map_err(|e| StageError::BadArchive(format!("gzip finish: {e}")))?;
    // Force XFL=2 (max compression) per R5 — flate2 may leave 0.
    if out.len() >= 10 {
        out[8] = 2;
    }
    Ok(out)
}

fn extract_ustar_gz(archive: &[u8]) -> Result<Vec<TarEntry>, StageError> {
    let tar = gunzip_r5(archive)?;
    parse_ustar(&tar)
}

/// Accept R5 single-member gzip (level-9 deflate or stored), FLG=0 MTIME=0 OS=255.
fn gunzip_r5(gz: &[u8]) -> Result<Vec<u8>, StageError> {
    if gz.len() < 18 {
        return Err(StageError::BadArchive("gzip too short".into()));
    }
    if gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8 {
        return Err(StageError::BadArchive("not gzip/deflate".into()));
    }
    let flg = gz[3];
    if flg != 0 {
        return Err(StageError::BadArchive(format!("gzip FLG={flg} want 0")));
    }
    if gz[4..8] != [0, 0, 0, 0] {
        return Err(StageError::BadArchive("gzip MTIME must be 0".into()));
    }
    // XFL: 2 = max compression (R5 level 9); 0/4 also RFC-valid for store/fast.
    let xfl = gz[8];
    if xfl != 2 && xfl != 0 && xfl != 4 {
        return Err(StageError::BadArchive(format!(
            "gzip XFL={xfl} unsupported"
        )));
    }
    if gz[9] != 255 {
        return Err(StageError::BadArchive(format!(
            "gzip OS={} want 255",
            gz[9]
        )));
    }

    use flate2::read::GzDecoder;
    use std::io::Cursor;
    let mut cursor = Cursor::new(gz);
    let mut out = Vec::new();
    {
        let mut dec = GzDecoder::new(&mut cursor);
        dec.read_to_end(&mut out)
            .map_err(|e| StageError::BadArchive(format!("gzip inflate: {e}")))?;
    }
    let consumed = cursor.position() as usize;
    if consumed != gz.len() {
        return Err(StageError::BadArchive("trailing bytes after gzip".into()));
    }
    Ok(out)
}

fn parse_ustar(tar: &[u8]) -> Result<Vec<TarEntry>, StageError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 512 <= tar.len() {
        let hdr = &tar[i..i + 512];
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        let name = cstr(&hdr[0..100]);
        let size = parse_octal(&hdr[124..136])?;
        let typeflag = hdr[156];
        if typeflag == b'1'
            || typeflag == b'2'
            || typeflag == b'3'
            || typeflag == b'4'
            || typeflag == b'6'
        {
            return Err(StageError::BadArchive(format!(
                "forbidden typeflag {}",
                typeflag as char
            )));
        }
        let magic = &hdr[257..262];
        if magic != b"ustar" {
            return Err(StageError::BadArchive("not ustar".into()));
        }
        i += 512;
        let data_end = i + size as usize;
        if data_end > tar.len() {
            return Err(StageError::BadArchive("tar entry OOB".into()));
        }
        let data = tar[i..data_end].to_vec();
        let pad = (512 - (size as usize % 512)) % 512;
        i = data_end + pad;
        if typeflag == b'5' {
            continue;
        }
        if typeflag != b'0' && typeflag != 0 {
            return Err(StageError::BadArchive(format!(
                "unsupported typeflag {}",
                typeflag as char
            )));
        }
        if name.contains("..") || name.starts_with('/') {
            return Err(StageError::BadArchive(format!("bad path {name}")));
        }
        if out.len() >= MAX_ENTRIES {
            return Err(StageError::BadArchive("too many entries".into()));
        }
        if size > MAX_FILE_BYTES {
            return Err(StageError::BadArchive("file too large".into()));
        }
        let mode = parse_octal(&hdr[100..108]).unwrap_or(0o644) as u32;
        out.push(TarEntry {
            path: name,
            data,
            mode,
            is_dir: false,
        });
    }
    let mut sorted = out.clone();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    if sorted.iter().map(|e| &e.path).collect::<Vec<_>>()
        != out.iter().map(|e| &e.path).collect::<Vec<_>>()
    {
        return Err(StageError::BadArchive("entries not sorted".into()));
    }
    Ok(out)
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn parse_octal(bytes: &[u8]) -> Result<u64, StageError> {
    let s = cstr(bytes);
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| StageError::BadArchive(format!("bad octal {s}")))
}

fn parse_manifest(entries: &[TarEntry]) -> Result<HostManifestV1, StageError> {
    let m = entries
        .iter()
        .find(|e| e.path == "host-manifest.json")
        .ok_or_else(|| StageError::Manifest("missing host-manifest.json".into()))?;
    let man: HostManifestV1 =
        serde_json::from_slice(&m.data).map_err(|e| StageError::Manifest(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&m.data).map_err(|e| StageError::Manifest(e.to_string()))?;
    if v.get("archiveSha256").is_some() {
        return Err(StageError::Manifest(
            "host-manifest must not embed archiveSha256".into(),
        ));
    }
    Ok(man)
}

fn verify_entries_match_manifest(
    entries: &[TarEntry],
    manifest: &HostManifestV1,
) -> Result<(), StageError> {
    for me in &manifest.entries {
        if me.relative_path == "host-manifest.json" {
            continue;
        }
        let e = entries
            .iter()
            .find(|e| e.path == me.relative_path)
            .ok_or_else(|| StageError::Manifest(format!("missing {}", me.relative_path)))?;
        if e.data.len() as u64 != me.length {
            return Err(StageError::Manifest(format!(
                "length mismatch {}",
                me.relative_path
            )));
        }
        let h = sha256_hex(&e.data);
        if h != me.content_sha256 {
            return Err(StageError::Manifest(format!(
                "hash mismatch {}",
                me.relative_path
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_layout(root: &Path) -> HostLayout {
        let state = root.join("state");
        let cache = root.join("cache");
        let paths = xai_grok_config::OrcaPaths {
            config_file: root.join("config.toml"),
            data_root: root.join("data"),
            state_root: state,
            cache_root: cache,
            runtime_root: root.join("runtime"),
            logs_dir: root.join("state/logs"),
            from_orca_home: true,
        };
        HostLayout::from_paths(&paths, root)
    }

    fn with_fixture_keys<R>(f: impl FnOnce() -> R) -> R {
        let _g = ENV_LOCK.lock().unwrap();
        install_fixture_trust_env();
        let r = f();
        clear_fixture_trust_env();
        r
    }

    fn write_signed_archive(dir: &Path, name: &str, version: &str, payload: &[u8]) -> PathBuf {
        let bytes = build_r5_archive(version, "test-any", payload).unwrap();
        let ap = dir.join(name);
        fs::write(&ap, &bytes).unwrap();
        sign_and_write_fixture_sig(&ap, &bytes).unwrap();
        ap
    }

    #[test]
    fn stage_valid_archive() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let ap = write_signed_archive(
                dir.path(),
                "a.tar.gz",
                "0.0.0-test-a",
                b"#!/bin/sh\necho va\n",
            );
            let staged = stage_archive(&layout, &ap, None, false).unwrap();
            assert_eq!(staged.receipt.version, "0.0.0-test-a");
            assert_eq!(staged.receipt.signature_algorithm, SIG_ALG_ED25519);
            assert_eq!(staged.transaction.phase, TxnPhase::Staged);
            assert!(staged.staged_bin.is_file());
            assert!(layout.archive_sig_path(&staged.archive_sha256).is_file());
        });
    }

    #[test]
    fn r5_level9_gzip_accepted() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"payload-level9").unwrap();
            // Header contract: magic, deflate, FLG=0, MTIME=0, XFL=2, OS=255
            assert_eq!(&bytes[0..4], &[0x1f, 0x8b, 8, 0]);
            assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
            assert_eq!(bytes[8], 2);
            assert_eq!(bytes[9], 255);
            // Must be compressed deflate (not only store BTYPE=0) for non-trivial payload.
            let btype = (bytes[10] >> 1) & 3;
            assert!(
                btype == 1 || btype == 2,
                "expected fixed/dynamic Huffman BTYPE, got {btype}"
            );
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            sign_and_write_fixture_sig(&ap, &bytes).unwrap();
            let staged = stage_archive(&layout, &ap, None, false).unwrap();
            assert_eq!(staged.receipt.version, "0.0.0-test-a");
        });
    }

    #[test]
    fn forgeable_digest_sig_rejected_ed25519_required() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"x").unwrap();
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            // Old test-only-sha512-v1 construction (forgeable from public bytes).
            let h1 = {
                use sha2::{Digest, Sha256};
                let mut d = Sha256::new();
                d.update(&bytes);
                d.finalize()
            };
            let h2 = {
                use sha2::{Digest, Sha256};
                let mut d = Sha256::new();
                d.update(b"test-only-sha512-v1");
                d.update(&h1);
                d.finalize()
            };
            let mut fake = [0u8; 64];
            fake[..32].copy_from_slice(&h1);
            fake[32..].copy_from_slice(&h2);
            let mut sigp = ap.as_os_str().to_os_string();
            sigp.push(".sig");
            fs::write(PathBuf::from(sigp), fake).unwrap();
            let err = stage_archive(&layout, &ap, None, false).unwrap_err();
            assert!(
                matches!(err, StageError::BadSignature(_)),
                "forgeable digest sig must not promote: {err}"
            );
        });
    }

    #[test]
    fn missing_release_key_external_required() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_fixture_trust_env();
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"x").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        // Even a well-formed 64-byte sig cannot promote without pinned keys.
        let mut sigp = ap.as_os_str().to_os_string();
        sigp.push(".sig");
        fs::write(PathBuf::from(sigp), [1u8; 64]).unwrap();
        let err = stage_archive(&layout, &ap, None, false).unwrap_err();
        assert!(matches!(err, StageError::ExternalRequiredSigningKey));
    }

    #[test]
    fn same_version_conflict() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let a = build_r5_archive("1.0.0", "test-any", b"binary-a").unwrap();
            let b = build_r5_archive("1.0.0", "test-any", b"binary-b-different").unwrap();
            assert_ne!(sha256_hex(&a), sha256_hex(&b));
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &a).unwrap();
            sign_and_write_fixture_sig(&ap, &a).unwrap();
            let s = stage_archive(&layout, &ap, None, false).unwrap();
            s.receipt
                .write_atomic(&layout.receipt_path(&s.receipt.receipt_digest))
                .unwrap();
            let cur = super::receipt::CurrentHostV1 {
                schema_version: super::receipt::CURRENT_SCHEMA,
                version: s.receipt.version.clone(),
                archive_sha256: s.receipt.archive_sha256.clone(),
                receipt_digest: s.receipt.receipt_digest.clone(),
                binary_path: layout.managed_bin.display().to_string(),
                updated_at: now_rfc3339(),
            };
            cur.write_atomic(&layout.current_path).unwrap();
            let bp = dir.path().join("b.tar.gz");
            fs::write(&bp, &b).unwrap();
            sign_and_write_fixture_sig(&bp, &b).unwrap();
            let err = stage_archive(&layout, &bp, None, false).unwrap_err();
            assert!(matches!(err, StageError::VersionByteConflict(_)));
        });
    }

    #[test]
    fn bad_signature_rejected() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"x").unwrap();
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            let mut sigp = ap.as_os_str().to_os_string();
            sigp.push(".sig");
            fs::write(PathBuf::from(sigp), [0u8; 64]).unwrap();
            let err = stage_archive(&layout, &ap, None, false).unwrap_err();
            assert!(matches!(err, StageError::BadSignature(_)));
        });
    }

    #[test]
    fn target_mismatch() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            let bytes = build_r5_archive("0.0.0-test-a", "windows-x86_64", b"x").unwrap();
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            sign_and_write_fixture_sig(&ap, &bytes).unwrap();
            let err = stage_archive(&layout, &ap, None, false).unwrap_err();
            assert!(matches!(err, StageError::TargetMismatch { .. }));
        });
    }

    #[test]
    fn running_path_mismatch() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            fs::write(&layout.managed_bin, b"managed").unwrap();
            let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"x").unwrap();
            let ap = dir.path().join("a.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            sign_and_write_fixture_sig(&ap, &bytes).unwrap();
            let err = stage_archive(&layout, &ap, None, true).unwrap_err();
            assert!(matches!(err, StageError::RunningPathMismatch { .. }));
        });
    }

    #[test]
    fn crash_staged_abandons_old_host() {
        with_fixture_keys(|| {
            let dir = tempdir().unwrap();
            let layout = test_layout(dir.path());
            layout.ensure_dirs().unwrap();
            fs::write(&layout.managed_bin, b"old-host").unwrap();
            let bytes = build_r5_archive("0.0.0-test-b", "test-any", b"new-host").unwrap();
            let ap = dir.path().join("b.tar.gz");
            fs::write(&ap, &bytes).unwrap();
            sign_and_write_fixture_sig(&ap, &bytes).unwrap();
            let staged = stage_archive(&layout, &ap, None, false).unwrap();
            assert_eq!(staged.transaction.phase, TxnPhase::Staged);
            assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"old-host");
            let txn = HostUpdateTransactionV1::load(&staged.txn_path).unwrap();
            assert_eq!(txn.phase, TxnPhase::Staged);
        });
    }
}
