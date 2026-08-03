// allow: SIZE_OK — plan Task 16 owns R5 archive stage/verify + fixture builders.
//! Stage and verify R5 host archives (ustar+gzip FLG=0). Never promotes.

use super::receipt::{
    self, check_version_byte_conflict, host_bin_name, host_target_triple, now_rfc3339,
    sha256_hex, HostFileEntry, HostLayout, HostUpdateReceiptV1, HostUpdateTransactionV1, TxnPhase,
    ARCHIVE_FORMAT_ID, RECEIPT_SCHEMA, TEST_SIG_ALGORITHM, TXN_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
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
    Receipt(#[from] receipt::ReceiptError),
    #[error("bad archive: {0}")]
    BadArchive(String),
    #[error("bad signature: {0}")]
    BadSignature(String),
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

    verify_detached_sig(&archive_bytes, archive_path, sig_path)?;

    let entries = extract_ustar_gz(&archive_bytes)?;
    let manifest = parse_manifest(&entries)?;
    if manifest.product != "orca" {
        return Err(StageError::Manifest(format!(
            "product {}",
            manifest.product
        )));
    }
    let want_target = host_target_triple();
    if manifest.target != want_target && manifest.target != "any" && !manifest.target.is_empty() {
        // Allow test targets that start with "test-"
        if !manifest.target.starts_with("test-") {
            return Err(StageError::TargetMismatch {
                want: want_target,
                got: manifest.target,
            });
        }
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
    let bin_entry = entries
        .iter()
        .find(|e| e.path == "orca" || e.path == bin_name)
        .ok_or_else(|| StageError::BadArchive("missing orca binary entry".into()))?;

    let txn_id = format!("{}-{}", now_rfc3339(), &archive_sha256[..12]);
    let staged_root = layout.staging_dir.join(&txn_id);
    if staged_root.exists() {
        fs::remove_dir_all(&staged_root)?;
    }
    fs::create_dir_all(&staged_root)?;

    // Extract relative to staged_root (install_root is already bin/).
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

    // Retain archive bytes under state/host/archives.
    let retained = layout.archive_path(&archive_sha256);
    if !retained.exists() {
        fs::write(&retained, &archive_bytes)?;
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

    let sig_hex = sha256_hex(&sign_test_archive(&archive_bytes));
    let receipt = HostUpdateReceiptV1 {
        schema_version: RECEIPT_SCHEMA,
        product: "orca".into(),
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        archive_sha256: archive_sha256.clone(),
        archive_format: ARCHIVE_FORMAT_ID.into(),
        signature_algorithm: TEST_SIG_ALGORITHM.into(),
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
    // Crash at Staged abandons to old host — phase Staged means not yet applying.
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
    })
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
        let mode = u32::from_str_radix(mode_octal.trim_start_matches('0').get(..).unwrap_or("644"), 8)
            .unwrap_or(0o644);
        // If parse of full 4-digit
        let mode = u32::from_str_radix(mode_octal, 8).unwrap_or(mode);
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

fn verify_detached_sig(
    archive_bytes: &[u8],
    archive_path: &Path,
    sig_path: Option<&Path>,
) -> Result<(), StageError> {
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
    let expect = sign_test_archive(archive_bytes);
    if sig.as_slice() != expect.as_slice() {
        return Err(StageError::BadSignature("detached signature mismatch".into()));
    }
    Ok(())
}

/// Test-only detached signature: 64 bytes from two SHA-256 rounds (algorithm test-only-sha512-v1).
pub fn sign_test_archive(archive_bytes: &[u8]) -> [u8; 64] {
    let h1 = {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(archive_bytes);
        d.finalize()
    };
    let h2 = {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(b"test-only-sha512-v1");
        d.update(&h1);
        d.finalize()
    };
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h1);
    out[32..].copy_from_slice(&h2);
    out
}

// --- R5 ustar + gzip (store deflate) ---

#[derive(Clone)]
struct TarEntry {
    path: String,
    data: Vec<u8>,
    mode: u32,
    is_dir: bool,
}

/// Build a deterministic R5 archive for tests. Entries use relative path "orca" (not "bin/orca").
pub fn build_r5_archive(version: &str, target: &str, orca_bytes: &[u8]) -> Result<Vec<u8>, StageError> {
    let orca_hash = sha256_hex(orca_bytes);
    let manifest = HostManifestV1 {
        schema_version: 1,
        product: "orca".into(),
        version: version.into(),
        target: target.into(),
        entries: vec![
            HostManifestEntry {
                relative_path: "host-manifest.json".into(),
                mode_octal: "0644".into(),
                length: 0, // filled after
                content_sha256: String::new(),
            },
            HostManifestEntry {
                relative_path: "orca".into(),
                mode_octal: "0755".into(),
                length: orca_bytes.len() as u64,
                content_sha256: orca_hash,
            },
        ],
    };
    // Manifest without self hash first — finalize lengths
    let mut manifest = manifest;
manifest.entries = vec![HostManifestEntry {
        relative_path: "orca".into(),
        mode_octal: "0755".into(),
        length: orca_bytes.len() as u64,
        content_sha256: sha256_hex(orca_bytes),
    }];
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
    Ok(gzip_store(&tar))
}

pub fn write_sig_file(archive_path: &Path, archive_bytes: &[u8]) -> Result<PathBuf, StageError> {
    let sig = sign_test_archive(archive_bytes);
    let mut p = archive_path.as_os_str().to_os_string();
    p.push(".sig");
    let path = PathBuf::from(p);
    fs::write(&path, sig)?;
    Ok(path)
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
        let mode = if e.is_dir { e.mode } else { e.mode };
        write_octal(&mut hdr[100..108], mode as u64, 7);
        write_octal(&mut hdr[108..116], 0, 7); // uid
        write_octal(&mut hdr[116..124], 0, 7); // gid
        write_octal(&mut hdr[124..136], e.data.len() as u64, 11);
        write_octal(&mut hdr[136..148], 0, 11); // mtime
        // checksum placeholder spaces
        for b in &mut hdr[148..156] {
            *b = b' ';
        }
        hdr[156] = if e.is_dir { b'5' } else { b'0' };
        // magic ustar
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        // empty uname/gname
        let mut sum: u32 = 0;
        for b in &hdr {
            sum += *b as u32;
        }
        // checksum is 6 octal digits + NUL + space
        let cstr = format!("{sum:06o}");
        hdr[148..154].copy_from_slice(cstr.as_bytes());
        hdr[154] = 0;
        hdr[155] = b' ';
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&e.data);
        let pad = (512 - (e.data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    // two zero blocks
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

/// Gzip one member, FLG=0, MTIME=0, XFL=2, OS=255, store (non-compressed) deflate blocks.
fn gzip_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64 + data.len() / 65535 * 5);
    // header
    out.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255]);
    // deflate stored blocks
    let mut pos = 0;
    while pos < data.len() {
        let remaining = data.len() - pos;
        let chunk = remaining.min(65535);
        let is_last = pos + chunk >= data.len();
        let bfinal = if is_last { 1u8 } else { 0u8 };
        out.push(bfinal); // BTYPE=00 in low bits with bfinal
        let len = chunk as u16;
        let nlen = !len;
        out.push((len & 0xff) as u8);
        out.push((len >> 8) as u8);
        out.push((nlen & 0xff) as u8);
        out.push((nlen >> 8) as u8);
        out.extend_from_slice(&data[pos..pos + chunk]);
        pos += chunk;
    }
    if data.is_empty() {
        out.push(1); // final empty stored
        out.extend_from_slice(&[0, 0, 0xff, 0xff]);
    }
    let crc = crc32_ieee(data);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn extract_ustar_gz(archive: &[u8]) -> Result<Vec<TarEntry>, StageError> {
    let tar = gunzip_store(archive)?;
    parse_ustar(&tar)
}

fn gunzip_store(gz: &[u8]) -> Result<Vec<u8>, StageError> {
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
    // skip 10-byte header
    let mut i = 10usize;
    let mut out = Vec::new();
    loop {
        if i >= gz.len() {
            return Err(StageError::BadArchive("truncated deflate".into()));
        }
        let hdr = gz[i];
        i += 1;
        let bfinal = hdr & 1;
        let btype = (hdr >> 1) & 3;
        if btype != 0 {
            return Err(StageError::BadArchive(format!(
                "unsupported deflate BTYPE={btype} (fixtures use store)"
            )));
        }
        if i + 4 > gz.len() {
            return Err(StageError::BadArchive("truncated stored block".into()));
        }
        let len = u16::from_le_bytes([gz[i], gz[i + 1]]) as usize;
        let nlen = u16::from_le_bytes([gz[i + 2], gz[i + 3]]) as usize;
        i += 4;
        if (nlen as u16) != (!(len as u16)) {
            return Err(StageError::BadArchive("stored LEN/NLEN mismatch".into()));
        }
        if i + len > gz.len() {
            return Err(StageError::BadArchive("stored block OOB".into()));
        }
        out.extend_from_slice(&gz[i..i + len]);
        i += len;
        if bfinal == 1 {
            break;
        }
    }
    if i + 8 > gz.len() {
        return Err(StageError::BadArchive("missing gzip trailer".into()));
    }
    let crc = u32::from_le_bytes([gz[i], gz[i + 1], gz[i + 2], gz[i + 3]]);
    let isize = u32::from_le_bytes([gz[i + 4], gz[i + 5], gz[i + 6], gz[i + 7]]);
    if i + 8 != gz.len() {
        return Err(StageError::BadArchive("trailing bytes after gzip".into()));
    }
    if isize as usize != out.len() {
        return Err(StageError::BadArchive("ISIZE mismatch".into()));
    }
    if crc != crc32_ieee(&out) {
        return Err(StageError::BadArchive("CRC32 mismatch".into()));
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
        if typeflag == b'1' || typeflag == b'2' || typeflag == b'3' || typeflag == b'4' || typeflag == b'6' {
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
    // paths must be sorted
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
    // Ensure archiveSha256 is not embedded
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
    use tempfile::tempdir;

    fn test_layout(root: &Path) -> HostLayout {
        // Simulate ORCA_HOME layout
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

    #[test]
    fn stage_valid_archive() {
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"#!/bin/sh\necho va\n").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        write_sig_file(&ap, &bytes).unwrap();
        let staged = stage_archive(&layout, &ap, None, false).unwrap();
        assert_eq!(staged.receipt.version, "0.0.0-test-a");
        assert_eq!(staged.transaction.phase, TxnPhase::Staged);
        assert!(staged.staged_bin.is_file());
    }

    #[test]
    fn same_version_conflict() {
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        let a = build_r5_archive("1.0.0", "test-any", b"binary-a").unwrap();
        let b = build_r5_archive("1.0.0", "test-any", b"binary-b-different").unwrap();
        assert_ne!(sha256_hex(&a), sha256_hex(&b));
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &a).unwrap();
        write_sig_file(&ap, &a).unwrap();
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
        write_sig_file(&bp, &b).unwrap();
        let err = stage_archive(&layout, &bp, None, false).unwrap_err();
        assert!(matches!(err, StageError::VersionByteConflict(_)));
    }

    #[test]
    fn bad_signature_rejected() {
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
    }

    #[test]
    fn target_mismatch() {
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        let bytes = build_r5_archive("0.0.0-test-a", "windows-only-nope", b"x").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        write_sig_file(&ap, &bytes).unwrap();
        let err = stage_archive(&layout, &ap, None, false).unwrap_err();
        assert!(matches!(err, StageError::TargetMismatch { .. }));
    }

    #[test]
    fn running_path_mismatch() {
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        // Create managed bin different from current_exe
        fs::write(&layout.managed_bin, b"managed").unwrap();
        let bytes = build_r5_archive("0.0.0-test-a", "test-any", b"x").unwrap();
        let ap = dir.path().join("a.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        write_sig_file(&ap, &bytes).unwrap();
        let err = stage_archive(&layout, &ap, None, true).unwrap_err();
        assert!(matches!(err, StageError::RunningPathMismatch { .. }));
    }

    #[test]
    fn crash_staged_abandons_old_host() {
        let dir = tempdir().unwrap();
        let layout = test_layout(dir.path());
        layout.ensure_dirs().unwrap();
        // Install "old" host
        fs::write(&layout.managed_bin, b"old-host").unwrap();
        let bytes = build_r5_archive("0.0.0-test-b", "test-any", b"new-host").unwrap();
        let ap = dir.path().join("b.tar.gz");
        fs::write(&ap, &bytes).unwrap();
        write_sig_file(&ap, &bytes).unwrap();
        let staged = stage_archive(&layout, &ap, None, false).unwrap();
        assert_eq!(staged.transaction.phase, TxnPhase::Staged);
        // Simulate crash: do not apply. Old host remains.
        assert_eq!(fs::read(&layout.managed_bin).unwrap(), b"old-host");
        // Recovery: Staged txn is abandoned (not Applying/Committed).
        let txn = HostUpdateTransactionV1::load(&staged.txn_path).unwrap();
        assert_eq!(txn.phase, TxnPhase::Staged);
    }
}
