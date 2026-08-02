// allow: SIZE_OK — plan Task 3 owns a single import_grok.rs; preview/confirm/apply + secret gates are one transaction surface.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use xai_grok_config::{
    OrcaPathError, OrcaPaths, default_grok_home, ensure_private_dir, path_has_symlink_or_reparse,
    resolve_orca_paths_current,
};

pub const IMPORTABLE_REL_PATHS: &[&str] = &["config.toml", "pager.toml"];
pub const EXIT_OK: i32 = 0;
pub const EXIT_REFUSED: i32 = 2;

const SECRET_BASENAMES: &[&str] = &[
    "auth.json",
    "credentials",
    "credentials.json",
    "token",
    "tokens",
    "token.json",
    "tokens.json",
    "oauth.json",
    "secrets.toml",
    "id_rsa",
    "id_ed25519",
    "private_key",
    "private-key.pem",
];
const SECRET_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "bearer ",
    "-----begin ",
];

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("source Grok home not found: {0}")]
    SourceMissing(String),
    #[error("source path contains symlink or reparse point: {0}")]
    SourceSymlink(String),
    #[error("secret candidate refused: {0}")]
    SecretCandidate(String),
    #[error("preview digest mismatch: expected {expected}, got {got}")]
    StaleDigest { expected: String, got: String },
    #[error("destination conflict (exists and differs): {0}")]
    Conflict(String),
    #[error("path error: {0}")]
    Path(#[from] OrcaPathError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("write failure: {0}")]
    WriteFailure(String),
    #[error("no importable preferences found under {0}")]
    EmptyInventory(String),
    #[error("usage: orca import grok --preview | --confirm <digest>")]
    Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportEntry {
    pub relative_path: String,
    pub source_sha256: String,
    pub byte_len: u64,
    pub dest_relative: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub schema_version: u32,
    pub kind: String,
    pub source_root: String,
    pub source_root_sha256: String,
    pub entries: Vec<ImportEntry>,
    pub orca_config_file: String,
    pub orca_data_root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportApplyResult {
    pub schema_version: u32,
    pub kind: String,
    pub preview_digest: String,
    pub written: Vec<String>,
    pub backup_dir: String,
    pub source_hashes_unchanged: bool,
}

pub fn try_run_from_args<I, S>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if args.first().map(String::as_str) != Some("import") {
        return None;
    }
    if args.get(1).map(String::as_str) != Some("grok") {
        eprintln!("error: only `orca import grok` is supported");
        return Some(EXIT_REFUSED);
    }
    match run_import(&args[2..]) {
        Ok(()) => Some(EXIT_OK),
        Err(ImportError::Usage) => {
            eprintln!("usage: orca import grok --preview | --confirm <digest>");
            Some(EXIT_REFUSED)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Some(EXIT_REFUSED)
        }
    }
}

fn run_import(args: &[String]) -> Result<(), ImportError> {
    let mut preview = false;
    let mut confirm: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preview" => {
                if confirm.is_some() {
                    return Err(ImportError::Usage);
                }
                preview = true;
            }
            "--confirm" => {
                i += 1;
                let d = args.get(i).ok_or(ImportError::Usage)?;
                if preview {
                    return Err(ImportError::Usage);
                }
                confirm = Some(d.clone());
            }
            _ => return Err(ImportError::Usage),
        }
        i += 1;
    }
    let source = resolve_import_source_grok_home();
    let orca = resolve_orca_paths_current()?;
    match (preview, confirm) {
        (true, None) => {
            let p = preview_import(&source, &orca)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&p)
                    .map_err(|e| ImportError::WriteFailure(format!("serialize: {e}")))?
            );
            Ok(())
        }
        (false, Some(digest)) => {
            let result = confirm_import(&source, &orca, &digest)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .map_err(|e| ImportError::WriteFailure(format!("serialize: {e}")))?
            );
            Ok(())
        }
        _ => Err(ImportError::Usage),
    }
}

pub fn preview_import(
    source_grok_home: &Path,
    orca: &OrcaPaths,
) -> Result<ImportPreview, ImportError> {
    validate_source_root(source_grok_home)?;
    let mut entries = Vec::new();
    for rel in IMPORTABLE_REL_PATHS {
        let src = source_grok_home.join(rel);
        if !src.exists() {
            continue;
        }
        if path_has_symlink_or_reparse(&src) {
            return Err(ImportError::SourceSymlink(src.display().to_string()));
        }
        let bytes = fs::read(&src)?;
        refuse_if_secret(rel, &bytes)?;
        let dest_rel = if *rel == "config.toml" {
            "config.toml".into()
        } else {
            format!("imported/{rel}")
        };
        entries.push(ImportEntry {
            relative_path: (*rel).into(),
            source_sha256: sha256_hex(&bytes),
            byte_len: bytes.len() as u64,
            dest_relative: dest_rel,
        });
    }
    if entries.is_empty() {
        return Err(ImportError::EmptyInventory(
            source_grok_home.display().to_string(),
        ));
    }
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    let source_root_sha256 = hash_source_root(source_grok_home, &entries);
    let mut preview = ImportPreview {
        schema_version: 1,
        kind: "GrokImportPreviewV1".into(),
        source_root: source_grok_home.display().to_string(),
        source_root_sha256,
        entries,
        orca_config_file: orca.config_file.display().to_string(),
        orca_data_root: orca.data_root.display().to_string(),
        preview_digest: String::new(),
    };
    preview.preview_digest = compute_preview_digest(&preview)?;
    Ok(preview)
}

pub fn confirm_import(
    source_grok_home: &Path,
    orca: &OrcaPaths,
    expected_digest: &str,
) -> Result<ImportApplyResult, ImportError> {
    confirm_import_with_writer(source_grok_home, orca, expected_digest, |dest, bytes| {
        atomic_write(dest, bytes).map_err(|e| ImportError::WriteFailure(e.to_string()))
    })
}

pub fn confirm_import_with_writer<W>(
    source_grok_home: &Path,
    orca: &OrcaPaths,
    expected_digest: &str,
    mut writer: W,
) -> Result<ImportApplyResult, ImportError>
where
    W: FnMut(&Path, &[u8]) -> Result<(), ImportError>,
{
    let preview = preview_import(source_grok_home, orca)?;
    if preview.preview_digest != expected_digest {
        return Err(ImportError::StaleDigest {
            expected: expected_digest.into(),
            got: preview.preview_digest,
        });
    }
    let mut planned = Vec::new();
    for entry in &preview.entries {
        let src = source_grok_home.join(&entry.relative_path);
        if path_has_symlink_or_reparse(&src) {
            return Err(ImportError::SourceSymlink(src.display().to_string()));
        }
        let bytes = fs::read(&src)?;
        let hash = sha256_hex(&bytes);
        if hash != entry.source_sha256 {
            return Err(ImportError::StaleDigest {
                expected: entry.source_sha256.clone(),
                got: hash,
            });
        }
        refuse_if_secret(&entry.relative_path, &bytes)?;
        let dest = dest_path(orca, &entry.dest_relative);
        if dest.exists() && fs::read(&dest)? != bytes {
            return Err(ImportError::Conflict(dest.display().to_string()));
        }
        planned.push((entry.relative_path.clone(), bytes, dest));
    }

    let prefix = &preview.preview_digest[..16.min(preview.preview_digest.len())];
    let backup_dir = orca.import_backup_dir().join(prefix);
    if let Some(parent) = backup_dir.parent() {
        ensure_private_dir(parent)?;
    }
    ensure_private_dir(&backup_dir)?;
    let staging = orca.data_root.join(".staging").join("import-grok");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    ensure_private_dir(&staging)?;

    let mut written = Vec::new();
    for (rel, bytes, dest) in &planned {
        if dest.exists() {
            written.push(dest.display().to_string());
            continue;
        }
        if let Some(parent) = dest.parent() {
            ensure_private_dir(parent)?;
        }
        fs::write(backup_dir.join(rel.replace('/', "__")), b"")?;
        let stage = staging.join(rel.replace('/', "__"));
        writer(&stage, bytes)?;
        fs::rename(&stage, dest)
            .or_else(|_| fs::copy(&stage, dest).and_then(|_| fs::remove_file(&stage)))?;
        written.push(dest.display().to_string());
    }

    for entry in &preview.entries {
        let bytes = fs::read(source_grok_home.join(&entry.relative_path))?;
        if sha256_hex(&bytes) != entry.source_sha256 {
            return Err(ImportError::WriteFailure(
                "source hash changed during import".into(),
            ));
        }
    }
    let _ = fs::remove_dir_all(&staging);
    Ok(ImportApplyResult {
        schema_version: 1,
        kind: "GrokImportApplyResultV1".into(),
        preview_digest: preview.preview_digest.clone(),
        written,
        backup_dir: backup_dir.display().to_string(),
        source_hashes_unchanged: true,
    })
}

fn dest_path(orca: &OrcaPaths, dest_relative: &str) -> PathBuf {
    if dest_relative == "config.toml" {
        orca.config_file.clone()
    } else {
        orca.data_root.join(dest_relative)
    }
}

fn validate_source_root(source: &Path) -> Result<(), ImportError> {
    if !source.is_absolute() {
        return Err(ImportError::Path(OrcaPathError::NotAbsolute(
            source.display().to_string(),
        )));
    }
    if path_has_symlink_or_reparse(source) {
        return Err(ImportError::SourceSymlink(source.display().to_string()));
    }
    if !source.is_dir() {
        return Err(ImportError::SourceMissing(source.display().to_string()));
    }
    Ok(())
}

fn refuse_if_secret(rel: &str, bytes: &[u8]) -> Result<(), ImportError> {
    let base = Path::new(rel)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(rel)
        .to_ascii_lowercase();
    if SECRET_BASENAMES.contains(&base.as_str()) || base.ends_with(".pem") || base.ends_with(".key")
    {
        return Err(ImportError::SecretCandidate(rel.into()));
    }
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for marker in SECRET_MARKERS {
        if lower.contains(marker) {
            return Err(ImportError::SecretCandidate(format!(
                "{rel} (content marker {marker})"
            )));
        }
    }
    Ok(())
}

fn hash_source_root(source: &Path, entries: &[ImportEntry]) -> String {
    let mut h = Sha256::new();
    h.update(source.display().to_string().as_bytes());
    for e in entries {
        h.update(e.relative_path.as_bytes());
        h.update(e.source_sha256.as_bytes());
    }
    hex_encode(h.finalize())
}

fn compute_preview_digest(preview: &ImportPreview) -> Result<String, ImportError> {
    let mut for_hash = preview.clone();
    for_hash.preview_digest.clear();
    let json = serde_json::to_vec(&for_hash)
        .map_err(|e| ImportError::WriteFailure(format!("serialize preview: {e}")))?;
    Ok(sha256_hex(&json))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(h.finalize())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).or_else(|_| {
        fs::copy(&tmp, path)?;
        fs::remove_file(&tmp)?;
        Ok(())
    })
}

pub fn resolve_import_source_grok_home() -> PathBuf {
    std::env::var("GROK_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_grok_home())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xai_grok_config::{OrcaPathEnv, OrcaPlatform, resolve_orca_paths};

    fn setup() -> (tempfile::TempDir, PathBuf, OrcaPaths) {
        let tmp = tempfile::TempDir::new().unwrap();
        let grok = tmp.path().join("grok");
        let orca_home = tmp.path().join("orca");
        fs::create_dir_all(&grok).unwrap();
        fs::write(grok.join("config.toml"), b"[cli]\ntheme = \"dark\"\n").unwrap();
        let env = OrcaPathEnv {
            orca_home: Some(orca_home),
            home: Some(tmp.path().join("home")),
            uid: Some(1000),
            tmpdir: Some(tmp.path().join("tmp")),
            ..OrcaPathEnv::default()
        };
        let paths = resolve_orca_paths(OrcaPlatform::current(), &env).unwrap();
        (tmp, grok, paths)
    }

    #[test]
    fn preview_writes_nothing() {
        let (_t, grok, orca) = setup();
        let p = preview_import(&grok, &orca).unwrap();
        assert!(!p.preview_digest.is_empty());
        assert!(!orca.config_file.exists());
    }

    #[test]
    fn confirm_applies_source_unchanged() {
        let (_t, grok, orca) = setup();
        let src = sha256_hex(&fs::read(grok.join("config.toml")).unwrap());
        let p = preview_import(&grok, &orca).unwrap();
        let r = confirm_import(&grok, &orca, &p.preview_digest).unwrap();
        assert!(r.source_hashes_unchanged);
        assert!(orca.config_file.exists());
        assert_eq!(
            sha256_hex(&fs::read(grok.join("config.toml")).unwrap()),
            src
        );
    }

    #[test]
    fn stale_digest_refused() {
        let (_t, grok, orca) = setup();
        assert!(matches!(
            confirm_import(&grok, &orca, "deadbeef"),
            Err(ImportError::StaleDigest { .. })
        ));
        assert!(!orca.config_file.exists());
    }

    #[test]
    fn secret_content_refused() {
        let (_t, grok, orca) = setup();
        fs::write(grok.join("config.toml"), b"api_key = \"sk-x\"\n").unwrap();
        assert!(matches!(
            preview_import(&grok, &orca),
            Err(ImportError::SecretCandidate(_))
        ));
    }

    #[test]
    fn conflict_refused() {
        let (_t, grok, orca) = setup();
        if let Some(p) = orca.config_file.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(&orca.config_file, b"[cli]\ntheme = \"light\"\n").unwrap();
        let p = preview_import(&grok, &orca).unwrap();
        assert!(matches!(
            confirm_import(&grok, &orca, &p.preview_digest),
            Err(ImportError::Conflict(_))
        ));
    }

    #[test]
    fn injected_write_failure() {
        let (_t, grok, orca) = setup();
        let p = preview_import(&grok, &orca).unwrap();
        let err = confirm_import_with_writer(&grok, &orca, &p.preview_digest, |_, _| {
            Err(ImportError::WriteFailure("injected".into()))
        });
        assert!(matches!(err, Err(ImportError::WriteFailure(_))));
        assert!(!orca.config_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real");
        let link = tmp.path().join("link");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("config.toml"), b"[cli]\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let env = OrcaPathEnv {
            orca_home: Some(tmp.path().join("orca")),
            home: Some(tmp.path().join("home")),
            uid: Some(1),
            tmpdir: Some(tmp.path().join("t")),
            ..OrcaPathEnv::default()
        };
        let orca = resolve_orca_paths(OrcaPlatform::current(), &env).unwrap();
        assert!(matches!(
            preview_import(&link, &orca),
            Err(ImportError::SourceSymlink(_))
        ));
    }

    #[test]
    fn try_run_ignores_non_import() {
        assert!(try_run_from_args(["--help"]).is_none());
        assert!(try_run_from_args(["version"]).is_none());
    }
}
