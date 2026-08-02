// allow: SIZE_OK — plan Task 3 single-file path table + secure runtime for three OS schemas.

use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrcaPlatform {
    Linux,
    Macos,
    Windows,
}

impl OrcaPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OrcaPathEnv {
    pub home: Option<PathBuf>,
    pub orca_home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
    pub xdg_cache_home: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
    pub tmpdir: Option<PathBuf>,
    pub appdata: Option<PathBuf>,
    pub local_appdata: Option<PathBuf>,
    pub uid: Option<u32>,
}

impl OrcaPathEnv {
    pub fn from_process() -> Self {
        Self {
            home: env::var_os("HOME")
                .or_else(|| env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .or_else(|| {
                    #[allow(deprecated)]
                    env::home_dir()
                }),
            orca_home: env::var_os("ORCA_HOME").map(PathBuf::from),
            xdg_config_home: env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            xdg_data_home: env::var_os("XDG_DATA_HOME").map(PathBuf::from),
            xdg_state_home: env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            xdg_cache_home: env::var_os("XDG_CACHE_HOME").map(PathBuf::from),
            xdg_runtime_dir: env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            tmpdir: env::var_os("TMPDIR")
                .or_else(|| env::var_os("TMP"))
                .or_else(|| env::var_os("TEMP"))
                .map(PathBuf::from),
            appdata: env::var_os("APPDATA").map(PathBuf::from),
            local_appdata: env::var_os("LOCALAPPDATA").map(PathBuf::from),
            uid: current_uid(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrcaPaths {
    pub config_file: PathBuf,
    pub data_root: PathBuf,
    pub state_root: PathBuf,
    pub cache_root: PathBuf,
    pub runtime_root: PathBuf,
    pub logs_dir: PathBuf,
    pub from_orca_home: bool,
}

impl OrcaPaths {
    pub fn plugins_dir(&self) -> PathBuf {
        self.data_root.join("plugins")
    }
    pub fn plugins_cache_dir(&self) -> PathBuf {
        self.plugins_dir().join("cache")
    }
    pub fn plugins_staging_dir(&self) -> PathBuf {
        self.plugins_dir().join(".staging")
    }
    pub fn plugins_data_dir(&self) -> PathBuf {
        self.data_root.join("plugins-data")
    }
    pub fn plugins_registry_path(&self) -> PathBuf {
        self.state_root.join("plugins").join("registry-v2.json")
    }
    pub fn plugins_transactions_dir(&self) -> PathBuf {
        self.state_root.join("plugins").join("transactions")
    }
    pub fn backend_default_path(&self) -> PathBuf {
        self.state_root.join("backend-default.json")
    }
    pub fn session_pins_dir(&self) -> PathBuf {
        self.state_root.join("session-pins")
    }
    pub fn plugin_downloads_dir(&self) -> PathBuf {
        self.cache_root.join("plugin-downloads")
    }
    pub fn backend_runtime_dir(&self, cohort_key: &str) -> PathBuf {
        self.runtime_root.join("backends").join(cohort_key)
    }
    pub fn import_backup_dir(&self) -> PathBuf {
        self.state_root.join("import-backups")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OrcaPathError {
    #[error("home directory is required for Orca path resolution")]
    MissingHome,
    #[error("ORCA_HOME must be an absolute path: {0}")]
    OrcaHomeNotAbsolute(String),
    #[error("path must be absolute: {0}")]
    NotAbsolute(String),
    #[error("insecure runtime directory: {path}: {reason}")]
    InsecureRuntime { path: String, reason: String },
    #[error("path contains a symlink or reparse point: {0}")]
    SymlinkOrReparse(String),
    #[error("cwd-relative state path rejected: {0}")]
    CwdRelative(String),
}

pub fn resolve_orca_paths(
    platform: OrcaPlatform,
    env: &OrcaPathEnv,
) -> Result<OrcaPaths, OrcaPathError> {
    if let Some(orca_home) = &env.orca_home {
        return resolve_orca_home_override(orca_home);
    }
    let home = env.home.as_ref().ok_or(OrcaPathError::MissingHome)?.clone();
    require_absolute(&home, "HOME")?;
    match platform {
        OrcaPlatform::Linux => Ok(resolve_linux(&home, env)),
        OrcaPlatform::Macos => Ok(resolve_macos(&home, env)),
        OrcaPlatform::Windows => resolve_windows(&home, env),
    }
}

pub fn resolve_orca_paths_current() -> Result<OrcaPaths, OrcaPathError> {
    resolve_orca_paths(OrcaPlatform::current(), &OrcaPathEnv::from_process())
}

fn resolve_orca_home_override(orca_home: &Path) -> Result<OrcaPaths, OrcaPathError> {
    require_absolute(orca_home, "ORCA_HOME")?;
    if orca_home.components().any(|c| {
        matches!(
            c,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(OrcaPathError::CwdRelative(orca_home.display().to_string()));
    }
    let state = orca_home.join("state");
    Ok(OrcaPaths {
        config_file: orca_home.join("config.toml"),
        data_root: orca_home.join("data"),
        state_root: state.clone(),
        cache_root: orca_home.join("cache"),
        runtime_root: orca_home.join("runtime"),
        logs_dir: state.join("logs"),
        from_orca_home: true,
    })
}

fn resolve_linux(home: &Path, env: &OrcaPathEnv) -> OrcaPaths {
    let config_home = env
        .xdg_config_home
        .clone()
        .unwrap_or_else(|| home.join(".config"));
    let data_home = env
        .xdg_data_home
        .clone()
        .unwrap_or_else(|| home.join(".local").join("share"));
    let state_home = env
        .xdg_state_home
        .clone()
        .unwrap_or_else(|| home.join(".local").join("state"));
    let cache_home = env
        .xdg_cache_home
        .clone()
        .unwrap_or_else(|| home.join(".cache"));
    let uid = env.uid.unwrap_or(0);
    let runtime_root = match &env.xdg_runtime_dir {
        Some(r) => r.join("orca"),
        None => env
            .tmpdir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(format!("orca-{uid}")),
    };
    let state_root = state_home.join("orca");
    OrcaPaths {
        config_file: config_home.join("orca").join("config.toml"),
        data_root: data_home.join("orca"),
        state_root: state_root.clone(),
        cache_root: cache_home.join("orca"),
        runtime_root,
        logs_dir: state_root.join("logs"),
        from_orca_home: false,
    }
}

fn resolve_macos(home: &Path, env: &OrcaPathEnv) -> OrcaPaths {
    let app = home
        .join("Library")
        .join("Application Support")
        .join("Orca");
    let uid = env.uid.unwrap_or(0);
    let tmp = env.tmpdir.clone().unwrap_or_else(|| PathBuf::from("/tmp"));
    OrcaPaths {
        config_file: app.join("config.toml"),
        data_root: app.clone(),
        state_root: app.join("state"),
        cache_root: home.join("Library").join("Caches").join("Orca"),
        runtime_root: tmp.join(format!("orca-{uid}")),
        logs_dir: home.join("Library").join("Logs").join("Orca"),
        from_orca_home: false,
    }
}

fn win_join(base: &Path, parts: &[&str]) -> PathBuf {
    let mut s = base.to_string_lossy().replace('/', "\\");
    while s.ends_with('\\') {
        s.pop();
    }
    for p in parts {
        s.push('\\');
        s.push_str(p);
    }
    PathBuf::from(s)
}

fn resolve_windows(home: &Path, env: &OrcaPathEnv) -> Result<OrcaPaths, OrcaPathError> {
    let appdata = env
        .appdata
        .clone()
        .unwrap_or_else(|| win_join(home, &["AppData", "Roaming"]));
    let local = env
        .local_appdata
        .clone()
        .unwrap_or_else(|| win_join(home, &["AppData", "Local"]));
    require_absolute(&appdata, "APPDATA")?;
    require_absolute(&local, "LOCALAPPDATA")?;
    let state_root = win_join(&local, &["Orca", "state"]);
    Ok(OrcaPaths {
        config_file: win_join(&appdata, &["Orca", "config.toml"]),
        data_root: win_join(&local, &["Orca", "data"]),
        state_root: state_root.clone(),
        cache_root: win_join(&local, &["Orca", "cache"]),
        runtime_root: win_join(&local, &["Orca", "runtime"]),
        logs_dir: win_join(&state_root, &["logs"]),
        from_orca_home: false,
    })
}

fn path_is_absolute(path: &Path) -> bool {
    if path.is_absolute() {
        return true;
    }
    let s = path.to_string_lossy();
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn require_absolute(path: &Path, label: &str) -> Result<(), OrcaPathError> {
    if path.as_os_str().is_empty() {
        return Err(OrcaPathError::MissingHome);
    }
    if !path_is_absolute(path) {
        if label == "ORCA_HOME" {
            return Err(OrcaPathError::OrcaHomeNotAbsolute(
                path.display().to_string(),
            ));
        }
        return Err(OrcaPathError::NotAbsolute(format!(
            "{label}={}",
            path.display()
        )));
    }
    Ok(())
}

fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub fn validate_runtime_root(path: &Path) -> Result<(), OrcaPathError> {
    if !path_is_absolute(path) {
        return Err(OrcaPathError::CwdRelative(path.display().to_string()));
    }
    if path_has_symlink_or_reparse(path) {
        return Err(OrcaPathError::SymlinkOrReparse(path.display().to_string()));
    }
    if !path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).map_err(|e| OrcaPathError::InsecureRuntime {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        if !meta.file_type().is_dir() {
            return Err(OrcaPathError::InsecureRuntime {
                path: path.display().to_string(),
                reason: "not a directory".into(),
            });
        }
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(OrcaPathError::InsecureRuntime {
                path: path.display().to_string(),
                reason: format!("mode {mode:04o} allows group/other access"),
            });
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(OrcaPathError::InsecureRuntime {
                path: path.display().to_string(),
                reason: format!("owner uid {} != euid {euid}", meta.uid()),
            });
        }
    }
    #[cfg(windows)]
    {
        let meta = std::fs::symlink_metadata(path).map_err(|e| OrcaPathError::InsecureRuntime {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(OrcaPathError::InsecureRuntime {
                path: path.display().to_string(),
                reason: "symlink or not a directory".into(),
            });
        }
    }
    Ok(())
}

fn is_system_firmlink(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some("/tmp")
            | Some("/var")
            | Some("/etc")
            | Some("/private/tmp")
            | Some("/private/var")
            | Some("/private/etc")
    )
}

pub fn path_has_symlink_or_reparse(path: &Path) -> bool {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                if is_system_firmlink(&cur) {
                    continue;
                }
                return true;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    false
}

pub fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    if path_has_symlink_or_reparse(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("symlink/reparse in path: {}", path.display()),
        ));
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    validate_runtime_root(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
    Ok(())
}
