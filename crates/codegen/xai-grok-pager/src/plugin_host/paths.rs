use std::path::{Path, PathBuf};
use xai_grok_config::{
    OrcaPathError, OrcaPaths, resolve_orca_paths_current, validate_runtime_root,
};

#[derive(Debug, Clone)]
pub struct HostPaths {
    inner: OrcaPaths,
}

impl HostPaths {
    pub fn resolve() -> Result<Self, OrcaPathError> {
        let inner = resolve_orca_paths_current()?;
        if inner.runtime_root.exists() {
            validate_runtime_root(&inner.runtime_root)?;
        }
        Ok(Self { inner })
    }
    pub fn as_orca_paths(&self) -> &OrcaPaths {
        &self.inner
    }
    pub fn config_file(&self) -> &Path {
        &self.inner.config_file
    }
    pub fn data_root(&self) -> &Path {
        &self.inner.data_root
    }
    pub fn state_root(&self) -> &Path {
        &self.inner.state_root
    }
    pub fn cache_root(&self) -> &Path {
        &self.inner.cache_root
    }
    pub fn runtime_root(&self) -> &Path {
        &self.inner.runtime_root
    }
    pub fn logs_dir(&self) -> &Path {
        &self.inner.logs_dir
    }
    pub fn plugins_dir(&self) -> PathBuf {
        self.inner.plugins_dir()
    }
    pub fn plugins_data_dir(&self) -> PathBuf {
        self.inner.plugins_data_dir()
    }
    pub fn plugins_registry_path(&self) -> PathBuf {
        self.inner.plugins_registry_path()
    }
    pub fn backend_default_path(&self) -> PathBuf {
        self.inner.backend_default_path()
    }
    pub fn session_pins_dir(&self) -> PathBuf {
        self.inner.session_pins_dir()
    }
    pub fn backend_runtime_dir(&self, cohort_key: &str) -> PathBuf {
        self.inner.backend_runtime_dir(cohort_key)
    }
}

pub fn host_orca_paths() -> Result<HostPaths, OrcaPathError> {
    HostPaths::resolve()
}
