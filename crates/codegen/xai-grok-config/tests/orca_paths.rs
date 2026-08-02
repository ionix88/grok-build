//! Path table + security tests for `orca_paths`.

use std::path::PathBuf;
use xai_grok_config::{
    OrcaPathEnv, OrcaPathError, OrcaPlatform, ensure_private_dir, resolve_orca_paths,
    validate_runtime_root,
};

fn env_with_home(home: &str) -> OrcaPathEnv {
    OrcaPathEnv {
        home: Some(PathBuf::from(home)),
        uid: Some(501),
        tmpdir: Some(PathBuf::from("/var/tmp")),
        ..OrcaPathEnv::default()
    }
}

#[test]
fn linux_xdg_defaults_match_table() {
    let p = resolve_orca_paths(OrcaPlatform::Linux, &env_with_home("/home/alice")).unwrap();
    assert_eq!(
        p.config_file,
        PathBuf::from("/home/alice/.config/orca/config.toml")
    );
    assert_eq!(p.data_root, PathBuf::from("/home/alice/.local/share/orca"));
    assert_eq!(p.state_root, PathBuf::from("/home/alice/.local/state/orca"));
    assert_eq!(p.cache_root, PathBuf::from("/home/alice/.cache/orca"));
    assert_eq!(p.runtime_root, PathBuf::from("/var/tmp/orca-501"));
    assert_eq!(
        p.logs_dir,
        PathBuf::from("/home/alice/.local/state/orca/logs")
    );
    assert!(!p.from_orca_home);
}

#[test]
fn linux_xdg_env_overrides() {
    let mut env = env_with_home("/home/alice");
    env.xdg_config_home = Some(PathBuf::from("/cfg"));
    env.xdg_data_home = Some(PathBuf::from("/data"));
    env.xdg_state_home = Some(PathBuf::from("/state"));
    env.xdg_cache_home = Some(PathBuf::from("/cache"));
    env.xdg_runtime_dir = Some(PathBuf::from("/run/user/501"));
    let p = resolve_orca_paths(OrcaPlatform::Linux, &env).unwrap();
    assert_eq!(p.config_file, PathBuf::from("/cfg/orca/config.toml"));
    assert_eq!(p.data_root, PathBuf::from("/data/orca"));
    assert_eq!(p.state_root, PathBuf::from("/state/orca"));
    assert_eq!(p.cache_root, PathBuf::from("/cache/orca"));
    assert_eq!(p.runtime_root, PathBuf::from("/run/user/501/orca"));
}

#[test]
fn macos_library_schema_match_table() {
    let p = resolve_orca_paths(OrcaPlatform::Macos, &env_with_home("/Users/alice")).unwrap();
    assert_eq!(
        p.config_file,
        PathBuf::from("/Users/alice/Library/Application Support/Orca/config.toml")
    );
    assert_eq!(
        p.data_root,
        PathBuf::from("/Users/alice/Library/Application Support/Orca")
    );
    assert_eq!(
        p.state_root,
        PathBuf::from("/Users/alice/Library/Application Support/Orca/state")
    );
    assert_eq!(
        p.cache_root,
        PathBuf::from("/Users/alice/Library/Caches/Orca")
    );
    assert_eq!(p.runtime_root, PathBuf::from("/var/tmp/orca-501"));
    assert_eq!(p.logs_dir, PathBuf::from("/Users/alice/Library/Logs/Orca"));
}

#[test]
fn windows_schema_match_table() {
    let mut env = env_with_home(r"C:\Users\alice");
    env.appdata = Some(PathBuf::from(r"C:\Users\alice\AppData\Roaming"));
    env.local_appdata = Some(PathBuf::from(r"C:\Users\alice\AppData\Local"));
    let p = resolve_orca_paths(OrcaPlatform::Windows, &env).unwrap();
    assert_eq!(
        p.config_file,
        PathBuf::from(r"C:\Users\alice\AppData\Roaming\Orca\config.toml")
    );
    assert_eq!(
        p.data_root,
        PathBuf::from(r"C:\Users\alice\AppData\Local\Orca\data")
    );
    assert_eq!(
        p.state_root,
        PathBuf::from(r"C:\Users\alice\AppData\Local\Orca\state")
    );
    assert_eq!(
        p.cache_root,
        PathBuf::from(r"C:\Users\alice\AppData\Local\Orca\cache")
    );
    assert_eq!(
        p.runtime_root,
        PathBuf::from(r"C:\Users\alice\AppData\Local\Orca\runtime")
    );
    assert_eq!(
        p.logs_dir,
        PathBuf::from(r"C:\Users\alice\AppData\Local\Orca\state\logs")
    );
}

#[test]
fn orca_home_override_is_portable_layout() {
    let mut env = env_with_home("/home/alice");
    env.orca_home = Some(PathBuf::from("/tmp/orca-test-home"));
    let p = resolve_orca_paths(OrcaPlatform::Linux, &env).unwrap();
    assert!(p.from_orca_home);
    assert_eq!(
        p.config_file,
        PathBuf::from("/tmp/orca-test-home/config.toml")
    );
    assert_eq!(p.data_root, PathBuf::from("/tmp/orca-test-home/data"));
    assert_eq!(p.state_root, PathBuf::from("/tmp/orca-test-home/state"));
    assert_eq!(p.cache_root, PathBuf::from("/tmp/orca-test-home/cache"));
    assert_eq!(p.runtime_root, PathBuf::from("/tmp/orca-test-home/runtime"));
    assert_eq!(p.logs_dir, PathBuf::from("/tmp/orca-test-home/state/logs"));
}

#[test]
fn orca_home_relative_rejected() {
    let mut env = env_with_home("/home/alice");
    env.orca_home = Some(PathBuf::from("relative/orca"));
    let err = resolve_orca_paths(OrcaPlatform::Linux, &env).unwrap_err();
    assert!(matches!(
        err,
        OrcaPathError::NotAbsolute(_) | OrcaPathError::OrcaHomeNotAbsolute(_)
    ));
}

#[test]
fn never_aliases_grok_home_env() {
    let prev = std::env::var_os("GROK_HOME");
    unsafe { std::env::set_var("GROK_HOME", "/tmp/should-not-be-used-as-orca") };
    let p = resolve_orca_paths(OrcaPlatform::Linux, &env_with_home("/home/alice")).unwrap();
    assert!(!p.data_root.starts_with("/tmp/should-not-be-used-as-orca"));
    assert!(!p.config_file.display().to_string().contains(".grok"));
    match prev {
        Some(v) => unsafe { std::env::set_var("GROK_HOME", v) },
        None => unsafe { std::env::remove_var("GROK_HOME") },
    }
}

#[test]
fn plugin_layout_helpers() {
    let p = resolve_orca_paths(OrcaPlatform::Linux, &env_with_home("/home/alice")).unwrap();
    assert_eq!(
        p.plugins_cache_dir(),
        PathBuf::from("/home/alice/.local/share/orca/plugins/cache")
    );
    assert_eq!(
        p.plugins_registry_path(),
        PathBuf::from("/home/alice/.local/state/orca/plugins/registry-v2.json")
    );
    assert_eq!(
        p.backend_runtime_dir("cohort-1"),
        PathBuf::from("/var/tmp/orca-501/backends/cohort-1")
    );
}

#[test]
fn insecure_runtime_group_writable_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = tmp.path().join("rt");
    std::fs::create_dir_all(&rt).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = validate_runtime_root(&rt).unwrap_err();
        assert!(matches!(err, OrcaPathError::InsecureRuntime { .. }));
    }
}

#[cfg(unix)]
#[test]
fn secure_runtime_owner_only_ok() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = tmp.path().join("rt");
    ensure_private_dir(&rt).unwrap();
    validate_runtime_root(&rt).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_in_runtime_path_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real = tmp.path().join("real");
    let link = tmp.path().join("link");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = validate_runtime_root(&link).unwrap_err();
    assert!(matches!(err, OrcaPathError::SymlinkOrReparse(_)));
}

#[test]
fn startup_sentinel_no_grok_home_access() {
    let tmp = tempfile::TempDir::new().unwrap();
    let grok = tmp.path().join("grok-home-probe");
    let marker = tmp.path().join("marker");
    std::fs::write(&marker, b"untouched").unwrap();
    assert!(!grok.exists());

    let prev = std::env::var_os("GROK_HOME");
    unsafe { std::env::set_var("GROK_HOME", &grok) };
    let env = OrcaPathEnv {
        home: Some(tmp.path().join("home")),
        uid: Some(1000),
        tmpdir: Some(tmp.path().join("tmp")),
        orca_home: Some(tmp.path().join("orca-home")),
        ..OrcaPathEnv::default()
    };
    let _ = resolve_orca_paths(OrcaPlatform::current(), &env).unwrap();
    assert!(!grok.exists(), "resolver must not create GROK_HOME");
    assert_eq!(std::fs::read(&marker).unwrap(), b"untouched");
    match prev {
        Some(v) => unsafe { std::env::set_var("GROK_HOME", v) },
        None => unsafe { std::env::remove_var("GROK_HOME") },
    }
}
