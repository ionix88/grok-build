//! Given/When/Then tests for backend selection precedence and defaults.

use super::*;
use crate::backend::registry::{BackendRegistry, DiscoverOpts};
use crate::backend::session_pin::{ExternalActivateRequest, ExternalCreateRequest, PinStore};
use crate::plugin_host::lifecycle::{ExternalPinState, SessionPinV1};
use crate::plugin_host::receipts::{
    ActivationPointerV1, FileRole, InstallReceiptV1, InventoryFile, LogicalDefaultV1,
    RegistryDocumentV2, TrustState,
};
use xai_grok_agent::plugins::agent_backend::HostPlatform;

fn h(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn host() -> HostPlatform {
    HostPlatform {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: None,
    }
}

fn mk_receipt(id: &str, ver: &str, archive: String) -> InstallReceiptV1 {
    InstallReceiptV1 {
        schema_version: 1,
        plugin_id: id.into(),
        version: ver.into(),
        archive_sha256: archive,
        install_root: format!("plugins/{id}/{ver}"),
        target: "darwin-aarch64".into(),
        files: vec![InventoryFile {
            relative_path: "bin/bridge".into(),
            role: FileRole::Executable,
            mode_octal: "0755".into(),
            length: 1,
            content_sha256: h(2),
        }],
        trust: TrustState::Consented {
            consent_digest: h(3),
            consented_at: "2026-08-03T00:00:00.000Z".into(),
        },
        native_code: true,
        capabilities: vec!["acp".into()],
        permissions: vec![],
        installed_at: "2026-08-03T00:00:00.000Z".into(),
        receipt_digest: String::new(),
    }
    .seal()
    .expect("seal")
}

fn fixture() -> (
    tempfile::TempDir,
    BackendRegistry,
    RegistryDocumentV2,
    PathBuf,
    PinStore,
) {
    let tmp = tempfile::TempDir::new().unwrap();
    let r1 = mk_receipt("go-orca", "1.0.0", h(1));
    let r2 = mk_receipt("go-orca", "1.1.0", h(4));
    let d1 = r1.receipt_digest.clone();
    let mut doc = RegistryDocumentV2::empty();
    doc.insert_receipt(r1).unwrap();
    doc.insert_receipt(r2).unwrap();
    let act = ActivationPointerV1 {
        schema_version: 1,
        backend_id: "go-orca".into(),
        install_receipt_digest: d1,
        activated_at: "2026-08-03T00:00:00.000Z".into(),
        pointer_digest: String::new(),
    }
    .seal()
    .unwrap();
    doc.activation.insert("go-orca".into(), act);
    let doc = doc.seal().unwrap();
    let reg = BackendRegistry::discover(Some(&doc), &host(), &DiscoverOpts::default()).unwrap();
    let def_path = tmp.path().join("backend-default.json");
    let pins = PinStore::open(tmp.path().join("session-pins")).unwrap();
    (tmp, reg, doc, def_path, pins)
}

fn input<'a>(
    explicit: Option<&'a str>,
    resume: Option<&'a str>,
    mode: LaunchMode,
    reg: &'a BackendRegistry,
    doc: &'a RegistryDocumentV2,
    def: &'a Path,
    pins: &'a PinStore,
) -> SelectionInput<'a> {
    SelectionInput {
        explicit,
        resume_host_session_id: resume,
        mode,
        registry: reg,
        registry_doc: Some(doc),
        default_path: def,
        pin_store: Some(pins),
    }
}

#[test]
fn parse_selector_id_and_version() {
    let s = parse_selector("go-orca").unwrap();
    assert_eq!(s.backend_id, "go-orca");
    assert!(s.version.is_none());
    let s = parse_selector("go-orca@1.1.0").unwrap();
    assert_eq!(s.version.as_deref(), Some("1.1.0"));
    assert!(parse_selector("").is_err());
    assert!(parse_selector("../evil").is_err());
}

#[test]
fn precedence_explicit_over_pin_default_native() {
    let (_t, reg, doc, def, pins) = fixture();
    set_user_default(&def, "go-orca").unwrap();
    // pin native session
    pins.write_native("sess-n", "nid").unwrap();

    // explicit external wins over pin and default
    let r = resolve(&input(
        Some("go-orca@1.1.0"),
        Some("sess-n"),
        LaunchMode::Headless,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.origin, SelectionOrigin::Explicit);
    assert_eq!(r.backend_id, "go-orca");
    assert_eq!(r.version.as_deref(), Some("1.1.0"));
    assert!(!r.native_start);

    // pin wins over default when no explicit
    let r = resolve(&input(
        None,
        Some("sess-n"),
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.origin, SelectionOrigin::SessionPin);
    assert!(r.native_start);

    // default wins when no pin
    let r = resolve(&input(
        None,
        None,
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.origin, SelectionOrigin::UserDefault);
    assert_eq!(r.backend_id, "go-orca");
    assert!(!r.native_start);

    // bare → native
    let empty = _t.path().join("no-default.json");
    let r = resolve(&input(
        None,
        None,
        LaunchMode::Interactive,
        &reg,
        &doc,
        &empty,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.origin, SelectionOrigin::NativeBuiltin);
    assert!(r.native_start);
}

#[test]
fn explicit_missing_external_fails_closed_no_native_start() {
    let (_t, reg, doc, def, pins) = fixture();
    let err = resolve(&input(
        Some("missing-backend"),
        None,
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap_err();
    assert!(matches!(err, SelectionError::ExplicitFailed(_)), "{err:?}");
    // headless same
    let err = resolve(&input(
        Some("go-orca@9.9.9"),
        None,
        LaunchMode::Headless,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap_err();
    assert!(matches!(err, SelectionError::ExplicitFailed(_)), "{err:?}");
}

#[test]
fn set_default_is_logical_only_install_does_not_mutate() {
    let (_t, reg, doc, def, pins) = fixture();
    // Given: no default file
    assert!(load_user_default(&def).unwrap().is_none());
    // When: set-default go-orca
    let d = set_user_default(&def, "go-orca").unwrap();
    assert_eq!(d.backend_id, "go-orca");
    assert_eq!(d.version_policy, "followActivation");
    // Then: no version/receipt in file
    let raw = std::fs::read_to_string(&def).unwrap();
    assert!(!raw.contains("installReceipt"));
    assert!(!raw.contains("1.0.0"));
    // set-default rejects @version
    assert!(set_user_default(&def, "go-orca@1.0.0").is_err());
    // installation alone: registry has receipts but default unchanged if we reset
    std::fs::remove_file(&def).unwrap();
    let r = resolve(&input(
        None,
        None,
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.backend_id, NATIVE_BACKEND_ID);
}

#[test]
fn corrupt_preference_interactive_warns_headless_fails() {
    let (_t, reg, doc, def, pins) = fixture();
    std::fs::write(&def, "{not-json").unwrap();
    let r = resolve(&input(
        None,
        None,
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert!(r.native_start);
    assert!(
        r.warning
            .as_deref()
            .unwrap()
            .contains("BACKEND_UNAVAILABLE")
    );
    // preference file unchanged
    assert_eq!(std::fs::read_to_string(&def).unwrap(), "{not-json");

    let err = resolve(&input(
        None,
        None,
        LaunchMode::Headless,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap_err();
    assert!(
        matches!(err, SelectionError::HeadlessDefaultFailed(_)),
        "{err:?}"
    );
}

#[test]
fn external_pin_resume_uses_exact_receipt_not_activation() {
    let (_t, reg, doc, def, pins) = fixture();
    // Activate points at 1.0.0; pin an older explicit receipt path via create
    let r1 = reg.by_id_version("go-orca", Some("1.0.0")).unwrap();
    let digest = r1.receipt_digest.clone().unwrap();
    let req = ExternalCreateRequest {
        host_session_id: "sess-ext".into(),
        creation_key: "0123456789abcdef0123456789abcdef".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: digest.clone(),
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&req).unwrap();
    pins.activate_external(&ExternalActivateRequest {
        host_session_id: "sess-ext".into(),
        acp_session_id: "acp-1".into(),
        committed_revision: 1,
        committed_cursor: 0,
    })
    .unwrap();
    // Change default and activation would not matter — pin wins
    set_user_default(&def, "native").unwrap();
    let r = resolve(&input(
        None,
        Some("sess-ext"),
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.origin, SelectionOrigin::SessionPin);
    assert_eq!(r.receipt_digest.as_deref(), Some(digest.as_str()));
    assert!(!r.native_start);
    match r.pin.unwrap() {
        SessionPinV1::External(e) => {
            assert_eq!(e.state, ExternalPinState::Active);
            assert_eq!(e.acp_session_id.as_deref(), Some("acp-1"));
        }
        _ => panic!("expected external"),
    }
}

#[test]
fn missing_receipt_for_creating_pin_no_native_fallback() {
    let (_t, reg, doc, def, pins) = fixture();
    let req = ExternalCreateRequest {
        host_session_id: "sess-miss".into(),
        creation_key: "0123456789abcdef0123456789abcdef".into(),
        request_digest: h(0xa),
        backend_id: "go-orca".into(),
        install_receipt_digest: h(0xe), // not in registry
        cohort_key: h(0xc),
        extension_schema_digest: h(0xd),
        renderer_contract_version: "1.0.0".into(),
    };
    pins.begin_external_create(&req).unwrap();
    let err = resolve(&input(
        None,
        Some("sess-miss"),
        LaunchMode::Interactive,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap_err();
    assert!(matches!(err, SelectionError::MissingReceipt(_)), "{err:?}");
    // Creating pin still on disk
    let still = pins.reconcile_creating("sess-miss").unwrap();
    assert_eq!(still.state, ExternalPinState::Creating);
}

#[test]
fn default_follow_activation_selects_activated_version() {
    let (_t, reg, doc, def, pins) = fixture();
    set_user_default(&def, "go-orca").unwrap();
    let r = resolve(&input(
        None,
        None,
        LaunchMode::Headless,
        &reg,
        &doc,
        &def,
        &pins,
    ))
    .unwrap();
    assert_eq!(r.version.as_deref(), Some("1.0.0")); // activation points at 1.0.0
}

#[test]
fn backend_cli_set_default_and_list() {
    let tmp = tempfile::TempDir::new().unwrap();
    let paths = BackendCliPaths {
        registry_path: tmp.path().join("missing-registry.json"),
        default_path: tmp.path().join("backend-default.json"),
        plugins_root: None,
    };
    let code = run_backend_cli(&["set-default".into(), "native".into()], &paths);
    assert_eq!(code, 0);
    let def = load_user_default(&paths.default_path).unwrap().unwrap();
    assert_eq!(def.backend_id, "native");
    let code = run_backend_cli(&["list".into()], &paths);
    assert_eq!(code, 0);
    assert!(try_run_from_args(["not-backend"]).is_none());
}

#[test]
fn list_status_json_contains_default_and_native_line() {
    let lines = vec![
        "id=native version=- kind=native selectable=yes".into(),
        "id=go-orca version=1.0.0 kind=external selectable=yes".into(),
    ];
    let raw = format_list_status_json("native", &lines).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["default"], "native");
    let status = v["statusLines"].as_array().unwrap();
    assert_eq!(status.len(), 2);
    assert!(status[0].as_str().unwrap().contains("id=native"));
}

#[test]
fn prepare_launch_explicit_missing_fails_without_native_start() {
    let tmp = tempfile::TempDir::new().unwrap();
    let paths = BackendCliPaths {
        registry_path: tmp.path().join("missing-registry.json"),
        default_path: tmp.path().join("state/backend-default.json"),
        plugins_root: Some(tmp.path().join("plugins")),
    };
    let pins = tmp.path().join("state/session-pins");
    let err = prepare_launch_with_paths(
        &LaunchBackendRequest {
            explicit_backend: Some("missing-backend-xyz"),
            resume_host_session_id: None,
            mode: LaunchMode::Interactive,
        },
        &paths,
        &pins,
    )
    .unwrap_err();
    assert!(
        matches!(err, SelectionError::ExplicitFailed(_)),
        "{err:?}"
    );
    let ok = prepare_launch_with_paths(
        &LaunchBackendRequest {
            explicit_backend: None,
            resume_host_session_id: None,
            mode: LaunchMode::Headless,
        },
        &paths,
        &pins,
    )
    .unwrap();
    assert!(ok.resolved.native_start);
    assert_eq!(ok.resolved.backend_id, NATIVE_BACKEND_ID);
}

#[test]
fn persist_native_session_pin_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let pins_dir = tmp.path().join("state").join("session-pins");
    std::fs::create_dir_all(pins_dir.parent().unwrap()).unwrap();
    let store = PinStore::open(&pins_dir).unwrap();
    persist_native_session_pin_in(&store, "host-sess-1", "native-id-1").unwrap();
    persist_native_session_pin_in(&store, "host-sess-1", "native-id-1").unwrap();
    let err = persist_native_session_pin_in(&store, "host-sess-1", "other-id").unwrap_err();
    assert!(matches!(err, SelectionError::Pin(_)), "{err:?}");
    let loaded = store.load_required("host-sess-1").unwrap();
    match loaded {
        SessionPinV1::Native(n) => assert_eq!(n.native_session_identity, "native-id-1"),
        SessionPinV1::External(_) => panic!("expected native pin"),
    }
}

// silence unused import if LogicalDefaultV1 only used via set
#[allow(dead_code)]
fn _touch(d: LogicalDefaultV1) {
    let _ = d;
}
