//! Resolver tests: placeholder substitution + lifecycle argv shapes.
use std::path::PathBuf;

use xai_grok_agent::plugins::agent_backend::{
    ResolveContext, resolve_argv, select_target,
};
use xai_grok_agent::plugins::manifest::parse_manifest_json;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/agent-backend-v2");
    p.push(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn ctx() -> ResolveContext {
    ResolveContext {
        plugin_root: PathBuf::from("/plugins/go-orca/1.2.0"),
        plugin_data: PathBuf::from("/var/orca/plugin-data/go-orca"),
        runtime_dir: PathBuf::from("/var/orca/runtime/go-orca"),
        bridge: PathBuf::from("/plugins/go-orca/1.2.0/bin/darwin-aarch64/go-orca"),
        daemon: PathBuf::from("/plugins/go-orca/1.2.0/bin/darwin-aarch64/go-orcad"),
        cohort_id: "cohort-abc".into(),
        purge_barrier: PathBuf::from("/var/orca/barriers/go-orca.barrier"),
        purge_barrier_parent_identity: "deadbeef".repeat(4),
        purge_barrier_revision: 7,
        provision_input: Some(PathBuf::from("/var/orca/tx/provision-input.json")),
    }
}

#[test]
fn resolve_supervisor_entrypoint_doctor_admin_provision_purge() {
    let m = parse_manifest_json(&fixture("canonical-go-orca.json")).unwrap();
    let b = &m.agent_backends[0];
    let c = ctx();
    let target = select_target(b, "darwin", "aarch64", None).expect("target");

    let sup = b.daemon.supervisor.as_ref().unwrap();
    let r = resolve_argv(&sup.argv, &sup.cwd, &c).expect("supervisor");
    assert_eq!(r.argv[0], c.bridge.to_string_lossy());
    assert!(r.argv.iter().any(|a| a == &c.plugin_data.to_string_lossy()));
    assert!(r.argv.iter().any(|a| a == &c.runtime_dir.to_string_lossy()));
    assert_eq!(r.cwd, c.plugin_root);

    let ep = resolve_argv(&target.entrypoint.argv, &target.entrypoint.cwd, &c).expect("entrypoint");
    assert_eq!(ep.argv[0], c.bridge.to_string_lossy());
    assert!(ep.argv.contains(&"agent".to_string()));
    assert!(ep.argv.contains(&"stdio".to_string()));

    let doctor = resolve_argv(&b.lifecycle.doctor.argv, "{pluginRoot}", &c).expect("doctor");
    assert!(doctor.argv.contains(&"doctor".to_string()));

    // admin: prefix + route + tail
    let mut admin = b.lifecycle.admin.argv_prefix.clone();
    admin.extend(["daemon".into(), "status".into()]);
    admin.extend(b.lifecycle.admin.argv_tail.iter().cloned());
    let admin_r = resolve_argv(&admin, "{pluginRoot}", &c).expect("admin");
    assert_eq!(
        admin_r.argv[..4],
        [
            c.bridge.to_string_lossy().as_ref(),
            "admin",
            "daemon",
            "status"
        ]
    );

    let prov = resolve_argv(&b.lifecycle.provision.argv, "{pluginRoot}", &c).expect("provision");
    assert!(
        prov.argv
            .iter()
            .any(|a| a.ends_with("provision-input.json"))
    );

    let purge = resolve_argv(&b.lifecycle.purge_prepare.argv, "{pluginRoot}", &c).expect("purge");
    assert!(purge.argv.contains(&"prepare-purge".to_string()));

    let pre = resolve_argv(&b.lifecycle.purge_preflight.argv, "{pluginRoot}", &c).expect("preflight");
    assert!(pre.argv.contains(&"purge-preflight".to_string()));
}

#[test]
fn select_target_unique_or_fail() {
    let m = parse_manifest_json(&fixture("canonical-go-orca.json")).unwrap();
    let b = &m.agent_backends[0];
    assert!(select_target(b, "darwin", "aarch64", None).is_ok());
    assert!(select_target(b, "linux", "amd64", None).is_ok());
    assert!(select_target(b, "windows", "amd64", None).is_err());
}

#[test]
fn resolve_rejects_relative_bridge_context() {
    let m = parse_manifest_json(&fixture("canonical-go-orca.json")).unwrap();
    let b = &m.agent_backends[0];
    let mut c = ctx();
    c.bridge = PathBuf::from("relative-bridge");
    let sup = b.daemon.supervisor.as_ref().unwrap();
    let err = resolve_argv(&sup.argv, &sup.cwd, &c).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("relative") || msg.contains("ambiguous"),
        "{msg}"
    );
}
