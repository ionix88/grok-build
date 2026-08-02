//! Bounded parser tests for manifest v2 + agentBackends.
use std::path::PathBuf;

use xai_grok_agent::plugins::agent_backend::AgentBackendError;
use xai_grok_agent::plugins::manifest::{ManifestError, parse_manifest_json};

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/agent-backend-v2");
    p.push(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn content_v1_still_loads() {
    let raw = fixture("content-v1.json");
    let m = parse_manifest_json(&raw).expect("v1 content manifest");
    assert_eq!(m.name, "deployment-tools");
    assert!(!m.has_agent_backends());
    assert!(m.manifest_version.is_none());
}

#[test]
fn canonical_go_orca_parses_and_round_trips() {
    let raw = fixture("canonical-go-orca.json");
    let m = parse_manifest_json(&raw).expect("canonical v2");
    assert_eq!(m.manifest_version, Some(2));
    assert_eq!(m.agent_backends.len(), 1);
    let b = &m.agent_backends[0];
    assert_eq!(b.id, "go-orca");
    assert_eq!(b.schema_version, 1);
    assert_eq!(b.targets.len(), 2);
    assert!(b.daemon.supervisor.is_some());
    assert_eq!(b.lifecycle.provision.argv.last().map(String::as_str), Some("{provisionInput}"));

    let again = serde_json::to_string(&m).expect("serialize");
    let m2 = parse_manifest_json(&again).expect("round-trip");
    assert_eq!(m2.agent_backends[0].id, "go-orca");
    assert_eq!(m2.agent_backends[0].targets.len(), 2);
    assert_eq!(
        m2.agent_backends[0].daemon.supervisor.as_ref().unwrap().argv,
        b.daemon.supervisor.as_ref().unwrap().argv
    );
    assert_eq!(m2.agent_backends[0].lifecycle.purge_prepare.argv, b.lifecycle.purge_prepare.argv);
}

#[test]
fn invalid_corpus_rejects_all_named_vectors() {
    let corpus: serde_json::Value =
        serde_json::from_str(&fixture("invalid-corpus.json")).expect("corpus json");
    let vectors = corpus["vectors"].as_array().expect("vectors");
    let base: serde_json::Value =
        serde_json::from_str(&fixture("canonical-go-orca.json")).expect("base");

    for v in vectors {
        let id = v["id"].as_str().expect("id");
        let expect = v["expect"].as_str().expect("expect");
        let manifest = if let Some(m) = v.get("manifest") {
            m.clone()
        } else {
            apply_patch(base.clone(), v.get("patch").expect("patch"))
        };
        let raw = serde_json::to_string(&manifest).expect("to_string");
        let err = parse_manifest_json(&raw).expect_err(&format!("vector {id} must fail"));
        assert!(
            error_matches(&err, expect),
            "vector {id}: expected {expect}, got {err:?}"
        );
    }
}

fn apply_patch(mut base: serde_json::Value, patch: &serde_json::Value) -> serde_json::Value {
    let kind = patch["kind"].as_str().expect("kind");
    match kind {
        "duplicate_first_target" => {
            let t0 = base["agentBackends"][0]["targets"][0].clone();
            base["agentBackends"][0]["targets"]
                .as_array_mut()
                .unwrap()
                .push(t0);
        }
        "set_bridge_path" => {
            base["agentBackends"][0]["targets"][0]["files"]["bridge"] =
                patch["value"].clone();
        }
        "set_entrypoint_argv0" => {
            base["agentBackends"][0]["targets"][0]["entrypoint"]["argv"][0] =
                patch["value"].clone();
        }
        "set_requires_orca" => {
            base["agentBackends"][0]["requires"]["orca"] = patch["value"].clone();
        }
        "set_schema_version" => {
            base["agentBackends"][0]["schemaVersion"] = patch["value"].clone();
        }
        "remove_lifecycle_key" => {
            let key = patch["value"].as_str().unwrap();
            base["agentBackends"][0]["lifecycle"]
                .as_object_mut()
                .unwrap()
                .remove(key);
        }
        "set_entrypoint_as_shell_string" => {
            base["agentBackends"][0]["targets"][0]["entrypoint"]["argv"] = patch["value"].clone();
        }
        "remove_manifest_version" => {
            base.as_object_mut().unwrap().remove("manifestVersion");
        }
        other => panic!("unknown patch kind {other}"),
    }
    base
}

fn error_matches(err: &ManifestError, expect: &str) -> bool {
    match (expect, err) {
        ("duplicate_backend_id", ManifestError::AgentBackend(AgentBackendError::DuplicateBackendId(_))) => {
            true
        }
        ("duplicate_target", ManifestError::AgentBackend(AgentBackendError::DuplicateTarget { .. })) => {
            true
        }
        ("path_escape", ManifestError::AgentBackend(AgentBackendError::PathEscape(_))) => true,
        ("relative_executable", ManifestError::AgentBackend(AgentBackendError::RelativeExecutable(_))) => {
            true
        }
        ("bad_placeholder", ManifestError::AgentBackend(AgentBackendError::BadPlaceholder(_))) => true,
        ("bad_semver_range", ManifestError::AgentBackend(AgentBackendError::BadSemverRange { .. })) => {
            true
        }
        ("unknown_schema_version", ManifestError::AgentBackend(AgentBackendError::UnknownSchemaVersion(_))) => {
            true
        }
        ("missing_lifecycle_route", ManifestError::AgentBackend(AgentBackendError::Json(_)))
        | ("missing_lifecycle_route", ManifestError::ParseError { .. }) => true,
        ("shell_text", ManifestError::AgentBackend(AgentBackendError::ShellText(_))) => true,
        ("manifest_version_required", ManifestError::AgentBackend(AgentBackendError::ManifestVersionRequired)) => {
            true
        }
        _ => false,
    }
}
