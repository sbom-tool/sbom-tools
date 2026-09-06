//! Bind the published JSON Schemas to the Rust validators.
//!
//! The schemas under schemas/ are the versioned public contract; the serde
//! structs and hand-rolled validators are the enforcement. Nothing else keeps
//! them aligned, so these tests fail on any one-sided edit: a schema pattern
//! the code does not enforce, a field the code requires but the schema
//! doesn't (or vice versa), or a fixture that drifts from both.

use regex::Regex;
use sbom_tools::verification::*;
use serde_json::Value;
use std::collections::BTreeMap;

fn schema_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::new(format!(
        "sha256:{}",
        char::from(byte).to_string().repeat(64)
    ))
    .unwrap()
}

fn receipt() -> PipelineShardReceipt {
    PipelineShardReceipt {
        schema: PIPELINE_SHARD_RECEIPT_SCHEMA.into(),
        repository: "org/repo".into(),
        workflow: "ci".into(),
        run_id: None,
        commit_sha: "a".repeat(40),
        source_fingerprint: digest(b'a'),
        trust_context: TrustContext::ProtectedMain,
        promotable: false,
        target: TargetIdentity {
            verification_scope: "unit".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            toolchain: "stable".into(),
            profile: "release".into(),
            features: vec![],
            binding_runtime: None,
        },
        lock_digest: digest(b'b'),
        versions: BTreeMap::new(),
        checks: vec![VerificationCheck {
            name: "build".into(),
            outcome: CheckOutcome::Passed,
            passed: 1,
            failed: 0,
            ignored: 0,
        }],
        artifacts: vec![],
        dagger_trace: None,
        started_at: "2026-01-01T00:00:00Z".into(),
        completed_at: "2026-01-01T00:01:00Z".into(),
        failure_classification: None,
    }
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

fn schema_string_list(value: &Value) -> Vec<String> {
    let mut list: Vec<String> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    list.sort();
    list
}

#[test]
fn verification_scope_validator_agrees_with_schema_pattern() {
    let schema = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let pattern = schema["$defs"]["target"]["properties"]["verification_scope"]["pattern"]
        .as_str()
        .unwrap();
    let regex = Regex::new(pattern).unwrap();
    // Corpus covering both sides of every historical divergence: dot-only,
    // leading-punctuation, and structural (slash/empty/traversal) cases.
    let corpus = [
        "ok",
        "a/b",
        "A1/b.c-d_e",
        "rust-lint",
        "x.y",
        "9start",
        "x.",
        "a/b/c",
        "...",
        "-x",
        ".hidden",
        "_x",
        "ok/.hidden",
        "a//b",
        "/a",
        "a/",
        "a b",
        "a\\b",
        "a/./b",
        "a/../b",
        ".",
        "..",
        "",
        "é",
        "a/é",
    ];
    for scope in corpus {
        let schema_accepts = regex.is_match(scope);
        let mut r = receipt();
        r.target.verification_scope = scope.into();
        let code_accepts = validate_receipt(&r).is_ok();
        assert_eq!(
            schema_accepts, code_accepts,
            "scope {scope:?}: schema={schema_accepts} code={code_accepts}"
        );
    }
}

#[test]
fn receipt_fields_match_schema_properties_and_required() {
    let schema = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let serialized = serde_json::to_value(receipt()).unwrap();
    // Every serialized field is a schema property, and vice versa.
    assert_eq!(keys(&serialized), keys(&schema["properties"]));
    // The receipt schema requires every property, nullable ones included.
    assert_eq!(
        schema_string_list(&schema["required"]),
        keys(&schema["properties"])
    );
    // Nullable-but-required semantics: deleting any key must fail
    // deserialization, null for the nullable ones must succeed.
    for key in keys(&serialized) {
        let mut pruned = serialized.clone();
        pruned.as_object_mut().unwrap().remove(&key);
        assert!(
            serde_json::from_value::<PipelineShardReceipt>(pruned).is_err(),
            "receipt deserialized without required key {key}"
        );
    }
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/pipeline-shard-receipt-v1.json")).unwrap();
    assert_eq!(keys(&fixture), keys(&schema["properties"]));
}

#[test]
fn generator_input_required_list_matches_struct_strictness() {
    let schema = schema_json("schemas/pipeline-shard-receipt/input-v1.schema.json");
    // The input schema also requires its nullable keys; the struct enforces
    // presence via require_nullable, so removing any required key must fail.
    let descriptor = serde_json::json!({
        "schema": PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA,
        "repository": "org/repo",
        "workflow": "ci",
        "commit_sha": "a".repeat(40),
        "source_root": "src-root",
        "lock_paths": ["Cargo.lock"],
        "artifact_root": "artifact-root",
        "artifacts": [],
        "target": serde_json::to_value(receipt().target).unwrap(),
        "versions": {},
        "checks": serde_json::to_value(receipt().checks).unwrap(),
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:01:00Z",
        "run_id": null,
        "dagger_trace": null,
        "failure_classification": null,
        "hosted": null,
        "local": true,
    });
    assert!(serde_json::from_value::<ReceiptGenerationInput>(descriptor.clone()).is_ok());
    assert_eq!(keys(&descriptor), keys(&schema["properties"]));
    for key in schema_string_list(&schema["required"]) {
        let mut pruned = descriptor.clone();
        pruned.as_object_mut().unwrap().remove(&key);
        assert!(
            serde_json::from_value::<ReceiptGenerationInput>(pruned).is_err(),
            "generator input deserialized without required key {key}"
        );
    }
}

#[test]
fn aggregate_policy_matches_published_schema() {
    let schema = schema_json("schemas/aggregate-policy/v1.schema.json");
    let policy = AggregatePolicy {
        schema: AGGREGATE_POLICY_SCHEMA.into(),
        expected_targets: vec![receipt().target],
        context: ExpectedContext {
            repository: "org/repo".into(),
            workflow: "ci".into(),
            commit_sha: "a".repeat(40),
            trust_context: TrustContext::ProtectedMain,
            promotable: false,
            source_fingerprint: digest(b'a'),
            lock_digest: digest(b'b'),
        },
        required_checks: vec!["build".into()],
        artifacts: vec![],
    };
    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(keys(&serialized), keys(&schema["properties"]));
    assert_eq!(
        schema_string_list(&schema["required"]),
        keys(&schema["properties"])
    );
    assert_eq!(
        keys(&serialized["context"]),
        keys(&schema["$defs"]["context"]["properties"])
    );
    // A policy asserting a different schema id is a gate verdict.
    let mut wrong = policy;
    wrong.schema = "aggregate-policy/v0".into();
    assert!(
        aggregate_receipts(&[], &wrong).is_err(),
        "policy with wrong schema id accepted"
    );
}

#[test]
fn job_manifests_validate_against_published_schema_shape() {
    let schema = schema_json("schemas/pipeline-shard-job-manifest/v1.schema.json");
    let schema_keys = keys(&schema["properties"]);
    assert_eq!(schema_string_list(&schema["required"]), schema_keys);
    for entry in std::fs::read_dir(".github/receipts/jobs").unwrap() {
        let path = entry.unwrap().path();
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(keys(&raw), schema_keys, "{path:?}");
        // Each checked-in manifest must deserialize under the strict struct.
        let manifest: ReceiptJobManifest = serde_json::from_value(raw).unwrap();
        assert_eq!(
            manifest.schema, PIPELINE_SHARD_JOB_MANIFEST_SCHEMA,
            "{path:?}"
        );
    }
}
