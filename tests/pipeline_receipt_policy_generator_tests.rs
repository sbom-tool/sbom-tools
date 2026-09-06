use sbom_tools::verification::*;
use std::{collections::BTreeMap, fs, process::Command};

fn target(scope: &str) -> TargetIdentity {
    TargetIdentity {
        verification_scope: scope.into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        toolchain: "stable".into(),
        profile: "release".into(),
        features: vec![],
        binding_runtime: None,
    }
}
fn manifest(root: &std::path::Path) -> AggregatePolicyManifest {
    AggregatePolicyManifest {
        schema: AGGREGATE_POLICY_MANIFEST_SCHEMA.into(),
        workflow: "verify".into(),
        source_root: root.into(),
        lock_paths: vec!["Cargo.lock".into()],
        artifact_root: root.join("artifacts"),
        expected_targets: vec![target("linux")],
        required_checks: vec!["build".into()],
        artifacts: vec![ReceiptArtifactInput {
            name: "report".into(),
            path: "report.json".into(),
        }],
    }
}
fn context() -> AggregatePolicyContextInput {
    AggregatePolicyContextInput {
        schema: AGGREGATE_POLICY_CONTEXT_SCHEMA.into(),
        repository: "org/repo".into(),
        commit_sha: "a".repeat(40),
        hosted: None,
        local: true,
    }
}
fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("Cargo.lock"), b"lock").unwrap();
    fs::create_dir(dir.path().join("artifacts")).unwrap();
    fs::write(dir.path().join("artifacts/report.json"), b"report").unwrap();
    dir
}

#[test]
fn manifest_schema_declares_collection_uniqueness() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/aggregate-policy-manifest/v1.schema.json"
    ))
    .unwrap();
    for field in [
        "lock_paths",
        "expected_targets",
        "required_checks",
        "artifacts",
    ] {
        assert_eq!(schema["properties"][field]["uniqueItems"], true);
    }
    assert_eq!(
        schema["$defs"]["target"]["properties"]["features"]["uniqueItems"],
        true
    );
    assert_eq!(
        schema["$defs"]["target"]["properties"]["features"]["items"]["minLength"],
        1
    );
}

#[test]
fn policy_generation_is_deterministic_and_hashes_artifacts() {
    let dir = setup();
    let one = generate_policy(manifest(dir.path()), context()).unwrap();
    let two = generate_policy(manifest(dir.path()), context()).unwrap();
    assert_eq!(one, two);
    assert!(!one.context.promotable);
    assert_eq!(one.context.trust_context, TrustContext::Local);
    assert_eq!(one.artifacts[0].sha256, Sha256Digest::from_bytes(b"report"));
}

#[test]
fn policy_generation_rejects_duplicate_topology_and_context_mismatch() {
    let dir = setup();
    let mut duplicate = manifest(dir.path());
    duplicate.expected_targets.push(target("linux"));
    assert!(generate_policy(duplicate, context()).is_err());
    let mut mismatch = context();
    mismatch.repository = "other/repo".into();
    let mut hosted = mismatch.clone();
    hosted.hosted = Some(HostedReceiptMetadata {
        event_name: "push".into(),
        ref_name: "refs/heads/main".into(),
        repository: "org/repo".into(),
        default_branch: "main".into(),
        sha: "a".repeat(40),
        head_repository: None,
    });
    assert!(generate_policy(manifest(dir.path()), hosted).is_err());

    let mut checks = manifest(dir.path());
    checks.required_checks.push("build".into());
    assert!(generate_policy(checks, context()).is_err());
    let mut locks = manifest(dir.path());
    locks.lock_paths.push("Cargo.lock".into());
    assert!(generate_policy(locks, context()).is_err());
    let mut artifacts = manifest(dir.path());
    artifacts.artifacts.push(artifacts.artifacts[0].clone());
    assert!(generate_policy(artifacts, context()).is_err());

    let mut ordered = manifest(dir.path());
    ordered.expected_targets[0].features = vec!["b".into(), "a".into()];
    ordered.expected_targets.push(TargetIdentity {
        features: vec!["a".into(), "b".into()],
        ..target("linux")
    });
    assert!(generate_policy(ordered, context()).is_err());
    let mut duplicate_features = manifest(dir.path());
    duplicate_features.expected_targets[0].features = vec!["a".into(), "a".into()];
    assert!(generate_policy(duplicate_features, context()).is_err());
}

#[test]
fn policy_generation_rejects_empty_roots_and_roundtrips_aggregate_validation() {
    let dir = setup();
    let mut bad_source = manifest(dir.path());
    bad_source.source_root = "".into();
    assert!(generate_policy(bad_source, context()).is_err());
    let mut bad_artifact = manifest(dir.path());
    bad_artifact.artifact_root = std::path::PathBuf::new();
    assert!(generate_policy(bad_artifact, context()).is_err());
    let policy = generate_policy(manifest(dir.path()), context()).unwrap();
    let receipt = generate_receipt_from_descriptor(ReceiptGenerationInput {
        schema: PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA.into(),
        repository: "org/repo".into(),
        workflow: "verify".into(),
        commit_sha: "a".repeat(40),
        source_root: dir.path().into(),
        lock_paths: vec!["Cargo.lock".into()],
        artifact_root: dir.path().join("artifacts"),
        artifacts: vec![ReceiptArtifactInput {
            name: "report".into(),
            path: "report.json".into(),
        }],
        target: target("linux"),
        versions: BTreeMap::new(),
        checks: vec![VerificationCheck {
            name: "build".into(),
            outcome: CheckOutcome::Passed,
            passed: 1,
            failed: 0,
            ignored: 0,
        }],
        started_at: "2026-01-01T00:00:00Z".into(),
        completed_at: "2026-01-01T00:01:00Z".into(),
        run_id: None,
        dagger_trace: None,
        failure_classification: None,
        hosted: None,
        local: true,
    })
    .unwrap();
    assert!(aggregate_receipts(&[receipt], &policy).is_ok());
    assert!(!policy.context.promotable);
}

#[cfg(unix)]
#[test]
fn policy_generation_rejects_empty_locks_and_artifact_path_attacks() {
    let dir = setup();
    let mut empty = manifest(dir.path());
    empty.lock_paths.clear();
    assert!(generate_policy(empty, context()).is_err());
    for path in ["missing.json", "../Cargo.lock"] {
        let mut bad = manifest(dir.path());
        bad.artifacts[0].path = path.into();
        assert!(generate_policy(bad, context()).is_err());
    }
    std::os::unix::fs::symlink("report.json", dir.path().join("artifacts/link")).unwrap();
    let mut symlink = manifest(dir.path());
    symlink.artifacts[0].path = "link".into();
    assert!(generate_policy(symlink, context()).is_err());
}

#[test]
fn compiled_policy_generator_has_zero_one_three_semantics_and_no_overwrite() {
    let dir = setup();
    let manifest_path = dir.path().join("manifest.json");
    let context_path = dir.path().join("context.json");
    let output = dir.path().join("policy.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest(dir.path()).clone()).unwrap(),
    )
    .unwrap();
    fs::write(&context_path, serde_json::to_vec(&context()).unwrap()).unwrap();
    let run = |out: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
            .args(["verify", "receipt-policy-generate", "--manifest"])
            .arg(&manifest_path)
            .args(["--context"])
            .arg(&context_path)
            .args(["--output"])
            .arg(out)
            .output()
            .unwrap()
    };
    assert_eq!(run(&output).status.code(), Some(0));
    assert_eq!(run(&output).status.code(), Some(3));
    let mut value = serde_json::to_value(manifest(dir.path())).unwrap();
    value["unexpected"] = true.into();
    fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(run(&dir.path().join("bad.json")).status.code(), Some(1));
    fs::write(&manifest_path, b"{").unwrap();
    assert_eq!(
        run(&dir.path().join("malformed.json")).status.code(),
        Some(3)
    );
}
