use sbom_tools::verification::*;
use std::{collections::BTreeMap, fs, process::Command};

fn target() -> TargetIdentity {
    TargetIdentity {
        verification_scope: "linux-x86_64".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        toolchain: "stable".into(),
        profile: "release".into(),
        features: vec!["z".into(), "a".into()],
        binding_runtime: None,
    }
}
fn descriptor(
    root: &std::path::Path,
    hosted: Option<HostedReceiptMetadata>,
    local: bool,
) -> ReceiptGenerationInput {
    ReceiptGenerationInput {
        schema: PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA.into(),
        repository: "org/repo".into(),
        workflow: "verify".into(),
        commit_sha: "a".repeat(40),
        source_root: root.into(),
        lock_paths: vec!["Cargo.lock".into()],
        artifact_root: root.join("artifacts"),
        artifacts: vec![ReceiptArtifactInput {
            name: "report".into(),
            path: "report.json".into(),
        }],
        target: target(),
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
        hosted,
        local,
    }
}
fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("Cargo.lock"), b"lock").unwrap();
    fs::create_dir(dir.path().join("artifacts")).unwrap();
    fs::write(dir.path().join("artifacts/report.json"), b"report").unwrap();
    dir
}
fn hosted(event: &str, reference: &str) -> HostedReceiptMetadata {
    HostedReceiptMetadata {
        event_name: event.into(),
        ref_name: reference.into(),
        repository: "org/repo".into(),
        default_branch: "main".into(),
        sha: "a".repeat(40),
        head_repository: Some("fork/repo".into()),
    }
}

#[test]
fn local_generation_is_deterministic_and_canonicalizes_features() {
    let dir = setup();
    let input = descriptor(dir.path(), None, true);
    let one = generate_receipt_from_descriptor(input.clone()).unwrap();
    let two = generate_receipt_from_descriptor(input).unwrap();
    assert_eq!(one, two);
    assert_eq!(one.target.features, vec!["a", "z"]);
    assert_eq!(one.trust_context, TrustContext::Local);
    assert!(!one.promotable);
    assert_eq!(one.artifacts[0].size, 6);
    assert_eq!(one.artifacts[0].sha256, Sha256Digest::from_bytes(b"report"));
}

#[test]
fn hosted_contexts_cover_pr_fork_main_and_release() {
    let dir = setup();
    for (event, reference, expected) in [
        (
            "pull_request",
            "refs/pull/7/merge",
            TrustContext::PullRequest,
        ),
        ("push", "refs/heads/main", TrustContext::ProtectedMain),
        ("push", "refs/tags/v1.0.0", TrustContext::Release),
    ] {
        let receipt = generate_receipt_from_descriptor(descriptor(
            dir.path(),
            Some(hosted(event, reference)),
            false,
        ))
        .unwrap();
        assert_eq!(receipt.trust_context, expected);
    }
}

#[test]
fn hosted_metadata_is_authoritative_and_rejects_mismatch_or_ambiguity() {
    let dir = setup();
    let mut bad = descriptor(dir.path(), Some(hosted("push", "refs/heads/main")), false);
    bad.commit_sha = "b".repeat(40);
    assert!(generate_receipt_from_descriptor(bad).is_err());
    let mut mismatch = descriptor(dir.path(), Some(hosted("push", "refs/heads/main")), false);
    mismatch.repository = "other/repo".into();
    assert!(generate_receipt_from_descriptor(mismatch).is_err());
    let ambiguous = descriptor(
        dir.path(),
        Some(hosted("pull_request", "refs/heads/main")),
        false,
    );
    assert!(generate_receipt_from_descriptor(ambiguous).is_err());
    let unsupported = descriptor(
        dir.path(),
        Some(hosted("workflow_dispatch", "refs/heads/main")),
        false,
    );
    assert!(generate_receipt_from_descriptor(unsupported).is_err());
}

#[test]
fn generator_rejects_duplicate_features_empty_locks_invalid_sha_and_unknown_fields() {
    let dir = setup();
    let mut duplicate = descriptor(dir.path(), None, true);
    duplicate.target.features.push("a".into());
    assert!(generate_receipt_from_descriptor(duplicate).is_err());
    let mut empty_locks = descriptor(dir.path(), None, true);
    empty_locks.lock_paths.clear();
    assert!(generate_receipt_from_descriptor(empty_locks).is_err());
    let mut invalid_sha = descriptor(dir.path(), None, true);
    invalid_sha.commit_sha = "not-sha".into();
    assert!(generate_receipt_from_descriptor(invalid_sha).is_err());
    let mut value = serde_json::to_value(descriptor(dir.path(), None, true)).unwrap();
    value["digest"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<ReceiptGenerationInput>(value).is_err());
    let mut invalid_scope = descriptor(dir.path(), None, true);
    invalid_scope.target.verification_scope = "../not-portable".into();
    assert!(generate_receipt_from_descriptor(invalid_scope).is_err());
}

#[cfg(unix)]
#[test]
fn artifact_missing_escape_and_symlink_are_rejected() {
    let dir = setup();
    let mut missing = descriptor(dir.path(), None, true);
    missing.artifacts[0].path = "missing".into();
    assert!(generate_receipt_from_descriptor(missing).is_err());
    let mut escape = descriptor(dir.path(), None, true);
    escape.artifacts[0].path = "../Cargo.lock".into();
    assert!(generate_receipt_from_descriptor(escape).is_err());
    std::os::unix::fs::symlink("report.json", dir.path().join("artifacts/link")).unwrap();
    let mut link = descriptor(dir.path(), None, true);
    link.artifacts[0].path = "link".into();
    assert!(generate_receipt_from_descriptor(link).is_err());
}

#[test]
fn compiled_cli_classifies_contract_failure() {
    let dir = setup();
    let input = dir.path().join("input.json");
    let output = dir.path().join("out.json");
    let mut value = serde_json::to_value(descriptor(dir.path(), None, true)).unwrap();
    value["digest"] = serde_json::Value::Bool(true);
    fs::write(&input, serde_json::to_vec(&value).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(["verify", "receipt-generate", "--input"])
        .arg(&input)
        .args(["--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!output.exists());
}

#[test]
fn compiled_cli_generates_a_readable_receipt() {
    let dir = setup();
    let input = dir.path().join("input.json");
    let output = dir.path().join("out.json");
    fs::write(
        &input,
        serde_json::to_vec(&descriptor(dir.path(), None, true)).unwrap(),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(["verify", "receipt-generate", "--input"])
        .arg(&input)
        .args(["--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(read_receipt(&output).is_ok());
    let malformed = dir.path().join("malformed.json");
    fs::write(&malformed, b"not-json").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(["verify", "receipt-generate", "--input"])
        .arg(&malformed)
        .args(["--output"])
        .arg(dir.path().join("bad.json"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    let result = Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(["verify", "receipt-generate", "--input"])
        .arg(&input)
        .args(["--output"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
}
