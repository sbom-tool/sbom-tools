use sbom_tools::verification::*;
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::new(format!(
        "sha256:{}",
        char::from(byte).to_string().repeat(64)
    ))
    .unwrap()
}
fn target() -> TargetIdentity {
    TargetIdentity {
        verification_scope: "unit".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        toolchain: "stable".into(),
        profile: "release".into(),
        features: vec![],
        binding_runtime: None,
    }
}
fn receipt(source: Sha256Digest, lock: Sha256Digest) -> PipelineShardReceipt {
    PipelineShardReceipt {
        schema: PIPELINE_SHARD_RECEIPT_SCHEMA.into(),
        repository: "org/repo".into(),
        workflow: "ci".into(),
        run_id: None,
        commit_sha: "a".repeat(40),
        source_fingerprint: source,
        trust_context: TrustContext::ProtectedMain,
        promotable: false,
        target: target(),
        lock_digest: lock,
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
fn policy(source: Sha256Digest, lock: Sha256Digest) -> AggregatePolicy {
    AggregatePolicy {
        expected_targets: vec![target()],
        context: ExpectedContext {
            repository: "org/repo".into(),
            workflow: "ci".into(),
            commit_sha: "a".repeat(40),
            trust_context: TrustContext::ProtectedMain,
            promotable: false,
            source_fingerprint: source,
            lock_digest: lock,
        },
        required_checks: vec!["build".into()],
        artifacts: vec![],
    }
}

#[test]
fn aggregate_success_and_source_mismatch() {
    let s = digest(b'a');
    let l = digest(b'b');
    assert!(
        aggregate_receipts(
            &[receipt(s.clone(), l.clone())],
            &policy(s.clone(), l.clone())
        )
        .is_ok()
    );
    assert!(aggregate_receipts(&[receipt(digest(b'c'), l.clone())], &policy(s, l)).is_err());
}
#[test]
fn aggregate_rejects_lock_context_and_promotable_mismatch() {
    let s = digest(b'a');
    let l = digest(b'b');
    assert!(
        aggregate_receipts(
            &[receipt(s.clone(), digest(b'c'))],
            &policy(s.clone(), l.clone())
        )
        .is_err()
    );
    let mut p = policy(s, l);
    p.context.repository = "other".into();
    assert!(aggregate_receipts(&[receipt(digest(b'a'), digest(b'b'))], &p).is_err());
    let mut r = receipt(digest(b'a'), digest(b'b'));
    r.promotable = true;
    assert!(validate_receipt(&r).is_err());
    let mut p = policy(digest(b'a'), digest(b'b'));
    p.context.promotable = true;
    p.artifacts.push(TrustedArtifact {
        name: "artifact".into(),
        path: "a.bin".into(),
        size: 1,
        sha256: digest(b'c'),
    });
    assert!(aggregate_receipts(&[receipt(digest(b'a'), digest(b'b'))], &p).is_err());
}

#[test]
fn schema_forbids_unsigned_promotable_receipts() {
    let schema = include_str!("../schemas/pipeline-shard-receipt/v1.schema.json");
    assert!(schema.contains("\"promotable\": {\"const\":false}"));
}
#[test]
fn policy_rejects_duplicate_checks_features_targets_and_artifacts() {
    let s = digest(b'a');
    let l = digest(b'b');
    let mut p = policy(s.clone(), l.clone());
    p.required_checks.push("build".into());
    assert!(aggregate_receipts(&[receipt(s.clone(), l.clone())], &p).is_err());
    let mut p = policy(s.clone(), l.clone());
    p.expected_targets[0].features = vec!["x".into(), "x".into()];
    assert!(aggregate_receipts(&[receipt(s.clone(), l.clone())], &p).is_err());
    let mut p = policy(s.clone(), l.clone());
    p.expected_targets.push(target());
    assert!(aggregate_receipts(&[receipt(s.clone(), l.clone())], &p).is_err());
    let a = TrustedArtifact {
        name: "".into(),
        path: "a.bin".into(),
        size: 0,
        sha256: digest(b'c'),
    };
    let mut p = policy(s, l);
    p.artifacts = vec![a.clone(), a];
    assert!(aggregate_receipts(&[receipt(digest(b'a'), digest(b'b'))], &p).is_err());
}
#[test]
fn receipt_rejects_unknown_fields_and_invalid_values() {
    let mut value = serde_json::to_value(receipt(digest(b'a'), digest(b'b'))).unwrap();
    value["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<PipelineShardReceipt>(value).is_err());
    assert!(Sha256Digest::new("sha256:AA").is_err());
    let mut r = receipt(digest(b'a'), digest(b'b'));
    r.commit_sha = "not-a-sha".into();
    assert!(validate_receipt(&r).is_err());
    r = receipt(digest(b'a'), digest(b'b'));
    r.completed_at = "2025-01-01T00:00:00Z".into();
    assert!(validate_receipt(&r).is_err());
}
#[test]
fn receipt_rejects_required_failed_cancelled_skipped_and_duplicate_checks() {
    for outcome in [
        CheckOutcome::Failed,
        CheckOutcome::Cancelled,
        CheckOutcome::Skipped,
    ] {
        let mut r = receipt(digest(b'a'), digest(b'b'));
        r.checks[0].outcome = outcome;
        r.checks[0].failed = if outcome == CheckOutcome::Skipped {
            0
        } else {
            1
        };
        r.failure_classification = (outcome != CheckOutcome::Skipped).then_some("test".into());
        assert!(aggregate_receipts(&[r], &policy(digest(b'a'), digest(b'b'))).is_err());
    }
    let mut r = receipt(digest(b'a'), digest(b'b'));
    r.checks.push(r.checks[0].clone());
    assert!(validate_receipt(&r).is_err());
}
#[test]
fn fingerprints_are_deterministic_and_reject_empty_or_unsafe_lock_inputs() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), b"one").unwrap();
    let first = source_fingerprint(dir.path()).unwrap();
    let second = source_fingerprint(dir.path()).unwrap();
    assert_eq!(first, second);
    fs::write(dir.path().join("a"), b"two").unwrap();
    assert_ne!(first, source_fingerprint(dir.path()).unwrap());
    assert!(lock_fingerprint(dir.path(), &[]).is_err());
    assert!(lock_fingerprint(dir.path(), &[PathBuf::from("../a")]).is_err());
    assert!(lock_fingerprint(dir.path(), &[PathBuf::from("/tmp/a")]).is_err());
}
#[cfg(unix)]
#[test]
fn source_fingerprint_rejects_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), b"one").unwrap();
    std::os::unix::fs::symlink("a", dir.path().join("link")).unwrap();
    assert!(source_fingerprint(dir.path()).is_err());
}

#[test]
fn relative_paths_reject_backslash_drive_unc_and_vacuous_values() {
    for value in ["a\\b", "C:/artifact", "//server/share", "", ".", "../a"] {
        let mut r = receipt(digest(b'a'), digest(b'b'));
        r.artifacts = vec![ReceiptArtifact {
            name: "artifact".into(),
            path: value.into(),
            size: 1,
            sha256: digest(b'c'),
        }];
        assert!(validate_receipt(&r).is_err(), "path {value:?} accepted");
    }
    let mut p = policy(digest(b'a'), digest(b'b'));
    p.required_checks = vec![];
    assert!(aggregate_receipts(&[receipt(digest(b'a'), digest(b'b'))], &p).is_err());
    p = policy(digest(b'a'), digest(b'b'));
    p.expected_targets = vec![];
    assert!(aggregate_receipts(&[receipt(digest(b'a'), digest(b'b'))], &p).is_err());
}

#[test]
fn receipt_rejects_empty_artifact_name() {
    let mut r = receipt(digest(b'a'), digest(b'b'));
    r.artifacts.push(ReceiptArtifact {
        name: String::new(),
        path: "artifact.bin".into(),
        size: 1,
        sha256: digest(b'c'),
    });
    assert!(validate_receipt(&r).is_err());
}

#[test]
fn fixture_and_scope_segments_validate() {
    let fixture = include_str!("fixtures/pipeline-shard-receipt-v1.json");
    let receipt: PipelineShardReceipt = serde_json::from_str(fixture).unwrap();
    validate_receipt(&receipt).unwrap();
    for scope in ["a//b", ".", "..", "a/./b", "a/../b", "/a", "a\\b"] {
        let mut receipt = receipt.clone();
        receipt.target.verification_scope = scope.into();
        assert!(validate_receipt(&receipt).is_err(), "accepted {scope}");
    }
}

#[test]
fn receipt_output_does_not_overwrite_existing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let receipt = receipt(digest(b'a'), digest(b'b'));
    fs::write(&path, b"original").unwrap();
    assert!(write_receipt(&path, &receipt).is_err());
    #[cfg(unix)]
    {
        let target = dir.path().join("target");
        fs::write(&target, b"target").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_receipt(&link, &receipt).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }
}

#[test]
fn aggregate_rejects_any_failed_or_cancelled_and_allows_optional_skipped() {
    let s = digest(b'a');
    let l = digest(b'b');
    for outcome in [CheckOutcome::Failed, CheckOutcome::Cancelled] {
        let mut r = receipt(s.clone(), l.clone());
        r.checks.push(VerificationCheck {
            name: "optional".into(),
            outcome,
            passed: 0,
            failed: 1,
            ignored: 0,
        });
        r.failure_classification = Some("failure".into());
        assert!(aggregate_receipts(&[r], &policy(s.clone(), l.clone())).is_err());
    }
    let mut r = receipt(s.clone(), l.clone());
    r.checks.push(VerificationCheck {
        name: "optional".into(),
        outcome: CheckOutcome::Skipped,
        passed: 0,
        failed: 0,
        ignored: 1,
    });
    assert!(aggregate_receipts(&[r], &policy(s, l)).is_ok());
}

fn cli_fixtures() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let valid = dir.path().join("valid.json");
    let invalid = dir.path().join("invalid.json");
    let policy_path = dir.path().join("policy.json");
    let receipt_dir = dir.path().join("receipts");
    fs::create_dir(&receipt_dir).unwrap();
    let s = digest(b'a');
    let l = digest(b'b');
    fs::write(
        &valid,
        serde_json::to_vec(&receipt(s.clone(), l.clone())).unwrap(),
    )
    .unwrap();
    fs::write(receipt_dir.join("z-valid.json"), fs::read(&valid).unwrap()).unwrap();
    fs::write(receipt_dir.join("README.txt"), b"ignored").unwrap();
    let mut bad = receipt(s.clone(), l.clone());
    bad.promotable = true;
    fs::write(&invalid, serde_json::to_vec(&bad).unwrap()).unwrap();
    fs::write(&policy_path, serde_json::to_vec(&policy(s, l)).unwrap()).unwrap();
    (dir, valid, invalid, policy_path, receipt_dir)
}

fn cli_run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_receipt_valid_and_quiet_contract() {
    let (_dir, valid, _invalid, _policy, _receipts) = cli_fixtures();
    let output = cli_run(&["verify", "receipt", valid.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty());
    let output = cli_run(&["--quiet", "verify", "receipt", valid.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_receipt_verdict_and_operational_errors() {
    let (dir, _valid, invalid, _policy, _receipts) = cli_fixtures();
    assert_eq!(
        cli_run(&["verify", "receipt", invalid.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    let missing = dir.path().join("missing.json");
    assert_eq!(
        cli_run(&["verify", "receipt", missing.to_str().unwrap()])
            .status
            .code(),
        Some(3)
    );
    fs::write(&missing, b"{").unwrap();
    assert_eq!(
        cli_run(&["verify", "receipt", missing.to_str().unwrap()])
            .status
            .code(),
        Some(3)
    );
}

#[test]
fn cli_aggregate_help_file_and_sorted_directory() {
    let (_dir, valid, _invalid, policy, receipts) = cli_fixtures();
    let help = cli_run(&["verify", "receipt-aggregate", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--policy"));
    assert!(help_text.contains("receipt-aggregate"));
    let output = cli_run(&[
        "verify",
        "receipt-aggregate",
        valid.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"Receipts valid\n");
    assert_eq!(
        cli_run(&[
            "verify",
            "receipt-aggregate",
            receipts.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap()
        ])
        .status
        .code(),
        Some(0)
    );
    let (_dir, _valid, invalid, policy, _receipts) = cli_fixtures();
    assert_eq!(
        cli_run(&[
            "verify",
            "receipt-aggregate",
            invalid.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .status
        .code(),
        Some(1)
    );
}
