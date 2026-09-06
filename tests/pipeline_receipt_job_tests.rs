use sbom_tools::verification::*;
use std::{fs, path::PathBuf};

fn target() -> TargetIdentity {
    TargetIdentity {
        verification_scope: "job".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        toolchain: "stable".into(),
        profile: "debug".into(),
        features: vec![],
        binding_runtime: None,
    }
}
fn manifest(root: PathBuf) -> ReceiptJobManifest {
    ReceiptJobManifest {
        schema: PIPELINE_SHARD_JOB_MANIFEST_SCHEMA.into(),
        workflow: "test".into(),
        source_root: root.clone(),
        lock_paths: vec!["Cargo.lock".into()],
        artifact_root: root,
        artifacts: vec![],
        target: target(),
        checks: vec!["producer".into()],
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
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("Cargo.lock"), b"lock").unwrap();
    dir
}

#[test]
fn outcomes_and_failure_classification_are_preserved() {
    let dir = fixture();
    for (value, classification) in [
        ("success", None),
        ("failure", Some("failed")),
        ("cancelled", Some("cancelled")),
        ("skipped", None),
    ] {
        let receipt = generate_job_receipt(
            manifest(dir.path().into()),
            context(),
            &[("producer".into(), value.into())],
            None,
            None,
        )
        .unwrap();
        assert_eq!(receipt.failure_classification.as_deref(), classification);
        assert_eq!(
            receipt.checks[0].outcome,
            match value {
                "success" => CheckOutcome::Passed,
                "failure" => CheckOutcome::Failed,
                "cancelled" => CheckOutcome::Cancelled,
                _ => CheckOutcome::Skipped,
            }
        );
    }
}

#[test]
fn rejects_identity_and_outcome_contract_violations() {
    let dir = fixture();
    let m = manifest(dir.path().into());
    assert!(
        generate_job_receipt(
            m.clone(),
            context(),
            &[("producer".into(), "success".into())],
            Some("Windows"),
            Some("X64")
        )
        .is_err()
    );
    assert!(generate_job_receipt(m.clone(), context(), &[], None, None).is_err());
    assert!(
        generate_job_receipt(
            m.clone(),
            context(),
            &[("extra".into(), "success".into())],
            None,
            None
        )
        .is_err()
    );
    assert!(
        generate_job_receipt(
            m,
            context(),
            &[
                ("producer".into(), "success".into()),
                ("producer".into(), "failed".into())
            ],
            None,
            None
        )
        .is_err()
    );
}

#[test]
fn context_writer_validates_and_does_not_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("context.json");
    write_context(&path, &context()).unwrap();
    assert!(write_context(&path, &context()).is_err());
    let mut invalid = context();
    invalid.commit_sha = "bad".into();
    assert!(write_context(&dir.path().join("invalid.json"), &invalid).is_err());
}

#[test]
fn cli_root_dispatches_receipt_context() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("context.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .args([
            "verify",
            "receipt-context",
            "--repository",
            "org/repo",
            "--commit-sha",
            &"a".repeat(40),
            "--event-name",
            "push",
            "--ref-name",
            "refs/heads/main",
            "--default-branch",
            "main",
            "--output",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(output.exists());
}

#[test]
fn source_token_resolves_from_runner_temp() {
    // RUNNER_TEMP is injected into a child process instead of set_var in this
    // one: libtest runs sibling tests on other threads, and mutating the
    // process environment races their getenv calls (tempfile reads TMPDIR).
    let dir = fixture();
    let source = dir.path().join("sbom-receipt-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("Cargo.lock"), b"lock").unwrap();
    let mut m = manifest("$RUNNER_TEMP/sbom-receipt-source".into());
    m.artifact_root = m.source_root.clone();
    let manifest_path = dir.path().join("manifest.json");
    let context_path = dir.path().join("context.json");
    let output_path = dir.path().join("receipt.json");
    fs::write(&manifest_path, serde_json::to_vec(&m).unwrap()).unwrap();
    fs::write(&context_path, serde_json::to_vec(&context()).unwrap()).unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_sbom-tools"))
        .env("RUNNER_TEMP", dir.path())
        .args([
            "verify",
            "receipt-job",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--context",
            context_path.to_str().unwrap(),
            "--outcome",
            "producer=success",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(read_receipt(&output_path).is_ok());
}

#[test]
fn cli_receipt_job_dispatch_and_operational_errors() {
    let dir = fixture();
    let manifest_path = dir.path().join("manifest.json");
    let context_path = dir.path().join("context.json");
    let output_path = dir.path().join("receipt.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest(dir.path().into())).unwrap(),
    )
    .unwrap();
    fs::write(&context_path, serde_json::to_vec(&context()).unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_sbom-tools");
    let base = [
        "verify",
        "receipt-job",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--context",
        context_path.to_str().unwrap(),
        "--outcome",
        "producer=success",
        "--output",
        output_path.to_str().unwrap(),
    ];
    assert_eq!(
        std::process::Command::new(binary)
            .args(base)
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    assert!(read_receipt(&output_path).is_ok());
    assert_eq!(
        std::process::Command::new(binary)
            .args([
                "verify",
                "receipt-job",
                "--manifest",
                manifest_path.to_str().unwrap(),
                "--context",
                context_path.to_str().unwrap(),
                "--outcome",
                "producer=success",
                "--output",
                dir.path().join("bad").to_str().unwrap(),
                "--runner-os",
                "Windows"
            ])
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
    assert_eq!(
        std::process::Command::new(binary)
            .args([
                "verify",
                "receipt-job",
                "--manifest",
                dir.path().join("missing").to_str().unwrap(),
                "--context",
                context_path.to_str().unwrap(),
                "--outcome",
                "producer=success",
                "--output",
                dir.path().join("missing-out").to_str().unwrap()
            ])
            .status()
            .unwrap()
            .code(),
        Some(3)
    );
    assert_eq!(
        std::process::Command::new(binary)
            .args(base)
            .status()
            .unwrap()
            .code(),
        Some(3)
    );
}
