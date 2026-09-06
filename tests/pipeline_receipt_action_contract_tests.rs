use std::fs;

#[test]
fn receipt_action_uses_canonical_archive_configuration() {
    let action = fs::read_to_string(".github/actions/emit-receipt/action.yml")
        .expect("receipt action must be present");

    assert!(
        action.contains(
            "git -c core.autocrlf=false -c core.eol=lf archive \"$RECEIPT_SHA\" | tar -x -C \"$target\""
        ),
        "receipt source snapshot must be independent of runner autocrlf settings"
    );
    assert!(
        !action.contains("\ngit archive \"$RECEIPT_SHA\"")
            && !action.contains("\n        git archive \"$RECEIPT_SHA\""),
        "receipt action must not regress to an environment-dependent archive"
    );
}

#[test]
fn aggregate_jobs_use_canonical_archive_configuration() {
    // The aggregate policy's source fingerprint is compared byte-for-byte
    // against every producer receipt, so the aggregate jobs' snapshot must
    // use the same canonical archive flags as emit-receipt.
    for path in [
        ".github/workflows/rust.yml",
        ".github/workflows/bindings.yml",
    ] {
        let workflow = fs::read_to_string(path).expect("workflow must be present");
        let archives: Vec<&str> = workflow
            .lines()
            .filter(|line| line.contains("git") && line.contains("archive \"${{ github.sha }}\""))
            .collect();
        assert!(!archives.is_empty(), "{path}: aggregate snapshot missing");
        for line in archives {
            assert!(
                line.contains("git -c core.autocrlf=false -c core.eol=lf archive"),
                "{path}: aggregate snapshot must pin autocrlf/eol: {line}"
            );
        }
    }
}
