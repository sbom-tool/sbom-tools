use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};

fn read(path: impl AsRef<Path>) -> Value {
    let path = path.as_ref();
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{path:?}: {e}")))
        .unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

fn targets(value: &Value) -> BTreeSet<String> {
    value["expected_targets"]
        .as_array()
        .expect("aggregate expected_targets")
        .iter()
        .map(|target| serde_json::to_string(target).unwrap())
        .collect()
}

#[test]
fn job_manifests_are_valid_and_match_aggregate_contracts() {
    for (prefix, workflow) in [("rust", "CI"), ("bindings", "Bindings")] {
        let aggregate = read(format!(".github/receipts/{prefix}-policy-manifest.json"));
        let aggregate_locks = aggregate["lock_paths"].clone();
        let expected = targets(&aggregate);
        let mut seen = BTreeSet::new();
        let entries = fs::read_dir(".github/receipts/jobs").unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            let value = read(&path);
            if value["workflow"] != workflow {
                continue;
            }
            assert_eq!(
                value["schema"], "pipeline-shard-job-manifest/v1",
                "{path:?}"
            );
            assert_eq!(value["lock_paths"], aggregate_locks, "{path:?}");
            assert_eq!(
                value["artifact_root"], aggregate["artifact_root"],
                "{path:?}"
            );
            let target = serde_json::to_string(&value["target"]).unwrap();
            assert!(
                seen.insert(target.clone()),
                "duplicate target in {workflow}: {target}"
            );
            assert!(expected.contains(&target), "unexpected target in {path:?}");
            assert_eq!(value["checks"], aggregate["required_checks"], "{path:?}");
        }
        assert_eq!(seen, expected, "{prefix} target parity");
    }
}
