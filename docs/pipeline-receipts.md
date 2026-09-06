# Pipeline shard receipts

`PipelineShardReceipt` is the unsigned, target-scoped evidence contract used by CI
verification jobs. Its schema identifier is `pipeline-shard-receipt/v1`.
Receipts bind a repository commit and deterministic source and lock fingerprints
to an OS, architecture, toolchain, profile, feature set, and binding runtime.

Validate one locally with:

```text
sbom-tools verify receipt path/to/receipt.json
sbom-tools verify receipt-aggregate receipts/ --policy aggregate-policy.json
sbom-tools verify receipt-generate --input receipt-input.json --output receipt.json
sbom-tools verify receipt-policy-generate --manifest policy-manifest.json \
  --context policy-context.json --output aggregate-policy.json
sbom-tools verify receipt-context --repository org/repo --commit-sha <sha> \
  --event-name push --ref-name refs/heads/main --default-branch main \
  --output context.json
sbom-tools verify receipt-job --manifest job-manifest.json --context context.json \
  --outcome producer=success --output receipt.json
```

`receipt-context` and `receipt-job` are the two subcommands CI actually runs:
the emit-receipt action writes a strict `aggregate-policy-context/v1` file from
CI-provided values, then generates one receipt from a checked-in
`pipeline-shard-job-manifest/v1` file (schema in
`schemas/pipeline-shard-job-manifest/v1.schema.json`) plus the job outcome.
Hosted `ref_name` canonically carries the full `github.ref` form; the
unambiguous `github.ref_name` short forms (`N/merge`, the default branch name)
are also accepted, and a bare tag name is rejected as ambiguous.

The generator input is the strict JSON contract in
`schemas/pipeline-shard-receipt/input-v1.schema.json` (schema identifier
`pipeline-shard-receipt-input/v1`). It contains repository/workflow and commit
metadata, source and lock paths, an artifact root plus name/path artifact
descriptors, target identity, checks, timestamps, and either explicit
`local: true` or hosted event metadata. It contains no digest fields: source,
lock, and artifact digests are computed by the generator. Unknown fields are
rejected. Hosted metadata is self-asserted and unsigned in v1; its `sha` is
authoritative for consistency checking and must equal `commit_sha`, and its
repository must equal `repository`. The generator cannot authorize promotion.

Receipts are unsigned and are non-promotion evidence; this slice rejects
`promotable: true`. Slice 5 must introduce signed promotion authority.
`source_fingerprint(root)` includes path-qualified file names and contents while
excluding only the top-level `.git/`, `target/`, and `receipts/` directories —
the exclusions are root-anchored and directory-only, so a vendored
`foo/target/` or a source file named `receipts` stays in the evidence, and a
symlink is rejected even when it carries an excluded name. Relative paths are
hashed with `/` separators regardless of host OS. `lock_fingerprint(root)`
uses the applicable Cargo, toolchain, binding, and Dagger lock inputs. Both
functions sort paths before hashing, so the result is reproducible across
filesystems and operating systems.

Receipts created from a local working tree must use `trust_context: "local"` and
`promotable: false`. Local receipts are useful for reproduction but cannot pass
a promotion gate. CI aggregation rejects missing or duplicate targets, source or
lock mismatches, failed/cancelled/skipped required checks, missing or digest-
invalid artifacts, and duplicate artifact identities.

The receipt is an action result, not a dependency cache. Cache keys must remain
separate from receipt and artifact identities; cache contents are never accepted
as verification evidence. Rust and Bindings workflows now emit one unsigned
receipt per producer target with `if: always()`, preserving native OS execution
and the existing Rust CI check name. Bindings fan-in is additive and validates
all producer receipts without filename collisions. The cargo-deny advisories
leg stays informational (`continue-on-error`) by explicit maintainer policy and
emits no receipt: surprise upstream CVEs must not hard-block unrelated PRs, and
a failed receipt in the evidence set would fail the aggregate closed and
reintroduce that blocking behavior indirectly.

Hosted failure/cancel and native cross-platform proof remain pending acceptance
gates. Producer and aggregate jobs share a `receipt-cli` build cache to bound
the cost of the per-producer CLI builds; no acceleration or savings claim is
made.

Fingerprinting reads ordinary filesystem paths and is non-atomic: a file can
change between enumeration and reading, so this is subject to local TOCTOU
races and does not describe an atomic filesystem snapshot. Artifact containment
checks have the same bounded local race.
The generator is deliberately local/non-promotable; aggregation trusts only
the externally supplied expected digests (they are policy inputs, not
recomputed by the aggregate command).

The aggregate policy is JSON with exactly `schema` (`aggregate-policy/v1`,
published in `schemas/aggregate-policy/v1.schema.json`), `expected_targets`,
`context`, `required_checks`, and `artifacts` fields; each field uses the
corresponding receipt contract shape. Unknown fields are rejected. I/O and
malformed JSON are operational errors and exit 3; readable JSON that violates
any contract shape — a receipt, policy, manifest, or generator input — is a
gate verdict and exits 1, uniformly across all receipt subcommands. Aggregate success, including an explicitly expected
`trust_context: "local"`, is verification only and never a promotion decision
in v1.

Policy generation takes two strict versioned inputs. The static
`aggregate-policy-manifest/v1` owns workflow, source and lock roots, expected
target topology, required check names, and trusted artifact name/path inputs.
The runtime `aggregate-policy-context/v1` owns repository, commit SHA, and
hosted or explicit local metadata. Source and lock fingerprints plus artifact
sizes and digests are computed from disk. Generated policies are always
non-promotable, deterministically ordered, and written with create-new
semantics.
