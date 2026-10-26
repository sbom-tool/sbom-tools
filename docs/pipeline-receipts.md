# Diagnostic pipeline receipts

This unit provides Rust types, schemas, local generation, and verification for
unsigned `pipeline-shard-receipt/v1` diagnostics. It adds no workflow producers,
actions, job manifests, required gates, signing, or release authority.

```sh
sbom-tools verify receipt receipt.json [--output json]
sbom-tools verify receipt-generate --input receipt-input.json --output receipt.json
sbom-tools verify receipt-aggregate receipts/ --policy aggregate-policy.json [--output json]
```

## Inputs and results

The public schemas are `schemas/pipeline-shard-receipt/v1.schema.json`,
`schemas/pipeline-shard-receipt/input-v1.schema.json`, and
`schemas/aggregate-policy/v1.schema.json`. Unknown fields and duplicate keys
(at any level, including inside `versions`) are rejected, so no two JSON
parsers can disagree about a document's meaning. Required nullable keys must be
present, using `null` for an absent value. Documents larger than 16 MiB are
rejected before parsing. The schemas' `format: date-time` is an annotation in
JSON Schema 2020-12; the Rust validator enforces RFC 3339 timestamps.

The generator computes source, lock, and artifact digests from the descriptor's
paths; relative `source_root` and `artifact_root` values resolve against the
current working directory. It validates every caller-supplied field before
hashing anything. It records supplied checks, versions, and timestamps; it does
not execute checks or authenticate those claims. Output creation preserves
existing files.

Artifact and lock paths use one portable grammar on every OS (the schemas'
`$defs/relative_path`): `/`-separated nonempty segments, none equal to `.` or
`..`, with no backslash, colon, or control characters. Lock paths must be
unique, and no component of an artifact or lock path may be a symlink.

Exit codes are 0 for accepted verification, 1 for readable JSON violating the
contract (including oversized documents), and 3 for I/O or malformed JSON. CLI
usage errors also exit 3, as in every command. `--quiet` suppresses success
output; failure diagnostics remain on stderr. With `--output json`,
`verify receipt` and `verify receipt-aggregate` print a JSON verdict (`valid`,
`error`, and for aggregation `receipt_count`/`artifact_count`) on stdout for
both outcomes, regardless of `--quiet`.

## Identity

`trust-context / target / lock-digest / source-fingerprint`

Target includes verification scope, OS, architecture, toolchain, profile,
features, and optional binding runtime. The descriptor generator sorts features.
`versions` is supplied metadata, not proof of the executables that ran.

Source fingerprinting hashes sorted UTF-8 relative names joined with `/` and
exact file bytes, streamed so memory use does not grow with the tree. Only the
root `.git` entry (directory or worktree/submodule pointer file) and the root
`target/` and `receipts/` directories are excluded. Nested entries and regular
files with those names remain inputs. A file whose size changes while it is
hashed fails the run instead of producing a digest.
Encountered symlinks are rejected before exclusions. Empty directories and file
permission bits are not encoded. Line endings are not normalized.

For future `pull_request` producers, `commit_sha` intentionally identifies the
tested synthetic merge (`github.sha`). Updating the base can change this SHA and
the source content, even for the same contributor head. A content fingerprint
only changes if included names or bytes change. This means "this merge result
was checked." Unit 1 adds no separate head SHA; future producers must retain
run/PR metadata if head/base lineage is needed.

The lock digest covers exactly the path-qualified bytes in `lock_paths`.
Examples include `Cargo.lock`, `rust-toolchain.toml`,
`dagger/rust-sdk/Cargo.lock`, `bindings/go/go.mod`,
`bindings/nodejs/package-lock.json`, `bindings/python/pyproject.toml`, and
`bindings/swift/Package.swift`. Only explicitly selected inputs are hashed.
Workflow action SHAs, installed runtime versions, and remote tools are not
implicitly included. A digest does not describe the complete toolchain.

## Trust model

All v1 receipts must have `promotable: false`. Context labels are self-asserted
diagnostic metadata; they cannot authorize promotion, authenticate a runner, or
prove branch protection. Local descriptors choose `local: true` without hosted
metadata. Hosted repository and SHA must equal the receipt identity.

Ordinary `pull_request` descriptors classify as `pull-request`.
`pull_request_target` descriptors are rejected: that event executes in the base
repository context and can have secrets and write authority depending on
settings. Future PR producers must explicitly minimize token permissions and
avoid secrets. Event strings do not establish token capabilities.
Default-branch and tag pushes can be labeled `protected-main` and `release`,
but remain unsigned diagnostics. Hosted producers require separate agreement.
See GitHub's [event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

The canonical `ref_name` representation is full `github.ref`. For
`pull_request` runs the numeric `N/merge` short form is also accepted, since
the event disambiguates it. Push runs require the full form: a bare `main` is
also the `github.ref_name` of a tag called `main`, so bare branch and tag names
are rejected as ambiguous.

## Verification and recovery

Single-receipt validation checks structure and semantic consistency. Local
aggregate verification compares a receipt set with a supplied versioned policy:
expected targets, context, fingerprints, required checks, and artifact metadata.
Missing/duplicate targets, mismatched digests, failed/cancelled checks, skipped
required checks, or inconsistent artifact metadata reject the set. Aggregation
does not download artifacts, rehash artifact files, or authenticate the supplied
policy. Agreement between documents is not proof of origin.

Retain rejected inputs and inspect stderr before retrying. Reproduce against
the same source snapshot, then write corrected output to a new path to preserve
history. An interrupted or failed write may leave a partial file, which must
not be treated as a valid receipt. Hashing is non-atomic and subject to TOCTOU;
callers must supply a stable snapshot. Future Git archive producers and
verifiers must use identical commits and explicit `core.autocrlf=false` and
`core.eol=lf` settings on both sides.

## Acceptance and later adoption

Contract, generator, schema-binding, and fingerprint tests run through the
existing native Rust matrix. The fingerprint suite compares a fixed nested tree
with a predetermined digest on each OS. Negative cases cover path/content
changes, exclusions, malformed/invalid documents, context, and non-promotability.
No workflow files change in Unit 1; MSRV remains 1.88 and dependencies retain
the upstream lockfile.

Workflow adoption needs a named baseline of `main` run/job IDs, commits, queue
times, execution times, compute minutes, and cache hits/misses (unknown where
unavailable). Compare reusable CLI artifacts or a measured cache path before
adoption, including cold-cache correctness and upload/download failure recovery.
Derive topology from one source of truth. Verify and document GitHub's existing
[cache isolation](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#restrictions-for-accessing-a-cache)
and `save-if` controls. Cargo-deny advisories remain informational.

Receipt generation adds work. Savings are expected from later native FFI reuse
and require measurement; this unit claims none. Bounded Dagger fan-out, native
artifact consumption, coordination, and signed release attestations are future
work requiring separate evidence and agreement.
