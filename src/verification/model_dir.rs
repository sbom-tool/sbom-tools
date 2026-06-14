//! Model-weight integrity verification.
//!
//! Verifies the on-disk weight files of `MachineLearningModel` / `Data`
//! components against the hashes recorded in an SBOM (typically injected by the
//! HuggingFace enricher). For each such component this:
//!
//! 1. locates candidate weight files under a model directory, looking both for
//!    direct filenames AND the HuggingFace cache snapshot layout where blob
//!    files are named by their SHA-256 content hash, then
//! 2. verifies the located file against the component's hash via the shared
//!    [`verify_file_hash`](crate::verification::verify_file_hash).
//!
//! The result is a per-component pass / fail / missing report suitable for CI
//! gating.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{Component, ComponentType, HashAlgorithm, NormalizedSbom};
use crate::verification::verify_file_hash;

/// Outcome of verifying a single model component's weights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelVerifyResult {
    /// A weight file was located and its hash matched the SBOM.
    Verified,
    /// A weight file was located but its hash did NOT match (possible tampering).
    Mismatch,
    /// The component declares hashes but no matching weight file was found.
    Missing,
    /// The component declares no usable (SHA-256/384/512) hash to verify against.
    NoHash,
}

impl ModelVerifyResult {
    /// Short status label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Mismatch => "MISMATCH",
            Self::Missing => "MISSING",
            Self::NoHash => "NO-HASH",
        }
    }
}

/// Per-component model-weight verification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentModelVerification {
    /// Component name.
    pub name: String,
    /// Component version.
    pub version: Option<String>,
    /// Verification outcome.
    pub result: ModelVerifyResult,
    /// Hash value (hex) that was checked, when applicable.
    pub hash: Option<String>,
    /// Path of the weight file that was located, when applicable (relative to
    /// the model directory for readability).
    pub file: Option<String>,
}

/// Aggregate model-weight verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVerifyReport {
    /// Model directory that was searched.
    pub model_dir: String,
    /// ML-model / dataset components inspected.
    pub total_models: usize,
    /// Components verified successfully.
    pub verified_count: usize,
    /// Components whose located weight file mismatched.
    pub mismatch_count: usize,
    /// Components with hashes but no located weight file.
    pub missing_count: usize,
    /// Components without a usable hash to verify.
    pub no_hash_count: usize,
    /// Per-component records.
    pub components: Vec<ComponentModelVerification>,
}

impl ModelVerifyReport {
    /// Whether the run had any failing component (mismatch or missing).
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.mismatch_count > 0 || self.missing_count > 0
    }
}

/// Whether a hash algorithm is one we can verify a located file against.
///
/// We compute SHA-256 / SHA-512 over candidate files; SHA-384 shares SHA-512's
/// preimage but a distinct digest, so only the two directly-computable forms are
/// treated as verifiable here (matching `verify_file_hash`).
const fn is_verifiable(alg: &HashAlgorithm) -> bool {
    matches!(alg, HashAlgorithm::Sha256 | HashAlgorithm::Sha512)
}

/// Verify the weight files of all model/dataset components in `sbom` against the
/// files found under `model_dir`.
#[must_use]
pub fn verify_model_dir(sbom: &NormalizedSbom, model_dir: &Path) -> ModelVerifyReport {
    // Canonicalize the model-dir root once so symlink-escape detection (below)
    // compares against a fully-resolved root. If the root itself can't be
    // canonicalized (e.g. it does not exist), fall back to the path as given;
    // the walk will simply find nothing.
    let root = std::fs::canonicalize(model_dir).unwrap_or_else(|_| model_dir.to_path_buf());

    // Index files by basename (for direct-filename matches) once, so a large
    // model directory is walked a single time. Paths that resolve outside the
    // root (via symlinks) are excluded by the index.
    let index = FileIndex::build(&root);

    let mut report = ModelVerifyReport {
        model_dir: model_dir.display().to_string(),
        total_models: 0,
        verified_count: 0,
        mismatch_count: 0,
        missing_count: 0,
        no_hash_count: 0,
        components: Vec::new(),
    };

    for component in sbom.components.values() {
        if !is_model_like(component) {
            continue;
        }
        report.total_models += 1;

        let record = verify_component(component, &root, &index);
        match record.result {
            ModelVerifyResult::Verified => report.verified_count += 1,
            ModelVerifyResult::Mismatch => report.mismatch_count += 1,
            ModelVerifyResult::Missing => report.missing_count += 1,
            ModelVerifyResult::NoHash => report.no_hash_count += 1,
        }
        report.components.push(record);
    }

    report
}

/// Components whose weights we attempt to verify: trained models and datasets.
fn is_model_like(component: &Component) -> bool {
    matches!(
        component.component_type,
        ComponentType::MachineLearningModel | ComponentType::Data
    )
}

/// Verify a single component, returning its record.
fn verify_component(
    component: &Component,
    model_dir: &Path,
    index: &FileIndex,
) -> ComponentModelVerification {
    let make = |result, hash: Option<String>, file: Option<String>| ComponentModelVerification {
        name: component.name.clone(),
        version: component.version.clone(),
        result,
        hash,
        file,
    };

    // Only consider hashes we can recompute over a file.
    let verifiable: Vec<_> = component
        .hashes
        .iter()
        .filter(|h| is_verifiable(&h.algorithm))
        .collect();

    if verifiable.is_empty() {
        return make(ModelVerifyResult::NoHash, None, None);
    }

    // Candidate filenames to look for, in addition to sha256-named blobs:
    // any external-reference / model-card filename heuristics would be noisy, so
    // we rely on (a) the hash-named blob (HF cache layout) and (b) the
    // component name as a filename stem.
    let name_candidates = filename_candidates(component);

    let mut last_missing_hash: Option<String> = None;

    for hash in verifiable {
        let hash_hex = hash.value.to_lowercase();
        last_missing_hash = Some(hash_hex.clone());

        // 1. HuggingFace cache layout: a blob file is literally named by its
        //    sha256. A direct hit means the bytes are present under that name.
        if let Some(path) = index.by_basename(&hash_hex) {
            return verify_against(component, &hash_hex, path, model_dir);
        }

        // 2. Direct filenames (e.g. `model.safetensors`, `<name>.safetensors`).
        for candidate in &name_candidates {
            if let Some(path) = index.by_basename(candidate) {
                return verify_against(component, &hash_hex, path, model_dir);
            }
        }
    }

    make(ModelVerifyResult::Missing, last_missing_hash, None)
}

/// Run `verify_file_hash` for a located file and build the record.
fn verify_against(
    component: &Component,
    hash_hex: &str,
    path: &Path,
    model_dir: &Path,
) -> ComponentModelVerification {
    let rel = path
        .strip_prefix(model_dir)
        .unwrap_or(path)
        .display()
        .to_string();
    let make = |result| ComponentModelVerification {
        name: component.name.clone(),
        version: component.version.clone(),
        result,
        hash: Some(hash_hex.to_string()),
        file: Some(rel.clone()),
    };

    match verify_file_hash(path, hash_hex) {
        Ok(r) if r.verified => make(ModelVerifyResult::Verified),
        Ok(_) => make(ModelVerifyResult::Mismatch),
        // An I/O error on a located file is treated as a mismatch: the file is
        // present (it was indexed) but unreadable, which is a verification
        // failure, not a clean "missing".
        Err(_) => make(ModelVerifyResult::Mismatch),
    }
}

/// Candidate weight filenames for a component, by name.
///
/// Real weight files are not named after the component in the HF layout (they
/// are sha256-named blobs, handled separately), but locally-laid-out model
/// directories often use `model.*` or `<name>.*`. These are basename matches,
/// so the directory walk handles any nesting.
fn filename_candidates(component: &Component) -> Vec<String> {
    let exts = [
        "safetensors",
        "bin",
        "pt",
        "pth",
        "onnx",
        "gguf",
        "ggml",
        "h5",
        "pb",
        "tflite",
    ];
    let stems = ["model", "pytorch_model", component.name.as_str()];

    let mut out = Vec::new();
    for stem in stems {
        if stem.is_empty() {
            continue;
        }
        for ext in exts {
            out.push(format!("{stem}.{ext}"));
        }
    }
    out
}

/// A flat index of every file under a directory, keyed by basename.
///
/// The HuggingFace cache stores weight bytes as `blobs/<sha256>` with
/// human-named symlinks under `snapshots/<rev>/`; indexing by basename lets us
/// match both the sha256-named blob and a plain `model.safetensors` regardless
/// of nesting. When several files share a basename the first seen wins; that is
/// acceptable because hash verification still rejects a wrong file.
///
/// Indexed paths are stored in canonicalized form and are guaranteed to resolve
/// *inside* the model-dir root: a symlink (or a `..` segment) that escapes the
/// root is skipped, so `verify --model-dir` can never be tricked into reading a
/// file outside the tree it was pointed at. HuggingFace's intra-tree
/// `snapshots → blobs` symlinks still resolve fine because they stay under root.
struct FileIndex {
    by_name: HashMap<String, PathBuf>,
}

impl FileIndex {
    /// Build the index from a *canonicalized* `root`. Every candidate path is
    /// itself canonicalized (which follows symlinks) and only retained when the
    /// resolved path is still within `root`; this is the symlink-escape bound.
    fn build(root: &Path) -> Self {
        let mut by_name = HashMap::new();
        let mut stack = vec![root.to_path_buf()];
        // Directories are canonical here, so a `visited` set makes the walk
        // robust against symlinked-directory cycles within the tree.
        let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        while let Some(dir) = stack.pop() {
            if !visited.insert(dir.clone()) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Resolve the entry fully (follows symlinks, normalizes `..`).
                // A path that fails to resolve (dangling symlink) is skipped.
                let Ok(resolved) = std::fs::canonicalize(&path) else {
                    continue;
                };
                // Reject anything that escapes the model-dir root. Without this a
                // crafted `model.safetensors -> /etc/passwd` (or `../secret`)
                // symlink would let an attacker have the verifier read an
                // arbitrary file outside the directory under audit.
                if !resolved.starts_with(root) {
                    continue;
                }
                let meta = match std::fs::metadata(&resolved) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.is_dir() {
                    stack.push(resolved);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Key on the on-disk basename (e.g. the human-readable
                    // snapshot name), but store the bounded, resolved path so the
                    // subsequent hash read targets the in-tree bytes.
                    by_name
                        .entry(name.to_lowercase())
                        .or_insert_with(|| resolved.clone());
                }
            }
        }

        Self { by_name }
    }

    /// Look up a file by basename (case-insensitive).
    fn by_basename(&self, name: &str) -> Option<&Path> {
        self.by_name.get(&name.to_lowercase()).map(PathBuf::as_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DocumentMetadata, Hash};
    use sha2::{Digest, Sha256};
    use std::fs;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn model_component(name: &str, hash_hex: &str) -> Component {
        let mut c = Component::new(name.to_string(), format!("{name}-ref"))
            .with_version("1.0.0".to_string());
        c.component_type = ComponentType::MachineLearningModel;
        c.hashes
            .push(Hash::new(HashAlgorithm::Sha256, hash_hex.to_string()));
        c
    }

    #[test]
    fn verifies_against_hf_blob_named_by_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let weights = b"fake model weights";
        let hex = sha256_hex(weights);

        // HuggingFace cache layout: blobs/<sha256>.
        let blobs = dir.path().join("blobs");
        fs::create_dir_all(&blobs).unwrap();
        fs::write(blobs.join(&hex), weights).unwrap();

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("bert", &hex));

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.total_models, 1);
        assert_eq!(report.verified_count, 1);
        assert_eq!(report.components[0].result, ModelVerifyResult::Verified);
        assert!(!report.has_failures());
    }

    #[test]
    fn verifies_against_direct_filename() {
        let dir = tempfile::tempdir().unwrap();
        let weights = b"safetensors bytes";
        let hex = sha256_hex(weights);
        fs::write(dir.path().join("model.safetensors"), weights).unwrap();

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("bert", &hex));

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.verified_count, 1);
        assert_eq!(
            report.components[0].file.as_deref(),
            Some("model.safetensors")
        );
    }

    #[test]
    fn detects_tampering_as_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // The file's real content does not match the SBOM hash → tampering.
        fs::write(dir.path().join("model.safetensors"), b"tampered bytes").unwrap();
        let claimed = sha256_hex(b"original bytes");

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("bert", &claimed));

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.mismatch_count, 1);
        assert_eq!(report.components[0].result, ModelVerifyResult::Mismatch);
        assert!(report.has_failures());
    }

    #[test]
    fn reports_missing_when_no_file_found() {
        let dir = tempfile::tempdir().unwrap();
        let hex = sha256_hex(b"weights that are not on disk");

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("bert", &hex));

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.missing_count, 1);
        assert_eq!(report.components[0].result, ModelVerifyResult::Missing);
    }

    #[test]
    fn reports_no_hash_when_only_weak_hash_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Component::new("bert".to_string(), "bert-ref".to_string());
        c.component_type = ComponentType::MachineLearningModel;
        c.hashes
            .push(Hash::new(HashAlgorithm::Md5, "deadbeef".to_string()));

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(c);

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.no_hash_count, 1);
        assert_eq!(report.components[0].result, ModelVerifyResult::NoHash);
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlink_escaping_model_dir() {
        use std::os::unix::fs::symlink;

        // The real weight bytes live OUTSIDE the model directory.
        let outside = tempfile::tempdir().unwrap();
        let weights = b"weights that live outside the model dir";
        let hex = sha256_hex(weights);
        let secret = outside.path().join("model.safetensors");
        fs::write(&secret, weights).unwrap();

        // Inside the model dir, a symlink with a plausible weight name points at
        // the out-of-tree file. A naive verifier would follow it and report
        // VERIFIED, leaking the result of reading an arbitrary path.
        let model_dir = tempfile::tempdir().unwrap();
        symlink(&secret, model_dir.path().join("model.safetensors")).unwrap();

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("escape", &hex));

        let report = verify_model_dir(&sbom, model_dir.path());
        assert_eq!(report.total_models, 1);
        assert_eq!(
            report.verified_count, 0,
            "a symlink escaping the model dir must not be followed/verified"
        );
        assert_eq!(
            report.components[0].result,
            ModelVerifyResult::Missing,
            "out-of-tree symlink target is treated as no in-tree file found"
        );
    }

    #[cfg(unix)]
    #[test]
    fn follows_intra_tree_symlink_like_hf_cache() {
        use std::os::unix::fs::symlink;

        // HuggingFace layout: blobs/<sha256> with a snapshots/ symlink that stays
        // WITHIN the model dir. This must still verify (the escape guard only
        // rejects targets that leave the root).
        let dir = tempfile::tempdir().unwrap();
        let weights = b"in-tree hf blob bytes";
        let hex = sha256_hex(weights);

        let blobs = dir.path().join("blobs");
        let snapshots = dir.path().join("snapshots").join("main");
        fs::create_dir_all(&blobs).unwrap();
        fs::create_dir_all(&snapshots).unwrap();
        let blob = blobs.join(&hex);
        fs::write(&blob, weights).unwrap();
        symlink(&blob, snapshots.join("model.safetensors")).unwrap();

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(model_component("bert", &hex));

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(
            report.verified_count, 1,
            "intra-tree HF snapshot→blob symlink must still verify"
        );
    }

    #[test]
    fn ignores_non_model_components() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Component::new("lib".to_string(), "lib-ref".to_string());
        c.component_type = ComponentType::Library;
        c.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "a".repeat(64)));

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(c);

        let report = verify_model_dir(&sbom, dir.path());
        assert_eq!(report.total_models, 0, "library components are not models");
    }
}
