//! File hash verification.
//!
//! Verifies SBOM file integrity against SHA-256, SHA-512, or other hash values.

use std::fmt;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256, Sha512};

/// Result of a file hash verification
#[derive(Debug, Clone)]
pub struct HashVerifyResult {
    /// Whether the hash matched
    pub verified: bool,
    /// Algorithm used
    pub algorithm: String,
    /// Expected hash value
    pub expected: String,
    /// Actual computed hash value
    pub actual: String,
}

impl fmt::Display for HashVerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.verified {
            write!(f, "OK: {} hash verified", self.algorithm)
        } else {
            write!(
                f,
                "MISMATCH: {} hash\n  expected: {}\n  actual:   {}",
                self.algorithm, self.expected, self.actual
            )
        }
    }
}

/// Verify a file's hash against an expected value.
///
/// Supports formats:
/// - `sha256:<hex>` or `sha512:<hex>` (prefixed)
/// - bare hex string (auto-detected by length: 64=SHA-256, 128=SHA-512)
/// - `<hash>  <filename>` (sha256sum output format — hash portion extracted)
///
/// # Errors
///
/// Returns error if the file cannot be read or the hash format is unrecognized.
pub fn verify_file_hash(path: &Path, expected: &str) -> anyhow::Result<HashVerifyResult> {
    let content = fs::read(path)?;
    let expected = expected.trim();

    // Parse hash file format: "<hash>  <filename>" or "<hash> <filename>"
    let expected = if expected.contains(' ') {
        expected.split_whitespace().next().unwrap_or(expected)
    } else {
        expected
    };

    // Detect algorithm from prefix or length (case-insensitive prefix)
    let expected_lower = expected.to_lowercase();
    let (algorithm, expected_hex) = if let Some(hex) = expected_lower.strip_prefix("sha256:") {
        ("SHA-256", hex.to_string())
    } else if let Some(hex) = expected_lower.strip_prefix("sha512:") {
        ("SHA-512", hex.to_string())
    } else {
        match expected.len() {
            64 => ("SHA-256", expected.to_string()),
            128 => ("SHA-512", expected.to_string()),
            _ => anyhow::bail!(
                "unrecognized hash format (length {}). Use sha256:<hex> or sha512:<hex>, \
                 or provide a 64-char (SHA-256) or 128-char (SHA-512) hex string",
                expected.len()
            ),
        }
    };

    let actual_hex = match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        }
        "SHA-512" => {
            let mut hasher = Sha512::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        }
        _ => unreachable!(),
    };

    let expected_lower = expected_hex.to_lowercase();
    let verified = actual_hex == expected_lower;

    Ok(HashVerifyResult {
        verified,
        algorithm: algorithm.to_string(),
        expected: expected_lower,
        actual: actual_hex,
    })
}

/// Read a hash from a `.sha256` sidecar file.
///
/// Expects format: `<hex>  <filename>` or bare `<hex>`.
///
/// # Errors
///
/// Returns error if the file cannot be read.
pub fn read_hash_file(path: &Path) -> anyhow::Result<String> {
    let content = fs::read_to_string(path)?;
    let trimmed = content.trim();
    let hash = trimmed.split_whitespace().next().unwrap_or(trimmed);
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn verify_sha256_match() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        // SHA-256 of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let result = verify_file_hash(f.path(), expected).unwrap();
        assert!(result.verified);
        assert_eq!(result.algorithm, "SHA-256");
    }

    #[test]
    fn verify_sha256_mismatch() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let expected = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_file_hash(f.path(), expected).unwrap();
        assert!(!result.verified);
    }

    #[test]
    fn verify_prefixed_sha256() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let expected = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let result = verify_file_hash(f.path(), expected).unwrap();
        assert!(result.verified);
    }

    #[test]
    fn verify_sha256sum_file_format() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let expected =
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  somefile.json";
        let result = verify_file_hash(f.path(), expected).unwrap();
        assert!(result.verified);
    }

    #[test]
    fn verify_bad_length() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"test").unwrap();
        f.flush().unwrap();

        let result = verify_file_hash(f.path(), "abcdef");
        assert!(result.is_err());
    }

    #[test]
    fn read_hash_file_format() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "abcd1234  sbom.json").unwrap();
        f.flush().unwrap();

        let hash = read_hash_file(f.path()).unwrap();
        assert_eq!(hash, "abcd1234");
    }
}
