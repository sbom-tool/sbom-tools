//! Quality metrics for SBOM assessment.
//!
//! Provides detailed metrics for different aspects of SBOM quality.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::{
    AlgorithmClass, CompletenessDeclaration, ComponentType, CreatorType, CryptoAssetType,
    CryptoMaterialState, CryptoPrimitive, EolStatus, ExternalRefType, HashAlgorithm,
    NormalizedSbom, StalenessLevel, classify_algorithm,
};
use serde::{Deserialize, Serialize};

/// Overall completeness metrics for an SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletenessMetrics {
    /// Percentage of components with versions (0-100)
    pub components_with_version: f32,
    /// Percentage of components with PURLs (0-100)
    pub components_with_purl: f32,
    /// Percentage of components with CPEs (0-100)
    pub components_with_cpe: f32,
    /// Percentage of components with suppliers (0-100)
    pub components_with_supplier: f32,
    /// Percentage of components with hashes (0-100)
    pub components_with_hashes: f32,
    /// Percentage of components with licenses (0-100)
    pub components_with_licenses: f32,
    /// Percentage of components with descriptions (0-100)
    pub components_with_description: f32,
    /// Whether document has creator information
    pub has_creator_info: bool,
    /// Whether document has timestamp
    pub has_timestamp: bool,
    /// Whether document has serial number/ID
    pub has_serial_number: bool,
    /// Total component count
    pub total_components: usize,
}

impl CompletenessMetrics {
    /// Calculate completeness metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        if total == 0 {
            return Self::empty();
        }

        let mut with_version = 0;
        let mut with_purl = 0;
        let mut with_cpe = 0;
        let mut with_supplier = 0;
        let mut with_hashes = 0;
        let mut with_licenses = 0;
        let mut with_description = 0;

        // File/snippet inventory entries are not packages: NTIA-style
        // completeness fields (version, supplier, purl, …) do not apply to
        // them. Counting them cratered scores for file-cataloguing SBOMs
        // (thousands of files → ~0% version coverage on an otherwise
        // complete document).
        let mut countable = 0;

        for comp in sbom.components.values() {
            if !comp.component_type.is_package_scoped() {
                continue;
            }
            countable += 1;
            if comp.version.is_some() {
                with_version += 1;
            }
            if comp.identifiers.purl.is_some() {
                with_purl += 1;
            }
            if !comp.identifiers.cpe.is_empty() {
                with_cpe += 1;
            }
            if comp.supplier.is_some() {
                with_supplier += 1;
            }
            if !comp.hashes.is_empty() {
                with_hashes += 1;
            }
            // A NOASSERTION entry carries zero license information (the
            // CycloneDX parser emits declared=["NOASSERTION"] for empty
            // license objects), so it must not count as "has license".
            // SPDX NONE *is* information (the author asserts no license
            // exists) and still counts as documented.
            let has_license_info = comp
                .licenses
                .declared
                .iter()
                .any(|l| l.expression != "NOASSERTION")
                || comp
                    .licenses
                    .concluded
                    .as_ref()
                    .is_some_and(|c| c.expression != "NOASSERTION");
            if has_license_info {
                with_licenses += 1;
            }
            if comp.description.is_some() {
                with_description += 1;
            }
        }

        let pct = |count: usize| {
            if countable == 0 {
                0.0
            } else {
                (count as f32 / countable as f32) * 100.0
            }
        };

        Self {
            components_with_version: pct(with_version),
            components_with_purl: pct(with_purl),
            components_with_cpe: pct(with_cpe),
            components_with_supplier: pct(with_supplier),
            components_with_hashes: pct(with_hashes),
            components_with_licenses: pct(with_licenses),
            components_with_description: pct(with_description),
            has_creator_info: !sbom.document.creators.is_empty(),
            // A missing/invalid source timestamp is stored as the epoch
            // sentinel — report it as absent, not hardcoded true.
            has_timestamp: sbom.document.has_known_timestamp(),
            has_serial_number: sbom.document.serial_number.is_some(),
            total_components: total,
        }
    }

    /// Create empty metrics
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            components_with_version: 0.0,
            components_with_purl: 0.0,
            components_with_cpe: 0.0,
            components_with_supplier: 0.0,
            components_with_hashes: 0.0,
            components_with_licenses: 0.0,
            components_with_description: 0.0,
            has_creator_info: false,
            has_timestamp: false,
            has_serial_number: false,
            total_components: 0,
        }
    }

    /// Calculate overall completeness score (0-100)
    #[must_use]
    pub fn overall_score(&self, weights: &CompletenessWeights) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        // Component field scores
        score += self.components_with_version * weights.version;
        total_weight += weights.version * 100.0;

        score += self.components_with_purl * weights.purl;
        total_weight += weights.purl * 100.0;

        score += self.components_with_cpe * weights.cpe;
        total_weight += weights.cpe * 100.0;

        score += self.components_with_supplier * weights.supplier;
        total_weight += weights.supplier * 100.0;

        score += self.components_with_hashes * weights.hashes;
        total_weight += weights.hashes * 100.0;

        score += self.components_with_licenses * weights.licenses;
        total_weight += weights.licenses * 100.0;

        // Document metadata scores
        if self.has_creator_info {
            score += 100.0 * weights.creator_info;
        }
        total_weight += weights.creator_info * 100.0;

        if self.has_serial_number {
            score += 100.0 * weights.serial_number;
        }
        total_weight += weights.serial_number * 100.0;

        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }
}

/// Weights for completeness score calculation
#[derive(Debug, Clone)]
pub struct CompletenessWeights {
    pub version: f32,
    pub purl: f32,
    pub cpe: f32,
    pub supplier: f32,
    pub hashes: f32,
    pub licenses: f32,
    pub creator_info: f32,
    pub serial_number: f32,
}

impl Default for CompletenessWeights {
    fn default() -> Self {
        Self {
            version: 1.0,
            purl: 1.5, // Higher weight for PURL
            cpe: 0.5,  // Lower weight, nice to have
            supplier: 1.0,
            hashes: 1.0,
            licenses: 1.2, // Important for compliance
            creator_info: 0.3,
            serial_number: 0.2,
        }
    }
}

// ============================================================================
// Hash quality metrics
// ============================================================================

/// Hash/integrity quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashQualityMetrics {
    /// Components with any hash
    pub components_with_any_hash: usize,
    /// Components with at least one strong hash (SHA-256+, SHA-3, BLAKE, Blake3)
    pub components_with_strong_hash: usize,
    /// Components with only weak hashes (MD5, SHA-1) and no strong backup
    pub components_with_weak_only: usize,
    /// Distribution of hash algorithms across all components
    pub algorithm_distribution: BTreeMap<String, usize>,
    /// Total hash entries across all components
    pub total_hashes: usize,
    /// Vendor-supplied components — a known supplier, manufacturer or author
    /// (a `NOASSERTION` or placeholder name names no vendor) AND a
    /// non-synthetic canonical identifier (PURL/CPE/SWHID/SWID).
    /// Tracks how many such "upstream" components exist, used to verify
    /// CRA prEN 40000-1-3 `[PRE-7-RQ-07-RE]` (carry-through of vendor hashes).
    pub vendor_components_total: usize,
    /// Vendor components that carry at least one hash entry.
    pub vendor_components_with_hash: usize,
    /// Vendor components that carry at least one strong hash (SHA-256+).
    pub vendor_components_with_strong_hash: usize,
}

impl HashQualityMetrics {
    /// Calculate hash quality metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_any = 0;
        let mut with_strong = 0;
        let mut with_weak_only = 0;
        let mut distribution: BTreeMap<String, usize> = BTreeMap::new();
        let mut total_hashes = 0;
        let mut vendor_total = 0;
        let mut vendor_with_hash = 0;
        let mut vendor_with_strong = 0;

        for comp in sbom.components.values() {
            // Vendor-component classification (independent of hash presence).
            // The sentinel-aware producer test: a NOASSERTION supplier names
            // no vendor, exactly as an absent one, so it neither enters nor
            // leaves the PRE-7-RQ-07-RE cohort on its own.
            let is_vendor = crate::quality::compliance::has_known_producer(comp)
                && !matches!(
                    comp.canonical_id.source(),
                    crate::model::IdSource::Synthetic
                        | crate::model::IdSource::FormatSpecific
                        | crate::model::IdSource::NameVersion
                );
            if is_vendor {
                vendor_total += 1;
            }

            if comp.hashes.is_empty() {
                continue;
            }
            with_any += 1;
            total_hashes += comp.hashes.len();

            let mut has_strong = false;
            let mut has_weak = false;

            for hash in &comp.hashes {
                let label = hash_algorithm_label(&hash.algorithm);
                *distribution.entry(label).or_insert(0) += 1;

                if is_strong_hash(&hash.algorithm) {
                    has_strong = true;
                } else {
                    has_weak = true;
                }
            }

            if has_strong {
                with_strong += 1;
            } else if has_weak {
                with_weak_only += 1;
            }

            if is_vendor {
                vendor_with_hash += 1;
                if has_strong {
                    vendor_with_strong += 1;
                }
            }
        }

        Self {
            components_with_any_hash: with_any,
            components_with_strong_hash: with_strong,
            components_with_weak_only: with_weak_only,
            algorithm_distribution: distribution,
            total_hashes,
            vendor_components_total: vendor_total,
            vendor_components_with_hash: vendor_with_hash,
            vendor_components_with_strong_hash: vendor_with_strong,
        }
    }

    /// Vendor-hash coverage (fraction of vendor-supplied components carrying
    /// at least one hash). Returns `None` when there are no vendor components,
    /// so the caller can suppress the violation rather than divide by zero.
    #[must_use]
    pub fn vendor_hash_coverage(&self) -> Option<f64> {
        if self.vendor_components_total == 0 {
            None
        } else {
            #[allow(clippy::cast_precision_loss)]
            Some(self.vendor_components_with_hash as f64 / self.vendor_components_total as f64)
        }
    }

    /// Vendor strong-hash coverage (fraction with at least one SHA-256+ hash).
    #[must_use]
    pub fn vendor_strong_hash_coverage(&self) -> Option<f64> {
        if self.vendor_components_total == 0 {
            None
        } else {
            #[allow(clippy::cast_precision_loss)]
            Some(
                self.vendor_components_with_strong_hash as f64
                    / self.vendor_components_total as f64,
            )
        }
    }

    /// Calculate integrity quality score (0-100)
    ///
    /// Base 60% for any-hash coverage + 40% bonus for strong-hash coverage,
    /// with a penalty for weak-only components.
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        let any_coverage = self.components_with_any_hash as f32 / total_components as f32;
        let strong_coverage = self.components_with_strong_hash as f32 / total_components as f32;
        let weak_only_ratio = self.components_with_weak_only as f32 / total_components as f32;

        let base = any_coverage * 60.0;
        let strong_bonus = strong_coverage * 40.0;
        let weak_penalty = weak_only_ratio * 10.0;

        (base + strong_bonus - weak_penalty).clamp(0.0, 100.0)
    }
}

/// Whether a hash algorithm is considered cryptographically strong
fn is_strong_hash(algo: &HashAlgorithm) -> bool {
    matches!(
        algo,
        HashAlgorithm::Sha256
            | HashAlgorithm::Sha384
            | HashAlgorithm::Sha512
            | HashAlgorithm::Sha3_256
            | HashAlgorithm::Sha3_384
            | HashAlgorithm::Sha3_512
            | HashAlgorithm::Blake2b256
            | HashAlgorithm::Blake2b384
            | HashAlgorithm::Blake2b512
            | HashAlgorithm::Blake3
            | HashAlgorithm::Streebog256
            | HashAlgorithm::Streebog512
    )
}

/// Human-readable label for a hash algorithm
fn hash_algorithm_label(algo: &HashAlgorithm) -> String {
    match algo {
        HashAlgorithm::Md5 => "MD5".to_string(),
        HashAlgorithm::Sha1 => "SHA-1".to_string(),
        HashAlgorithm::Sha256 => "SHA-256".to_string(),
        HashAlgorithm::Sha384 => "SHA-384".to_string(),
        HashAlgorithm::Sha512 => "SHA-512".to_string(),
        HashAlgorithm::Sha3_256 => "SHA3-256".to_string(),
        HashAlgorithm::Sha3_384 => "SHA3-384".to_string(),
        HashAlgorithm::Sha3_512 => "SHA3-512".to_string(),
        HashAlgorithm::Blake2b256 => "BLAKE2b-256".to_string(),
        HashAlgorithm::Blake2b384 => "BLAKE2b-384".to_string(),
        HashAlgorithm::Blake2b512 => "BLAKE2b-512".to_string(),
        HashAlgorithm::Blake3 => "BLAKE3".to_string(),
        HashAlgorithm::Streebog256 => "Streebog-256".to_string(),
        HashAlgorithm::Streebog512 => "Streebog-512".to_string(),
        HashAlgorithm::Other(s) => s.clone(),
    }
}

// ============================================================================
// Identifier quality metrics
// ============================================================================

/// Identifier quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierMetrics {
    /// Components with valid PURLs
    pub valid_purls: usize,
    /// Components with invalid/malformed PURLs
    pub invalid_purls: usize,
    /// Components with at least one valid CPE
    pub valid_cpes: usize,
    /// Components with at least one invalid/malformed CPE
    pub invalid_cpes: usize,
    /// Components with SWID tags
    pub with_swid: usize,
    /// Components with at least one valid identifier of any kind. This is the
    /// coverage numerator: summing the per-type counts would let one
    /// multi-identifier component mask components with no identifier at all.
    #[serde(default)]
    pub components_with_valid_id: usize,
    /// Unique ecosystems identified
    pub ecosystems: Vec<String>,
    /// Components missing all identifiers (only name)
    pub missing_all_identifiers: usize,
    /// File and cryptographic-asset entries excluded from per-component
    /// counting (denominator plumbing for `quality_score`; not part of the
    /// report).
    #[serde(skip)]
    pub non_package_components: usize,
}

impl IdentifierMetrics {
    /// Calculate identifier metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut valid_purls = 0;
        let mut invalid_purls = 0;
        let mut valid_cpes = 0;
        let mut invalid_cpes = 0;
        let mut with_swid = 0;
        let mut with_valid_id = 0;
        let mut missing_all = 0;
        let mut non_package_components = 0;
        let mut ecosystems = std::collections::HashSet::new();

        for comp in sbom.components.values() {
            // File/snippet inventory entries are not packages: they
            // structurally lack purl/cpe/swid, and counting them cratered
            // identifier coverage for file-cataloguing SBOMs (same exemption
            // as CompletenessMetrics).
            if !comp.component_type.is_package_scoped() {
                non_package_components += 1;
                continue;
            }

            let has_purl = comp.identifiers.purl.is_some();
            let has_cpe = !comp.identifiers.cpe.is_empty();
            let has_swid = comp.identifiers.swid.is_some();

            let mut purl_valid = false;
            if let Some(ref purl) = comp.identifiers.purl {
                if is_valid_purl(purl) {
                    purl_valid = true;
                    valid_purls += 1;
                    // Extract ecosystem from PURL
                    if let Some(eco) = extract_ecosystem_from_purl(purl) {
                        ecosystems.insert(eco);
                    }
                } else {
                    invalid_purls += 1;
                }
            }

            // Per-COMPONENT, not per-entry: a component with several CPEs
            // counts once, so it cannot mask components with no identifier.
            let any_cpe_valid = comp.identifiers.cpe.iter().any(|c| is_valid_cpe(c));
            let any_cpe_invalid = comp.identifiers.cpe.iter().any(|c| !is_valid_cpe(c));
            if any_cpe_valid {
                valid_cpes += 1;
            }
            if any_cpe_invalid {
                invalid_cpes += 1;
            }

            if has_swid {
                with_swid += 1;
            }

            if purl_valid || any_cpe_valid || has_swid {
                with_valid_id += 1;
            }

            if !has_purl && !has_cpe && !has_swid {
                missing_all += 1;
            }
        }

        let mut ecosystem_list: Vec<String> = ecosystems.into_iter().collect();
        ecosystem_list.sort();

        Self {
            valid_purls,
            invalid_purls,
            valid_cpes,
            invalid_cpes,
            with_swid,
            components_with_valid_id: with_valid_id,
            ecosystems: ecosystem_list,
            missing_all_identifiers: missing_all,
            non_package_components,
        }
    }

    /// Calculate identifier quality score (0-100)
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        // File entries are exempt from identifier counting (see from_sbom),
        // so remove them from the denominator too — otherwise a file
        // catalogue dilutes package identifier coverage.
        let countable = total_components.saturating_sub(self.non_package_components);
        if countable == 0 {
            return 0.0;
        }

        // Coverage over components with at least one valid identifier — NOT
        // the sum of per-type counts, which a single PURL+CPE+SWID component
        // would inflate 3x (masking identifier-less components).
        let coverage =
            (self.components_with_valid_id.min(countable) as f32 / countable as f32) * 100.0;

        // Penalize invalid identifiers
        let invalid_count = self.invalid_purls + self.invalid_cpes;
        let penalty = (invalid_count as f32 / countable as f32) * 20.0;

        (coverage - penalty).clamp(0.0, 100.0)
    }
}

/// License quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseMetrics {
    /// Components with at least one real (non-NOASSERTION) declared license
    pub with_declared: usize,
    /// Components with concluded licenses
    pub with_concluded: usize,
    /// Components whose declared licenses are all valid SPDX expressions
    /// (subset of `with_declared`)
    pub valid_spdx_expressions: usize,
    /// Components with at least one non-standard declared license name
    /// (subset of `with_declared`; disjoint with `valid_spdx_expressions`)
    pub non_standard_licenses: usize,
    /// Components with at least one NOASSERTION declared entry
    pub noassertion_count: usize,
    /// Components with at least one deprecated SPDX license identifier
    pub deprecated_licenses: usize,
    /// Components with restrictive/copyleft licenses (GPL family)
    pub restrictive_licenses: usize,
    /// Specific copyleft license identifiers found
    pub copyleft_license_ids: Vec<String>,
    /// Unique licenses found
    pub unique_licenses: Vec<String>,
    /// File and cryptographic-asset entries excluded from per-component
    /// counting (denominator plumbing for `quality_score`; not part of the
    /// report).
    #[serde(skip)]
    pub non_package_components: usize,
}

impl LicenseMetrics {
    /// Calculate license metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_declared = 0;
        let mut with_concluded = 0;
        let mut valid_spdx = 0;
        let mut non_standard = 0;
        let mut noassertion = 0;
        let mut deprecated = 0;
        let mut restrictive = 0;
        let mut non_package_components = 0;
        let mut licenses = HashSet::new();
        let mut copyleft_ids = HashSet::new();

        // All counters are PER-COMPONENT (matching the field docs). The old
        // per-entry counting let a component with several declared licenses
        // push valid_spdx_expressions above with_declared, blowing the SPDX
        // ratio past 1.0 — and a NOASSERTION-only component counted as
        // license-documented.
        for comp in sbom.components.values() {
            // File/snippet inventory entries are not packages: per-file
            // license facts (e.g. SPDX LicenseInfoInFile) must not dilute
            // per-component license counting (same exemption as
            // CompletenessMetrics). Their license strings still feed the
            // informational unique/copyleft lists below.
            let is_non_package = !comp.component_type.is_package_scoped();
            if is_non_package {
                non_package_components += 1;
            }

            let mut has_real_entry = false;
            let mut has_noassertion = false;
            let mut all_valid = true;
            let mut any_deprecated = false;
            let mut any_restrictive = false;

            for lic in &comp.licenses.declared {
                let expr = &lic.expression;
                licenses.insert(expr.clone());

                if expr == "NOASSERTION" {
                    has_noassertion = true;
                    continue;
                }
                has_real_entry = true;

                // is_valid_spdx is computed at construction via the `spdx`
                // crate (real expression parsing), unlike the old substring
                // heuristic that accepted any string containing " OR ".
                if !lic.is_valid_spdx {
                    all_valid = false;
                }
                if is_deprecated_spdx_license(expr) {
                    any_deprecated = true;
                }
                if is_restrictive_license(expr) {
                    any_restrictive = true;
                    copyleft_ids.insert(expr.clone());
                }
            }

            if is_non_package {
                // Exempt from all per-component counters (license strings
                // were still collected above).
                continue;
            }

            if has_noassertion {
                noassertion += 1;
            }
            if has_real_entry {
                with_declared += 1;
                if all_valid {
                    valid_spdx += 1;
                } else {
                    non_standard += 1;
                }
                if any_deprecated {
                    deprecated += 1;
                }
                if any_restrictive {
                    restrictive += 1;
                }
            }

            if comp.licenses.concluded.is_some() {
                with_concluded += 1;
            }
        }

        let mut license_list: Vec<String> = licenses.into_iter().collect();
        license_list.sort();

        let mut copyleft_list: Vec<String> = copyleft_ids.into_iter().collect();
        copyleft_list.sort();

        Self {
            with_declared,
            with_concluded,
            valid_spdx_expressions: valid_spdx,
            non_standard_licenses: non_standard,
            noassertion_count: noassertion,
            deprecated_licenses: deprecated,
            restrictive_licenses: restrictive,
            copyleft_license_ids: copyleft_list,
            unique_licenses: license_list,
            non_package_components,
        }
    }

    /// Calculate license quality score (0-100)
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        // File entries are exempt from per-component license counting (see
        // from_sbom), so remove them from the denominator too — otherwise a
        // file catalogue dilutes package license coverage.
        let countable = total_components.saturating_sub(self.non_package_components);
        if countable == 0 {
            return 0.0;
        }

        let coverage = (self.with_declared as f32 / countable as f32) * 60.0;

        // Bonus for SPDX compliance
        let spdx_ratio = if self.with_declared > 0 {
            self.valid_spdx_expressions as f32 / self.with_declared as f32
        } else {
            0.0
        };
        let spdx_bonus = spdx_ratio * 30.0;

        // Penalty for NOASSERTION
        let noassertion_penalty = (self.noassertion_count as f32 / countable as f32) * 10.0;

        // Penalty for deprecated licenses (2 points each, capped)
        let deprecated_penalty = (self.deprecated_licenses as f32 * 2.0).min(10.0);

        (coverage + spdx_bonus - noassertion_penalty - deprecated_penalty).clamp(0.0, 100.0)
    }
}

/// Vulnerability information quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMetrics {
    /// Components with vulnerability information
    pub components_with_vulns: usize,
    /// Total vulnerabilities reported
    pub total_vulnerabilities: usize,
    /// Vulnerabilities with CVSS scores
    pub with_cvss: usize,
    /// Vulnerabilities with CWE information
    pub with_cwe: usize,
    /// Vulnerabilities with remediation info
    pub with_remediation: usize,
    /// Components with VEX status
    pub with_vex_status: usize,
}

impl VulnerabilityMetrics {
    /// Calculate vulnerability metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut components_with_vulns = 0;
        let mut total_vulns = 0;
        let mut with_cvss = 0;
        let mut with_cwe = 0;
        let mut with_remediation = 0;
        let mut with_vex = 0;

        for comp in sbom.components.values() {
            if !comp.vulnerabilities.is_empty() {
                components_with_vulns += 1;
            }

            for vuln in &comp.vulnerabilities {
                total_vulns += 1;

                if !vuln.cvss.is_empty() {
                    with_cvss += 1;
                }
                if !vuln.cwes.is_empty() {
                    with_cwe += 1;
                }
                if vuln.remediation.is_some() {
                    with_remediation += 1;
                }
            }

            if comp.vex_status.is_some()
                || comp.vulnerabilities.iter().any(|v| v.vex_status.is_some())
            {
                with_vex += 1;
            }
        }

        Self {
            components_with_vulns,
            total_vulnerabilities: total_vulns,
            with_cvss,
            with_cwe,
            with_remediation,
            with_vex_status: with_vex,
        }
    }

    /// Calculate vulnerability documentation quality score (0-100)
    ///
    /// Returns `None` when no vulnerability data exists, signaling that this
    /// category should be excluded from the weighted score (N/A-aware).
    /// This prevents inflating the overall score when vulnerability assessment
    /// was not performed.
    ///
    /// Disclosing vulnerabilities at all earns a 40-point baseline; the
    /// remaining 60 points reward per-vulnerability documentation quality
    /// (CVSS 24, CWE 18, remediation 18). Without the baseline, a bare
    /// disclosure scored 0 — LOWER than saying nothing (N/A redistributes the
    /// category weight), which punished transparency: an author was better
    /// off stripping vulnerability data than disclosing it undocumented.
    #[must_use]
    pub fn documentation_score(&self) -> Option<f32> {
        if self.total_vulnerabilities == 0 {
            return None; // No vulnerability data — treat as N/A
        }

        let cvss_ratio = self.with_cvss as f32 / self.total_vulnerabilities as f32;
        let cwe_ratio = self.with_cwe as f32 / self.total_vulnerabilities as f32;
        let remediation_ratio = self.with_remediation as f32 / self.total_vulnerabilities as f32;

        let quality = remediation_ratio.mul_add(18.0, cvss_ratio.mul_add(24.0, cwe_ratio * 18.0));
        Some((40.0 + quality).min(100.0))
    }
}

// ============================================================================
// Dependency graph quality metrics
// ============================================================================

/// Maximum edge count before skipping expensive graph analysis
const MAX_EDGES_FOR_GRAPH_ANALYSIS: usize = 1_000_000;

// ============================================================================
// Software complexity index
// ============================================================================

/// Complexity level bands for the software complexity index
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ComplexityLevel {
    /// Simplicity 75–100 (raw complexity 0–0.25)
    Low,
    /// Simplicity 50–74 (raw complexity 0.26–0.50)
    Moderate,
    /// Simplicity 25–49 (raw complexity 0.51–0.75)
    High,
    /// Simplicity 0–24 (raw complexity 0.76–1.00)
    VeryHigh,
}

impl ComplexityLevel {
    /// Determine complexity level from a simplicity score (0–100)
    #[must_use]
    pub const fn from_score(simplicity: f32) -> Self {
        match simplicity as u32 {
            75..=100 => Self::Low,
            50..=74 => Self::Moderate,
            25..=49 => Self::High,
            _ => Self::VeryHigh,
        }
    }

    /// Human-readable label
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Moderate => "Moderate",
            Self::High => "High",
            Self::VeryHigh => "Very High",
        }
    }
}

impl std::fmt::Display for ComplexityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Breakdown of the five factors that compose the software complexity index.
/// Each factor is normalized to 0.0–1.0 where higher = more complex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityFactors {
    /// Log-scaled edge density: `min(1.0, ln(1 + edges/components) / ln(20))`
    pub dependency_volume: f32,
    /// Depth ratio: `min(1.0, max_depth / 15.0)`
    pub normalized_depth: f32,
    /// Hub dominance: `min(1.0, max_out_degree / max(components * 0.25, 4))`
    pub fanout_concentration: f32,
    /// Cycle density: `min(1.0, cycle_count / max(1, components * 0.05))`
    pub cycle_ratio: f32,
    /// Extra disconnected subgraphs: `(islands - 1) / max(1, components - 1)`
    pub fragmentation: f32,
}

/// Dependency graph quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyMetrics {
    /// Total dependency relationships
    pub total_dependencies: usize,
    /// Components with at least one dependency
    pub components_with_deps: usize,
    /// Maximum dependency depth (computed via BFS from roots)
    pub max_depth: Option<usize>,
    /// Average dependency depth across all reachable components
    pub avg_depth: Option<f32>,
    /// Orphan components (no incoming or outgoing deps)
    pub orphan_components: usize,
    /// Root components (no incoming deps, but has outgoing)
    pub root_components: usize,
    /// Number of dependency cycles detected (SCCs with more than one node, plus self-loops)
    pub cycle_count: usize,
    /// Number of disconnected subgraphs (islands)
    pub island_count: usize,
    /// Whether graph analysis was skipped due to size
    pub graph_analysis_skipped: bool,
    /// Maximum out-degree (most dependencies from a single component)
    pub max_out_degree: usize,
    /// Software complexity index (0–100, higher = simpler). `None` when graph analysis skipped.
    pub software_complexity_index: Option<f32>,
    /// Complexity level band. `None` when graph analysis skipped.
    pub complexity_level: Option<ComplexityLevel>,
    /// Factor breakdown. `None` when graph analysis skipped.
    pub complexity_factors: Option<ComplexityFactors>,
    /// File and cryptographic-asset entries excluded from the coverage
    /// denominator in `quality_score` (denominator plumbing; not part of the
    /// report).
    #[serde(skip)]
    pub non_package_components: usize,
}

impl DependencyMetrics {
    /// Calculate dependency metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        use crate::model::CanonicalId;

        let total_deps = sbom.edges.len();

        // File/snippet inventory entries are not dependency-graph members:
        // nobody "depends on" a file, so they are excluded from the coverage
        // denominator in quality_score (same exemption as
        // CompletenessMetrics). Cycle/orphan penalties for real packages are
        // unchanged.
        let non_package_components = sbom
            .components
            .values()
            .filter(|c| !c.component_type.is_package_scoped())
            .count();

        // Build adjacency lists using CanonicalId.value() for string keys
        let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut has_outgoing: HashSet<&str> = HashSet::new();
        let mut has_incoming: HashSet<&str> = HashSet::new();

        for edge in &sbom.edges {
            children
                .entry(edge.from.value())
                .or_default()
                .push(edge.to.value());
            has_outgoing.insert(edge.from.value());
            has_incoming.insert(edge.to.value());
        }

        let all_ids: Vec<&str> = sbom.components.keys().map(CanonicalId::value).collect();

        let orphans = all_ids
            .iter()
            .filter(|c| !has_outgoing.contains(*c) && !has_incoming.contains(*c))
            .count();

        let roots: Vec<&str> = has_outgoing
            .iter()
            .filter(|c| !has_incoming.contains(*c))
            .copied()
            .collect();
        let root_count = roots.len();

        // Compute max out-degree (single pass over adjacency, O(V))
        let max_out_degree = children.values().map(Vec::len).max().unwrap_or(0);

        // Skip expensive graph analysis for very large graphs
        if total_deps > MAX_EDGES_FOR_GRAPH_ANALYSIS {
            return Self {
                total_dependencies: total_deps,
                components_with_deps: has_outgoing.len(),
                max_depth: None,
                avg_depth: None,
                orphan_components: orphans,
                root_components: root_count,
                cycle_count: 0,
                island_count: 0,
                graph_analysis_skipped: true,
                max_out_degree,
                software_complexity_index: None,
                complexity_level: None,
                complexity_factors: None,
                non_package_components,
            };
        }

        // BFS from roots to compute depth
        let (max_depth, avg_depth) = compute_depth(&roots, &children);

        // Iterative Tarjan SCC cycle detection
        let cycle_count = detect_cycles(&all_ids, &children);

        // Union-Find for island/subgraph detection
        let island_count = count_islands(&all_ids, &sbom.edges);

        // Compute software complexity index
        let component_count = all_ids.len();
        let (complexity_index, complexity_lvl, factors) = compute_complexity(
            total_deps,
            component_count,
            max_depth.unwrap_or(0),
            max_out_degree,
            cycle_count,
            orphans,
            island_count,
        );

        Self {
            total_dependencies: total_deps,
            components_with_deps: has_outgoing.len(),
            max_depth,
            avg_depth,
            orphan_components: orphans,
            root_components: root_count,
            cycle_count,
            island_count,
            graph_analysis_skipped: false,
            max_out_degree,
            software_complexity_index: Some(complexity_index),
            complexity_level: Some(complexity_lvl),
            complexity_factors: Some(factors),
            non_package_components,
        }
    }

    /// Calculate dependency graph quality score (0-100)
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        // File entries are not dependency-graph members (see from_sbom), so
        // they are excluded from the coverage denominator — otherwise a file
        // catalogue dilutes package dependency coverage.
        let countable = total_components.saturating_sub(self.non_package_components);

        // Score based on how many components have dependency info. Clamp to
        // 100 BEFORE subtracting penalties: with an N/(N-1) denominator a
        // fully-cyclic graph reaches ~125% coverage, which silently absorbed
        // the cycle/orphan penalties below.
        let coverage = if countable > 1 {
            ((self.components_with_deps as f32 / (countable - 1) as f32) * 100.0).min(100.0)
        } else {
            100.0 // Single package (or pure file inventory)
        };

        // Slight penalty for orphan components
        let orphan_ratio = self.orphan_components as f32 / total_components as f32;
        let orphan_penalty = orphan_ratio * 10.0;

        // Penalty for cycles (5 points each, capped at 20)
        let cycle_penalty = (self.cycle_count as f32 * 5.0).min(20.0);

        // Penalty for excessive islands (>3 in multi-component SBOMs)
        let island_penalty = if total_components > 5 && self.island_count > 3 {
            ((self.island_count - 3) as f32 * 3.0).min(15.0)
        } else {
            0.0
        };

        (coverage - orphan_penalty - cycle_penalty - island_penalty).clamp(0.0, 100.0)
    }
}

/// BFS from roots to compute max and average depth
fn compute_depth(
    roots: &[&str],
    children: &HashMap<&str, Vec<&str>>,
) -> (Option<usize>, Option<f32>) {
    use std::collections::VecDeque;

    if roots.is_empty() {
        return (None, None);
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
    let mut max_d: usize = 0;
    let mut total_depth: usize = 0;
    let mut count: usize = 0;

    for &root in roots {
        if visited.insert(root) {
            queue.push_back((root, 0));
        }
    }

    while let Some((node, depth)) = queue.pop_front() {
        max_d = max_d.max(depth);
        total_depth += depth;
        count += 1;

        if let Some(kids) = children.get(node) {
            for &kid in kids {
                if visited.insert(kid) {
                    queue.push_back((kid, depth + 1));
                }
            }
        }
    }

    let avg = if count > 0 {
        Some(total_depth as f32 / count as f32)
    } else {
        None
    };

    (Some(max_d), avg)
}

/// Iterative Tarjan SCC-based cycle detection.
///
/// Counts each strongly connected component with more than one node as a
/// single cycle, plus single-node components with a self-loop. Uses explicit
/// stacks instead of recursion so arbitrarily deep graphs cannot overflow
/// the call stack.
fn detect_cycles(all_nodes: &[&str], children: &HashMap<&str, Vec<&str>>) -> usize {
    let mut index_of: HashMap<&str, usize> = HashMap::with_capacity(all_nodes.len());
    for &node in all_nodes {
        let next = index_of.len();
        index_of.entry(node).or_insert(next);
    }
    for (&from, kids) in children {
        let next = index_of.len();
        index_of.entry(from).or_insert(next);
        for &kid in kids {
            let next = index_of.len();
            index_of.entry(kid).or_insert(next);
        }
    }

    let node_count = index_of.len();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); node_count];
    let mut has_self_loop = vec![false; node_count];
    for (from, kids) in children {
        let from_idx = index_of[from];
        for kid in kids {
            let kid_idx = index_of[kid];
            if from_idx == kid_idx {
                has_self_loop[from_idx] = true;
            }
            adjacency[from_idx].push(kid_idx);
        }
    }

    const UNVISITED: usize = usize::MAX;
    let mut order = vec![UNVISITED; node_count];
    let mut lowlink = vec![0usize; node_count];
    let mut on_stack = vec![false; node_count];
    let mut scc_stack: Vec<usize> = Vec::new();
    let mut call_stack: Vec<(usize, usize)> = Vec::new();
    let mut next_order = 0usize;
    let mut cycles = 0usize;

    for start in 0..node_count {
        if order[start] != UNVISITED {
            continue;
        }
        call_stack.push((start, 0));
        while let Some(frame) = call_stack.last_mut() {
            let node = frame.0;
            if frame.1 == 0 {
                order[node] = next_order;
                lowlink[node] = next_order;
                next_order += 1;
                scc_stack.push(node);
                on_stack[node] = true;
            }
            if let Some(&target) = adjacency[node].get(frame.1) {
                frame.1 += 1;
                if order[target] == UNVISITED {
                    call_stack.push((target, 0));
                } else if on_stack[target] {
                    lowlink[node] = lowlink[node].min(order[target]);
                }
            } else {
                call_stack.pop();
                if let Some(&(parent, _)) = call_stack.last() {
                    lowlink[parent] = lowlink[parent].min(lowlink[node]);
                }
                if lowlink[node] == order[node] {
                    let mut scc_size = 0usize;
                    while let Some(member) = scc_stack.pop() {
                        on_stack[member] = false;
                        scc_size += 1;
                        if member == node {
                            break;
                        }
                    }
                    if scc_size > 1 || has_self_loop[node] {
                        cycles += 1;
                    }
                }
            }
        }
    }

    cycles
}

/// Union-Find to count disconnected subgraphs (islands)
fn count_islands(all_nodes: &[&str], edges: &[crate::model::DependencyEdge]) -> usize {
    if all_nodes.is_empty() {
        return 0;
    }

    // Map node IDs to indices
    let node_idx: HashMap<&str, usize> =
        all_nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut parent: Vec<usize> = (0..all_nodes.len()).collect();
    let mut rank: Vec<u8> = vec![0; all_nodes.len()];

    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]); // path compression
        }
        parent[x]
    }

    fn union(parent: &mut Vec<usize>, rank: &mut [u8], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            if rank[ra] < rank[rb] {
                parent[ra] = rb;
            } else if rank[ra] > rank[rb] {
                parent[rb] = ra;
            } else {
                parent[rb] = ra;
                rank[ra] += 1;
            }
        }
    }

    for edge in edges {
        if let (Some(&a), Some(&b)) = (
            node_idx.get(edge.from.value()),
            node_idx.get(edge.to.value()),
        ) {
            union(&mut parent, &mut rank, a, b);
        }
    }

    // Count unique roots
    let mut roots = HashSet::new();
    for i in 0..all_nodes.len() {
        roots.insert(find(&mut parent, i));
    }

    roots.len()
}

/// Compute the software complexity index and factor breakdown.
///
/// Returns `(simplicity_index, complexity_level, factors)`.
/// `simplicity_index` is 0–100 where 100 = simplest.
fn compute_complexity(
    edges: usize,
    components: usize,
    max_depth: usize,
    max_out_degree: usize,
    cycle_count: usize,
    _orphans: usize,
    islands: usize,
) -> (f32, ComplexityLevel, ComplexityFactors) {
    if components == 0 {
        let factors = ComplexityFactors {
            dependency_volume: 0.0,
            normalized_depth: 0.0,
            fanout_concentration: 0.0,
            cycle_ratio: 0.0,
            fragmentation: 0.0,
        };
        return (100.0, ComplexityLevel::Low, factors);
    }

    // Factor 1: dependency volume — log-scaled edge density
    let edge_ratio = edges as f64 / components as f64;
    let dependency_volume = ((1.0 + edge_ratio).ln() / 20.0_f64.ln()).min(1.0) as f32;

    // Factor 2: normalized depth
    let normalized_depth = (max_depth as f32 / 15.0).min(1.0);

    // Factor 3: fanout concentration — hub dominance
    // Floor of 4.0 prevents small graphs from being penalized for max_out_degree of 1
    let fanout_denom = (components as f32 * 0.25).max(4.0);
    let fanout_concentration = (max_out_degree as f32 / fanout_denom).min(1.0);

    // Factor 4: cycle ratio
    let cycle_threshold = (components as f32 * 0.05).max(1.0);
    let cycle_ratio = (cycle_count as f32 / cycle_threshold).min(1.0);

    // Factor 5: fragmentation — extra disconnected subgraphs beyond the ideal of 1
    // Uses (islands - 1) because orphans are already counted as individual islands.
    let extra_islands = islands.saturating_sub(1);
    let fragmentation = if components > 1 {
        (extra_islands as f32 / (components - 1) as f32).min(1.0)
    } else {
        0.0
    };

    let factors = ComplexityFactors {
        dependency_volume,
        normalized_depth,
        fanout_concentration,
        cycle_ratio,
        fragmentation,
    };

    let raw_complexity = 0.30 * dependency_volume
        + 0.20 * normalized_depth
        + 0.20 * fanout_concentration
        + 0.20 * cycle_ratio
        + 0.10 * fragmentation;

    let simplicity_index = (100.0 - raw_complexity * 100.0).clamp(0.0, 100.0);
    let level = ComplexityLevel::from_score(simplicity_index);

    (simplicity_index, level, factors)
}

// ============================================================================
// Provenance metrics
// ============================================================================

/// Document provenance and authorship quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetrics {
    /// Whether the SBOM was created by an identified tool
    pub has_tool_creator: bool,
    /// Whether the tool creator includes version information
    pub has_tool_version: bool,
    /// Whether an organization is identified as creator
    pub has_org_creator: bool,
    /// Whether any creator has a contact email
    pub has_contact_email: bool,
    /// Whether the document has a serial number / namespace
    pub has_serial_number: bool,
    /// Whether the document has a name
    pub has_document_name: bool,
    /// Age of the SBOM in days (since creation timestamp). Meaningful only
    /// when `timestamp_known` is true; a missing timestamp is not "very old".
    pub timestamp_age_days: u32,
    /// Whether the document carries a real creation timestamp (vs. the epoch
    /// sentinel parsers substitute for a missing/invalid one).
    #[serde(default = "default_timestamp_known")]
    pub timestamp_known: bool,
    /// Whether the SBOM is considered fresh (< 90 days old). False when the
    /// timestamp is unknown — a missing timestamp is not fresh.
    pub is_fresh: bool,
    /// Whether a primary/described component is identified
    pub has_primary_component: bool,
    /// SBOM lifecycle phase (from CycloneDX 1.5+ metadata)
    pub lifecycle_phase: Option<String>,
    /// Self-declared completeness level of the SBOM
    pub completeness_declaration: CompletenessDeclaration,
    /// Whether the SBOM has a digital signature
    pub has_signature: bool,
    /// Whether the SBOM has data provenance citations (CycloneDX 1.7+)
    pub has_citations: bool,
    /// Number of data provenance citations
    pub citations_count: usize,
}

/// Freshness threshold in days
const FRESHNESS_THRESHOLD_DAYS: u32 = 90;

/// serde default for `ProvenanceMetrics::timestamp_known` when deserializing
/// older records that predate the field: assume the timestamp was known
/// (the field only distinguishes the epoch-sentinel case introduced later).
const fn default_timestamp_known() -> bool {
    true
}

impl ProvenanceMetrics {
    /// Compute provenance metrics, measuring document age at `now` (the
    /// scorer's `--as-of` instant) instead of the wall clock.
    #[must_use]
    pub fn from_sbom_at(sbom: &NormalizedSbom, now: chrono::DateTime<chrono::Utc>) -> Self {
        Self::compute(sbom, now)
    }

    /// Calculate provenance metrics from an SBOM, measuring document age
    /// against the wall clock. Use [`Self::from_sbom_at`] to pin the instant.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        Self::compute(sbom, chrono::Utc::now())
    }

    fn compute(sbom: &NormalizedSbom, now: chrono::DateTime<chrono::Utc>) -> Self {
        let doc = &sbom.document;

        let has_tool_creator = doc
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Tool);
        let has_tool_version = doc.creators.iter().any(|c| {
            c.creator_type == CreatorType::Tool
                && (c.name.contains(' ')
                    || c.name.contains('/')
                    || c.name.contains('@')
                    // SPDX 2.3 §6.8 mandates the hyphen-joined
                    // "toolidentifier-version" form (e.g. "LicenseFind-1.0"),
                    // which the separator heuristics above never match.
                    || c.name
                        .match_indices('-')
                        .any(|(i, _)| c.name[i + 1..].starts_with(|ch: char| ch.is_ascii_digit())))
        });
        let has_org_creator = doc
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Organization);
        let has_contact_email = doc.creators.iter().any(|c| c.email.is_some());

        let timestamp_known = doc.has_known_timestamp();
        // Signed age: negative means the document is dated in the future.
        let age_days_signed = (now - doc.created).num_days();
        let age_days = age_days_signed.max(0) as u32;

        Self {
            has_tool_creator,
            has_tool_version,
            has_org_creator,
            has_contact_email,
            has_serial_number: doc.serial_number.is_some(),
            has_document_name: doc.name.is_some(),
            // Report 0 for an unknown timestamp rather than ~20000 days;
            // consumers gate the display on timestamp_known.
            timestamp_age_days: if timestamp_known { age_days } else { 0 },
            timestamp_known,
            // A missing timestamp is not fresh, and neither is a FUTURE-dated
            // document (negative signed age): a bogus forward date must not
            // read as "recently generated". Display-only — freshness is
            // deliberately NOT part of quality_score (see below).
            is_fresh: timestamp_known
                && (0..i64::from(FRESHNESS_THRESHOLD_DAYS)).contains(&age_days_signed),
            has_primary_component: sbom.primary_component_id.is_some(),
            lifecycle_phase: doc.lifecycle_phase.clone(),
            completeness_declaration: doc.completeness_declaration.clone(),
            has_signature: doc.signature.is_some(),
            has_citations: doc.citations_count > 0,
            citations_count: doc.citations_count,
        }
    }

    /// Calculate provenance quality score (0-100)
    ///
    /// Weighted checklist: tool creator (15%), tool version (5%), org creator (12%),
    /// contact email (8%), serial number (8%), document name (5%),
    /// primary component (12%), completeness declaration (8%), signature (5%),
    /// lifecycle phase (10% CDX-only).
    ///
    /// Freshness (`is_fresh`) is deliberately NOT scored: it is computed from
    /// the live wall clock, so identical SBOM bytes would score differently
    /// across days (and flip at midnight). It remains available as display
    /// metadata; the score itself is a pure function of the document.
    #[must_use]
    pub fn quality_score(&self, is_cyclonedx: bool) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        let completeness_declared =
            self.completeness_declaration != CompletenessDeclaration::Unknown;

        let checks: &[(bool, f32)] = &[
            (self.has_tool_creator, 15.0),
            (self.has_tool_version, 5.0),
            (self.has_org_creator, 12.0),
            (self.has_contact_email, 8.0),
            (self.has_serial_number, 8.0),
            (self.has_document_name, 5.0),
            (self.has_primary_component, 12.0),
            (completeness_declared, 8.0),
            (self.has_signature, 5.0),
        ];

        for &(present, weight) in checks {
            if present {
                score += weight;
            }
            total_weight += weight;
        }

        // Lifecycle phase: only applicable for CycloneDX 1.5+
        if is_cyclonedx {
            let weight = 10.0;
            if self.lifecycle_phase.is_some() {
                score += weight;
            }
            total_weight += weight;

            // Data provenance citations bonus (CycloneDX 1.7+)
            let citations_weight = 5.0;
            if self.has_citations {
                score += citations_weight;
            }
            total_weight += citations_weight;
        }

        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }
}

// ============================================================================
// Auditability metrics
// ============================================================================

/// External reference and auditability quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditabilityMetrics {
    /// Components with VCS (version control) references
    pub components_with_vcs: usize,
    /// Components with website references
    pub components_with_website: usize,
    /// Components with security advisory references
    pub components_with_advisories: usize,
    /// Components with any external reference
    pub components_with_any_external_ref: usize,
    /// Whether the document has a security contact
    pub has_security_contact: bool,
    /// Whether the document has a vulnerability disclosure URL
    pub has_vuln_disclosure_url: bool,
}

impl AuditabilityMetrics {
    /// Calculate auditability metrics from an SBOM
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let mut with_vcs = 0;
        let mut with_website = 0;
        let mut with_advisories = 0;
        let mut with_any = 0;

        for comp in sbom.components.values() {
            if comp.external_refs.is_empty() {
                continue;
            }
            with_any += 1;

            let has_vcs = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Vcs);
            let has_website = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Website);
            let has_advisories = comp
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Advisories);

            if has_vcs {
                with_vcs += 1;
            }
            if has_website {
                with_website += 1;
            }
            if has_advisories {
                with_advisories += 1;
            }
        }

        Self {
            components_with_vcs: with_vcs,
            components_with_website: with_website,
            components_with_advisories: with_advisories,
            components_with_any_external_ref: with_any,
            has_security_contact: sbom.document.security_contact.is_some(),
            has_vuln_disclosure_url: sbom.document.vulnerability_disclosure_url.is_some(),
        }
    }

    /// Calculate auditability quality score (0-100)
    ///
    /// Component-level coverage (60%) + document-level security metadata (40%).
    #[must_use]
    pub fn quality_score(&self, total_components: usize) -> f32 {
        if total_components == 0 {
            return 0.0;
        }

        // Component-level: external ref coverage
        let ref_coverage =
            (self.components_with_any_external_ref as f32 / total_components as f32) * 40.0;
        let vcs_coverage = (self.components_with_vcs as f32 / total_components as f32) * 20.0;

        // Document-level security metadata
        let security_contact_score = if self.has_security_contact { 20.0 } else { 0.0 };
        let disclosure_score = if self.has_vuln_disclosure_url {
            20.0
        } else {
            0.0
        };

        (ref_coverage + vcs_coverage + security_contact_score + disclosure_score).min(100.0)
    }
}

// ============================================================================
// Lifecycle metrics
// ============================================================================

/// Component lifecycle quality metrics (requires enrichment data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleMetrics {
    /// Components that have reached end-of-life
    pub eol_components: usize,
    /// Components classified as stale (no updates for 1+ years)
    pub stale_components: usize,
    /// Components explicitly marked as deprecated
    pub deprecated_components: usize,
    /// Components with archived repositories
    pub archived_components: usize,
    /// Components with a newer version available
    pub outdated_components: usize,
    /// Components that had lifecycle enrichment data
    pub enriched_components: usize,
    /// Enrichment coverage percentage (0-100)
    pub enrichment_coverage: f32,
}

impl LifecycleMetrics {
    /// Calculate lifecycle metrics from an SBOM
    ///
    /// These metrics are only meaningful after enrichment. When
    /// `enrichment_coverage == 0`, the lifecycle score should be
    /// treated as N/A and excluded from the weighted total.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        let mut eol = 0;
        let mut stale = 0;
        let mut deprecated = 0;
        let mut archived = 0;
        let mut outdated = 0;
        let mut enriched = 0;

        for comp in sbom.components.values() {
            let has_lifecycle_data = comp.eol.is_some() || comp.staleness.is_some();
            if has_lifecycle_data {
                enriched += 1;
            }

            if let Some(ref eol_info) = comp.eol
                && eol_info.status == EolStatus::EndOfLife
            {
                eol += 1;
            }

            if let Some(ref stale_info) = comp.staleness {
                if matches!(
                    stale_info.level,
                    StalenessLevel::Stale | StalenessLevel::Abandoned
                ) {
                    stale += 1;
                }
                // The enrichment sets level=Deprecated AND is_deprecated=true
                // together (same for Archived), so counting both branches
                // double-counted every deprecated/archived component in the
                // normal case. Count each component at most once per state.
                if stale_info.level == StalenessLevel::Deprecated || stale_info.is_deprecated {
                    deprecated += 1;
                }
                if stale_info.level == StalenessLevel::Archived || stale_info.is_archived {
                    archived += 1;
                }
                if stale_info.latest_version.is_some() {
                    outdated += 1;
                }
            }
        }

        let coverage = if total > 0 {
            (enriched as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        Self {
            eol_components: eol,
            stale_components: stale,
            deprecated_components: deprecated,
            archived_components: archived,
            outdated_components: outdated,
            enriched_components: enriched,
            enrichment_coverage: coverage,
        }
    }

    /// Whether enrichment data is available for scoring
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.enriched_components > 0
    }

    /// Calculate lifecycle quality score (0-100)
    ///
    /// Starts at 100, subtracts penalties for problematic components.
    /// Returns `None` if no enrichment data is available.
    #[must_use]
    pub fn quality_score(&self) -> Option<f32> {
        if !self.has_data() {
            return None;
        }

        let mut score = 100.0_f32;

        // EOL: severe penalty (15 points each, capped at 60)
        score -= (self.eol_components as f32 * 15.0).min(60.0);
        // Stale: moderate penalty (5 points each, capped at 30)
        score -= (self.stale_components as f32 * 5.0).min(30.0);
        // Deprecated/archived: moderate penalty (3 points each, capped at 20)
        score -= ((self.deprecated_components + self.archived_components) as f32 * 3.0).min(20.0);
        // Outdated: mild penalty (1 point each, capped at 10)
        score -= (self.outdated_components as f32 * 1.0).min(10.0);

        Some(score.clamp(0.0, 100.0))
    }
}

// ============================================================================
// Cryptography Metrics
// ============================================================================

/// Cryptographic asset metrics for quantum readiness and crypto hygiene assessment.
///
/// Computed from components with `component_type == Cryptographic` and
/// populated `crypto_properties`. Returns `None` for quality score when
/// no crypto components are present (N/A-aware).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptographyMetrics {
    /// Total number of cryptographic-asset components
    pub total_crypto_components: usize,
    /// Number of algorithm assets
    pub algorithms_count: usize,
    /// Number of certificate assets
    pub certificates_count: usize,
    /// Number of key material assets
    pub keys_count: usize,
    /// Number of protocol assets
    pub protocols_count: usize,
    /// Algorithms with `nistQuantumSecurityLevel > 0`
    pub quantum_safe_count: usize,
    /// Algorithms with `nistQuantumSecurityLevel == 0`
    pub quantum_vulnerable_count: usize,
    /// Algorithms flagged as weak/broken (MD5, SHA-1, DES, etc.)
    pub weak_algorithm_count: usize,
    /// Hybrid PQC combiner algorithms
    pub hybrid_pqc_count: usize,
    /// Certificates past `notValidAfter`
    pub expired_certificates: usize,
    /// Certificates expiring within 90 days
    pub expiring_soon_certificates: usize,
    /// Key material in `compromised` state
    pub compromised_keys: usize,
    /// Symmetric keys < 128 bits or asymmetric keys below recommended minimum
    pub inadequate_key_sizes: usize,
    /// Names of weak/broken algorithms found
    pub weak_algorithm_names: Vec<String>,

    // --- Algorithm completeness (slot 1: Crpt) ---
    /// Algorithms with an OID identifier
    pub algorithms_with_oid: usize,
    /// Algorithms with `algorithm_family` set
    pub algorithms_with_family: usize,
    /// Algorithms with a recognized primitive (not `Other`)
    pub algorithms_with_primitive: usize,
    /// Algorithms with classical or quantum security level set
    pub algorithms_with_security_level: usize,

    // --- Cross-reference resolution (slot 4: Refs) ---
    /// Certificates with `signature_algorithm_ref` set
    pub certs_with_signature_algo_ref: usize,
    /// Keys with `algorithm_ref` set
    pub keys_with_algorithm_ref: usize,
    /// Protocols with at least one cipher suite
    pub protocols_with_cipher_suites: usize,
    /// Protocols linked to the algorithms they use by any means: cipher
    /// suites, `cryptoRefArray` / `relatedCryptographicAssets`, or IKEv2
    /// transform types
    #[serde(default)]
    pub protocols_with_algorithm_refs: usize,

    // --- Key lifecycle (slot 5: Life) ---
    /// Keys with `state` tracked
    pub keys_with_state: usize,
    /// Keys with `secured_by` protection
    pub keys_with_protection: usize,
    /// Keys with `creation_date` or `activation_date`
    pub keys_with_lifecycle_dates: usize,

    // --- Certificate health (slot 5: Life) ---
    /// Certificates with both `not_valid_before` and `not_valid_after`
    pub certs_with_validity_dates: usize,
}

impl CryptographyMetrics {
    /// Compute cryptography metrics from an SBOM, judging certificate expiry
    /// against the wall clock. Use [`Self::from_sbom_at`] to pin the instant.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        Self::from_sbom_at(sbom, chrono::Utc::now())
    }

    /// Compute cryptography metrics, judging certificate expiry at `now`
    /// (the scorer's `--as-of` instant).
    #[must_use]
    pub fn from_sbom_at(sbom: &NormalizedSbom, now: chrono::DateTime<chrono::Utc>) -> Self {
        let mut m = Self::default();
        // References only earn credit when they resolve inside the SBOM.
        let index = sbom.build_index();
        let resolves = |r: &str| index.resolve_bom_ref(r).is_some();

        for comp in sbom.components.values() {
            if comp.component_type != ComponentType::Cryptographic {
                continue;
            }
            let Some(cp) = &comp.crypto_properties else {
                // A Cryptographic component with no cryptoProperties carries no
                // evaluable crypto data. Counting it toward total_crypto_
                // components would make has_data() true and let the CBOM
                // sub-scores return 100 on empty denominators (grade A for
                // undocumented crypto), so only count documented assets.
                continue;
            };
            m.total_crypto_components += 1;

            match cp.asset_type {
                CryptoAssetType::Algorithm => {
                    m.algorithms_count += 1;
                    if cp.oid.is_some() {
                        m.algorithms_with_oid += 1;
                    }
                    if let Some(algo) = &cp.algorithm_properties {
                        if algo.algorithm_family.is_some() {
                            m.algorithms_with_family += 1;
                        }
                        if !matches!(algo.primitive, CryptoPrimitive::Other(_)) {
                            m.algorithms_with_primitive += 1;
                        }
                        if algo.classical_security_level.is_some()
                            || algo.nist_quantum_security_level.is_some()
                        {
                            m.algorithms_with_security_level += 1;
                        }
                        if algo.is_hybrid_pqc() {
                            m.hybrid_pqc_count += 1;
                        }
                    }

                    // Weakness / quantum posture come from the same shared
                    // classifier the compliance checkers use (family, OID,
                    // name, curve, alias normalization), unioned with the
                    // declared-field helpers — so the quality score cannot
                    // be softer than `validate` on the same file (a name
                    // like "HMAC_SHA1" escaped the old `starts_with` check).
                    let algo = cp.algorithm_properties.as_ref();
                    let cls = classify_algorithm(
                        algo.and_then(|a| a.algorithm_family.as_deref()),
                        Some(&comp.name),
                        cp.oid.as_deref(),
                        algo.and_then(|a| a.parameter_set_identifier.as_deref()),
                        algo.and_then(|a| a.elliptic_curve.as_deref()),
                    );
                    // A classical public-key family (RSA/ECDSA/DH/…) is
                    // quantum-vulnerable on the family alone — real CBOMs
                    // rarely set nistQuantumSecurityLevel=0. A broken
                    // algorithm (RSA-1024, …) is counted as weak below, not
                    // here as well: counting it twice inflated the
                    // quantum-vulnerable figure past what `validate` reports.
                    if cls.class != AlgorithmClass::Broken
                        && (cls.class == AlgorithmClass::ClassicalQuantumVulnerable
                            || algo.is_some_and(|a| {
                                a.is_classical_quantum_vulnerable()
                                    || a.nist_quantum_security_level == Some(0)
                            }))
                    {
                        m.quantum_vulnerable_count += 1;
                    } else if matches!(cls.class, AlgorithmClass::PostQuantum(_))
                        || algo.is_some_and(|a| a.is_quantum_safe())
                    {
                        m.quantum_safe_count += 1;
                    }
                    if cls.class == AlgorithmClass::Broken
                        || algo.is_some_and(|a| a.is_weak_by_name(&comp.name))
                    {
                        m.weak_algorithm_count += 1;
                        m.weak_algorithm_names.push(comp.name.clone());
                    }
                }
                CryptoAssetType::Certificate => {
                    m.certificates_count += 1;
                    if let Some(cert) = &cp.certificate_properties {
                        if cert.not_valid_before.is_some() && cert.not_valid_after.is_some() {
                            m.certs_with_validity_dates += 1;
                        }
                        if cert.signature_algorithm_refs().into_iter().any(&resolves) {
                            m.certs_with_signature_algo_ref += 1;
                        }
                        if cert.is_expired_at(now) {
                            m.expired_certificates += 1;
                        } else if cert.is_expiring_soon_at(90, now) {
                            m.expiring_soon_certificates += 1;
                        }
                    }
                }
                CryptoAssetType::RelatedCryptoMaterial => {
                    m.keys_count += 1;
                    if let Some(mat) = &cp.related_crypto_material_properties {
                        if mat.state.is_some() {
                            m.keys_with_state += 1;
                        }
                        if mat.secured_by.is_some() {
                            m.keys_with_protection += 1;
                        }
                        if mat.creation_date.is_some() || mat.activation_date.is_some() {
                            m.keys_with_lifecycle_dates += 1;
                        }
                        if mat.algorithm_ref.as_deref().is_some_and(resolves) {
                            m.keys_with_algorithm_ref += 1;
                        }
                        if mat.state == Some(CryptoMaterialState::Compromised) {
                            m.compromised_keys += 1;
                        }
                        // Flag inadequate key sizes. A key size is a BIT-LENGTH,
                        // and its adequacy is key-type-dependent: an ECC curve
                        // bit-length (P-256 → 256) provides ~size/2-bit security,
                        // so 256-bit ECC is strong, whereas RSA/finite-field
                        // needs ≥2048. The old flat `<2048` rule false-failed
                        // every standard ECC key. Recognize the strong ECC curve
                        // sizes; otherwise apply the finite-field ≥2048 rule.
                        if let Some(size) = mat.size {
                            let is_symmetric = matches!(
                                mat.material_type,
                                crate::model::CryptoMaterialType::SymmetricKey
                                    | crate::model::CryptoMaterialType::SecretKey
                            );
                            // Curve bit-lengths giving ≥128-bit security:
                            // Curve25519(255), P-256, P-384, Curve448, P-521.
                            // 512 is deliberately EXCLUDED: a 512-bit RSA/DSA key
                            // is trivially factorable, and matching it here would
                            // false-PASS it; a 512-bit ECC curve (brainpoolP512r1,
                            // rare) instead takes the finite-field path and is
                            // flagged — an acceptable over-caution vs. a false pass.
                            const STRONG_ECC_SIZES: &[u32] = &[255, 256, 384, 448, 521];
                            let inadequate = if is_symmetric {
                                size < 128
                            } else if STRONG_ECC_SIZES.contains(&size) {
                                false
                            } else {
                                size < 2048
                            };
                            if inadequate {
                                m.inadequate_key_sizes += 1;
                            }
                        }
                    }
                }
                CryptoAssetType::Protocol => {
                    m.protocols_count += 1;
                    if let Some(proto) = &cp.protocol_properties {
                        if !proto.cipher_suites.is_empty() {
                            m.protocols_with_cipher_suites += 1;
                        }
                        if !proto.cipher_suites.is_empty()
                            || !proto.crypto_ref_array.is_empty()
                            || proto.ikev2_transform_types.is_some()
                        {
                            m.protocols_with_algorithm_refs += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        m
    }

    /// Whether any crypto components exist (i.e., CBOM data is present).
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.total_crypto_components > 0
    }

    /// Percentage of algorithms that are quantum-safe (0-100).
    /// Returns `None` when no algorithms are present: a 0/0 readiness is
    /// absence of evidence, not a perfect score, and every renderer shows
    /// it as "n/a" rather than a vacuous 100.
    #[must_use]
    pub fn quantum_readiness_score(&self) -> Option<f32> {
        if self.algorithms_count == 0 {
            return None;
        }
        Some((self.quantum_safe_count as f32 / self.algorithms_count as f32) * 100.0)
    }

    /// Quality score (0-100) based on crypto hygiene. Returns `None` if no crypto data.
    #[must_use]
    pub fn quality_score(&self) -> Option<f32> {
        if !self.has_data() {
            return None;
        }

        // Documented crypto assets exist but NONE are classifiable as an
        // algorithm/certificate/key/protocol, so no penalty below can ever
        // trigger and the 100 baseline would be vacuous. The compliance
        // checkers treat such an inventory as unverifiable (the CNSA2/PQC
        // "evaluable assets" gates fail it), so the score reads fully
        // degraded instead of perfect.
        let classified = self.algorithms_count
            + self.certificates_count
            + self.keys_count
            + self.protocols_count;
        if classified == 0 {
            return Some(0.0);
        }

        let mut score = 100.0_f32;

        // Weak algorithms: severe penalty (15 each, capped at 50)
        score -= (self.weak_algorithm_count as f32 * 15.0).min(50.0);
        // Quantum-vulnerable: moderate penalty (8 each, capped at 40)
        score -= (self.quantum_vulnerable_count as f32 * 8.0).min(40.0);
        // Expired certs: moderate penalty (10 each, capped at 30)
        score -= (self.expired_certificates as f32 * 10.0).min(30.0);
        // Compromised keys: severe penalty (20 each, capped at 40)
        score -= (self.compromised_keys as f32 * 20.0).min(40.0);
        // Inadequate key sizes: mild penalty (5 each, capped at 20)
        score -= (self.inadequate_key_sizes as f32 * 5.0).min(20.0);
        // Expiring-soon certs: mild penalty (3 each, capped at 15)
        score -= (self.expiring_soon_certificates as f32 * 3.0).min(15.0);
        // Unresolved crypto references: cert/key/protocol assets whose
        // algorithm linkage can't be resolved are documented-but-unverifiable
        // (the compliance checkers warn on them, and none of the penalties
        // above can ever fire for them), so an inventory of opaque refs must
        // not read as perfect hygiene. Proportional, mirroring
        // `crypto_dependency_score`.
        let linkable = self.certificates_count + self.keys_count + self.protocols_count;
        if linkable > 0 {
            let resolved = self.certs_with_signature_algo_ref
                + self.keys_with_algorithm_ref
                + self.protocols_with_algorithm_refs;
            let unresolved_pct = 1.0 - (resolved as f32 / linkable as f32);
            score -= unresolved_pct * 30.0;
        }
        // Hybrid PQC bonus: +2 each (capped at +10)
        score += (self.hybrid_pqc_count as f32 * 2.0).min(10.0);

        Some(score.clamp(0.0, 100.0))
    }

    // ----- Per-category scores for CBOM ScoringProfile -----

    /// Crypto completeness: how fully documented are the crypto assets?
    #[must_use]
    pub fn crypto_completeness_score(&self) -> f32 {
        if self.algorithms_count == 0 {
            return 100.0;
        }
        let family_pct = self.algorithms_with_family as f32 / self.algorithms_count as f32;
        let primitive_pct = self.algorithms_with_primitive as f32 / self.algorithms_count as f32;
        let level_pct = self.algorithms_with_security_level as f32 / self.algorithms_count as f32;
        (family_pct * 40.0 + primitive_pct * 30.0 + level_pct * 30.0).clamp(0.0, 100.0)
    }

    /// Crypto identifier quality: OID coverage.
    #[must_use]
    pub fn crypto_identifier_score(&self) -> f32 {
        if self.algorithms_count == 0 {
            return 100.0;
        }
        let oid_pct = self.algorithms_with_oid as f32 / self.algorithms_count as f32;
        (oid_pct * 100.0).clamp(0.0, 100.0)
    }

    /// Algorithm strength: penalizes broken/weak/quantum-vulnerable algorithms.
    #[must_use]
    pub fn algorithm_strength_score(&self) -> f32 {
        if self.algorithms_count == 0 {
            return 100.0;
        }
        let mut score = 100.0_f32;
        score -= (self.weak_algorithm_count as f32 * 15.0).min(60.0);
        score -= (self.inadequate_key_sizes as f32 * 8.0).min(30.0);
        if self.algorithms_count > 0 {
            let vuln_pct = self.quantum_vulnerable_count as f32 / self.algorithms_count as f32;
            score -= vuln_pct * 30.0;
        }
        score.clamp(0.0, 100.0)
    }

    /// Crypto dependency references: how well are cert/key/protocol -> algorithm refs resolved?
    #[must_use]
    pub fn crypto_dependency_score(&self) -> f32 {
        let linkable = self.certificates_count + self.keys_count + self.protocols_count;
        if linkable == 0 {
            return 100.0;
        }
        let resolved = self.certs_with_signature_algo_ref
            + self.keys_with_algorithm_ref
            + self.protocols_with_algorithm_refs;
        let pct = resolved as f32 / linkable as f32;
        (pct * 100.0).clamp(0.0, 100.0)
    }

    /// Crypto lifecycle: merged key management + certificate health.
    #[must_use]
    pub fn crypto_lifecycle_score(&self) -> f32 {
        let mut score = 100.0_f32;

        if self.keys_count > 0 {
            let state_pct = self.keys_with_state as f32 / self.keys_count as f32;
            let protection_pct = self.keys_with_protection as f32 / self.keys_count as f32;
            let lifecycle_pct = self.keys_with_lifecycle_dates as f32 / self.keys_count as f32;
            let key_completeness =
                (state_pct * 0.4 + protection_pct * 0.3 + lifecycle_pct * 0.3) * 100.0;
            score = score * 0.5 + key_completeness * 0.5;
            score -= (self.compromised_keys as f32 * 20.0).min(40.0);
            score -= (self.inadequate_key_sizes as f32 * 5.0).min(20.0);
        }

        if self.certificates_count > 0 {
            let validity_pct =
                self.certs_with_validity_dates as f32 / self.certificates_count as f32;
            score -= (1.0 - validity_pct) * 15.0;
            score -= (self.expired_certificates as f32 * 15.0).min(45.0);
            score -= (self.expiring_soon_certificates as f32 * 5.0).min(20.0);
        }

        score.clamp(0.0, 100.0)
    }

    /// PQC readiness: quantum migration preparedness.
    /// Returns `None` when no algorithms are present — there is nothing to
    /// be ready about, so the scorer redistributes this category's weight
    /// (mirroring `vulnerability_score`) instead of granting a vacuous 100.
    #[must_use]
    pub fn pqc_readiness_score(&self) -> Option<f32> {
        if self.algorithms_count == 0 {
            return None;
        }
        let mut score = 0.0_f32;
        let qs_pct = self.quantum_safe_count as f32 / self.algorithms_count as f32;
        score += qs_pct * 60.0;
        if self.hybrid_pqc_count > 0 {
            score += 15.0;
        }
        if self.weak_algorithm_count == 0 {
            score += 25.0;
        } else {
            score += (25.0 - self.weak_algorithm_count as f32 * 5.0).max(0.0);
        }
        Some(score.clamp(0.0, 100.0))
    }

    /// Percentage of algorithms that are quantum-safe (for overview display).
    #[must_use]
    pub fn quantum_readiness_pct(&self) -> f32 {
        if self.algorithms_count == 0 {
            return 0.0;
        }
        (self.quantum_safe_count as f32 / self.algorithms_count as f32) * 100.0
    }

    /// Category labels for CBOM quality chart.
    #[must_use]
    pub const fn cbom_category_labels() -> [&'static str; 8] {
        ["Crpt", "OIDs", "Algo", "Refs", "Life", "PQC", "Prov", "Lic"]
    }

    /// Full category names for CBOM quality scoring, in the same slot order
    /// as [`Self::cbom_category_labels`] (the short chart labels) and as the
    /// scorer's CBOM slot substitution (`scorer.rs`). These are the names
    /// serialized into diff `QualityDelta` categories for CBOM pairs and the
    /// names the TUI's CBOM category rows display — one category, one name.
    #[must_use]
    pub const fn cbom_category_names() -> [&'static str; 8] {
        [
            "Crypto Compl",
            "OIDs",
            "Algo Strength",
            "Crypto Refs",
            "Crypto Life",
            "PQC Readiness",
            "Provenance",
            "Licenses",
        ]
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn is_valid_purl(purl: &str) -> bool {
    // Basic PURL validation: pkg:type/namespace/name@version
    purl.starts_with("pkg:") && purl.contains('/')
}

fn extract_ecosystem_from_purl(purl: &str) -> Option<String> {
    // Extract type from pkg:type/...
    if let Some(rest) = purl.strip_prefix("pkg:")
        && let Some(slash_idx) = rest.find('/')
    {
        return Some(rest[..slash_idx].to_string());
    }
    None
}

fn is_valid_cpe(cpe: &str) -> bool {
    // Basic CPE validation
    cpe.starts_with("cpe:2.3:") || cpe.starts_with("cpe:/")
}

/// Whether a license identifier is on the SPDX deprecated list.
///
/// These are license IDs that SPDX has deprecated in favor of more specific
/// identifiers (e.g., `GPL-2.0` → `GPL-2.0-only` or `GPL-2.0-or-later`).
fn is_deprecated_spdx_license(expr: &str) -> bool {
    const DEPRECATED: &[&str] = &[
        "GPL-2.0",
        "GPL-2.0+",
        "GPL-3.0",
        "GPL-3.0+",
        "LGPL-2.0",
        "LGPL-2.0+",
        "LGPL-2.1",
        "LGPL-2.1+",
        "LGPL-3.0",
        "LGPL-3.0+",
        "AGPL-1.0",
        "AGPL-3.0",
        "GFDL-1.1",
        "GFDL-1.2",
        "GFDL-1.3",
        "BSD-2-Clause-FreeBSD",
        "BSD-2-Clause-NetBSD",
        "eCos-2.0",
        "Nunit",
        "StandardML-NJ",
        "wxWindows",
    ];
    let trimmed = expr.trim();
    DEPRECATED.contains(&trimmed)
}

/// Whether a license is considered restrictive/copyleft (GPL family).
///
/// This is informational — restrictive licenses are not inherently a quality
/// issue, but organizations need to know about them for compliance.
fn is_restrictive_license(expr: &str) -> bool {
    let trimmed = expr.trim().to_uppercase();
    trimmed.starts_with("GPL")
        || trimmed.starts_with("LGPL")
        || trimmed.starts_with("AGPL")
        || trimmed.starts_with("EUPL")
        || trimmed.starts_with("SSPL")
        || trimmed.starts_with("OSL")
        || trimmed.starts_with("CPAL")
        || trimmed.starts_with("CC-BY-SA")
        || trimmed.starts_with("CC-BY-NC")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// File inventory entries (SPDX files/snippets, CycloneDX type=file)
    /// must not dilute package completeness percentages: files structurally
    /// lack version/supplier/purl, and a file-cataloguing SBOM with
    /// thousands of files would otherwise report ~0% coverage on an
    /// otherwise complete document.
    #[test]
    fn file_components_do_not_dilute_completeness() {
        use crate::model::{Component, ComponentType, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let pkg =
            Component::new("app".to_string(), "app@1".to_string()).with_version("1.0".to_string());
        sbom.add_component(pkg);
        for i in 0..10 {
            let mut f = Component::new(format!("file-{i}"), format!("file-{i}@x"));
            f.component_type = ComponentType::File;
            sbom.add_component(f);
        }

        let m = CompletenessMetrics::from_sbom(&sbom);
        assert!(
            (m.components_with_version - 100.0).abs() < f32::EPSILON,
            "10 files must not dilute the package's 100% version coverage, got {}",
            m.components_with_version
        );
    }

    /// Same File exemption for identifier scoring: files structurally lack
    /// purl/cpe/swid, so a file catalogue must not dilute package identifier
    /// coverage.
    #[test]
    fn file_components_do_not_dilute_identifier_score() {
        use crate::model::{Component, ComponentType, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut pkg = Component::new("app".to_string(), "app@1".to_string());
        pkg.identifiers.purl = Some("pkg:cargo/app@1.0.0".to_string());
        sbom.add_component(pkg);
        for i in 0..30 {
            let mut f = Component::new(format!("file-{i}"), format!("file-{i}@x"));
            f.component_type = ComponentType::File;
            sbom.add_component(f);
        }

        let im = IdentifierMetrics::from_sbom(&sbom);
        assert_eq!(im.non_package_components, 30);
        assert_eq!(
            im.missing_all_identifiers, 0,
            "exempt files must not count as identifier-less"
        );
        let score = im.quality_score(sbom.components.len());
        assert!(
            (score - 100.0).abs() < 0.01,
            "30 files must not dilute the package's identifier coverage, got {score}"
        );
    }

    /// Same File exemption for license scoring: per-file license facts are
    /// not package license documentation, so a file catalogue must not dilute
    /// package license coverage (license strings still reach the lists).
    #[test]
    fn file_components_do_not_dilute_license_score() {
        use crate::model::{Component, ComponentType, LicenseExpression, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut pkg = Component::new("app".to_string(), "app@1".to_string());
        pkg.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        sbom.add_component(pkg);
        for i in 0..30 {
            let mut f = Component::new(format!("file-{i}"), format!("file-{i}@x"));
            f.component_type = ComponentType::File;
            f.licenses
                .add_declared(LicenseExpression::new("GPL-2.0-only".to_string()));
            sbom.add_component(f);
        }

        let lm = LicenseMetrics::from_sbom(&sbom);
        assert_eq!(lm.non_package_components, 30);
        assert_eq!(lm.with_declared, 1, "files are exempt from counters");
        assert!(
            lm.unique_licenses.contains(&"GPL-2.0-only".to_string()),
            "file license strings still feed the informational lists"
        );
        // Coverage 1/1 * 60 + full SPDX bonus 30 = 90 for the one package.
        let score = lm.quality_score(sbom.components.len());
        assert!(
            (score - 90.0).abs() < 0.01,
            "30 files must not dilute the package's license coverage, got {score}"
        );
    }

    /// Same File exemption for the dependency-coverage denominator: files
    /// (typically attached via CONTAINS) are not dependency-graph members.
    #[test]
    fn file_components_do_not_dilute_dependency_coverage() {
        use crate::model::{
            Component, ComponentType, DependencyEdge, DependencyType, NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::default();
        let app = Component::new("app".to_string(), "app@1".to_string());
        let lib = Component::new("lib".to_string(), "lib@1".to_string());
        let app_id = app.canonical_id.clone();
        let lib_id = lib.canonical_id.clone();
        sbom.add_component(app);
        sbom.add_component(lib);
        sbom.add_edge(DependencyEdge::new(
            app_id.clone(),
            lib_id,
            DependencyType::DependsOn,
        ));
        for i in 0..30 {
            let mut f = Component::new(format!("file-{i}"), format!("file-{i}@x"));
            f.component_type = ComponentType::File;
            let file_id = f.canonical_id.clone();
            sbom.add_component(f);
            // SPDX-style package CONTAINS file relationship.
            sbom.add_edge(DependencyEdge::new(
                app_id.clone(),
                file_id,
                DependencyType::Contains,
            ));
        }

        let dm = DependencyMetrics::from_sbom(&sbom);
        assert_eq!(dm.non_package_components, 30);
        let score = dm.quality_score(sbom.components.len());
        assert!(
            (score - 100.0).abs() < 0.01,
            "30 contained files must not dilute dependency coverage, got {score}"
        );
    }

    /// A Cryptographic component with NO cryptoProperties must not count as
    /// crypto inventory — otherwise has_data() is true and the CBOM sub-scores
    /// return 100 (grade A) for undocumented crypto.
    #[test]
    fn property_less_crypto_component_is_not_crypto_inventory() {
        use crate::model::{Component, ComponentType, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("mystery-crypto".to_string(), "mc@1".to_string());
        c.component_type = ComponentType::Cryptographic;
        // No crypto_properties set.
        sbom.add_component(c);

        let m = CryptographyMetrics::from_sbom(&sbom);
        assert_eq!(
            m.total_crypto_components, 0,
            "undocumented crypto is not inventory"
        );
        assert!(
            !m.has_data(),
            "has_data must be false → CBOM scores are N/A, not 100"
        );
    }

    /// A CBOM whose documented crypto assets are ALL unclassifiable (asset
    /// types outside algorithm/certificate/key/protocol) has nothing
    /// evaluable, so no hygiene penalty can ever trigger — the score must
    /// read fully degraded, not a vacuous 100 (matching the CNSA2/PQC
    /// "evaluable assets" compliance gates, which fail such inventories).
    #[test]
    fn unclassifiable_crypto_inventory_scores_degraded_not_perfect() {
        use crate::model::{
            Component, ComponentType, CryptoAssetType, CryptoProperties, NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("mystery-asset".to_string(), "ma@1".to_string());
        c.component_type = ComponentType::Cryptographic;
        c.crypto_properties = Some(CryptoProperties::new(CryptoAssetType::Other(
            "unknown".to_string(),
        )));
        sbom.add_component(c);

        let m = CryptographyMetrics::from_sbom(&sbom);
        assert!(m.has_data(), "documented crypto assets are inventory");
        assert_eq!(m.algorithms_count, 0);
        assert_eq!(
            m.quality_score(),
            Some(0.0),
            "all-unclassifiable inventory must read degraded, not 100"
        );
    }

    /// Certificates/protocols whose algorithm references cannot be resolved
    /// are documented-but-unverifiable: none of the hygiene penalties can
    /// fire for them, so without the unresolved-reference penalty an
    /// inventory of opaque refs would read a perfect 100 while the
    /// compliance checkers warn on every asset.
    #[test]
    fn unresolved_crypto_references_degrade_the_quality_score() {
        use crate::model::{
            CertificateProperties, Component, ComponentType, CryptoAssetType, CryptoProperties,
            NormalizedSbom,
        };
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("opaque-cert".to_string(), "oc@1".to_string());
        c.component_type = ComponentType::Cryptographic;
        // Certificate with no signatureAlgorithmRef: classified, unlinked.
        c.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Certificate)
                .with_certificate_properties(CertificateProperties::new()),
        );
        sbom.add_component(c);

        let m = CryptographyMetrics::from_sbom(&sbom);
        assert_eq!(m.certificates_count, 1);
        assert_eq!(m.certs_with_signature_algo_ref, 0);
        let score = m.quality_score().expect("has data");
        assert!(
            score <= 70.0,
            "fully-unresolved references must degrade the score, got {score}"
        );
    }

    /// Standard ECC keys (P-256/384/etc.) must NOT be flagged as inadequate —
    /// their size is the curve bit-length, giving ~size/2-bit security. The old
    /// flat `<2048` rule false-failed every ECC key. RSA-1024 stays flagged.
    #[test]
    fn ecc_key_sizes_are_not_falsely_inadequate() {
        use crate::model::{
            Component, ComponentType, CryptoAssetType, CryptoMaterialType, CryptoProperties,
            NormalizedSbom, RelatedCryptoMaterialProperties,
        };
        let key = |name: &str, mtype: CryptoMaterialType, size: u32| {
            let mut c = Component::new(name.to_string(), format!("{name}@1"));
            c.component_type = ComponentType::Cryptographic;
            let mat = RelatedCryptoMaterialProperties::new(mtype).with_size(size);
            c.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
                    .with_related_crypto_material_properties(mat),
            );
            c
        };
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(key("ecc-p256", CryptoMaterialType::PublicKey, 256));
        sbom.add_component(key("ecc-p384", CryptoMaterialType::PublicKey, 384));
        sbom.add_component(key("ecc-p521", CryptoMaterialType::PublicKey, 521));
        sbom.add_component(key("rsa-1024", CryptoMaterialType::PublicKey, 1024));
        // A 512-bit key must be inadequate — it would be a factorable RSA/DSA
        // key; 512 must NOT be treated as a "strong ECC" size.
        sbom.add_component(key("weak-512", CryptoMaterialType::PublicKey, 512));
        sbom.add_component(key("aes-256", CryptoMaterialType::SymmetricKey, 256));

        let m = CryptographyMetrics::from_sbom(&sbom);
        assert_eq!(
            m.inadequate_key_sizes, 2,
            "RSA-1024 and the 512-bit key are inadequate; strong ECC (256/384/521) is not"
        );
    }

    /// A NOASSERTION-only component must not count as "has license" — the
    /// CycloneDX parser emits declared=["NOASSERTION"] for empty license
    /// objects, which carries zero license information.
    #[test]
    fn noassertion_only_component_is_not_licensed() {
        use crate::model::{Component, LicenseExpression, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("no-info".to_string(), "ni@1".to_string());
        c.licenses
            .add_declared(LicenseExpression::new("NOASSERTION".to_string()));
        sbom.add_component(c);
        let mut licensed = Component::new("real".to_string(), "real@1".to_string());
        licensed
            .licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        sbom.add_component(licensed);

        let completeness = CompletenessMetrics::from_sbom(&sbom);
        assert!(
            (completeness.components_with_licenses - 50.0).abs() < 0.01,
            "1 of 2 components has real license info, got {}",
            completeness.components_with_licenses
        );

        let lm = LicenseMetrics::from_sbom(&sbom);
        assert_eq!(
            lm.with_declared, 1,
            "NOASSERTION-only must not count as declared"
        );
        assert_eq!(lm.noassertion_count, 1);
        assert_eq!(lm.valid_spdx_expressions, 1);
    }

    /// spdx_ratio must never exceed 1.0: a component with several valid
    /// declared licenses previously pushed the per-entry numerator above the
    /// per-component denominator, blowing the 30-pt SPDX bonus past its cap.
    #[test]
    fn multi_license_component_does_not_inflate_spdx_bonus() {
        use crate::model::{Component, LicenseExpression, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut multi = Component::new("multi".to_string(), "m@1".to_string());
        for id in ["MIT", "Apache-2.0", "BSD-3-Clause"] {
            multi
                .licenses
                .add_declared(LicenseExpression::new(id.to_string()));
        }
        sbom.add_component(multi);
        // A second component with NO license at all.
        sbom.add_component(Component::new("bare".to_string(), "b@1".to_string()));

        let lm = LicenseMetrics::from_sbom(&sbom);
        assert_eq!(lm.with_declared, 1);
        assert_eq!(lm.valid_spdx_expressions, 1, "per-component, not per-entry");
        assert!(
            lm.valid_spdx_expressions <= lm.with_declared,
            "spdx ratio numerator must not exceed its denominator"
        );
        // coverage 50% of 60 = 30, bonus 1.0*30 = 30 → 60. The old per-entry
        // count gave ratio 3.0 → bonus 90 → clamped 100 despite 50% coverage.
        let score = lm.quality_score(2);
        assert!(
            (score - 60.0).abs() < 0.01,
            "expected 60 (half coverage + full SPDX bonus), got {score}"
        );
    }

    /// One component with many CPEs must not mask components with no
    /// identifier at all in the coverage score.
    #[test]
    fn multi_cpe_component_does_not_mask_identifierless_ones() {
        use crate::model::{Component, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let mut multi = Component::new("multi-cpe".to_string(), "mc@1".to_string());
        for i in 0..3 {
            multi
                .identifiers
                .cpe
                .push(format!("cpe:2.3:a:vendor:product{i}:1.0:*:*:*:*:*:*:*"));
        }
        sbom.add_component(multi);
        sbom.add_component(Component::new("bare-1".to_string(), "b1@1".to_string()));
        sbom.add_component(Component::new("bare-2".to_string(), "b2@1".to_string()));

        let im = IdentifierMetrics::from_sbom(&sbom);
        assert_eq!(im.components_with_valid_id, 1);
        assert_eq!(im.valid_cpes, 1, "per-component CPE count");
        assert_eq!(im.missing_all_identifiers, 2);
        let score = im.quality_score(3);
        assert!(
            (score - 33.33).abs() < 0.1,
            "1/3 coverage expected, got {score} (old per-entry count gave 100)"
        );
    }

    /// Deprecated/archived components are counted once, not twice, when the
    /// enrichment sets both the StalenessLevel and the boolean flag.
    #[test]
    fn lifecycle_does_not_double_count_deprecated() {
        use crate::model::{Component, NormalizedSbom, StalenessInfo, StalenessLevel};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("old-pkg".to_string(), "op@1".to_string());
        c.staleness = Some(StalenessInfo {
            level: StalenessLevel::Deprecated,
            last_published: None,
            is_deprecated: true, // enrichment sets both together
            is_archived: false,
            deprecation_message: None,
            days_since_update: None,
            latest_version: None,
        });
        sbom.add_component(c);

        let lm = LifecycleMetrics::from_sbom(&sbom);
        assert_eq!(
            lm.deprecated_components, 1,
            "one deprecated component must count once, not twice"
        );
    }

    /// Disclosing a bare vulnerability (no CVSS/CWE/remediation) earns the
    /// 40-point disclosure baseline, not 0 — scoring 0 made an SBOM better
    /// off stripping vulnerability data than disclosing it (non-monotonic).
    #[test]
    fn bare_vuln_disclosure_earns_baseline_credit() {
        use crate::model::{Component, NormalizedSbom, VulnerabilityRef, VulnerabilitySource};
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("app".to_string(), "app@1".to_string());
        c.vulnerabilities.push(VulnerabilityRef::new(
            "CVE-2024-0001".to_string(),
            VulnerabilitySource::Osv,
        ));
        sbom.add_component(c);

        let vm = VulnerabilityMetrics::from_sbom(&sbom);
        let score = vm.documentation_score().expect("vuln data present");
        assert!(
            (score - 40.0).abs() < 0.01,
            "bare disclosure must earn the 40-pt baseline, got {score}"
        );

        // No vulnerability data at all stays N/A (None), not 40.
        let empty = NormalizedSbom::default();
        assert!(
            VulnerabilityMetrics::from_sbom(&empty)
                .documentation_score()
                .is_none()
        );
    }

    /// The provenance score must be a pure function of the document — no
    /// wall-clock term. Freshness is display-only metadata.
    #[test]
    fn provenance_score_has_no_wall_clock_term() {
        let fresh = ProvenanceMetrics {
            is_fresh: true,
            ..base_provenance()
        };
        let stale = ProvenanceMetrics {
            is_fresh: false,
            ..base_provenance()
        };
        assert!(
            (fresh.quality_score(true) - stale.quality_score(true)).abs() < f32::EPSILON,
            "is_fresh must not affect the score"
        );
    }

    fn base_provenance() -> ProvenanceMetrics {
        ProvenanceMetrics {
            has_tool_creator: true,
            has_tool_version: false,
            has_org_creator: false,
            has_contact_email: false,
            has_serial_number: false,
            has_document_name: false,
            timestamp_age_days: 0,
            timestamp_known: true,
            is_fresh: false,
            has_primary_component: false,
            lifecycle_phase: None,
            completeness_declaration: CompletenessDeclaration::Unknown,
            has_signature: false,
            has_citations: false,
            citations_count: 0,
        }
    }

    /// A fully-cyclic dependency graph reaches >100% raw coverage via the
    /// N/(N-1) denominator; the clamp must land BEFORE the penalties so the
    /// cycle penalty is not silently absorbed.
    #[test]
    fn cyclic_graph_coverage_does_not_absorb_cycle_penalty() {
        use crate::model::{Component, DependencyEdge, DependencyType, NormalizedSbom};
        let mut sbom = NormalizedSbom::default();
        let n = 5;
        let mut ids = Vec::new();
        for i in 0..n {
            let c = Component::new(format!("c{i}"), format!("c{i}@1"));
            ids.push(c.canonical_id.clone());
            sbom.add_component(c);
        }
        // Ring: c0→c1→...→c4→c0 — every node has an outgoing edge.
        for i in 0..n {
            sbom.add_edge(DependencyEdge::new(
                ids[i].clone(),
                ids[(i + 1) % n].clone(),
                DependencyType::DependsOn,
            ));
        }
        let dm = DependencyMetrics::from_sbom(&sbom);
        assert!(dm.cycle_count >= 1, "ring must be detected as a cycle");
        let score = dm.quality_score(n);
        assert!(
            score <= 95.0,
            "cycle penalty must survive the clamp (raw coverage 125% \
             previously absorbed it), got {score}"
        );
    }

    #[test]
    fn test_purl_validation() {
        assert!(is_valid_purl("pkg:npm/@scope/name@1.0.0"));
        assert!(is_valid_purl("pkg:maven/group/artifact@1.0"));
        assert!(!is_valid_purl("npm:something"));
        assert!(!is_valid_purl("invalid"));
    }

    #[test]
    fn test_cpe_validation() {
        assert!(is_valid_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"));
        assert!(is_valid_cpe("cpe:/a:vendor:product:1.0"));
        assert!(!is_valid_cpe("something:else"));
    }

    /// License validity comes from the model's spdx-crate parse (stored in
    /// `LicenseExpression.is_valid_spdx`), not the old substring heuristic
    /// that accepted any string containing " OR "/" AND "/" WITH ".
    #[test]
    fn test_spdx_license_validation() {
        use crate::model::LicenseExpression;
        let valid = |e: &str| LicenseExpression::new(e.to_string()).is_valid_spdx;
        assert!(valid("MIT"));
        assert!(valid("Apache-2.0"));
        assert!(valid("MIT AND Apache-2.0"));
        assert!(valid("GPL-2.0 OR MIT"));
        assert!(valid("GPL-2.0-only WITH Classpath-exception-2.0"));
        assert!(valid("Zlib"));
        // The substring heuristic accepted these; real parsing must not.
        assert!(!valid("GARBAGE OR NONSENSE"));
        assert!(!valid("foo AND bar"));
        assert!(!valid("NOASSERTION"));
    }

    #[test]
    fn test_strong_hash_classification() {
        assert!(is_strong_hash(&HashAlgorithm::Sha256));
        assert!(is_strong_hash(&HashAlgorithm::Sha3_256));
        assert!(is_strong_hash(&HashAlgorithm::Blake3));
        assert!(!is_strong_hash(&HashAlgorithm::Md5));
        assert!(!is_strong_hash(&HashAlgorithm::Sha1));
        assert!(!is_strong_hash(&HashAlgorithm::Other("custom".to_string())));
    }

    #[test]
    fn test_deprecated_license_detection() {
        assert!(is_deprecated_spdx_license("GPL-2.0"));
        assert!(is_deprecated_spdx_license("LGPL-2.1"));
        assert!(is_deprecated_spdx_license("AGPL-3.0"));
        assert!(!is_deprecated_spdx_license("GPL-2.0-only"));
        assert!(!is_deprecated_spdx_license("MIT"));
        assert!(!is_deprecated_spdx_license("Apache-2.0"));
    }

    #[test]
    fn test_restrictive_license_detection() {
        assert!(is_restrictive_license("GPL-3.0-only"));
        assert!(is_restrictive_license("LGPL-2.1-or-later"));
        assert!(is_restrictive_license("AGPL-3.0-only"));
        assert!(is_restrictive_license("EUPL-1.2"));
        assert!(is_restrictive_license("CC-BY-SA-4.0"));
        assert!(!is_restrictive_license("MIT"));
        assert!(!is_restrictive_license("Apache-2.0"));
        assert!(!is_restrictive_license("BSD-3-Clause"));
    }

    #[test]
    fn test_hash_quality_score_no_components() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 0,
            components_with_strong_hash: 0,
            components_with_weak_only: 0,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 0,
            vendor_components_total: 0,
            vendor_components_with_hash: 0,
            vendor_components_with_strong_hash: 0,
        };
        assert_eq!(metrics.quality_score(0), 0.0);
    }

    #[test]
    fn test_hash_quality_score_all_strong() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 10,
            components_with_strong_hash: 10,
            components_with_weak_only: 0,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 10,
            vendor_components_total: 0,
            vendor_components_with_hash: 0,
            vendor_components_with_strong_hash: 0,
        };
        assert_eq!(metrics.quality_score(10), 100.0);
    }

    #[test]
    fn test_hash_quality_score_weak_only_penalty() {
        let metrics = HashQualityMetrics {
            components_with_any_hash: 10,
            components_with_strong_hash: 0,
            components_with_weak_only: 10,
            algorithm_distribution: BTreeMap::new(),
            total_hashes: 10,
            vendor_components_total: 0,
            vendor_components_with_hash: 0,
            vendor_components_with_strong_hash: 0,
        };
        // 60 (any) + 0 (strong) - 10 (weak penalty) = 50
        assert_eq!(metrics.quality_score(10), 50.0);
    }

    #[test]
    fn test_lifecycle_no_enrichment_returns_none() {
        let metrics = LifecycleMetrics {
            eol_components: 0,
            stale_components: 0,
            deprecated_components: 0,
            archived_components: 0,
            outdated_components: 0,
            enriched_components: 0,
            enrichment_coverage: 0.0,
        };
        assert!(!metrics.has_data());
        assert!(metrics.quality_score().is_none());
    }

    #[test]
    fn test_lifecycle_with_eol_penalty() {
        let metrics = LifecycleMetrics {
            eol_components: 2,
            stale_components: 0,
            deprecated_components: 0,
            archived_components: 0,
            outdated_components: 0,
            enriched_components: 10,
            enrichment_coverage: 100.0,
        };
        // 100 - 30 (2 * 15) = 70
        assert_eq!(metrics.quality_score(), Some(70.0));
    }

    #[test]
    fn test_cycle_detection_no_cycles() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["b"]), ("b", vec!["c"])]);
        let all_nodes = vec!["a", "b", "c"];
        // Linear chain has no SCC with more than one node
        assert_eq!(detect_cycles(&all_nodes, &children), 0);
    }

    #[test]
    fn test_cycle_detection_with_cycle() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["b"]), ("b", vec!["c"]), ("c", vec!["a"])]);
        let all_nodes = vec!["a", "b", "c"];
        // a→b→c→a forms a single 3-node SCC = one cycle
        assert_eq!(detect_cycles(&all_nodes, &children), 1);
    }

    #[test]
    fn test_cycle_detection_deep_linear_chain_no_overflow() {
        let n = 40_000usize;
        let names: Vec<String> = (0..n).map(|i| format!("node-{i}")).collect();
        let all_nodes: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
        for w in all_nodes.windows(2) {
            children.entry(w[0]).or_default().push(w[1]);
        }
        assert_eq!(detect_cycles(&all_nodes, &children), 0);
    }

    #[test]
    fn test_cycle_detection_diamond_dag() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["b", "c"]), ("b", vec!["d"]), ("c", vec!["d"])]);
        let all_nodes = vec!["a", "b", "c", "d"];
        assert_eq!(detect_cycles(&all_nodes, &children), 0);
    }

    #[test]
    fn test_cycle_detection_multi_back_edge_scc_counts_once() {
        let children: HashMap<&str, Vec<&str>> = HashMap::from([
            ("a", vec!["b", "c"]),
            ("b", vec!["a", "c"]),
            ("c", vec!["a", "b"]),
        ]);
        let all_nodes = vec!["a", "b", "c"];
        // One SCC with multiple back edges still counts as a single cycle
        assert_eq!(detect_cycles(&all_nodes, &children), 1);
    }

    #[test]
    fn test_cycle_detection_self_loop_counts_once() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("a", vec!["a", "b"]), ("b", vec!["c"])]);
        let all_nodes = vec!["a", "b", "c"];
        assert_eq!(detect_cycles(&all_nodes, &children), 1);
    }

    #[test]
    fn test_quality_scorer_deep_chain_end_to_end() {
        use crate::model::{Component, DependencyEdge, DependencyType};
        use crate::quality::{QualityScorer, ScoringProfile};

        let n = 40_000usize;
        let mut sbom = NormalizedSbom::default();
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let component = Component::new(format!("node-{i}"), format!("ref-{i}"));
            ids.push(component.canonical_id.clone());
            sbom.add_component(component);
        }
        for w in ids.windows(2) {
            sbom.add_edge(DependencyEdge::new(
                w[0].clone(),
                w[1].clone(),
                DependencyType::DependsOn,
            ));
        }

        let report = QualityScorer::new(ScoringProfile::Standard).score(&sbom);
        assert!(!report.dependency_metrics.graph_analysis_skipped);
        assert_eq!(report.dependency_metrics.cycle_count, 0);
        assert_eq!(report.dependency_metrics.max_depth, Some(n - 1));
    }

    #[test]
    fn test_depth_computation() {
        let children: HashMap<&str, Vec<&str>> =
            HashMap::from([("root", vec!["a", "b"]), ("a", vec!["c"])]);
        let roots = vec!["root"];
        let (max_d, avg_d) = compute_depth(&roots, &children);
        assert_eq!(max_d, Some(2)); // root -> a -> c
        assert!(avg_d.is_some());
    }

    #[test]
    fn test_depth_empty_roots() {
        let children: HashMap<&str, Vec<&str>> = HashMap::new();
        let roots: Vec<&str> = vec![];
        let (max_d, avg_d) = compute_depth(&roots, &children);
        assert_eq!(max_d, None);
        assert_eq!(avg_d, None);
    }

    #[test]
    fn test_provenance_quality_score() {
        let metrics = ProvenanceMetrics {
            has_tool_creator: true,
            has_tool_version: true,
            has_org_creator: true,
            has_contact_email: true,
            has_serial_number: true,
            has_document_name: true,
            timestamp_age_days: 10,
            timestamp_known: true,
            is_fresh: true,
            has_primary_component: true,
            lifecycle_phase: Some("build".to_string()),
            completeness_declaration: CompletenessDeclaration::Complete,
            has_signature: true,
            has_citations: true,
            citations_count: 3,
        };
        // All checks pass for CycloneDX
        assert_eq!(metrics.quality_score(true), 100.0);
    }

    #[test]
    fn test_provenance_score_without_cyclonedx() {
        let metrics = ProvenanceMetrics {
            has_tool_creator: true,
            has_tool_version: true,
            has_org_creator: true,
            has_contact_email: true,
            has_serial_number: true,
            has_document_name: true,
            timestamp_age_days: 10,
            timestamp_known: true,
            is_fresh: true,
            has_primary_component: true,
            lifecycle_phase: None,
            completeness_declaration: CompletenessDeclaration::Complete,
            has_signature: true,
            has_citations: false,
            citations_count: 0,
        };
        // Lifecycle phase and citations excluded for non-CDX
        assert_eq!(metrics.quality_score(false), 100.0);
    }

    #[test]
    fn test_complexity_empty_graph() {
        let (simplicity, level, factors) = compute_complexity(0, 0, 0, 0, 0, 0, 0);
        assert_eq!(simplicity, 100.0);
        assert_eq!(level, ComplexityLevel::Low);
        assert_eq!(factors.dependency_volume, 0.0);
    }

    #[test]
    fn test_complexity_single_node() {
        // 1 component, no edges, no cycles, 1 orphan, 1 island
        let (simplicity, level, _) = compute_complexity(0, 1, 0, 0, 0, 1, 1);
        assert!(
            simplicity >= 80.0,
            "Single node simplicity {simplicity} should be >= 80"
        );
        assert_eq!(level, ComplexityLevel::Low);
    }

    #[test]
    fn test_complexity_monotonic_edges() {
        // More edges should never increase simplicity
        let (s1, _, _) = compute_complexity(5, 10, 2, 3, 0, 1, 1);
        let (s2, _, _) = compute_complexity(20, 10, 2, 3, 0, 1, 1);
        assert!(
            s2 <= s1,
            "More edges should not increase simplicity: {s2} vs {s1}"
        );
    }

    #[test]
    fn test_complexity_monotonic_cycles() {
        let (s1, _, _) = compute_complexity(10, 10, 2, 3, 0, 1, 1);
        let (s2, _, _) = compute_complexity(10, 10, 2, 3, 3, 1, 1);
        assert!(
            s2 <= s1,
            "More cycles should not increase simplicity: {s2} vs {s1}"
        );
    }

    #[test]
    fn test_complexity_monotonic_depth() {
        let (s1, _, _) = compute_complexity(10, 10, 2, 3, 0, 1, 1);
        let (s2, _, _) = compute_complexity(10, 10, 10, 3, 0, 1, 1);
        assert!(
            s2 <= s1,
            "More depth should not increase simplicity: {s2} vs {s1}"
        );
    }

    #[test]
    fn test_complexity_graph_skipped() {
        // When graph_analysis_skipped, DependencyMetrics should have None complexity fields.
        // We test compute_complexity separately; the from_sbom integration handles the None case.
        let (simplicity, _, _) = compute_complexity(100, 50, 5, 10, 2, 5, 3);
        assert!(simplicity >= 0.0 && simplicity <= 100.0);
    }

    #[test]
    fn test_complexity_level_bands() {
        assert_eq!(ComplexityLevel::from_score(100.0), ComplexityLevel::Low);
        assert_eq!(ComplexityLevel::from_score(75.0), ComplexityLevel::Low);
        assert_eq!(ComplexityLevel::from_score(74.0), ComplexityLevel::Moderate);
        assert_eq!(ComplexityLevel::from_score(50.0), ComplexityLevel::Moderate);
        assert_eq!(ComplexityLevel::from_score(49.0), ComplexityLevel::High);
        assert_eq!(ComplexityLevel::from_score(25.0), ComplexityLevel::High);
        assert_eq!(ComplexityLevel::from_score(24.0), ComplexityLevel::VeryHigh);
        assert_eq!(ComplexityLevel::from_score(0.0), ComplexityLevel::VeryHigh);
    }

    #[test]
    fn test_completeness_declaration_display() {
        assert_eq!(CompletenessDeclaration::Complete.to_string(), "complete");
        assert_eq!(
            CompletenessDeclaration::IncompleteFirstPartyOnly.to_string(),
            "incomplete (first-party only)"
        );
        assert_eq!(CompletenessDeclaration::Unknown.to_string(), "unknown");
    }

    // ── CryptographyMetrics scoring tests ──

    #[test]
    fn crypto_completeness_all_documented() {
        let m = CryptographyMetrics {
            algorithms_count: 4,
            algorithms_with_family: 4,
            algorithms_with_primitive: 4,
            algorithms_with_security_level: 4,
            ..Default::default()
        };
        let score = m.crypto_completeness_score();
        assert!(
            (score - 100.0).abs() < 0.1,
            "fully documented → 100, got {score}"
        );
    }

    #[test]
    fn crypto_completeness_partial() {
        let m = CryptographyMetrics {
            algorithms_count: 4,
            algorithms_with_family: 2,         // 50%
            algorithms_with_primitive: 4,      // 100%
            algorithms_with_security_level: 0, // 0%
            ..Default::default()
        };
        // 0.5*40 + 1.0*30 + 0.0*30 = 20+30+0 = 50
        let score = m.crypto_completeness_score();
        assert!((score - 50.0).abs() < 0.1, "partial → 50, got {score}");
    }

    #[test]
    fn crypto_identifier_full_oid_coverage() {
        let m = CryptographyMetrics {
            algorithms_count: 5,
            algorithms_with_oid: 5,
            ..Default::default()
        };
        assert!((m.crypto_identifier_score() - 100.0).abs() < 0.1);
    }

    #[test]
    fn crypto_identifier_no_oids() {
        let m = CryptographyMetrics {
            algorithms_count: 5,
            algorithms_with_oid: 0,
            ..Default::default()
        };
        assert!((m.crypto_identifier_score() - 0.0).abs() < 0.1);
    }

    #[test]
    fn algorithm_strength_weak_penalty() {
        let m = CryptographyMetrics {
            algorithms_count: 5,
            weak_algorithm_count: 2,
            ..Default::default()
        };
        // 100 - 2*15 = 70
        let score = m.algorithm_strength_score();
        assert!((score - 70.0).abs() < 0.1, "2 weak → 70, got {score}");
    }

    #[test]
    fn algorithm_strength_quantum_vulnerable() {
        let m = CryptographyMetrics {
            algorithms_count: 10,
            quantum_vulnerable_count: 10,
            ..Default::default()
        };
        // 100 - (10/10)*30 = 70
        let score = m.algorithm_strength_score();
        assert!(
            (score - 70.0).abs() < 0.1,
            "all quantum vuln → 70, got {score}"
        );
    }

    #[test]
    fn crypto_lifecycle_compromised_keys() {
        let m = CryptographyMetrics {
            keys_count: 3,
            keys_with_state: 3,
            keys_with_protection: 3,
            keys_with_lifecycle_dates: 3,
            compromised_keys: 1,
            ..Default::default()
        };
        let score = m.crypto_lifecycle_score();
        // With full key completeness: 100*0.5 + 100*0.5 = 100, then -20 penalty
        assert!(score < 85.0);
        assert!(score > 50.0);
    }

    #[test]
    fn crypto_lifecycle_expired_certs() {
        let m = CryptographyMetrics {
            certificates_count: 4,
            certs_with_validity_dates: 4,
            expired_certificates: 2,
            expiring_soon_certificates: 1,
            ..Default::default()
        };
        let score = m.crypto_lifecycle_score();
        // 100 - 2*15 - 1*5 = 100 - 30 - 5 = 65
        assert!(score < 70.0);
    }

    #[test]
    fn pqc_readiness_all_quantum_safe() {
        let m = CryptographyMetrics {
            algorithms_count: 5,
            quantum_safe_count: 5,
            hybrid_pqc_count: 2,
            weak_algorithm_count: 0,
            ..Default::default()
        };
        // (5/5)*60 + 15 + 25 = 100
        let score = m.pqc_readiness_score().expect("algorithms present");
        assert!(
            (score - 100.0).abs() < 0.1,
            "all safe + hybrid → 100, got {score}"
        );
    }

    #[test]
    fn pqc_readiness_no_quantum_safe() {
        let m = CryptographyMetrics {
            algorithms_count: 5,
            quantum_safe_count: 0,
            hybrid_pqc_count: 0,
            weak_algorithm_count: 0,
            ..Default::default()
        };
        // 0*60 + 0 + 25 = 25
        let score = m.pqc_readiness_score().expect("algorithms present");
        assert!(
            (score - 25.0).abs() < 0.1,
            "no safe, no weak → 25, got {score}"
        );
    }

    /// Zero algorithms is absence of evidence, not readiness: both quantum
    /// readiness scores must be `None` so renderers show "n/a" and the CBOM
    /// scorer redistributes the PQC weight instead of granting a free 100.
    #[test]
    fn readiness_scores_none_with_zero_algorithms() {
        let m = CryptographyMetrics {
            algorithms_count: 0,
            certificates_count: 2, // crypto data exists, just no algorithms
            ..Default::default()
        };
        assert!(m.quantum_readiness_score().is_none());
        assert!(m.pqc_readiness_score().is_none());
    }

    #[test]
    fn crypto_dependency_all_resolved() {
        let m = CryptographyMetrics {
            certificates_count: 2,
            keys_count: 3,
            protocols_count: 1,
            certs_with_signature_algo_ref: 2,
            keys_with_algorithm_ref: 3,
            protocols_with_cipher_suites: 1,
            protocols_with_algorithm_refs: 1,
            ..Default::default()
        };
        assert!((m.crypto_dependency_score() - 100.0).abs() < 0.1);
    }

    #[test]
    fn crypto_dependency_none_resolved() {
        let m = CryptographyMetrics {
            certificates_count: 2,
            keys_count: 3,
            protocols_count: 1,
            ..Default::default()
        };
        assert!((m.crypto_dependency_score() - 0.0).abs() < 0.1);
    }

    #[test]
    fn quality_score_none_when_no_crypto() {
        let m = CryptographyMetrics::default();
        assert!(m.quality_score().is_none());
    }

    #[test]
    fn quantum_readiness_pct_zero_algorithms() {
        let m = CryptographyMetrics::default();
        assert!((m.quantum_readiness_pct() - 0.0).abs() < 0.01);
    }

    /// A document with no timestamp (epoch sentinel) must NOT be counted as
    /// fresh, and its age must report as unknown (0), not ~20000 days — the
    /// old Utc::now() fallback silently granted freshness credit.
    #[test]
    fn provenance_missing_timestamp_is_not_fresh() {
        let cdx = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
            "components":[{"type":"library","name":"a","version":"1.0"}]}"#;
        let sbom = crate::parsers::parse_sbom_str(cdx).expect("parse");
        assert!(
            !sbom.document.has_known_timestamp(),
            "fixture must have no timestamp"
        );
        let prov = ProvenanceMetrics::from_sbom(&sbom);
        assert!(!prov.timestamp_known);
        assert!(!prov.is_fresh, "a timestamp-less SBOM must not be fresh");
        assert_eq!(
            prov.timestamp_age_days, 0,
            "unknown age must not leak a huge number"
        );

        // A recently-timestamped document is fresh.
        let now = chrono::Utc::now().to_rfc3339();
        let cdx_ts = format!(
            r#"{{"bomFormat":"CycloneDX","specVersion":"1.5",
            "metadata":{{"timestamp":"{now}"}},
            "components":[{{"type":"library","name":"a","version":"1.0"}}]}}"#
        );
        let sbom_ts = crate::parsers::parse_sbom_str(&cdx_ts).expect("parse");
        let prov_ts = ProvenanceMetrics::from_sbom(&sbom_ts);
        assert!(prov_ts.timestamp_known && prov_ts.is_fresh);

        // A FUTURE-dated document is known but must NOT read as fresh —
        // a bogus forward date is not "recently generated".
        let cdx_future = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
            "metadata":{"timestamp":"3999-01-01T00:00:00Z"},
            "components":[{"type":"library","name":"a","version":"1.0"}]}"#;
        let sbom_future = crate::parsers::parse_sbom_str(cdx_future).expect("parse");
        let prov_future = ProvenanceMetrics::from_sbom(&sbom_future);
        assert!(prov_future.timestamp_known);
        assert!(!prov_future.is_fresh, "future-dated must not be fresh");
    }
}
