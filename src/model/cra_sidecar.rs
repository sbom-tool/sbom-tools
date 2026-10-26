//! CRA Sidecar Metadata Support
//!
//! Allows loading additional CRA-required metadata from a sidecar file
//! when the SBOM doesn't contain this information.
//!
//! The sidecar file can be JSON or YAML and supplements the SBOM with:
//! - Security contact information
//! - Vulnerability disclosure URLs
//! - Support end dates
//! - Manufacturer details

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// CRA sidecar metadata that supplements SBOM information
///
/// `deny_unknown_fields` makes a typo'd key (e.g. snake_case
/// `security_contact` instead of `securityContact`) a load error instead of
/// silently deserializing to an all-`None` sidecar that then fails
/// compliance checks for the wrong reason.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CraSidecarMetadata {
    /// Security contact email or URL for vulnerability disclosure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_contact: Option<String>,

    /// URL for vulnerability disclosure policy/portal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_disclosure_url: Option<String>,

    /// End of support/security updates date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_end_date: Option<DateTime<Utc>>,

    /// Manufacturer/vendor name (supplements SBOM creator info)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_name: Option<String>,

    /// Manufacturer contact email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_email: Option<String>,

    /// Product name (supplements SBOM document name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,

    /// Product version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,

    /// CE marking declaration reference (URL or document ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ce_marking_reference: Option<String>,

    /// Security update delivery mechanism description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_mechanism: Option<String>,

    // -------- CRA Article 14 reporting-readiness fields (apply 2026-09-11) --------
    /// PSIRT (Product Security Incident Response Team) public URL.
    /// Required to handle external vulnerability reports under Annex I Part II
    /// and Art. 14 incident reporting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psirt_url: Option<String>,

    /// Channel (email, URL, phone) for the 24-hour early-warning notification
    /// to ENISA / CSIRT under CRA Art. 14(1) when an actively-exploited
    /// vulnerability is identified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_warning_contact: Option<String>,

    /// Channel for the 72-hour incident report under CRA Art. 14(2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident_report_contact: Option<String>,

    /// How the manufacturer reaches the ENISA Single Reporting Platform
    /// (Art. 14(7); live since 2026-09-11 at
    /// <https://portal.cra-srp.enisa.europa.eu/>). Naming the CSIRT
    /// designated as coordinator is enough: the one Art. 14(7) assigns by
    /// the manufacturer's main establishment and every notification selects
    /// on the platform. No registration on the platform is needed before a
    /// notification is due, and ENISA advises registering only then; a
    /// registration already made may be recorded instead. Free text; the
    /// platform publishes no machine-readable identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enisa_reporting_platform_id: Option<String>,

    /// Coordinated vulnerability disclosure policy URL.
    /// Distinct from `vulnerability_disclosure_url` (which may point at a
    /// portal) — this is the published *policy* that meets CRA Annex I
    /// Part II (5) / Art. 13(8) and ISO/IEC 29147 expectations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinated_disclosure_policy_url: Option<String>,

    // -------- CRA Article 13(2) risk-assessment fields --------
    /// URL or document reference for the documented risk assessment
    /// required by CRA Art. 13(2); Art. 13(4) requires it to be included
    /// in the Annex VII technical documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_assessment_url: Option<String>,

    /// Methodology used for the risk assessment (e.g.,
    /// "ISO/IEC 27005:2022", "NIST SP 800-30 r1", "ETSI TS 102 165-1 TVRA").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_assessment_methodology: Option<String>,

    // -------- CRA Annex III/IV product class & conformity-assessment route --------
    /// CRA product class drives the conformity-assessment route and the
    /// severity calibration of compliance checks (vendor-hash coverage,
    /// PSIRT, EUCC reference, attestation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_class: Option<CraProductClass>,

    /// Conformity-assessment route per CRA Annex VIII (Module A self-assessment,
    /// B+C EU-type examination, H full QA, or EUCC). Sidecar value wins over
    /// any CLI-provided default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformity_assessment_route: Option<ConformityRoute>,

    // -------- CRA Article 24 — open-source steward profile --------
    /// Whether this product is supplied by an open-source software steward
    /// (CRA Art. 24). When `true`, manufacturer-only obligations (DoC,
    /// notified-body attestation, manufacturer email) are not enforced;
    /// SBOM, vulnerability-handling, and CVD policy are still required.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_oss_steward: bool,

    // -------- Adjacent regulation overlap (CRA-P4.4) --------
    /// True if the manufacturer is a NIS2 essential entity (Annex I of
    /// Directive (EU) 2022/2555). Triggers Art. 23 incident-reporting
    /// guidance in the cra-docs dossier.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_nis2_essential_entity: bool,

    /// True if the manufacturer is a NIS2 important entity (Annex II of
    /// Directive (EU) 2022/2555).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_nis2_important_entity: bool,

    /// True when the product processes personal data (GDPR Art. 32
    /// security-of-processing applies in parallel to CRA Annex I).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub processes_personal_data: bool,

    /// True when the product is a high-risk AI system per the AI Act
    /// (Regulation (EU) 2024/1689). AI-Act conformity coordination must
    /// be handled alongside CRA Module assessment.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_high_risk_ai: bool,

    /// Date until which the Radio Equipment Directive (RED, Directive
    /// 2014/53/EU) cybersecurity provisions still apply for this product.
    /// CRA repeals RED Art. 3(3)(d/e/f) on 2025-08-01; older device
    /// inventories may carry RED references through their support
    /// horizon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub red_repealed_until: Option<DateTime<Utc>>,

    // -------- EUCC Substantial (CRA-P5.4 reference profile) --------
    /// Common Criteria Protection Profile identifier (e.g., "PP-CC-MFR-2024-01").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_protection_profile_id: Option<String>,

    /// Common Criteria Target of Evaluation reference (URL or document ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_target_of_evaluation: Option<String>,

    /// IT Security Evaluation Facility (ITSEF) identifier — the accredited
    /// laboratory that performed the EUCC evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_itsef_identifier: Option<String>,

    /// EUCC certificate valid-until date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eucc_valid_until: Option<DateTime<Utc>>,

    // -------- prEN 40000-1-2/1-4 controls-assertion (CRA-P5.5) --------
    /// Per-control assertions for CRA Annex I Part I, keyed by control ID
    /// (e.g., `"1.a"` through `"1.l"` for §1, `"2.a"` through `"2.m"` for
    /// §2 vulnerability-handling). Each entry records whether the
    /// manufacturer claims the control is satisfied, the evidence URL,
    /// and the methodology used.
    ///
    /// `BTreeMap` for deterministic ordering in dossier output.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annex_i_part_i_controls: BTreeMap<String, ControlAssertion>,
}

/// A manufacturer-supplied assertion that a specific Annex I Part I control
/// is satisfied. Surfaced verbatim in the cra-docs technical-documentation
/// dossier and cross-checked by `ComplianceChecker` (a control claimed
/// `satisfied = true` without an `evidence_url` is flagged as a Warning).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlAssertion {
    /// Whether the manufacturer claims this control is satisfied.
    #[serde(default)]
    pub satisfied: bool,
    /// URL pointing at the evidence document (test report, design review,
    /// SAST/DAST output, etc.). Required when `satisfied = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,
    /// Methodology / standard the assertion was made against
    /// (e.g., `"prEN 40000-1-2 §5.3"`, `"OWASP ASVS L2"`,
    /// `"NIST SP 800-53 SI-10"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methodology: Option<String>,
    /// Free-form notes from the manufacturer (rationale, caveats).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// CRA product class per Regulation (EU) 2024/2847 Annex III/IV. Commission
/// Implementing Regulation (EU) 2025/2392 (Art. 7(4)) gives the technical
/// description of each class's product categories: its Annex I for the
/// Annex III classes I and II, its Annex II for the Annex IV critical
/// products.
///
/// The class drives the conformity-assessment route and the severity
/// calibration of compliance checks (per CRA-P3.2 calibration table):
/// stricter classes upgrade Warning→Error and add EUCC / attestation
/// expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CraProductClass {
    /// Default — neither Annex III nor Annex IV. Module A self-assessment.
    #[serde(rename = "default")]
    Default,
    /// Annex III class I (19 categories, e.g. identity management systems,
    /// browsers, password managers, VPNs, operating systems, routers).
    /// Module A or B+C.
    #[serde(
        rename = "important-class-1",
        alias = "important1",
        alias = "ImportantClass1"
    )]
    ImportantClass1,
    /// Annex III class II (4 categories: hypervisors and container runtimes,
    /// firewalls and intrusion detection/prevention, tamper-resistant
    /// microprocessors and microcontrollers). Module B+C, H, or EUCC.
    #[serde(
        rename = "important-class-2",
        alias = "important2",
        alias = "ImportantClass2"
    )]
    ImportantClass2,
    /// Annex IV (critical: hardware devices with security boxes, smart
    /// meter gateways, smartcards and secure elements). EUCC mandatory.
    #[serde(rename = "critical")]
    Critical,
}

impl CraProductClass {
    /// Short label for compact display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::ImportantClass1 => "Important-1",
            Self::ImportantClass2 => "Important-2",
            Self::Critical => "Critical",
        }
    }

    /// Long human-readable name including Annex reference.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "Default (no Annex)",
            Self::ImportantClass1 => "Important Class I (Annex III, class I)",
            Self::ImportantClass2 => "Important Class II (Annex III, class II)",
            Self::Critical => "Critical (Annex IV)",
        }
    }

    /// Parse from the CLI-friendly kebab-case form. Accepts a few aliases.
    #[must_use]
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "default" | "none" => Some(Self::Default),
            "important-class-1" | "important-1" | "important1" | "annex-iii-1" => {
                Some(Self::ImportantClass1)
            }
            "important-class-2" | "important-2" | "important2" | "annex-iii-2" => {
                Some(Self::ImportantClass2)
            }
            "critical" | "annex-iv" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Strict variant of [`Self::parse_cli`]: an unrecognized spelling is an
    /// error naming the valid values instead of `None`.
    ///
    /// Used by the `--cra-product-class` CLI flags and the config-file
    /// validator so a typo can never be silently dropped (which would score
    /// the SBOM as `Default` class and flip CRA verdicts).
    ///
    /// # Errors
    /// Returns a message listing the valid canonical spellings when `s` is
    /// not a recognized product class.
    pub fn parse_cli_strict(s: &str) -> Result<Self, String> {
        Self::parse_cli(s).ok_or_else(|| {
            format!(
                "Invalid product class '{s}'. Valid options: \
                 default, important-class-1, important-class-2, critical"
            )
        })
    }

    /// The conformity-assessment route the regulation expects (or strictly
    /// requires) for this class. Manufacturers may choose a stricter route.
    #[must_use]
    pub const fn default_route(self) -> ConformityRoute {
        match self {
            Self::Default | Self::ImportantClass1 => ConformityRoute::ModuleA,
            Self::ImportantClass2 => ConformityRoute::ModuleBC,
            Self::Critical => ConformityRoute::Eucc,
        }
    }
}

/// Conformity-assessment module per CRA Annex VIII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ConformityRoute {
    /// Module A — internal control / self-assessment.
    ModuleA,
    /// Module B+C — EU-type examination plus production conformity.
    ModuleBC,
    /// Module H — full quality assurance.
    ModuleH,
    /// EUCC — Common Criteria via European Cybersecurity Certification scheme.
    Eucc,
}

impl ConformityRoute {
    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModuleA => "Module A",
            Self::ModuleBC => "Module B+C",
            Self::ModuleH => "Module H",
            Self::Eucc => "EUCC",
        }
    }

    /// Long descriptive name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ModuleA => "Module A — internal control (self-assessment)",
            Self::ModuleBC => "Module B+C — EU-type examination + production conformity",
            Self::ModuleH => "Module H — full quality assurance",
            Self::Eucc => "EUCC — Common Criteria via EU certification scheme",
        }
    }

    /// Parse from the CLI-friendly kebab-case form.
    #[must_use]
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "module-a" | "a" | "self-assessment" => Some(Self::ModuleA),
            "module-bc" | "module-b+c" | "module-b-c" | "bc" | "b+c" => Some(Self::ModuleBC),
            "module-h" | "h" => Some(Self::ModuleH),
            "eucc" | "common-criteria" => Some(Self::Eucc),
            _ => None,
        }
    }
}

/// Format a serde parse error for sidecar files. serde already names the
/// offending key on unknown-field errors; append a camelCase hint because the
/// most common mistake is writing SBOM-style snake_case keys.
fn sidecar_parse_error(e: &dyn std::fmt::Display) -> CraSidecarError {
    let msg = e.to_string();
    if msg.contains("unknown field") {
        CraSidecarError::ParseError(format!(
            "{msg}. Note: CRA sidecar keys use camelCase (e.g. `securityContact`, \
             not `security_contact`)"
        ))
    } else {
        CraSidecarError::ParseError(msg)
    }
}

impl CraSidecarMetadata {
    /// Load sidecar metadata from a JSON file
    pub fn from_json_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_json::from_str(&content).map_err(|e| sidecar_parse_error(&e))
    }

    /// Load sidecar metadata from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self, CraSidecarError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CraSidecarError::IoError(e.to_string()))?;
        serde_yaml_ng::from_str(&content).map_err(|e| sidecar_parse_error(&e))
    }

    /// Load sidecar metadata, auto-detecting format from extension
    pub fn from_file(path: &Path) -> Result<Self, CraSidecarError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "json" => Self::from_json_file(path),
            "yaml" | "yml" => Self::from_yaml_file(path),
            _ => Err(CraSidecarError::UnsupportedFormat(extension)),
        }
    }

    /// Try to find and load a sidecar file for the given SBOM path.
    ///
    /// Looks for `<stem>.cra.{json,yaml,yml}` and `<stem>-cra.{json,yaml,yml}`
    /// alongside the SBOM. Multi-extension stems (`app.cdx.json`,
    /// `app.spdx.json`, `app.spdx3.json`) also try the inner stem
    /// (`app.cra.json`) so the common SBOM naming conventions work
    /// without forcing operators to repeat the format suffix.
    ///
    /// Discovery is **strict**: once a candidate file exists, it must load.
    /// A broken discovered sidecar (typo'd field, bad YAML) is a hard error
    /// naming the file and field — exactly like an explicitly passed
    /// `--cra-sidecar` — instead of a stderr warning that silently shifts
    /// the compliance verdict.
    ///
    /// Stdin input (`-`) has no adjacent files, so it never resolves a
    /// sidecar (previously this probed a literal `-.cra.json`).
    pub fn discover_for_sbom(sbom_path: &Path) -> Result<Option<Self>, CraSidecarError> {
        // Stdin: no directory to discover in.
        if sbom_path.as_os_str() == "-" {
            return Ok(None);
        }
        let Some(parent) = sbom_path.parent() else {
            return Ok(None);
        };
        let Some(stem) = sbom_path.file_stem().and_then(|s| s.to_str()) else {
            return Ok(None);
        };

        // Build the list of stems to try. Strip well-known SBOM format
        // suffixes (`.cdx`, `.spdx`, `.spdx3`, `.cyclonedx`) so e.g.
        // `app.cdx.json` looks for `app.cra.json` as well as
        // `app.cdx.cra.json`.
        let mut stems: Vec<&str> = vec![stem];
        for suffix in [".cdx", ".cyclonedx", ".spdx", ".spdx3"] {
            if let Some(inner) = stem.strip_suffix(suffix)
                && !inner.is_empty()
            {
                stems.push(inner);
            }
        }

        for s in &stems {
            for pattern in [
                format!("{s}.cra.json"),
                format!("{s}.cra.yaml"),
                format!("{s}.cra.yml"),
                format!("{s}-cra.json"),
                format!("{s}-cra.yaml"),
                format!("{s}-cra.yml"),
            ] {
                let sidecar_path = parent.join(&pattern);
                if sidecar_path.exists() {
                    // First existing candidate is authoritative: it either
                    // loads or the command fails naming the broken file.
                    return Self::from_file(&sidecar_path)
                        .map(Some)
                        .map_err(|e| e.with_path(&sidecar_path));
                }
            }
        }

        Ok(None)
    }

    /// Lenient wrapper around [`Self::discover_for_sbom`] that downgrades a
    /// broken discovered sidecar to a warning.
    ///
    /// Transitional: call sites should migrate to [`Self::discover_for_sbom`]
    /// so a broken sidecar aborts the command instead of silently shifting
    /// the verdict; this wrapper only exists to keep the old signature alive
    /// until they do.
    #[must_use]
    pub fn find_for_sbom(sbom_path: &Path) -> Option<Self> {
        match Self::discover_for_sbom(sbom_path) {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!("Ignoring auto-discovered CRA sidecar: {e}");
                None
            }
        }
    }

    /// Whether the sidecar carries live EUCC evidence: a non-empty
    /// Protection-Profile / Target-of-Evaluation / ITSEF identifier, or a
    /// certificate validity date that has not expired — and no validity
    /// date that has. Empty strings and expired certificates must not
    /// satisfy the Critical-class Annex IV gate (mirrors the dedicated EUCC
    /// profile, which reports an expired certificate as an Error): the
    /// identifiers of an expired certificate describe one that no longer
    /// holds.
    #[must_use]
    pub fn has_live_eucc_evidence(&self) -> bool {
        self.has_live_eucc_evidence_at(Utc::now())
    }

    /// [`Self::has_live_eucc_evidence`] against a pinned evaluation instant
    /// (reproducible compliance runs; see `ComplianceChecker::with_as_of`).
    #[must_use]
    pub fn has_live_eucc_evidence_at(&self, now: DateTime<Utc>) -> bool {
        if self.eucc_valid_until.is_some_and(|d| d <= now) {
            return false;
        }
        let live = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
        live(&self.eucc_protection_profile_id)
            || live(&self.eucc_target_of_evaluation)
            || live(&self.eucc_itsef_identifier)
            || self.eucc_valid_until.is_some()
    }

    /// Check if any CRA-relevant fields are populated
    #[must_use]
    pub fn has_cra_data(&self) -> bool {
        self.security_contact.is_some()
            || self.vulnerability_disclosure_url.is_some()
            || self.support_end_date.is_some()
            || self.manufacturer_name.is_some()
            || self.ce_marking_reference.is_some()
            || self.psirt_url.is_some()
            || self.early_warning_contact.is_some()
            || self.incident_report_contact.is_some()
            || self.enisa_reporting_platform_id.is_some()
            || self.coordinated_disclosure_policy_url.is_some()
            || self.risk_assessment_url.is_some()
            || self.risk_assessment_methodology.is_some()
            || self.product_class.is_some()
            || self.conformity_assessment_route.is_some()
            || self.is_oss_steward
            || self.is_nis2_essential_entity
            || self.is_nis2_important_entity
            || self.processes_personal_data
            || self.is_high_risk_ai
            || self.red_repealed_until.is_some()
            || self.eucc_protection_profile_id.is_some()
            || self.eucc_target_of_evaluation.is_some()
            || self.eucc_itsef_identifier.is_some()
            || self.eucc_valid_until.is_some()
            || !self.annex_i_part_i_controls.is_empty()
    }

    /// Generate an example sidecar file content
    #[must_use]
    pub fn example_json() -> String {
        let example = Self {
            security_contact: Some("security@example.com".to_string()),
            vulnerability_disclosure_url: Some("https://example.com/security".to_string()),
            support_end_date: Some(Utc::now() + chrono::Duration::days(365 * 2)),
            manufacturer_name: Some("Example Corp".to_string()),
            manufacturer_email: Some("contact@example.com".to_string()),
            product_name: Some("Example Product".to_string()),
            product_version: Some("1.0.0".to_string()),
            ce_marking_reference: Some("EU-DoC-2024-001".to_string()),
            update_mechanism: Some("Automatic OTA updates via secure channel".to_string()),
            psirt_url: Some("https://example.com/psirt".to_string()),
            early_warning_contact: Some("psirt@example.com".to_string()),
            incident_report_contact: Some("incidents@example.com".to_string()),
            enisa_reporting_platform_id: Some("EU-MFR-12345".to_string()),
            coordinated_disclosure_policy_url: Some(
                "https://example.com/security/cvd-policy".to_string(),
            ),
            risk_assessment_url: Some(
                "https://example.com/docs/risk-assessment-2026.pdf".to_string(),
            ),
            risk_assessment_methodology: Some("ISO/IEC 27005:2022".to_string()),
            product_class: Some(CraProductClass::ImportantClass1),
            conformity_assessment_route: Some(ConformityRoute::ModuleA),
            is_oss_steward: false,
            is_nis2_essential_entity: false,
            is_nis2_important_entity: false,
            processes_personal_data: false,
            is_high_risk_ai: false,
            red_repealed_until: None,
            eucc_protection_profile_id: None,
            eucc_target_of_evaluation: None,
            eucc_itsef_identifier: None,
            eucc_valid_until: None,
            annex_i_part_i_controls: BTreeMap::new(),
        };
        serde_json::to_string_pretty(&example).unwrap_or_default()
    }
}

/// Errors that can occur when loading sidecar metadata
#[derive(Debug)]
pub enum CraSidecarError {
    IoError(String),
    ParseError(String),
    UnsupportedFormat(String),
}

impl std::fmt::Display for CraSidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error reading sidecar file: {e}"),
            Self::ParseError(e) => write!(f, "Parse error in sidecar file: {e}"),
            Self::UnsupportedFormat(ext) => {
                write!(f, "Unsupported sidecar file format: .{ext}")
            }
        }
    }
}

impl std::error::Error for CraSidecarError {}

impl CraSidecarError {
    /// Prefix the error message with the sidecar path so discovery errors
    /// name the exact file that failed (serde already names the field).
    #[must_use]
    pub fn with_path(self, path: &Path) -> Self {
        let p = path.display();
        match self {
            Self::IoError(e) => Self::IoError(format!("{p}: {e}")),
            Self::ParseError(e) => Self::ParseError(format!("{p}: {e}")),
            Self::UnsupportedFormat(e) => Self::UnsupportedFormat(format!("{e} ({p})")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_has_no_data() {
        let sidecar = CraSidecarMetadata::default();
        assert!(!sidecar.has_cra_data());
    }

    #[test]
    fn test_has_cra_data_with_contact() {
        let sidecar = CraSidecarMetadata {
            security_contact: Some("security@example.com".to_string()),
            ..Default::default()
        };
        assert!(sidecar.has_cra_data());
    }

    #[test]
    fn test_example_json_is_valid() {
        let json = CraSidecarMetadata::example_json();
        let parsed: Result<CraSidecarMetadata, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_json_roundtrip() {
        let original = CraSidecarMetadata {
            security_contact: Some("test@example.com".to_string()),
            support_end_date: Some(Utc::now()),
            ..Default::default()
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CraSidecarMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(original.security_contact, parsed.security_contact);
    }

    #[test]
    fn unknown_field_is_rejected_not_silently_dropped() {
        // A snake_case typo used to deserialize to an all-None sidecar; it
        // must now fail, and the error must name the offending key.
        let json = r#"{"security_contact": "security@example.com"}"#;
        let err = serde_json::from_str::<CraSidecarMetadata>(json).unwrap_err();
        assert!(
            err.to_string().contains("security_contact"),
            "error must name the offending key: {err}"
        );
    }

    #[test]
    fn from_file_unknown_field_error_names_key_and_hints_camel_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typo.cra.json");
        std::fs::write(&path, r#"{"security_contact": "security@example.com"}"#).unwrap();
        let err = CraSidecarMetadata::from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("security_contact"),
            "error must name the offending key: {msg}"
        );
        assert!(
            msg.contains("camelCase") && msg.contains("securityContact"),
            "error must hint at camelCase keys: {msg}"
        );
    }

    #[test]
    fn from_yaml_file_unknown_field_is_rejected_with_hint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typo.cra.yaml");
        std::fs::write(&path, "manufacturer_name: ExampleCorp\n").unwrap();
        let err = CraSidecarMetadata::from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("manufacturer_name"), "{msg}");
        assert!(msg.contains("camelCase"), "{msg}");
    }

    #[test]
    fn known_camel_case_fields_still_deserialize() {
        let json = r#"{
            "securityContact": "security@example.com",
            "productClass": "critical",
            "isOssSteward": true,
            "annexIPartIControls": {
                "1.a": { "satisfied": true, "evidenceUrl": "https://example.com/e" }
            }
        }"#;
        let sidecar: CraSidecarMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(
            sidecar.security_contact.as_deref(),
            Some("security@example.com")
        );
        assert_eq!(sidecar.product_class, Some(CraProductClass::Critical));
        assert!(sidecar.is_oss_steward);
        assert!(sidecar.annex_i_part_i_controls["1.a"].satisfied);
    }

    #[test]
    fn discover_for_sbom_hard_fails_on_broken_candidate_naming_file_and_field() {
        // Strict discovery: a broken adjacent sidecar is a hard error that
        // names the file and the offending field — the same treatment an
        // explicit --cra-sidecar gets — never a silent verdict shift.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(&sbom_path, "{}").unwrap();
        std::fs::write(
            dir.path().join("app.cra.json"),
            r#"{"security_contact": "typo"}"#,
        )
        .unwrap();
        let err = CraSidecarMetadata::discover_for_sbom(&sbom_path)
            .expect_err("broken discovered sidecar must hard-error");
        let msg = err.to_string();
        assert!(msg.contains("app.cra.json"), "must name the file: {msg}");
        assert!(
            msg.contains("security_contact"),
            "must name the field: {msg}"
        );

        // The transitional lenient wrapper still downgrades to None.
        assert!(CraSidecarMetadata::find_for_sbom(&sbom_path).is_none());
    }

    #[test]
    fn discover_for_sbom_skips_stdin() {
        // Stdin input previously probed a literal `-.cra.json` in the cwd.
        assert!(
            CraSidecarMetadata::discover_for_sbom(Path::new("-"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn discover_for_sbom_finds_hyphen_yml_variant() {
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(&sbom_path, "{}").unwrap();
        std::fs::write(
            dir.path().join("app-cra.yml"),
            "securityContact: sec@example.com\n",
        )
        .unwrap();
        let found = CraSidecarMetadata::discover_for_sbom(&sbom_path)
            .unwrap()
            .expect("hyphen .yml sidecar must be discovered");
        assert_eq!(found.security_contact.as_deref(), Some("sec@example.com"));
    }

    #[test]
    fn discover_for_sbom_loads_valid_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(&sbom_path, "{}").unwrap();
        std::fs::write(
            dir.path().join("app.cra.json"),
            r#"{"securityContact": "sec@example.com"}"#,
        )
        .unwrap();
        let found = CraSidecarMetadata::discover_for_sbom(&sbom_path)
            .unwrap()
            .expect("valid sidecar must be discovered");
        assert_eq!(found.security_contact.as_deref(), Some("sec@example.com"));
    }

    #[test]
    fn product_class_parse_cli_accepts_aliases() {
        assert_eq!(
            CraProductClass::parse_cli("default"),
            Some(CraProductClass::Default)
        );
        assert_eq!(
            CraProductClass::parse_cli("important-class-1"),
            Some(CraProductClass::ImportantClass1)
        );
        assert_eq!(
            CraProductClass::parse_cli("important-2"),
            Some(CraProductClass::ImportantClass2)
        );
        assert_eq!(
            CraProductClass::parse_cli("CRITICAL"),
            Some(CraProductClass::Critical)
        );
        assert_eq!(CraProductClass::parse_cli("nonsense"), None);
    }

    #[test]
    fn product_class_default_route_matches_regulation() {
        assert_eq!(
            CraProductClass::Default.default_route(),
            ConformityRoute::ModuleA
        );
        assert_eq!(
            CraProductClass::ImportantClass1.default_route(),
            ConformityRoute::ModuleA
        );
        assert_eq!(
            CraProductClass::ImportantClass2.default_route(),
            ConformityRoute::ModuleBC
        );
        assert_eq!(
            CraProductClass::Critical.default_route(),
            ConformityRoute::Eucc
        );
    }

    #[test]
    fn product_class_serde_kebab_case() {
        let json = serde_json::to_string(&CraProductClass::ImportantClass1).unwrap();
        assert_eq!(json, "\"important-class-1\"");
        let parsed: CraProductClass = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(parsed, CraProductClass::Critical);
    }

    #[test]
    fn conformity_route_parse_cli_accepts_aliases() {
        assert_eq!(
            ConformityRoute::parse_cli("module-a"),
            Some(ConformityRoute::ModuleA)
        );
        assert_eq!(
            ConformityRoute::parse_cli("B+C"),
            Some(ConformityRoute::ModuleBC)
        );
        assert_eq!(
            ConformityRoute::parse_cli("Module-H"),
            Some(ConformityRoute::ModuleH)
        );
        assert_eq!(
            ConformityRoute::parse_cli("EUCC"),
            Some(ConformityRoute::Eucc)
        );
        assert_eq!(ConformityRoute::parse_cli("module-z"), None);
    }

    /// Live EUCC evidence: a non-blank identifier or an unexpired validity
    /// date, and never an expired one — an expired certificate voids the
    /// identifiers that describe it.
    #[test]
    fn live_eucc_evidence_requires_an_unexpired_certificate() {
        let now = DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&Utc);
        let day = chrono::Duration::days(1);
        let sidecar = |pp: Option<&str>, valid_until: Option<DateTime<Utc>>| CraSidecarMetadata {
            eucc_protection_profile_id: pp.map(str::to_string),
            eucc_valid_until: valid_until,
            ..CraSidecarMetadata::default()
        };
        let cases = [
            (sidecar(None, None), false, "nothing declared"),
            (sidecar(Some(" "), None), false, "blank identifier"),
            (sidecar(Some("PP-01"), None), true, "identifier, no date"),
            (sidecar(None, Some(now + day)), true, "unexpired date alone"),
            (
                sidecar(Some("PP-01"), Some(now + day)),
                true,
                "identifier, unexpired",
            ),
            (sidecar(None, Some(now - day)), false, "expired date alone"),
            (
                sidecar(Some("PP-01"), Some(now - day)),
                false,
                "identifier, expired",
            ),
            (
                sidecar(Some("PP-01"), Some(now)),
                false,
                "identifier, expiring now",
            ),
        ];
        for (sidecar, live, label) in cases {
            assert_eq!(sidecar.has_live_eucc_evidence_at(now), live, "{label}");
        }
    }
}
