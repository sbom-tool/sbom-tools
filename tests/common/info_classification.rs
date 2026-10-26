//! The reviewed classification of every rule that reports at Info.
//!
//! A check that affirms what the SBOM gets right is a passed check
//! (`PASS_RULE_IDS`, reported in `ComplianceResult::passed`); a check that
//! reports a gap or gives advice stays a violation even at Info. Every rule
//! that can report an Info violation is listed here with the reason it stays
//! one, so a new Info emission has to be classified before it ships:
//! `tests/compliance_passes_tests.rs` holds the registry and the fixture
//! corpus to this list, and `run_matrix` (tests/common/rule_matrix.rs) every
//! matrix fixture.

// Each test binary uses a subset of these helpers.
#![allow(dead_code)]

/// Rules that report Info violations, with why each stays a violation
/// rather than a pass: a gap the SBOM should close, or advice on an element
/// it could improve. Rules whose Info is a context-dependent level of a
/// stronger default say when they are Info.
pub const INFO_FINDINGS: &[(&str, &str)] = &[
    // ── CRA: elements the SBOM lacks ─────────────────────────────────────
    (
        "SBOM-CRA-ART-13-5",
        "gap: up to half the components lack licence information (Warning above half)",
    ),
    (
        "SBOM-CRA-ART-13-5-PROFILE",
        "gap: SPDX 3.0 licence data without SimpleLicensing profile conformance",
    ),
    (
        "SBOM-CRA-ART-13-8",
        "gap: no support end date for security updates",
    ),
    (
        "SBOM-CRA-LIFECYCLE",
        "gap: no component lifecycle or end-of-support evidence",
    ),
    (
        "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
        "advice: components reach end-of-life within six months",
    ),
    (
        "SBOM-CRA-VULN-STATEMENT",
        "gap: no vulnerability data and no statement of no known vulnerabilities",
    ),
    (
        "SBOM-CRA-VULN-METADATA-REMEDIATION",
        "gap: a remediation gives neither a fixed version nor a description",
    ),
    (
        "SBOM-CRA-VULN-METADATA-PROFILE",
        "gap: SPDX 3.0 vulnerabilities without Security profile conformance",
    ),
    (
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
        "gap: transitive dependencies without a supplier (Warning in Phase 2 above 30%)",
    ),
    (
        "SBOM-CRA-ANNEX-I-INTEGRITY",
        "gap: a component carries no cryptographic hash",
    ),
    (
        "SBOM-CRA-DOC-INTEGRITY",
        "gap: no document-level integrity metadata",
    ),
    (
        "SBOM-CRA-ANNEX-IV",
        "gap: no EUCC reference for an important-class-II product (Error for critical)",
    ),
    (
        "SBOM-CRA-ANNEX-V",
        "gap: no EU Declaration of Conformity reference (Info for the default class, escalated by class)",
    ),
    (
        "SBOM-CRA-ART-14-ENISA",
        "gap: no ENISA single reporting platform identifier",
    ),
    (
        "SBOM-CRA-ART-14-PSIRT",
        "gap: no PSIRT channel; Info only before the 2026-09-11 Art. 14 deadline",
    ),
    (
        "SBOM-CRA-ART-14-EARLY-WARNING",
        "gap: no 24-hour early-warning channel; Info only before the 2026-09-11 deadline",
    ),
    (
        "SBOM-CRA-ART-14-NOTIFICATION",
        "gap: no 72-hour notification channel; Info only before the 2026-09-11 deadline",
    ),
    (
        "SBOM-CRA-SBOM-FRESHNESS",
        "advice: the SBOM is 31-90 days old, regenerate after component changes (Warning beyond)",
    ),
    // ── CRA: elements only the CRA sidecar supplies ──────────────────────
    (
        "SBOM-CRA-ART-13-16",
        "advice: the manufacturer is named only in the CRA sidecar; the SBOM should name it (Warning when neither does)",
    ),
    (
        "SBOM-CRA-ART-13-15-PRODUCT",
        "advice: the product name comes only from the CRA sidecar; the SBOM should carry it (Warning when neither does)",
    ),
    (
        "SBOM-CRA-ART-13-17-CONTACT",
        "advice: the security contact comes only from the CRA sidecar; the SBOM should reference it (Warning when neither does)",
    ),
    (
        "SBOM-CRA-CVD-POLICY",
        "advice: the CVD policy URL comes only from the CRA sidecar; the SBOM should reference it (Warning when neither does)",
    ),
    // ── Generic path: format conformance ─────────────────────────────────
    (
        "SBOM-QUALITY-ELEMENT-ID",
        "gap: a component's bom-ref or SPDX identifier is missing or malformed",
    ),
    (
        "SBOM-NTIA-ELEMENT-ID",
        "gap: a component's bom-ref or SPDX identifier is missing or malformed",
    ),
    (
        "SBOM-CRA-ELEMENT-ID",
        "gap: a component's bom-ref or SPDX identifier is missing or malformed",
    ),
    (
        "SBOM-FDA-ELEMENT-ID",
        "gap: a component's bom-ref or SPDX identifier is missing or malformed",
    ),
    (
        "SBOM-QUALITY-SPEC-VERSION",
        "advice: CycloneDX older than 1.4 is outdated (Warning when newer than sbom-tools reads)",
    ),
    (
        "SBOM-NTIA-SPEC-VERSION",
        "advice: CycloneDX older than 1.4 is outdated (Warning when newer than sbom-tools reads)",
    ),
    (
        "SBOM-CRA-SPEC-VERSION",
        "advice: CycloneDX older than 1.4 is outdated (Warning when newer than sbom-tools reads)",
    ),
    (
        "SBOM-FDA-SPEC-VERSION",
        "advice: CycloneDX older than 1.4 is outdated (Warning when newer than sbom-tools reads)",
    ),
    // ── NIST SSDF ────────────────────────────────────────────────────────
    (
        "SBOM-SSDF-PO3",
        "gap: no build metadata reference or PO.3 attestation",
    ),
    (
        "SBOM-SSDF-PW6",
        "gap: no vulnerability data, advisory reference or PW.6 attestation",
    ),
    // ── PCI DSS 6.3.2 ────────────────────────────────────────────────────
    (
        "SBOM-PCI-6-3-2-COMPLETENESS",
        "gap: no completeness declaration, or an unrecognized one (Warning for a declared gap)",
    ),
    (
        "SBOM-PCI-6-3-2-FRESHNESS",
        "advice: the SBOM is older than the 365-day tool-policy threshold (Warning without a timestamp)",
    ),
    (
        "SBOM-PCI-6-3-2-VULN-EVIDENCE",
        "gap: no vulnerability-management hook",
    ),
    // ── CISA FSCT aspirational goals ─────────────────────────────────────
    ("SBOM-FSCT-SBOM-TYPE", "gap: the SBOM type is not declared"),
    (
        "SBOM-FSCT-DYNAMIC-DEPS",
        "gap: no dynamic, runtime or provided dependency relationship",
    ),
    (
        "SBOM-FSCT-LICENSE-ALL",
        "gap: components without licence information",
    ),
    (
        "SBOM-FSCT-LICENSE-CONCLUDED",
        "gap: no concluded-licence attestation",
    ),
    (
        "SBOM-FSCT-COPYRIGHT-ALL",
        "gap: components without a copyright notice",
    ),
    (
        "SBOM-FSCT-SIGNATURE",
        "gap: no verifiable digital signature",
    ),
    // ── EU AI Act readiness ──────────────────────────────────────────────
    (
        "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
        "gap: no model declares its training energy",
    ),
    (
        "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
        "gap: models state no limitations (Error for a high-risk system)",
    ),
    (
        "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
        "advice: training data involves personal data; document the GDPR interaction (Warning for a high-risk system)",
    ),
    // ── BSI/G7 SBOM-for-AI readiness ─────────────────────────────────────
    ("SBOM-BSIAI-META-SIGNATURE", "gap: no document signature"),
    (
        "SBOM-BSIAI-SYS-DATAFLOW",
        "gap: no AI-system data-flow description (no SBOM field carries one)",
    ),
    (
        "SBOM-BSIAI-INFRA-RUNTIME",
        "gap: no ML component links to its runtime or framework",
    ),
    (
        "SBOM-BSIAI-SEC-CONTROLS",
        "gap: no AI-specific security controls declared (no SBOM field carries them)",
    ),
    (
        "SBOM-BSIAI-SEC-EXPLOITABILITY",
        "gap: no exploitability reference declared (no SBOM field carries one)",
    ),
];

/// Why `rule_id` reports Info violations, if it is classified.
pub fn info_finding_reason(rule_id: &str) -> Option<&'static str> {
    INFO_FINDINGS
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, reason)| *reason)
}
