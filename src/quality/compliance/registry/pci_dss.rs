//! The rules of the PCI DSS v4.0.1 Req. 6.3.2 profile.

use super::*;

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
        "SBOM-PCI-6-3-2-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-INVENTORY",
            name: "PciDssInventory",
            short_description: "PCI DSS Req. 6.3.2: SBOM is a non-empty inventory with a resolvable primary component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "The SBOM must inventory at least one component and identify the bespoke/custom application it describes as its primary component. An empty or headless document cannot serve as the Req. 6.3.2 inventory.",
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-PCI-6-3-2-NAME" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-NAME",
            name: "PciDssComponentName",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Name every inventoried component — an unnamed entry cannot be correlated with vendor advisories or patches. File/snippet inventory records are exempt, so a file-cataloguing SBOM does not auto-fail the profile.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-PCI-6-3-2-VERSION" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VERSION",
            name: "PciDssComponentVersion",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a concrete version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Declare a concrete release version for every inventoried component (a version range is acceptable only for external components) — patch management, the requirement's stated purpose, is impossible without versions. File/snippet inventory records are exempt.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-PCI-6-3-2-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-SUPPLIER",
            name: "PciDssComponentSupplier",
            short_description: "PCI DSS Req. 6.3.2: third-party components identify their supplier/source",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Identify each third-party component's supplier, or fall back to author / group / ecosystem-bearing PURL evidence, so vendor security-patch availability can be monitored.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-PCI-6-3-2-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-IDENTIFIER",
            name: "PciDssComponentIdentifier",
            short_description: "PCI DSS Req. 6.3.2: components carry a stable unique identifier for vulnerability correlation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Add a stable unique identifier (PURL preferred, else CPE/SWID) so the inventory can be machine-correlated with vulnerability sources per the 'facilitate vulnerability and patch management' clause. PCI DSS prescribes no identifier scheme — this is enabling evidence, not a mandated field.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-PCI-6-3-2-THIRD-PARTY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-THIRD-PARTY",
            name: "PciDssThirdPartyComponents",
            short_description: "PCI DSS TP 6.3.2.b: inventory enumerates incorporated third-party components, not just the application",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "Enumerate the third-party components incorporated into the bespoke/custom software, not only the application itself; a primary-only SBOM passes only when its completeness declaration is Complete (a genuinely dependency-free application). This is an inference — TP 6.3.2.b's real comparison against the software is assessor work.",
            advice: None,
        },
        "SBOM-PCI-6-3-2-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-COMPLETENESS",
            name: "PciDssCompleteness",
            short_description: "PCI DSS TP 6.3.2.b: completeness declaration — self-declared inventory gaps flagged",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "TP 6.3.2.b")],
            remediation: "Declare the inventory Complete. Explicit Incomplete* declarations warn as self-declared gaps against TP 6.3.2.b; Unknown (no declaration made / explicitly unknown) and NotSpecified (declared but unrecognized, or a no-assertion value) are informational.",
            advice: Some(&ADVICE_COMPLETENESS),
        },
        "SBOM-PCI-6-3-2-FRESHNESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-FRESHNESS",
            name: "PciDssFreshness",
            short_description: "PCI DSS Req. 6.3.2: 'is maintained' — the SBOM carries a creation timestamp",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Carry a creation timestamp so the inventory's maintenance can be evidenced. The SBOM proves generation time, not the inventory process — a stale timestamp is advisory only. A timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-PCI-6-3-2-VULN-EVIDENCE" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VULN-EVIDENCE",
            name: "PciDssVulnerabilityEvidence",
            short_description: "PCI DSS TP 6.3.2.a: vulnerability-management hooks (embedded data, advisory refs, or security contact)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::PciDss4, "TP 6.3.2.a")],
            remediation: "Surface vulnerability-management hooks: embedded vulnerability entries, an Advisories / vulnerability-assertion / linked-VDR external reference, a security contact, or a disclosure URL. A contact must reach someone: placeholders such as NOASSERTION or n/a, and addresses at example.com, example.net or example.org, do not count. Absence is not a Req. 6.3.2 failure — the inventory may feed an external scanner; actual use of the inventory is assessor-verified.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-PCI-11-3-1-1-SEVERITY" => RuleMeta {
            sarif_id: "SBOM-PCI-11-3-1-1-SEVERITY",
            name: "PciDssVulnerabilityRiskRanking",
            short_description: "PCI DSS Req. 6.3.1 / 11.3.1.1: embedded vulnerability entries carry a risk ranking",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 11.3.1.1"), (K::PciDss4, "Req. 6.3.1")],
            remediation: "Give every embedded vulnerability entry a risk ranking — a Critical/High/Medium/Low severity or a CVSS score (an entry with only Info/None/Unknown severity and no CVSS is unranked) — so non-high-risk findings can be managed per the entity's Req. 6.3.1 rankings and the 11.3.1.1 targeted risk analysis. A vulnerability whose own VEX statement is not_affected and names a justification needs no ranking and is not counted, as under the CRA and FDA profiles: it does not apply to the product. A bare not_affected claim still needs one. Emitted only when vulnerability data is present (no vacuous pass/fail).",
            advice: Some(&ADVICE_VULN_SEVERITY),
        },
        // Generic bucket for PCI-DSS-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PCI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PCI-GENERAL",
            name: "PciDssGeneralRequirement",
            short_description: "PCI DSS v4.0.1 Req. 6.3.2: general software-inventory requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Catch-all for PCI DSS Req. 6.3.2 findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Make the SBOM a usable inventory: identify the bespoke application as the primary component, and give every component a name, version, supplier and unique identifier.",
            advice: None,
        },
        _ => return None,
    };
    Some(meta)
}
