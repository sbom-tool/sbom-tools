//! `cra-docs` command handler.
//!
//! Generates a CRA technical-documentation dossier (Annex V templates)
//! prefilled from the SBOM and an optional CRA sidecar. Output is a
//! directory containing three Markdown files that a notified body or
//! auditor can use as a starting point:
//!
//! - `eu-declaration-of-conformity.md` — Annex V Declaration of Conformity
//! - `technical-documentation.md`      — Annex V technical-documentation summary
//! - `vulnerability-handling-policy.md` — Annex I Part II policy stub
//!
//! Fields the SBOM/sidecar can supply are filled in; everything else is
//! left as `_TBD_` so the operator can complete the document by hand.

use crate::model::{ConformityRoute, CraProductClass, CraSidecarMetadata, NormalizedSbom};
use crate::pipeline::parse_sbom_with_context;
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Run the `cra-docs` command. Generates 3 Markdown files in `output_dir`.
#[allow(clippy::needless_pass_by_value)]
pub fn run_cra_docs(
    sbom_path: PathBuf,
    output_dir: PathBuf,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
) -> Result<()> {
    let parsed = parse_sbom_with_context(&sbom_path, false)?;
    let sbom = parsed.sbom();

    // Sidecar resolution: explicit path → auto-discover.
    let sidecar = match cra_sidecar_path {
        Some(p) => Some(CraSidecarMetadata::from_file(&p).map_err(|e| {
            anyhow::anyhow!("Failed to load CRA sidecar from {}: {e}", p.display())
        })?),
        None => CraSidecarMetadata::find_for_sbom(&sbom_path),
    };

    // Effective product class: sidecar wins, else CLI flag, else Default.
    let cli_class = cra_product_class
        .as_deref()
        .and_then(CraProductClass::parse_cli);
    let sidecar_class = sidecar.as_ref().and_then(|s| s.product_class);
    if let (Some(cli), Some(side)) = (cli_class, sidecar_class)
        && cli != side
    {
        tracing::warn!(
            "CRA product class mismatch: --cra-product-class={} but sidecar says {}; using sidecar.",
            cli.label(),
            side.label()
        );
    }
    let effective_class = sidecar_class
        .or(cli_class)
        .unwrap_or(CraProductClass::Default);

    // Build a compliance result so the dossier can summarise readiness.
    let mut checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
    if let Some(sc) = sidecar.clone() {
        checker = checker.with_sidecar(sc);
    }
    checker = checker.with_product_class(effective_class);
    let compliance = checker.check(sbom);
    let route = checker.effective_route();

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("creating output directory {}", output_dir.display()))?;

    write_doc(
        &output_dir.join("eu-declaration-of-conformity.md"),
        &render_doc(sbom, sidecar.as_ref(), effective_class, route),
    )?;
    write_doc(
        &output_dir.join("technical-documentation.md"),
        &render_tech_doc(sbom, sidecar.as_ref(), effective_class, route, &compliance),
    )?;
    write_doc(
        &output_dir.join("vulnerability-handling-policy.md"),
        &render_vuln_policy(sbom, sidecar.as_ref()),
    )?;

    println!(
        "CRA dossier written to {} ({} files)",
        output_dir.display(),
        3
    );
    Ok(())
}

fn write_doc(path: &std::path::Path, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

/// Render the EU Declaration of Conformity (Annex V) template.
fn render_doc(
    sbom: &NormalizedSbom,
    sidecar: Option<&CraSidecarMetadata>,
    class: CraProductClass,
    route: ConformityRoute,
) -> String {
    let manufacturer = sidecar
        .and_then(|s| s.manufacturer_name.as_deref())
        .or_else(|| {
            sbom.document
                .creators
                .iter()
                .find(|c| matches!(c.creator_type, crate::model::CreatorType::Organization))
                .map(|c| c.name.as_str())
        })
        .unwrap_or("_TBD: manufacturer name_");
    let manufacturer_email = sidecar
        .and_then(|s| s.manufacturer_email.as_deref())
        .unwrap_or("_TBD: manufacturer email_");
    let product_name = sidecar
        .and_then(|s| s.product_name.as_deref())
        .or(sbom.document.name.as_deref())
        .unwrap_or("_TBD: product name_");
    let product_version = sidecar
        .and_then(|s| s.product_version.as_deref())
        .unwrap_or("_TBD: product version_");
    let ce_marking = sidecar
        .and_then(|s| s.ce_marking_reference.as_deref())
        .unwrap_or("_TBD: CE marking reference / DoC document ID_");

    // §6 "other Union legislation". When the sidecar flags the product as a
    // high-risk AI system, name the AI Act explicitly and point the operator at
    // the Annex IV technical-documentation readiness check; otherwise keep the
    // hand-completable placeholder.
    let other_legislation = if sidecar.is_some_and(|s| s.is_high_risk_ai) {
        "- Regulation (EU) 2024/1689 (AI Act) — high-risk AI system: \
         draw up Annex IV technical documentation. Run \
         `sbom-tools validate <sbom> --standard ai-act --cra-sidecar <sidecar>` \
         for an Annex IV documentation-readiness check (readiness only, not a \
         legal-conformity guarantee).\n\
         - _TBD: list any other applicable EU regulations (NIS2, GDPR, …)_"
    } else {
        "- _TBD: list any other applicable EU regulations (NIS2, GDPR, AI Act, …)_"
    };

    format!(
        "# EU Declaration of Conformity (Cyber Resilience Act, Annex V)\n\n\
         > **Generated by sbom-tools cra-docs.** Review and complete the `_TBD_` \
         placeholders before relying on this document for conformity assessment.\n\n\
         **1. Product**\n\
         - Name: {product_name}\n\
         - Version: {product_version}\n\
         - CE marking / DoC reference: {ce_marking}\n\
         - CRA product class: {class_name}\n\n\
         **2. Manufacturer**\n\
         - Name: {manufacturer}\n\
         - Contact: {manufacturer_email}\n\
         - Address: _TBD: registered office address_\n\n\
         **3. Conformity-assessment route (CRA Annex VIII)**\n\
         - Route: {route_name}\n\
         - Notified body (if applicable): _TBD: notified body name + 4-digit number_\n\
         - Certificate / attestation reference: _TBD_\n\n\
         **4. Applicable CRA requirements**\n\
         - Regulation (EU) 2024/2847 — Annex I (Essential cybersecurity requirements)\n\
         - Annex I Part I (1) — Cybersecurity properties of products with digital elements\n\
         - Annex I Part I (2) — Vulnerability-handling requirements\n\
         - Annex II — Information and instructions to the user\n\n\
         **5. Harmonised standards / common specifications applied**\n\
         - prEN 40000-1-3 (horizontal SBOM and vulnerability-handling requirements)\n\
         - BSI TR-03183-2 (German national CRA-aligned SBOM technical guideline)\n\
         - _TBD: any vertical EN 304-6xx product-class standards applied_\n\n\
         **6. Other Union legislation in conjunction with which conformity is declared**\n\
         {other_legislation}\n\n\
         **7. Signed for and on behalf of the manufacturer**\n\
         - Place: _TBD_\n\
         - Date: _TBD_\n\
         - Name and function: _TBD_\n\
         - Signature: _TBD_\n",
        product_name = product_name,
        product_version = product_version,
        ce_marking = ce_marking,
        class_name = class.name(),
        manufacturer = manufacturer,
        manufacturer_email = manufacturer_email,
        route_name = route.name(),
        other_legislation = other_legislation,
    )
}

/// Render the Annex V technical-documentation summary.
fn render_tech_doc(
    sbom: &NormalizedSbom,
    sidecar: Option<&CraSidecarMetadata>,
    class: CraProductClass,
    route: ConformityRoute,
    compliance: &ComplianceResult,
) -> String {
    let component_count = sbom.components.len();
    let dependency_count = sbom.edges.len();
    let format_label = format!("{:?} {}", sbom.document.format, sbom.document.spec_version);
    let risk_assessment = sidecar
        .and_then(|s| s.risk_assessment_url.as_deref())
        .unwrap_or("_TBD: link to documented risk assessment (CRA Art. 13(2))_");
    let methodology = sidecar
        .and_then(|s| s.risk_assessment_methodology.as_deref())
        .unwrap_or("_TBD: e.g., ISO/IEC 27005:2022_");
    let psirt = sidecar
        .and_then(|s| s.psirt_url.as_deref())
        .unwrap_or("_TBD: PSIRT URL (CRA Art. 14)_");
    let support_end = sidecar
        .and_then(|s| s.support_end_date)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "_TBD: support end date (CRA Art. 13(8))_".to_string());

    let adjacent_regulation_md = render_adjacent_regulation_section(sidecar);
    let controls_assertion_md = render_controls_assertion_section(sidecar);

    let mut violations_md = String::new();
    if compliance.violations.is_empty() {
        violations_md.push_str("_No CRA compliance issues detected by sbom-tools._\n");
    } else {
        let errors = compliance.error_count;
        let warnings = compliance.warning_count;
        let infos = compliance.info_count;
        violations_md.push_str(&format!(
            "**Compliance check summary** ({errors} errors, {warnings} warnings, {infos} info):\n\n"
        ));
        for v in compliance.violations.iter().take(10) {
            let sev = match v.severity {
                crate::quality::ViolationSeverity::Error => "ERROR",
                crate::quality::ViolationSeverity::Warning => "WARN",
                crate::quality::ViolationSeverity::Info => "INFO",
            };
            violations_md.push_str(&format!(
                "- **[{}] {}** — {}\n",
                sev, v.requirement, v.message
            ));
        }
        if compliance.violations.len() > 10 {
            violations_md.push_str(&format!(
                "- … and {} more findings (see SARIF / JSON output)\n",
                compliance.violations.len() - 10
            ));
        }
    }

    format!(
        "# Technical Documentation Summary (CRA Annex V)\n\n\
         > **Generated by sbom-tools cra-docs.** Use this document as a \
         starting point; complete the `_TBD_` fields and attach evidence \
         before submission.\n\n\
         ## 1. Product description\n\
         - SBOM format: {format_label}\n\
         - Components in scope: {component_count}\n\
         - Declared dependency edges: {dependency_count}\n\
         - CRA product class: {class_name}\n\
         - Conformity route: {route_name}\n\n\
         ## 2. Risk assessment (CRA Art. 13(2))\n\
         - Risk-assessment document: {risk_assessment}\n\
         - Methodology: {methodology}\n\
         - Annex II Part 3 risk-acceptance criteria: _TBD_\n\n\
         ## 3. Vulnerability-handling process (Annex I Part II)\n\
         - Process description: see `vulnerability-handling-policy.md` in this dossier\n\
         - PSIRT: {psirt}\n\
         - Support / security-update end date: {support_end}\n\n\
         ## 4. Software Bill of Materials\n\
         - Embedded SBOM: provided as a separate file in this submission\n\
         - Generated by sbom-tools v{tool_version}\n\
         - SBOM serial number: {serial}\n\n\
         ## 5. Compliance check summary\n\n\
         {violations_md}\n\
         ## 6. Test and evaluation reports\n\
         - Penetration test report: _TBD_\n\
         - Code review / SAST report: _TBD_\n\
         - DAST / fuzzing report: _TBD_\n\
         - Third-party attestation (Module B+C / H / EUCC): _TBD_\n\n\
         ## 7. Cybersecurity-relevant changes since previous version\n\
         - _TBD: changelog of security-relevant changes_\n\
         {controls_assertion_md}\
         {adjacent_regulation_md}",
        format_label = format_label,
        component_count = component_count,
        dependency_count = dependency_count,
        class_name = class.name(),
        route_name = route.name(),
        risk_assessment = risk_assessment,
        methodology = methodology,
        psirt = psirt,
        support_end = support_end,
        tool_version = env!("CARGO_PKG_VERSION"),
        serial = sbom
            .document
            .serial_number
            .as_deref()
            .unwrap_or("_TBD: assign a unique serial / namespace_"),
        violations_md = violations_md,
        controls_assertion_md = controls_assertion_md,
        adjacent_regulation_md = adjacent_regulation_md,
    )
}

/// Render the prEN 40000-1-2/1-4 controls-assertion block (CRA-P5.5).
/// Empty sidecars or sidecars without `annex_i_part_i_controls` skip the
/// section entirely so the dossier stays clean for products that don't
/// claim per-control assertions.
fn render_controls_assertion_section(sidecar: Option<&CraSidecarMetadata>) -> String {
    let Some(sc) = sidecar else {
        return String::new();
    };
    if sc.annex_i_part_i_controls.is_empty() {
        return String::new();
    }
    let mut s = String::from("\n## 8. Annex I Part I controls assertion (prEN 40000-1-2/1-4)\n\n");
    s.push_str(
        "Per-control assertions for CRA Annex I Part I, sourced from the \
         sidecar `annex_i_part_i_controls` block. `Satisfied` rows must \
         carry an evidence URL — un-evidenced claims are flagged by \
         `sbom-tools validate --standard cra` as Warnings.\n\n",
    );
    s.push_str("| Control | Satisfied | Methodology | Evidence | Note |\n");
    s.push_str("|---------|-----------|-------------|----------|------|\n");
    for (id, claim) in &sc.annex_i_part_i_controls {
        let satisfied = if claim.satisfied { "✅" } else { "❌" };
        let methodology = claim.methodology.as_deref().unwrap_or("_TBD_");
        let evidence = claim
            .evidence_url
            .as_deref()
            .map(|u| format!("[link]({u})"))
            .unwrap_or_else(|| "_TBD_".to_string());
        let note = claim.note.as_deref().unwrap_or("");
        s.push_str(&format!(
            "| {id} | {satisfied} | {methodology} | {evidence} | {note} |\n"
        ));
    }
    s.push('\n');
    s
}

/// Render the "Adjacent regulation" section (CRA-P4.4). Only fires for
/// the regulatory overlap flags actually set on the sidecar, so an
/// SBOM-only dossier (no sidecar) skips the section entirely.
fn render_adjacent_regulation_section(sidecar: Option<&CraSidecarMetadata>) -> String {
    let Some(sc) = sidecar else {
        return String::new();
    };
    let any = sc.is_nis2_essential_entity
        || sc.is_nis2_important_entity
        || sc.processes_personal_data
        || sc.is_high_risk_ai
        || sc.red_repealed_until.is_some();
    if !any {
        return String::new();
    }

    // Numbered after the controls-assertion block so the dossier reads
    // 7 → 8 → 9 when both are present (controls = §8, adjacent = §9).
    let mut s = String::from("\n## 9. Adjacent regulation\n\n");
    s.push_str(
        "The CRA does not operate in isolation. The following adjacent EU \
         legal acts apply to this product based on the sidecar declarations \
         and must be coordinated with CRA conformity assessment.\n\n",
    );

    if sc.is_nis2_essential_entity || sc.is_nis2_important_entity {
        let entity_kind = if sc.is_nis2_essential_entity {
            "essential entity (NIS2 Annex I)"
        } else {
            "important entity (NIS2 Annex II)"
        };
        s.push_str(&format!(
            "### NIS2 — Directive (EU) 2022/2555\n\n\
             - Manufacturer is registered as an **{entity_kind}**.\n\
             - **Art. 23 incident reporting** runs in parallel with CRA \
             Art. 14: a 24-hour early warning to the national CSIRT *and* \
             ENISA, followed by a 72-hour incident notification, and a \
             1-month final report.\n\
             - **Art. 21 risk-management measures** overlap with CRA \
             Annex I Part I and the documented risk assessment in §2 \
             above.\n\
             - National competent authority registration (NIS2 Art. 27) \
             is a precondition for the Art. 23 reporting channels listed \
             in `vulnerability-handling-policy.md`.\n\n",
        ));
    }

    if sc.processes_personal_data {
        s.push_str(
            "### GDPR — Regulation (EU) 2016/679\n\n\
             - The product processes personal data, so **GDPR Art. 32 \
             (security of processing)** applies alongside CRA Annex I \
             Part I (1) cybersecurity properties.\n\
             - Personal-data breaches must additionally be reported to \
             the supervisory authority under **Art. 33** (within 72 h) \
             and to data subjects under **Art. 34** when the breach is \
             likely to result in a high risk.\n\
             - The CRA technical-documentation set (this dossier) should \
             cross-reference the Data Protection Impact Assessment \
             (DPIA) when one has been performed under Art. 35.\n\n",
        );
    }

    if sc.is_high_risk_ai {
        s.push_str(
            "### AI Act — Regulation (EU) 2024/1689\n\n\
             - The product is a **high-risk AI system** within the meaning \
             of the AI Act.\n\
             - AI-Act conformity assessment runs **in addition to** CRA \
             Annex VIII; the CE marking covers both regulations \
             simultaneously and the EU Declaration of Conformity must \
             list both legal bases.\n\
             - The post-market monitoring plan (AI Act Art. 72) and \
             serious-incident reporting (Art. 73) are coordinated with \
             CRA Art. 14 reporting; use the same channels listed in \
             `vulnerability-handling-policy.md`.\n\
             - For an Annex IV technical-documentation **readiness** check \
             over the AI-BOM (model description, training-data \
             characteristics, validation metrics), run \
             `sbom-tools validate <sbom> --standard ai-act --cra-sidecar <sidecar>`. \
             This is a documentation-readiness aid, not a legal-conformity \
             guarantee.\n\n",
        );
    }

    if let Some(until) = sc.red_repealed_until {
        s.push_str(&format!(
            "### Radio Equipment Directive (RED) — Directive 2014/53/EU\n\n\
             - The cybersecurity provisions in **RED Art. 3(3)(d/e/f)** \
             apply to this product until **{}** (sidecar field \
             `red_repealed_until`).\n\
             - Once superseded by the CRA, RED references in the SBOM / \
             technical documentation should be retired and replaced with \
             the matching CRA Annex I requirement.\n\n",
            until.format("%Y-%m-%d"),
        ));
    }

    s
}

/// Render the Annex I Part II vulnerability-handling policy stub.
fn render_vuln_policy(sbom: &NormalizedSbom, sidecar: Option<&CraSidecarMetadata>) -> String {
    let psirt = sidecar
        .and_then(|s| s.psirt_url.as_deref())
        .unwrap_or("_TBD: PSIRT URL_");
    let security_contact = sidecar
        .and_then(|s| s.security_contact.as_deref())
        .unwrap_or("_TBD: security contact email_");
    let cvd_policy = sidecar
        .and_then(|s| s.coordinated_disclosure_policy_url.as_deref())
        .unwrap_or("_TBD: coordinated vulnerability-disclosure policy URL_");
    let early = sidecar
        .and_then(|s| s.early_warning_contact.as_deref())
        .unwrap_or("_TBD: 24-hour early-warning channel (CRA Art. 14(1))_");
    let incident = sidecar
        .and_then(|s| s.incident_report_contact.as_deref())
        .unwrap_or("_TBD: 72-hour incident-report channel (CRA Art. 14(2))_");
    let enisa = sidecar
        .and_then(|s| s.enisa_reporting_platform_id.as_deref())
        .unwrap_or("_TBD: ENISA single-reporting-platform manufacturer ID (Art. 14(7))_");

    format!(
        "# Vulnerability-Handling Policy (CRA Annex I Part II)\n\n\
         > **Generated by sbom-tools cra-docs.** Replace `_TBD_` placeholders \
         with your operational details before publishing this document.\n\n\
         ## 1. Scope\n\
         This policy applies to all products with digital elements identified in \
         the accompanying SBOM ({components} components, primary identifier \
         {primary_id}).\n\n\
         ## 2. Reporting channels\n\
         | Channel | Endpoint |\n\
         |---|---|\n\
         | PSIRT (public reporting portal) | {psirt} |\n\
         | Security contact (encrypted email) | {security_contact} |\n\
         | Coordinated disclosure policy | {cvd_policy} |\n\
         | 24-hour early warning (CRA Art. 14(1)) | {early} |\n\
         | 72-hour incident report (CRA Art. 14(2)) | {incident} |\n\
         | ENISA single reporting platform (Art. 14(7)) | {enisa} |\n\n\
         ## 3. Process commitments\n\
         - **Acknowledgement**: we will acknowledge receipt of any vulnerability \
         report within _TBD_ business days.\n\
         - **Assessment**: we will perform an initial impact assessment within \
         _TBD_ business days.\n\
         - **Disclosure**: we follow ISO/IEC 29147 / 30111 coordinated-disclosure \
         practice (target embargo: _TBD_).\n\
         - **Patch availability**: security patches are made available free of \
         charge for the duration of the support period.\n\n\
         ## 4. Active-exploitation handling\n\
         - We monitor CISA KEV, ENISA EU-VDB, and OSV.dev for actively-exploited \
         vulnerabilities affecting components in our SBOMs.\n\
         - When an actively-exploited vulnerability is confirmed, the early-warning \
         channel above is engaged within 24 hours and a CSAF v2.0 advisory is \
         published as soon as a remediation or mitigation is available.\n\n\
         ## 5. SBOM update commitment\n\
         - The SBOM accompanying this product is regenerated and re-signed on \
         every release that introduces, removes, or upgrades a tracked \
         component (CRA Art. 13(3)).\n\
         - VEX statements (CSAF v2.0 / OpenVEX / CycloneDX VEX) are published \
         alongside the SBOM whenever a vulnerability affecting a tracked \
         component is acknowledged.\n",
        components = sbom.components.len(),
        primary_id = sbom
            .primary_component_id
            .as_ref()
            .map(|c| c.value().to_string())
            .unwrap_or_else(|| "_TBD: primary component ID_".to_string()),
        psirt = psirt,
        security_contact = security_contact,
        cvd_policy = cvd_policy,
        early = early,
        incident = incident,
        enisa = enisa,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;
    use tempfile::tempdir;

    #[test]
    fn dossier_files_created_for_minimal_sbom() {
        let dir = tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let out = dir.path().join("dossier");

        run_cra_docs(sbom_path, out.clone(), None, None).expect("cra-docs runs");

        assert!(out.join("eu-declaration-of-conformity.md").exists());
        assert!(out.join("technical-documentation.md").exists());
        assert!(out.join("vulnerability-handling-policy.md").exists());
    }

    #[test]
    fn doc_template_is_filled_from_sidecar() {
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(Component::new("c".to_string(), "c".to_string()));
        let sidecar = CraSidecarMetadata {
            manufacturer_name: Some("ExCorp".to_string()),
            manufacturer_email: Some("legal@example.com".to_string()),
            product_name: Some("ExProduct".to_string()),
            product_version: Some("1.0".to_string()),
            ce_marking_reference: Some("EU-DoC-2026-001".to_string()),
            ..Default::default()
        };
        let doc = render_doc(
            &sbom,
            Some(&sidecar),
            CraProductClass::ImportantClass1,
            ConformityRoute::ModuleA,
        );
        assert!(doc.contains("ExCorp"));
        assert!(doc.contains("legal@example.com"));
        assert!(doc.contains("ExProduct"));
        assert!(doc.contains("EU-DoC-2026-001"));
        assert!(doc.contains("Important Class I"));
        assert!(doc.contains("Module A"));
    }

    #[test]
    fn vuln_policy_filled_from_sidecar() {
        let sbom = NormalizedSbom::default();
        let sidecar = CraSidecarMetadata {
            psirt_url: Some("https://example.com/psirt".to_string()),
            security_contact: Some("security@example.com".to_string()),
            coordinated_disclosure_policy_url: Some("https://example.com/security/cvd".to_string()),
            early_warning_contact: Some("ew@example.com".to_string()),
            incident_report_contact: Some("incidents@example.com".to_string()),
            enisa_reporting_platform_id: Some("EU-MFR-1".to_string()),
            ..Default::default()
        };
        let policy = render_vuln_policy(&sbom, Some(&sidecar));
        assert!(policy.contains("https://example.com/psirt"));
        assert!(policy.contains("security@example.com"));
        assert!(policy.contains("https://example.com/security/cvd"));
        assert!(policy.contains("ew@example.com"));
        assert!(policy.contains("incidents@example.com"));
        assert!(policy.contains("EU-MFR-1"));
    }

    #[test]
    fn tech_doc_includes_compliance_summary() {
        let mut sbom = NormalizedSbom::default();
        sbom.add_component(Component::new("c".to_string(), "c".to_string()));
        let result = ComplianceChecker::new(ComplianceLevel::CraPhase2).check(&sbom);
        let tech = render_tech_doc(
            &sbom,
            None,
            CraProductClass::Default,
            ConformityRoute::ModuleA,
            &result,
        );
        // should mention component count + compliance summary header
        assert!(tech.contains("Components in scope: 1"));
        assert!(tech.contains("Compliance check summary"));
    }
}
