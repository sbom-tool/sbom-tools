//! Small shared helpers reused across the compliance checkers.

use super::{Violation, ViolationCategory, ViolationSeverity};
use crate::model::{
    Component, ComponentType, CreatorType, ExternalRefType, ExternalReference, Hash, HashAlgorithm,
    NormalizedSbom, Organization, VexState, VulnerabilityRef, is_known_contact,
};
// The placeholder and sentinel tests every check reads live in the model,
// which merges a component's entries with the same classification.
pub(crate) use crate::model::{is_declared_unknown, is_placeholder};

/// The components package rules apply to: everything except files,
/// snippets, cryptographic assets and services (see
/// [`ComponentType::is_package_scoped`]). Every per-component package check
/// iterates through this, so no standard can forget the carve-out.
pub(crate) fn package_components(sbom: &NormalizedSbom) -> impl Iterator<Item = &Component> {
    sbom.components
        .values()
        .filter(|c| c.component_type.is_package_scoped())
}

/// The inventory-absent finding for `rule_id`, or `None` when the SBOM lists
/// at least one package-scoped component.
///
/// Package rules (version, supplier, identifier, hash, license) only judge
/// package-scoped components, so a document with no components at all — or
/// with only files, snippets or cryptographic assets — used to pass them
/// vacuously, scoring like a perfect SBOM. Every standard that judges a
/// software inventory reports that instead, as PCI DSS already did. The
/// primary component counts: a leaf application with no dependencies is a
/// legitimate inventory.
pub(crate) fn inventory_absent_violation(
    sbom: &NormalizedSbom,
    rule_id: &'static str,
    requirement: &str,
) -> Option<Violation> {
    if package_components(sbom).next().is_some() {
        return None;
    }
    let total = sbom.components.len();
    let message = if total == 0 {
        "SBOM lists no components; an empty document is not a software inventory".to_string()
    } else {
        let all_crypto = sbom
            .components
            .values()
            .all(|c| c.component_type == ComponentType::Cryptographic);
        let what = if all_crypto {
            "cryptographic assets"
        } else {
            "files, snippets, services or cryptographic assets"
        };
        let mut message = format!(
            "SBOM lists no software components, only {total} {what}; it is not a software inventory"
        );
        if all_crypto {
            message.push_str(" (validate a CBOM with --standard cnsa2 or pqc)");
        }
        message
    };
    Some(Violation {
        severity: ViolationSeverity::Error,
        category: ViolationCategory::DocumentMetadata,
        message,
        element: None,
        requirement: requirement.to_string(),
        rule_id,
        component_id: None,
        counts: None,
        standard_refs: Vec::new(),
        remediation: None,
        finding_detail: None,
        deadline: None,
    })
}

/// The longest SBOM value a finding message quotes, in characters. A longer
/// value is cut, with an ellipsis.
const MAX_QUOTED_CHARS: usize = 64;

/// `value` as a finding message quotes it: cut to [`MAX_QUOTED_CHARS`]
/// characters.
fn quoted(value: &str) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(MAX_QUOTED_CHARS).collect();
    if chars.next().is_some() {
        format!("'{head}…'")
    } else {
        format!("'{head}'")
    }
}

/// How a timestamp check names a creation timestamp the document wrote but
/// that is not an RFC 3339 date-time: "an unparseable creation timestamp
/// '…', not an RFC 3339 date-time". `None` when the document's timestamp
/// parsed or is absent: a check without a known timestamp then reports it
/// missing, and with one it reports the value, so a user does not look for a
/// field they did set.
pub(crate) fn unparseable_timestamp(sbom: &NormalizedSbom) -> Option<String> {
    sbom.document.created_unparsed.as_deref().map(|value| {
        format!(
            "an unparseable creation timestamp {}, not an RFC 3339 date-time",
            quoted(value)
        )
    })
}

/// The freshness finding for an SBOM dated in the future, or `None` when its
/// creation timestamp is missing or not later than `as_of`.
///
/// Freshness checks measure the document's age at the evaluation instant. A
/// timestamp after that instant gave a negative age, which read as "just
/// generated" and passed every staleness threshold. A future-dated SBOM shows
/// nothing about when the inventory was last updated (usually the generator's
/// clock or time zone is wrong), so it is reported at the severity both
/// freshness rules give a missing timestamp: Warning, because clock-skewed
/// generators are common and the rest of the document is unaffected. There is
/// no skew tolerance, as for attestation evidence created after `as_of`.
/// `citation` prefixes the message, e.g. `"[PCI DSS 6.3.2]"`.
pub(crate) fn future_timestamp_violation(
    sbom: &NormalizedSbom,
    as_of: chrono::DateTime<chrono::Utc>,
    rule_id: &'static str,
    citation: &str,
    requirement: &str,
) -> Option<Violation> {
    let created = sbom.document.created;
    if !sbom.document.has_known_timestamp() || created <= as_of {
        return None;
    }
    // The message names only the document's timestamp: the evaluation
    // instant is the wall clock unless pinned, and would make the text
    // differ on every run.
    Some(Violation {
        severity: ViolationSeverity::Warning,
        category: ViolationCategory::DocumentMetadata,
        message: format!(
            "{citation} SBOM creation timestamp {} is later than the evaluation instant; a \
             future-dated SBOM does not show when the inventory was last updated (check the \
             generator's clock and time zone)",
            created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
        element: None,
        requirement: requirement.to_string(),
        rule_id,
        component_id: None,
        counts: None,
        standard_refs: Vec::new(),
        remediation: None,
        finding_detail: None,
        deadline: None,
    })
}

/// Components whose external references can carry manufacturer-level
/// evidence (security contact, CVD policy, disclosure process, risk
/// assessment, certificates and attestations): the components the document
/// describes — the primary component and the other described roots (see
/// [`NormalizedSbom::described_components`]; an SPDX document can describe
/// several sibling products).
///
/// SBOM generators routinely copy upstream registry metadata — a third-party
/// dependency's own GitHub advisories, support URL or certification — onto
/// dependency components; such references say nothing about the
/// *manufacturer's* obligations and must not satisfy them, wherever the
/// dependency sits in the graph (a sparse `dependencies` section leaves
/// third-party libraries with no incoming edge).
///
/// Only a document that names no product falls back to the roots of its
/// dependency graph (no incoming edge), or, when the graph is fully cyclic,
/// to every component, rather than making the evidence unsatisfiable.
pub(crate) fn manufacturer_scope_components(sbom: &NormalizedSbom) -> Vec<&Component> {
    let described = sbom.described_components();
    if !described.is_empty() {
        return described;
    }
    let incoming: std::collections::HashSet<_> = sbom.edges.iter().map(|e| &e.to).collect();
    let roots: Vec<&Component> = sbom
        .components
        .iter()
        .filter(|(id, _)| !incoming.contains(id))
        .map(|(_, c)| c)
        .collect();
    if roots.is_empty() {
        // Fully cyclic graph with no identified primary: no component is
        // provably a dependency-only node, so fall back to scanning all
        // components rather than making manufacturer evidence unsatisfiable.
        return sbom.components.values().collect();
    }
    roots
}

/// Whether any manufacturer-scope component (see
/// [`manufacturer_scope_components`]) carries an external reference that
/// `accepts`.
pub(crate) fn manufacturer_reference(
    sbom: &NormalizedSbom,
    accepts: impl Fn(&ExternalReference) -> bool,
) -> bool {
    manufacturer_scope_components(sbom)
        .iter()
        .any(|c| c.external_refs.iter().any(&accepts))
}

/// Whether the SBOM names the product's manufacturer: an organization
/// creator that is identified (see [`creator_identified`]), the supplier of
/// the described product (CycloneDX `metadata.supplier`), or a known
/// manufacturer or supplier on a component the document describes
/// (CycloneDX `metadata.component.manufacturer` or `.supplier`, the SPDX
/// described package's supplier). CycloneDX 1.6 moved the manufacturer of
/// the product from `metadata.manufacture` to
/// `metadata.component.manufacturer`. Placeholders such as `NOASSERTION` or
/// `TBD` name nobody. The CRA sidecar is checked by the callers.
pub(crate) fn manufacturer_identified(sbom: &NormalizedSbom) -> bool {
    manufacturer_name(sbom).is_some()
        || sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Organization && creator_identified(c))
}

/// The manufacturer's name: the first one the sources of
/// [`manufacturer_identified`] give, in its order. That is an organization
/// creator of the SBOM, then the supplier of the described product
/// (CycloneDX `metadata.supplier`), then the manufacturer or supplier of a
/// component the document describes. Placeholders name nobody. `None` when
/// no source gives a name, which includes an organization creator known only
/// by its email address. The `cra-docs` dossier prints this name.
pub(crate) fn manufacturer_name(sbom: &NormalizedSbom) -> Option<&str> {
    sbom.document
        .creators
        .iter()
        .filter(|c| c.creator_type == CreatorType::Organization)
        .find_map(|c| known_value(Some(c.name.as_str())))
        .or_else(|| known_organization_name(sbom.document.supplier.as_ref()))
        .or_else(|| {
            sbom.described_components().into_iter().find_map(|c| {
                known_organization_name(c.manufacturer.as_ref())
                    .or_else(|| known_organization_name(c.supplier.as_ref()))
            })
        })
}

/// Whether a component's name is real. Empty/whitespace and the SPDX
/// `NOASSERTION` sentinel never count. `none`/`unknown` are placeholder-ish
/// but are also genuine package names (npm ships both), so they count when
/// corroborated by a unique identifier whose name segment matches.
pub(crate) fn known_component_name(comp: &Component) -> bool {
    let name = comp.name.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("NOASSERTION") {
        return false;
    }
    if !(name.eq_ignore_ascii_case("NONE") || name.eq_ignore_ascii_case("UNKNOWN")) {
        return true;
    }
    // Suspicious placeholder spelling: require a corroborating identifier
    // (e.g. pkg:npm/none@1.0.0 corroborates a component named "none").
    comp.identifiers.purl.as_deref().is_some_and(|purl| {
        purl.rsplit('/')
            .next()
            .and_then(|seg| seg.split('@').next())
            .is_some_and(|purl_name| purl_name.eq_ignore_ascii_case(name))
    })
}

/// Render a slice of names as a comma-separated list, truncated with
/// "…and N more" once `max` items are emitted. Keeps long-tail violation
/// messages bounded for terminal/SARIF output.
pub(crate) fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let head = items[..max].join(", ");
        let rest = items.len() - max;
        format!("{head}, …and {rest} more")
    }
}

/// What a field says about a required element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueState {
    /// A real value.
    Known,
    /// An explicit sentinel (`NOASSERTION`, `NONE`, `UNKNOWN`): the author
    /// states the value is unknown. CISA 2026 and FSCT accept this where
    /// their texts allow an explicit unknown; every other standard does not.
    DeclaredUnknown,
    /// Absent, empty, or a placeholder such as `TBD` or `N/A`. Never
    /// satisfies an element.
    Missing,
}

/// Classify a field value; see [`ValueState`].
pub(crate) fn value_state(value: Option<&str>) -> ValueState {
    match value.map(str::trim) {
        None => ValueState::Missing,
        Some(v) if v.is_empty() || is_placeholder(v) => ValueState::Missing,
        Some(v) if is_declared_unknown(v) => ValueState::DeclaredUnknown,
        Some(_) => ValueState::Known,
    }
}

/// Return the trimmed value only when it carries real information
/// ([`ValueState::Known`]): not empty, not a sentinel such as `NOASSERTION`,
/// and not a placeholder such as `TBD`. This is the presence test for every
/// element that needs a real value.
pub(crate) fn known_value(value: Option<&str>) -> Option<&str> {
    let v = value?.trim();
    (value_state(Some(v)) == ValueState::Known).then_some(v)
}

/// `known_value` convenience for `Option<String>` model fields.
pub(crate) fn has_known_value(value: &Option<String>) -> bool {
    known_value(value.as_deref()).is_some()
}

/// Whether an organization is present and its name is not a placeholder
/// sentinel.
pub(crate) fn has_known_organization(org: Option<&Organization>) -> bool {
    known_organization_name(org).is_some()
}

/// The organization's trimmed name, when it is present and its name is not
/// a placeholder sentinel.
fn known_organization_name(org: Option<&Organization>) -> Option<&str> {
    known_value(Some(org?.name.as_str()))
}

/// Whether a component carries real producer attribution: a supplier or
/// manufacturer organization, or an author, whose name is not a placeholder
/// sentinel. CycloneDX 1.6+ names the creating organization `manufacturer`
/// (and people `authors`, folded into `author` by the parser); both identify
/// "the entity that creates, defines, and identifies components" as well as
/// a supplier does.
pub(crate) fn has_known_producer(comp: &crate::model::Component) -> bool {
    has_known_organization(comp.supplier.as_ref())
        || has_known_organization(comp.manufacturer.as_ref())
        || has_known_value(&comp.author)
}

/// Whether the component carries at least one real license expression,
/// declared or concluded: an SPDX expression or a `LicenseRef-*`, not a
/// sentinel such as `NOASSERTION` and not a placeholder such as `TBD` (see
/// [`license_state`]). Every licence check asks this, except CISA 2026,
/// which also accepts the explicit unknown.
pub(crate) fn has_known_license(comp: &Component) -> bool {
    license_state(comp) == ValueState::Known
}

/// What the component's licences say about its licence: [`ValueState::Known`]
/// when one of them, declared or concluded, is a real expression,
/// [`ValueState::DeclaredUnknown`] when the best of them is a sentinel such
/// as `NOASSERTION` (a CycloneDX licence with neither an id nor a name reads
/// as one), and [`ValueState::Missing`] otherwise.
pub(crate) fn license_state(comp: &Component) -> ValueState {
    comp.licenses
        .all_licenses()
        .iter()
        .map(|l| value_state(Some(l.expression.as_str())))
        .min_by_key(|state| match state {
            ValueState::Known => 0,
            ValueState::DeclaredUnknown => 1,
            ValueState::Missing => 2,
        })
        .unwrap_or(ValueState::Missing)
}

/// Whether `value` is a contact that reaches someone: present, known and no
/// address at a documentation domain such as `example.com` (see
/// [`crate::model::is_known_contact`], beside the placeholder list). Every
/// check that reads a vulnerability contact asks this, in the SBOM and in
/// the CRA sidecar.
pub(crate) fn known_contact(value: Option<&str>) -> bool {
    value.is_some_and(is_known_contact)
}

/// Whether `r` is a contact reference whose locator reaches someone: a
/// security contact, advisories or support reference (see
/// [`known_contact`]).
pub(crate) fn is_contact_reference(r: &ExternalReference) -> bool {
    is_contact_type(&r.ref_type) && known_contact(Some(r.url.as_str()))
}

/// Whether `ref_type` is a contact reference type: a security contact,
/// advisories or support reference.
fn is_contact_type(ref_type: &ExternalRefType) -> bool {
    matches!(
        ref_type,
        ExternalRefType::SecurityContact | ExternalRefType::Advisories | ExternalRefType::Support
    )
}

/// The first vulnerability contact the SBOM gives that reaches nobody (see
/// [`known_contact`]): its security contact, its disclosure URL, or the
/// locator of a contact reference on a manufacturer-scope component. A
/// finding about a missing contact names it, so the reader sees why the
/// contact did not count.
pub(crate) fn unreachable_contact(sbom: &NormalizedSbom) -> Option<&str> {
    let document = [
        sbom.document.security_contact.as_deref(),
        sbom.document.vulnerability_disclosure_url.as_deref(),
    ];
    document
        .into_iter()
        .flatten()
        .chain(
            manufacturer_scope_components(sbom)
                .into_iter()
                .flat_map(|c| {
                    c.external_refs
                        .iter()
                        .filter(|r| is_contact_type(&r.ref_type))
                        .map(|r| r.url.as_str())
                }),
        )
        .find(|value| !known_contact(Some(*value)))
}

/// The clause a contact finding appends when the SBOM gives a contact that
/// reaches nobody (see [`unreachable_contact`]), or an empty string.
pub(crate) fn unreachable_contact_note(sbom: &NormalizedSbom) -> String {
    unreachable_contact(sbom).map_or_else(String::new, |value| {
        format!(
            "; the contact '{}' reaches nobody (a placeholder, or an address at example.com, \
             example.net or example.org)",
            value.trim()
        )
    })
}

/// The clause a contact finding appends when the CRA sidecar gives a
/// contact that reaches nobody (see [`known_contact`]), or an empty string.
pub(crate) fn unreachable_sidecar_note(value: Option<&str>) -> String {
    match value {
        Some(v) if !known_contact(Some(v)) => format!(
            "; the sidecar value '{}' reaches nobody (a placeholder, or an address at \
             example.com, example.net or example.org)",
            v.trim()
        ),
        _ => String::new(),
    }
}

/// Whether `r` references the product's EUCC (Common Criteria) certificate:
/// a certification or attestation reference whose URL names the scheme
/// (`eucc`, `common-criteria` or `commoncriteria`, in any case). The CRA
/// Annex IV check, the conformity summary's EUCC rows and
/// SBOM-EUCC-CERTREF all ask this.
pub(crate) fn is_eucc_reference(r: &ExternalReference) -> bool {
    let url = r.url.to_ascii_lowercase();
    matches!(
        r.ref_type,
        ExternalRefType::Certification | ExternalRefType::Attestation
    ) && ["eucc", "common-criteria", "commoncriteria"]
        .iter()
        .any(|keyword| url.contains(keyword))
}

/// Whether the SBOM carries an in-document signature with a value: a
/// CycloneDX JSF signature or enveloped XML-DSig, or an SPDX 3 `verifiedUsing`
/// signature on the document. Nothing is verified cryptographically; an
/// entry without a value is no signature.
pub(crate) fn document_signed(sbom: &NormalizedSbom) -> bool {
    sbom.document
        .signature
        .as_ref()
        .is_some_and(|s| s.has_value)
}

/// Whether the vulnerability's own VEX statement is `not_affected` and names
/// its justification (CycloneDX `analysis.justification`, OpenVEX
/// `justification`, SPDX 3.0 `justificationType`).
///
/// The CRA FAQ (v1.4, 4.3.1) has the manufacturer judge a vulnerability's
/// relevance for the product; where it "cannot be exploited", the
/// manufacturer "may be expected, for example, to document the
/// vulnerability, but may decide not to fix it with a dedicated update". A
/// justified `not_affected` statement is that record (Annex I Part II (1)),
/// and Annex I Part II (4), which asks for the severity and the remediation,
/// covers fixed vulnerabilities. A bare `not_affected` claim gives no reason
/// and counts for nothing, nor does a free-text detail without a
/// justification. Only the vulnerability's own statement counts: the
/// component-level VEX status sums up all of the component's statements and
/// is no statement about this one. Every check that asks whether a
/// vulnerability is still open (the CRA Phase 2 vulnerability checks and
/// SBOM-FDA-SECURITY) skips such a vulnerability.
pub(crate) fn justified_not_affected(vuln: &VulnerabilityRef) -> bool {
    vuln.vex_status
        .as_ref()
        .is_some_and(|vex| vex.status == VexState::NotAffected && vex.justification.is_some())
}

/// How many hex digits a digest of `algorithm` has, when the algorithm fixes
/// its output length. `None` for an extendable-output or unknown algorithm
/// (BLAKE3, MD6, …). Algorithms the model has no variant for are matched by
/// name, as the parsers keep it (SPDX `SHA224`, SPDX 3 `sha3_224`, …).
fn digest_hex_digits(algorithm: &HashAlgorithm) -> Option<usize> {
    match algorithm {
        HashAlgorithm::Md5 => Some(32),
        HashAlgorithm::Sha1 => Some(40),
        HashAlgorithm::Sha256
        | HashAlgorithm::Sha3_256
        | HashAlgorithm::Blake2b256
        | HashAlgorithm::Streebog256 => Some(64),
        HashAlgorithm::Sha384 | HashAlgorithm::Sha3_384 | HashAlgorithm::Blake2b384 => Some(96),
        HashAlgorithm::Sha512
        | HashAlgorithm::Sha3_512
        | HashAlgorithm::Blake2b512
        | HashAlgorithm::Streebog512 => Some(128),
        HashAlgorithm::Blake3 => None,
        HashAlgorithm::Other(name) => {
            let name: String = name
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .map(|c| c.to_ascii_uppercase())
                .collect();
            match name.as_str() {
                "SHA224" | "SHA3224" => Some(56),
                "MD2" | "MD4" => Some(32),
                "ADLER32" => Some(8),
                _ => None,
            }
        }
    }
}

/// Why `value` is not a plausible digest of `algorithm`, or `None` when it
/// is (see [`plausible_digest`]), e.g. "SHA-512 digest is not 128 hex
/// characters".
pub(crate) fn digest_problem(algorithm: &HashAlgorithm, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return Some(format!("{algorithm} digest is empty"));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!("{algorithm} digest is not hexadecimal"));
    }
    match digest_hex_digits(algorithm) {
        Some(digits) if value.len() != digits => {
            Some(format!("{algorithm} digest is not {digits} hex characters"))
        }
        _ => None,
    }
}

/// Whether `value` can be a digest of `algorithm`: hexadecimal digits only
/// (upper or lower case; surrounding whitespace is ignored), as many as the
/// algorithm's output has where the algorithm fixes it (MD5 32, SHA-1 40,
/// SHA-224 56, SHA-256 / SHA3-256 / BLAKE2b-256 / Streebog-256 64, SHA-384 /
/// SHA3-384 / BLAKE2b-384 96, SHA-512 / SHA3-512 / BLAKE2b-512 /
/// Streebog-512 128), and at least one for a variable-length or unknown
/// algorithm. Parsers keep a digest as the document gives it, so an empty
/// or garbage value reaches the checks: every hash rule counts only
/// plausible digests.
pub(crate) fn plausible_digest(algorithm: &HashAlgorithm, value: &str) -> bool {
    digest_problem(algorithm, value).is_none()
}

/// Why each of `hashes` that is no plausible digest does not count, each
/// reason once, in order.
pub(crate) fn digest_problems<'a>(hashes: impl IntoIterator<Item = &'a Hash>) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    for problem in hashes
        .into_iter()
        .filter_map(|h| digest_problem(&h.algorithm, &h.value))
    {
        if !problems.contains(&problem) {
            problems.push(problem);
        }
    }
    problems
}

/// `name` for a list in a finding message, followed by why its digests that
/// are not plausible do not count: "libalpha (SHA-256 digest is empty)".
/// Just `name` when every digest counts.
pub(crate) fn name_with_digest_problems<'a>(
    name: &str,
    hashes: impl IntoIterator<Item = &'a Hash>,
) -> String {
    let problems = digest_problems(hashes);
    if problems.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({})", problems.join("; "))
    }
}

/// The tail of a coverage finding over `components`, which carry no
/// plausible digest: the ones among them whose present hashes did not
/// count, and why — "; hashes that do not count: libalpha (SHA-256 digest
/// is empty)". Empty when none of them carries a hash at all, so the
/// message of a document without bad digests is unchanged.
pub(crate) fn invalid_digest_note<'a>(
    components: impl IntoIterator<Item = &'a Component>,
) -> String {
    let named: Vec<String> = components
        .into_iter()
        .filter(|c| !c.hashes.is_empty())
        .map(|c| name_with_digest_problems(&c.name, &c.hashes))
        .collect();
    if named.is_empty() {
        String::new()
    } else {
        format!("; hashes that do not count: {}", truncate_list(&named, 5))
    }
}

/// Whether a creator identifies a real entity: a known name, or failing
/// that a known email address.
pub(crate) fn creator_identified(creator: &crate::model::Creator) -> bool {
    known_value(Some(creator.name.as_str())).is_some()
        || known_value(creator.email.as_deref()).is_some()
}

/// Simple email format validation (checks basic structure, not full RFC 5322)
pub(crate) fn is_valid_email_format(email: &str) -> bool {
    // Basic checks: contains @, has local and domain parts, no spaces
    if email.contains(' ') || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot and not start/end with dot
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_state_separates_known_declared_unknown_and_missing() {
        for known in ["1.2.3", "Acme Corp", "0", "none-of-the-above"] {
            assert_eq!(value_state(Some(known)), ValueState::Known, "{known:?}");
        }
        for declared in ["NOASSERTION", "noassertion", "NONE", "Unknown", " UNKNOWN "] {
            assert_eq!(
                value_state(Some(declared)),
                ValueState::DeclaredUnknown,
                "{declared:?}"
            );
        }
        for missing in [
            "", "   ", "TBD", "tbd", "N/A", "n.a.", "TODO", "-", "?", "null",
        ] {
            assert_eq!(
                value_state(Some(missing)),
                ValueState::Missing,
                "{missing:?}"
            );
        }
        assert_eq!(value_state(None), ValueState::Missing);
        assert_eq!(known_value(Some(" 1.0 ")), Some("1.0"));
        assert_eq!(known_value(Some("N/A")), None);
        assert_eq!(known_value(Some("NOASSERTION")), None);
    }

    #[test]
    fn plausible_digests_are_hex_of_the_algorithms_length() {
        use HashAlgorithm as A;
        let hex = |n: usize| "a".repeat(n);
        for (algorithm, digits) in [
            (A::Md5, 32),
            (A::Sha1, 40),
            (A::Other("SHA224".to_string()), 56),
            (A::Other("sha3_224".to_string()), 56),
            (A::Sha256, 64),
            (A::Sha3_256, 64),
            (A::Blake2b256, 64),
            (A::Streebog256, 64),
            (A::Sha384, 96),
            (A::Sha3_384, 96),
            (A::Blake2b384, 96),
            (A::Sha512, 128),
            (A::Sha3_512, 128),
            (A::Blake2b512, 128),
            (A::Streebog512, 128),
        ] {
            assert!(plausible_digest(&algorithm, &hex(digits)), "{algorithm}");
            for wrong in [digits - 1, digits + 1, digits / 2] {
                assert_eq!(
                    digest_problem(&algorithm, &hex(wrong)),
                    Some(format!("{algorithm} digest is not {digits} hex characters")),
                    "{algorithm} with {wrong} digits"
                );
            }
        }
        // Upper and lower case both count; surrounding whitespace is ignored.
        let mixed = "E3B0C44298FC1C149AFBF4C8996FB92427ae41e4649b934ca495991b7852b855";
        assert!(plausible_digest(&A::Sha256, mixed));
        assert!(plausible_digest(&A::Sha256, &format!(" {mixed}\n")));
        // Variable-length and unknown algorithms: any non-empty hex.
        for algorithm in [A::Blake3, A::Other("MD6".to_string())] {
            assert!(plausible_digest(&algorithm, "ab"), "{algorithm}");
            assert!(plausible_digest(&algorithm, &hex(200)), "{algorithm}");
        }
        assert_eq!(
            digest_problem(&A::Sha512, ""),
            Some("SHA-512 digest is empty".to_string())
        );
        assert_eq!(
            digest_problem(&A::Sha256, "   "),
            Some("SHA-256 digest is empty".to_string())
        );
        assert_eq!(
            digest_problem(&A::Blake3, "not-a-digest"),
            Some("BLAKE3 digest is not hexadecimal".to_string())
        );
        // A hex-looking value with a stray character is not hex.
        assert_eq!(
            digest_problem(&A::Sha256, &format!("{}g", hex(63))),
            Some("SHA-256 digest is not hexadecimal".to_string())
        );
    }

    #[test]
    fn digest_problems_name_each_reason_once() {
        let hashes = [
            Hash::new(HashAlgorithm::Sha256, String::new()),
            Hash::new(HashAlgorithm::Sha256, " ".to_string()),
            Hash::new(HashAlgorithm::Sha512, "abc".to_string()),
            Hash::new(
                HashAlgorithm::Md5,
                "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            ),
        ];
        assert_eq!(
            digest_problems(&hashes),
            vec![
                "SHA-256 digest is empty".to_string(),
                "SHA-512 digest is not 128 hex characters".to_string(),
            ]
        );
        assert_eq!(
            name_with_digest_problems("lib", &hashes[2..]),
            "lib (SHA-512 digest is not 128 hex characters)"
        );
        assert_eq!(name_with_digest_problems("lib", &hashes[3..]), "lib");
    }

    /// A component carrying one external reference of `ref_type`.
    fn with_ref(name: &str, ref_type: crate::model::ExternalRefType) -> Component {
        let mut c = Component::new(name.to_string(), name.to_string());
        c.external_refs.push(ExternalReference {
            ref_type,
            url: format!("https://{name}.example/security"),
            comment: None,
            hashes: Vec::new(),
        });
        c
    }

    /// The scope is the described product: a third-party component outside
    /// the dependency graph is no root of it once the document names the
    /// product, and an SPDX document's other described roots join the
    /// primary.
    #[test]
    fn manufacturer_scope_is_the_described_product() {
        use crate::model::{DependencyEdge, DependencyType, ExternalRefType};
        let mut sbom = NormalizedSbom::default();
        let app = Component::new("app".to_string(), "app".to_string());
        let lib = Component::new("lib".to_string(), "lib".to_string());
        let orphan = with_ref("orphan", ExternalRefType::Advisories);
        let (app_id, lib_id, orphan_id) = (
            app.canonical_id.clone(),
            lib.canonical_id.clone(),
            orphan.canonical_id.clone(),
        );
        for c in [app, lib, orphan] {
            sbom.add_component(c);
        }
        sbom.edges.push(DependencyEdge::new(
            app_id.clone(),
            lib_id,
            DependencyType::DependsOn,
        ));
        let names = |sbom: &NormalizedSbom| -> Vec<String> {
            manufacturer_scope_components(sbom)
                .iter()
                .map(|c| c.name.clone())
                .collect()
        };
        let advisories = |sbom: &NormalizedSbom| {
            manufacturer_reference(sbom, |r| r.ref_type == ExternalRefType::Advisories)
        };

        // No product named: the graph roots, the orphan among them.
        assert_eq!(names(&sbom), vec!["app", "orphan"]);
        assert!(advisories(&sbom));

        // The primary named: the orphan dependency's references no longer
        // count for the product.
        sbom.set_primary_component(app_id);
        assert_eq!(names(&sbom), vec!["app"]);
        assert!(!advisories(&sbom));

        // A second described product is in scope, once.
        sbom.add_described_root(orphan_id.clone());
        sbom.add_described_root(orphan_id);
        assert_eq!(names(&sbom), vec!["app", "orphan"]);
        assert!(advisories(&sbom));
    }

    #[test]
    fn the_manufacturer_is_named_by_a_creator_the_supplier_or_the_product() {
        use crate::model::{Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        let mut app = Component::new("app".to_string(), "app".to_string());
        app.author = Some("Dana Developer".to_string());
        let app_id = app.canonical_id.clone();
        sbom.add_component(app);
        sbom.set_primary_component(app_id.clone());
        let mut lib = Component::new("lib".to_string(), "lib".to_string());
        lib.supplier = Some(Organization::new("Upstream Ltd".to_string()));
        sbom.add_component(lib);
        // A dependency's supplier and the product's author name no
        // manufacturer.
        assert!(!manufacturer_identified(&sbom));

        fn product<'a>(
            sbom: &'a mut NormalizedSbom,
            id: &crate::model::CanonicalId,
        ) -> &'a mut Component {
            sbom.components.get_mut(id).expect("the primary is listed")
        }
        for placeholder in ["NOASSERTION", "TBD", "n/a", " "] {
            product(&mut sbom, &app_id).manufacturer =
                Some(Organization::new(placeholder.to_string()));
            assert!(!manufacturer_identified(&sbom), "{placeholder:?}");
        }
        product(&mut sbom, &app_id).manufacturer = Some(Organization::new("Acme GmbH".to_string()));
        assert!(manufacturer_identified(&sbom));
        product(&mut sbom, &app_id).manufacturer = None;
        product(&mut sbom, &app_id).supplier = Some(Organization::new("Acme GmbH".to_string()));
        assert!(manufacturer_identified(&sbom));
        product(&mut sbom, &app_id).supplier = None;

        sbom.document.supplier = Some(Organization::new("NOASSERTION".to_string()));
        assert!(!manufacturer_identified(&sbom));
        sbom.document.supplier = Some(Organization::new("Acme GmbH".to_string()));
        assert!(manufacturer_identified(&sbom));
        sbom.document.supplier = None;

        let creator = |name: &str, email: Option<&str>| Creator {
            creator_type: CreatorType::Organization,
            name: name.to_string(),
            email: email.map(str::to_string),
        };
        sbom.document.creators = vec![creator("NOASSERTION", None)];
        assert!(!manufacturer_identified(&sbom));
        sbom.document.creators = vec![creator("N/A", Some("psirt@acme.example"))];
        assert!(
            manufacturer_identified(&sbom),
            "a known email identifies it"
        );
        sbom.document.creators = vec![creator("Acme GmbH", None)];
        assert!(manufacturer_identified(&sbom));
        sbom.document.creators[0].creator_type = CreatorType::Person;
        assert!(
            !manufacturer_identified(&sbom),
            "a person creator is no organization"
        );
    }

    /// The manufacturer's name comes from the first source that gives one,
    /// in the order `manufacturer_identified` reads them, and exists exactly
    /// when that test passes, but for a creator known by its email alone.
    #[test]
    fn the_manufacturer_name_follows_the_sources_in_order() {
        use crate::model::{Creator, CreatorType};
        let mut sbom = NormalizedSbom::default();
        let mut app = Component::new("app".to_string(), "app".to_string());
        app.supplier = Some(Organization::new("Product Supplier Ltd".to_string()));
        app.manufacturer = Some(Organization::new("Product Maker GmbH".to_string()));
        let app_id = app.canonical_id.clone();
        sbom.add_component(app);
        sbom.set_primary_component(app_id.clone());
        assert_eq!(manufacturer_name(&sbom), Some("Product Maker GmbH"));

        sbom.components
            .get_mut(&app_id)
            .expect("listed")
            .manufacturer = Some(Organization::new("NOASSERTION".to_string()));
        assert_eq!(manufacturer_name(&sbom), Some("Product Supplier Ltd"));

        sbom.document.supplier = Some(Organization::new("Document Supplier AG".to_string()));
        assert_eq!(manufacturer_name(&sbom), Some("Document Supplier AG"));

        let organization = |name: &str, email: Option<&str>| Creator {
            creator_type: CreatorType::Organization,
            name: name.to_string(),
            email: email.map(str::to_string),
        };
        sbom.document.creators = vec![
            organization("TBD", Some("sbom@acme.example")),
            organization("Acme Networks GmbH", None),
        ];
        assert_eq!(
            manufacturer_name(&sbom),
            Some("Acme Networks GmbH"),
            "the first organization creator with a name, a placeholder skipped"
        );

        // A creator known only by its email identifies the manufacturer but
        // gives no name.
        let mut email_only = NormalizedSbom::default();
        email_only.document.creators = vec![organization("N/A", Some("sbom@acme.example"))];
        assert!(manufacturer_identified(&email_only));
        assert_eq!(manufacturer_name(&email_only), None);
        assert!(!manufacturer_identified(&NormalizedSbom::default()));
        assert_eq!(manufacturer_name(&NormalizedSbom::default()), None);
    }

    #[test]
    fn a_licence_is_known_declared_unknown_or_missing() {
        use crate::model::LicenseExpression;
        let with = |declared: &[&str], concluded: Option<&str>| {
            let mut c = Component::new("lib".to_string(), "lib".to_string());
            for l in declared {
                c.licenses
                    .add_declared(LicenseExpression::new((*l).to_string()));
            }
            c.licenses.concluded = concluded.map(|l| LicenseExpression::new(l.to_string()));
            c
        };
        for known in [
            with(&["MIT"], None),
            with(&["LicenseRef-acme-proprietary"], None),
            with(&["NOASSERTION"], Some("Apache-2.0")),
            with(&["TBD", "MIT OR Apache-2.0"], None),
        ] {
            assert_eq!(license_state(&known), ValueState::Known);
            assert!(has_known_license(&known));
        }
        for declared_unknown in [with(&["NOASSERTION"], None), with(&["NONE", "TBD"], None)] {
            assert_eq!(
                license_state(&declared_unknown),
                ValueState::DeclaredUnknown
            );
            assert!(!has_known_license(&declared_unknown));
        }
        for missing in [
            with(&[], None),
            with(&["TBD"], None),
            with(&["N/A", " "], None),
        ] {
            assert_eq!(license_state(&missing), ValueState::Missing);
            assert!(!has_known_license(&missing));
        }
    }

    /// The values themselves are judged beside the placeholder list
    /// (`model::known`); this pins that the checks' helpers ask it.
    #[test]
    fn a_contact_must_reach_someone() {
        assert!(known_contact(Some("psirt@acme.example")));
        assert!(!known_contact(Some("NOASSERTION")));
        assert!(!known_contact(Some("security@example.com")));
        assert!(!known_contact(None));
        let reference = |ref_type, url: &str| ExternalReference {
            ref_type,
            url: url.to_string(),
            comment: None,
            hashes: Vec::new(),
        };
        assert!(is_contact_reference(&reference(
            ExternalRefType::Advisories,
            "https://acme.example/advisories"
        )));
        assert!(!is_contact_reference(&reference(
            ExternalRefType::Advisories,
            "https://example.com/advisories"
        )));
        assert!(!is_contact_reference(&reference(
            ExternalRefType::Vcs,
            "https://acme.example/repo.git"
        )));
    }

    #[test]
    fn an_eucc_reference_names_the_scheme_in_its_url() {
        let reference = |ref_type, url: &str| ExternalReference {
            ref_type,
            url: url.to_string(),
            comment: None,
            hashes: Vec::new(),
        };
        for url in [
            "https://certification.enisa.europa.eu/eucc/certificates/1.pdf",
            "https://lab.acme.example/Common-Criteria/cert.pdf",
            "https://www.commoncriteriaportal.org/files/epfiles/cert.pdf",
        ] {
            assert!(is_eucc_reference(&reference(
                ExternalRefType::Certification,
                url
            )));
            assert!(is_eucc_reference(&reference(
                ExternalRefType::Attestation,
                url
            )));
            assert!(
                !is_eucc_reference(&reference(ExternalRefType::Advisories, url)),
                "only a certification or attestation reference is a certificate"
            );
        }
        assert!(!is_eucc_reference(&reference(
            ExternalRefType::Certification,
            "https://notified-body.acme.example/certificates/0815.pdf"
        )));
    }

    #[test]
    fn only_a_timestamp_after_the_evaluation_instant_is_future_dated() {
        let ts = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .expect("test timestamp must parse")
                .with_timezone(&chrono::Utc)
        };
        let as_of = ts("2026-10-12T00:00:00Z");
        let dated = |created: chrono::DateTime<chrono::Utc>| {
            let mut sbom = NormalizedSbom::default();
            sbom.document.created = created;
            future_timestamp_violation(&sbom, as_of, "SBOM-PCI-6-3-2-FRESHNESS", "[PCI]", "req")
        };

        let future = dated(ts("2026-10-12T00:00:01Z")).expect("one second later is future");
        assert_eq!(future.severity, ViolationSeverity::Warning);
        assert_eq!(future.rule_id, "SBOM-PCI-6-3-2-FRESHNESS");
        assert!(
            future
                .message
                .starts_with("[PCI] SBOM creation timestamp 2026-10-12T00:00:01Z"),
            "the message names the document's timestamp: {}",
            future.message
        );
        assert!(
            !future.message.contains("2026-10-12T00:00:00Z"),
            "the evaluation instant stays out of the message: {}",
            future.message
        );

        // The instant itself and anything earlier are not in the future, and
        // a missing timestamp (the parsers' epoch sentinel) is reported by
        // the missing-timestamp branch instead.
        assert!(dated(as_of).is_none());
        assert!(dated(ts("2026-01-01T00:00:00Z")).is_none());
        assert!(dated(chrono::DateTime::UNIX_EPOCH).is_none());
    }
}
