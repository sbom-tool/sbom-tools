//! Small shared helpers reused across the compliance checkers.

use super::{Violation, ViolationCategory, ViolationSeverity};
use crate::model::{
    Component, ComponentType, CreatorType, ExternalReference, Hash, HashAlgorithm, NormalizedSbom,
    Organization,
};

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
    sbom.document
        .creators
        .iter()
        .any(|c| c.creator_type == CreatorType::Organization && creator_identified(c))
        || has_known_organization(sbom.document.supplier.as_ref())
        || sbom.described_components().iter().any(|c| {
            has_known_organization(c.manufacturer.as_ref())
                || has_known_organization(c.supplier.as_ref())
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

/// Placeholder values generators write instead of data (`TBD`, `N/A`, …).
/// Unlike the explicit sentinels (see [`is_declared_unknown`]) they declare
/// nothing, so they never satisfy an element in any standard. Curated
/// conservatively so genuine values are never flagged; CISA FSCT §2.3.1
/// calls these "ambiguous".
const PLACEHOLDERS: &[&str] = &[
    "tbd",
    "to be determined",
    "todo",
    "n/a",
    "n.a.",
    "placeholder",
    "unspecified",
    "not specified",
    "not available",
    "unavailable",
    "null",
    "nil",
    "undefined",
    "xxx",
    "-",
    "--",
    "?",
];

/// Whether `value` is a placeholder that declares nothing.
pub(crate) fn is_placeholder(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    PLACEHOLDERS.contains(&lower.as_str())
}

/// Whether `value` is one of the explicit sentinels SPDX and CycloneDX
/// producers write to assert that a value is unknown or absent
/// (`NOASSERTION`, `NONE`, `UNKNOWN`).
pub(crate) fn is_declared_unknown(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("NOASSERTION")
        || v.eq_ignore_ascii_case("NONE")
        || v.eq_ignore_ascii_case("UNKNOWN")
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
    org.is_some_and(|o| known_value(Some(o.name.as_str())).is_some())
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
/// declared or concluded (sentinels and placeholders do not count).
pub(crate) fn has_known_license(comp: &Component) -> bool {
    comp.licenses
        .all_licenses()
        .iter()
        .any(|l| known_value(Some(l.expression.as_str())).is_some())
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
