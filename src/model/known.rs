//! Whether a value an SBOM gives carries information.
//!
//! Generators write placeholders (`TBD`, `N/A`) and sentinels (`NOASSERTION`,
//! `NONE`, `UNKNOWN`) where they have no value. The compliance checks never
//! count one as the element they ask for (`quality::compliance`'s
//! `value_state` classifies with these helpers), and the merge of a
//! component's entries never keeps one over a real value. A contact also
//! has to reach someone: an address at a documentation domain such as
//! `example.com` is a template value ([`is_known_contact`]).

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

/// Whether `value` carries information: it is not empty or blank, not a
/// sentinel ([`is_declared_unknown`]) and not a placeholder
/// ([`is_placeholder`]).
pub(crate) fn is_known(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && !is_placeholder(v) && !is_declared_unknown(v)
}

/// The domains RFC 2606 §3 reserves for documentation. Generator templates
/// and the format specifications' examples use them, so a contact at one of
/// them is a template value nobody filled in. The top-level domains RFC 2606
/// §2 reserves (`.example`, `.test`, `.invalid`, `.localhost`) are not on
/// the list: test data, this project's fixtures among it, uses them for a
/// stand-in real domain, and generator templates do not ship them.
const DOCUMENTATION_DOMAINS: [&str; 3] = ["example.com", "example.net", "example.org"];

/// The host an email address or URL points at, lowercased: the domain after
/// the last `@` of an address, or the host of a `scheme://` URL (without
/// its user, port or path). For other text, the host characters it starts
/// with.
fn address_host(value: &str) -> String {
    let value = value.trim();
    let after_scheme = value.find("://").map_or(value, |i| &value[i + 3..]);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect::<String>()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Whether `value`, an email address or URL, points at one of the
/// documentation domains or a host under one, such as `psirt.example.com`.
fn is_documentation_address(value: &str) -> bool {
    let host = address_host(value);
    DOCUMENTATION_DOMAINS.into_iter().any(|domain| {
        host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|sub| sub.ends_with('.'))
    })
}

/// Whether `value` is a contact that reaches someone: an email address, URL
/// or other text naming whom to write to. A `mailto:` prefix is ignored. The
/// rest must be known ([`is_known`]: not a sentinel such as `NOASSERTION` or
/// `unknown`, not a placeholder such as `n/a` or `TBD`) and no address at a
/// documentation domain: `example.com`, `example.net`, `example.org` or a
/// host under one.
pub(crate) fn is_known_contact(value: &str) -> bool {
    let value = value.trim();
    let rest = match value.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("mailto:") => &value[7..],
        _ => value,
    };
    is_known(rest) && !is_documentation_address(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinels_placeholders_and_blanks_are_not_known() {
        for value in [
            "",
            "  ",
            "NOASSERTION",
            "none",
            "Unknown",
            "TBD",
            "n/a",
            "-",
            " null ",
        ] {
            assert!(!is_known(value), "{value:?}");
        }
        for value in [
            "MIT",
            "Acme Corp",
            "1.0.0",
            "none-such",
            "pkg:npm/none@1.0.0",
        ] {
            assert!(is_known(value), "{value:?}");
        }
    }

    #[test]
    fn a_contact_must_reach_someone() {
        for reachable in [
            "psirt@acme.example",
            "mailto:psirt@acme.example",
            "https://acme.example/security",
            "Security Team <security@acme.example>",
            "+49 30 1234567",
            // Look-alikes of the documentation domains are real domains.
            "security@notexample.com",
            "https://example.com.acme.example/security",
            "security@example.com.au",
            "https://example.community/security",
        ] {
            assert!(is_known_contact(reachable), "{reachable:?}");
        }
        for nobody in [
            "",
            " ",
            "NOASSERTION",
            "unknown",
            "NONE",
            "n/a",
            "TBD",
            "mailto:",
            "MAILTO:n/a",
            "security@example.com",
            "mailto:Security@EXAMPLE.COM",
            "https://example.org/security",
            "https://psirt.example.net:8443/report?id=1",
            "https://user@example.com/",
            "Security Team <security@example.com>",
            "example.com/security",
            "https://example.com./security",
        ] {
            assert!(!is_known_contact(nobody), "{nobody:?}");
        }
    }
}
