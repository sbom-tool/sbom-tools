//! Document-level facts: format and spec version, timestamp, creators, name,
//! serial number and revision, contacts, support period, completeness,
//! primary component, signature, lifecycle phase, declared profiles, the
//! kinds of creators.

use chrono::{DateTime, Utc};

use super::super::shared::{
    creator_identified, document_signed, is_declared_unknown, is_spdx2, is_valid_email_format,
    known_contact,
};
use super::{ComponentIx, Text};
use crate::model::{
    CanonicalId, CompletenessDeclaration, Creator, CreatorType, NormalizedSbom, SbomFormat,
    SpecVersion,
};

/// The document-level facts of an SBOM.
#[derive(Debug)]
pub(crate) struct DocumentFacts<'a> {
    /// The document's format.
    pub(crate) format: &'a SbomFormat,
    /// The spec version as the document gives it, for a finding's message.
    pub(crate) spec_version_raw: &'a str,
    /// The spec version as numbers, parsed once; `None` when it does not
    /// parse (see `DocumentMetadata::spec_version_parsed`).
    pub(crate) spec_version: Option<SpecVersion>,
    /// Whether the document carries a real creation timestamp (see
    /// `DocumentMetadata::has_known_timestamp`).
    pub(crate) has_known_timestamp: bool,
    /// The creation timestamp the document wrote but that does not parse,
    /// as read.
    pub(crate) created_unparsed: Option<&'a str>,
    /// The document's creators, in document order.
    pub(crate) creators: Box<[CreatorFacts<'a>]>,
    /// The document's name.
    pub(crate) name: Text<'a>,
    /// The document's serial number or namespace, as read.
    pub(crate) serial_number: Option<&'a str>,
    /// Whether the document's security contact reaches someone (see
    /// `shared::known_contact`).
    pub(crate) security_contact_reaches: bool,
    /// Whether the document's vulnerability-disclosure URL reaches someone.
    pub(crate) vulnerability_disclosure_url_reaches: bool,
    /// Whether the document states when security support ends.
    pub(crate) support_end_declared: bool,
    /// What the document declares about the completeness of its inventory.
    pub(crate) completeness: &'a CompletenessDeclaration,
    /// The id the document gives its primary component, whether or not a
    /// component has it.
    pub(crate) primary_declared: Option<&'a CanonicalId>,
    /// The primary component, when its id names a component.
    pub(crate) primary: Option<ComponentIx>,
    /// The creation timestamp as parsed: the Unix epoch when the document
    /// gives none or one that does not parse, so it means something only
    /// when [`Self::has_known_timestamp`].
    pub(crate) created: DateTime<Utc>,
    /// Whether the document carries an in-document signature with a value
    /// (see `shared::document_signed`).
    pub(crate) signed: bool,
    /// Whether the document carries a signature entry, with a value or not.
    pub(crate) signature_present: bool,
    /// Whether the document is SPDX and its spec version, as written,
    /// starts with `3.`. The CRA SPDX 3 profile checks ask this; the other
    /// checks read the parsed version ([`Self::spec_version`]), and the two
    /// differ on versions such as `3`, `SPDX-3.0` or `3.0.1-rc`.
    pub(crate) spdx3_by_prefix: bool,
    /// Whether a profile the document declares conforming to names the
    /// Security profile (any case).
    pub(crate) security_profile_declared: bool,
    /// Whether a profile the document declares conforming to names the
    /// SimpleLicensing profile (any case).
    pub(crate) licensing_profile_declared: bool,
    /// Whether a creator is a person or an organization, not a tool: BSI
    /// TR-03183-2's creator of the SBOM. Other standards judge the author
    /// differently: most accept any creator, and CISA 2026 and FSCT require
    /// a non-tool creator that is also identified.
    pub(crate) has_non_tool_creator: bool,
    /// Whether the document is SPDX 2.x, which has no field for a
    /// signature, a lifecycle phase or a completeness declaration (see
    /// `shared::is_spdx2`; an SPDX version that does not parse counts as
    /// 2.x).
    pub(crate) spdx2: bool,
    /// Whether a creator that is not a tool is identified by a real name or
    /// email address (see `shared::creator_identified`): the SBOM author of
    /// CISA 2026 and FSCT. BSI TR-03183-2 accepts any non-tool creator (see
    /// [`Self::has_non_tool_creator`]), the other standards any creator.
    pub(crate) has_identified_non_tool_creator: bool,
    /// The lifecycle phase the document was generated in.
    pub(crate) lifecycle_phase: Text<'a>,
    /// Whether a creator of the document is a tool, whatever its name.
    pub(crate) has_tool_creator: bool,
    /// Whether a tool creator's name carries a version or an explicit
    /// unknown, by CISA 2026's heuristic (see [`tool_name_carries_version`]):
    /// a digit in the name's last segment, or a sentinel word. FSCT reads a
    /// tool version differently.
    pub(crate) tool_version_discernible: bool,
    /// The document's revision counter (CycloneDX `version`), when it
    /// gives one.
    pub(crate) doc_version: Option<u32>,
    /// The document's serial number or namespace, and what it says. CISA
    /// 2026 asks for a real value; the checks that read
    /// [`Self::serial_number`] ask only that one is present.
    pub(crate) serial_number_text: Text<'a>,
    /// Whether a tool creator's name has a digit in it: FSCT's reading of a
    /// tool version. The parsers fold a tool's version into the tool
    /// creator's name ("name version"). CISA 2026 reads a tool version
    /// differently.
    pub(crate) tool_name_has_digit: bool,
    /// Whether a creator of the document is an organization, whatever its
    /// name, a placeholder such as `NOASSERTION` included. BSI/G7
    /// SBOM-for-AI accepts it as the AI system's producer; the manufacturer
    /// checks want an identified one (`ManufacturerFacts::identified`).
    pub(crate) has_organization_creator: bool,
    /// The data format's version as the document gives it (`1.6` for
    /// CycloneDX 1.6), for the checks that read it beside
    /// [`Self::spec_version_raw`].
    pub(crate) format_version: &'a str,
}

/// One creator of the document.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CreatorFacts<'a> {
    /// The creator as read: its kind, name and email.
    pub(crate) creator: &'a Creator,
    /// Whether its email address is well formed (see
    /// `shared::is_valid_email_format`); `None` when it gives none.
    pub(crate) email_well_formed: Option<bool>,
}

impl<'a> DocumentFacts<'a> {
    pub(super) fn collect(sbom: &'a NormalizedSbom) -> Self {
        let document = &sbom.document;
        let creators = document
            .creators
            .iter()
            .map(|creator| CreatorFacts {
                creator,
                email_well_formed: creator.email.as_deref().map(is_valid_email_format),
            })
            .collect();
        let primary = sbom
            .primary_component_id
            .as_ref()
            .and_then(|id| sbom.components.get_index_of(id))
            .map(ComponentIx);
        Self {
            format: &document.format,
            spec_version_raw: &document.spec_version,
            spec_version: document.spec_version_parsed(),
            has_known_timestamp: document.has_known_timestamp(),
            created_unparsed: document.created_unparsed.as_deref(),
            creators,
            name: Text::of(document.name.as_deref()),
            serial_number: document.serial_number.as_deref(),
            security_contact_reaches: known_contact(document.security_contact.as_deref()),
            vulnerability_disclosure_url_reaches: known_contact(
                document.vulnerability_disclosure_url.as_deref(),
            ),
            support_end_declared: document.support_end_date.is_some(),
            completeness: &document.completeness_declaration,
            primary_declared: sbom.primary_component_id.as_ref(),
            primary,
            created: document.created,
            signed: document_signed(sbom),
            signature_present: document.signature.is_some(),
            spdx3_by_prefix: document.format == SbomFormat::Spdx
                && document.spec_version.starts_with("3."),
            security_profile_declared: declares_profile(&document.profile_conformance, "security"),
            licensing_profile_declared: declares_profile(
                &document.profile_conformance,
                "licensing",
            ),
            has_non_tool_creator: document
                .creators
                .iter()
                .any(|c| c.creator_type != CreatorType::Tool),
            spdx2: is_spdx2(sbom),
            has_identified_non_tool_creator: document
                .creators
                .iter()
                .any(|c| c.creator_type != CreatorType::Tool && creator_identified(c)),
            lifecycle_phase: Text::of(document.lifecycle_phase.as_deref()),
            has_tool_creator: document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Tool),
            tool_version_discernible: document
                .creators
                .iter()
                .filter(|c| c.creator_type == CreatorType::Tool)
                .any(|t| tool_name_carries_version(&t.name)),
            doc_version: document.doc_version,
            serial_number_text: Text::of(document.serial_number.as_deref()),
            tool_name_has_digit: document
                .creators
                .iter()
                .filter(|c| c.creator_type == CreatorType::Tool)
                .any(|t| t.name.chars().any(|ch| ch.is_ascii_digit())),
            has_organization_creator: document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization),
            format_version: &document.format_version,
        }
    }
}

/// Whether a declared profile's name contains `keyword`, in any case.
fn declares_profile(profiles: &[String], keyword: &str) -> bool {
    profiles.iter().any(|p| p.to_lowercase().contains(keyword))
}

/// Explicit-unknown sentinel: the marker an SBOM author uses to state that a
/// value is unknown rather than silently omitting it. The 2026 elements'
/// escape hatches ("the SBOM author should indicate the information is
/// unknown") make these markers *satisfy* the honesty requirement, so this
/// is deliberately the complement of `known_value` (which treats the same
/// sentinels as absent for the NTIA-style presence gates).
fn is_unknown_marker(value: &str) -> bool {
    is_declared_unknown(value)
}

/// Heuristic for the SBOM Tool Version element: whether a Tool creator's
/// name carries a version identifier (or an explicit unknown marker).
///
/// Heuristic by necessity: the parsers concatenate tool name and version
/// into one creator name — CycloneDX `metadata.tools` becomes
/// `"{name} {version}"` and the SPDX `Creator: Tool:` convention is
/// `name-version` — so there is no dedicated tool-version field to check.
/// A trailing whitespace- or hyphen-delimited segment containing an ASCII
/// digit counts as a version; a tool genuinely named with a trailing digit
/// (e.g. "syft2") is an accepted false pass, which is why the rule is a
/// Warning with heuristic wording rather than an Error.
pub(super) fn tool_name_carries_version(name: &str) -> bool {
    let name = name.trim();
    // The element's escape hatch: an explicit unknown marker satisfies it.
    if name.split_whitespace().any(is_unknown_marker) {
        return true;
    }
    let last_ws = name.rsplit(char::is_whitespace).next().unwrap_or(name);
    let last_seg = last_ws.rsplit('-').next().unwrap_or(last_ws);
    last_seg.chars().any(|c| c.is_ascii_digit())
}
