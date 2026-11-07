//! Document-level facts: format and spec version, timestamp, creators, name,
//! serial number, contacts, support period, completeness, primary component,
//! signature, declared profiles.

use chrono::{DateTime, Utc};

use super::super::shared::{document_signed, is_valid_email_format, known_contact};
use super::{ComponentIx, Text};
use crate::model::{
    CanonicalId, CompletenessDeclaration, Creator, NormalizedSbom, SbomFormat, SpecVersion,
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
    /// The creation timestamp as parsed: the epoch when the document gives
    /// none or one that does not parse (see [`Self::has_known_timestamp`]).
    pub(crate) created: DateTime<Utc>,
    /// Whether the document carries a signature with a value (see
    /// `shared::document_signed`).
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
        }
    }
}

/// Whether a declared profile's name contains `keyword`, in any case.
fn declares_profile(profiles: &[String], keyword: &str) -> bool {
    profiles.iter().any(|p| p.to_lowercase().contains(keyword))
}
