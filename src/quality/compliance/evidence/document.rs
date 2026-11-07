//! Document-level facts: format and spec version, timestamp, creators, name,
//! serial number, contacts, support period, completeness, primary component.

use chrono::{DateTime, Utc};

use super::super::shared::{is_valid_email_format, known_contact};
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
    /// The creation timestamp as parsed. The parsers write the Unix epoch
    /// when the document gives none or it does not parse, so it means
    /// something only when [`Self::has_known_timestamp`].
    pub(crate) created: DateTime<Utc>,
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
        }
    }
}
