//! The post-quantum migration calendar behind `--pqc-mode deadline`.
//!
//! Readiness mode, the default, reports every quantum-vulnerable algorithm
//! as an Error: today's strict view. Deadline mode judges the same findings
//! by the transition schedules at the evaluation date (`--as-of`, else
//! today), and every finding a schedule dates carries its [`Deadline`]:
//!
//! - NIST PQC (`pqc`), NIST IR 8547 (final, October 2026): the
//!   quantum-vulnerable signature and key-establishment schemes of Tables 2
//!   and 4 (ECDSA, EdDSA, RSA, finite-field and elliptic-curve DH and MQV)
//!   at 112 bits of classical security or more are "Deprecated after 2030"
//!   and "Disallowed after 2035": Info through 2030, Warning through 2035,
//!   Error after. Its symmetric rows apply where the checks judge them:
//!   SHA-1 is deprecated now and disallowed after 2030 (Table 8, note 4:
//!   Warning, then Error), and the 112-bit security level is disallowed
//!   after 2030 (§4.1.3: Info, then Error).
//! - [`PqcProfile::Federal`] adds the deadlines of federal high value
//!   assets and high impact systems: post-quantum key establishment by
//!   2030-12-31 and post-quantum signatures by 2031-12-31 (EO 14412
//!   §4(b)(ii) and (iii), OMB M-26-15), Warning until then and Error after,
//!   and TLS 1.3 by 2030-01-02 (EO 14306, OMB M-26-15).
//! - CNSA 2.0 (`cnsa2`), NSA's timeline (CSA PP-22-1338, Sept 2022): a CNSA
//!   1.0 algorithm or protocol, which stays allowed in the interim (ECDH or
//!   ECDSA over P-384, RSA or DH of 3072 bits or more, TLS 1.2), is Info
//!   until its equipment category must support and prefer CNSA 2.0, Warning
//!   until it must use CNSA 2.0 exclusively, and Error after.
//!   [`CnsaCategory`] picks the category; unset, the strictest applies.
//!
//! "By 2030" and "after 2030" both turn on 2030-12-31: a deadline is the
//! last day before a finding escalates, or, for an Error, the last day the
//! algorithm was allowed. A finding no schedule dates keeps its readiness
//! severity and carries no deadline: an algorithm already disallowed with
//! no transition (MD5, DES, RSA below 2048 bits), one IR 8547 does not list
//! (DSA, SM2), one that is not CNSA 1.0 either, ECB mode, and every finding
//! about evidence the checks cannot read (an unidentified algorithm, a
//! missing quantum level, an empty inventory).

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::ViolationSeverity;

/// How the crypto standards (`cnsa2`, `pqc`) judge quantum-vulnerable
/// cryptography: CLI `--pqc-mode`, [`super::ComplianceChecker::with_pqc_mode`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PqcMode {
    /// Today's strict view: every quantum-vulnerable algorithm is an error
    #[default]
    Readiness,
    /// By the migration calendar at the evaluation date: each finding names
    /// its deadline and the schedule that sets it
    Deadline,
}

/// Whose deadlines [`PqcMode::Deadline`] applies under NIST PQC (`pqc`):
/// CLI `--pqc-profile`, [`super::ComplianceChecker::with_pqc_profile`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PqcProfile {
    /// NIST IR 8547: deprecated after 2030, disallowed after 2035
    #[default]
    Nist,
    /// IR 8547 plus the federal deadlines for high value assets and high
    /// impact systems (EO 14412, OMB M-26-15)
    Federal,
}

/// A CNSA 2.0 equipment category of NSA's timeline (CSA "Announcing the
/// Commercial National Security Algorithm Suite 2.0", PP-22-1338, Sept
/// 2022): the year by which CNSA 2.0 is to be supported and preferred, and
/// the year by which it is to be used exclusively. CLI `--cnsa-category`,
/// [`super::ComplianceChecker::with_cnsa_category`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CnsaCategory {
    /// Software and firmware signing: preferred by 2025, exclusive by 2030
    SoftwareSigning,
    /// Web browsers, servers and cloud services: preferred by 2025,
    /// exclusive by 2033
    WebCloud,
    /// Traditional networking equipment (VPNs, routers): preferred by 2026,
    /// exclusive by 2030
    Networking,
    /// Operating systems: preferred by 2027, exclusive by 2033
    OperatingSystems,
    /// Niche equipment (constrained devices, large PKI systems): preferred by
    /// 2030, exclusive by 2033
    Niche,
    /// Custom applications and legacy equipment: updated or replaced by 2033
    CustomLegacy,
}

impl CnsaCategory {
    /// Every category, in the order of NSA's timeline.
    pub const ALL: [Self; 6] = [
        Self::SoftwareSigning,
        Self::WebCloud,
        Self::Networking,
        Self::OperatingSystems,
        Self::Niche,
        Self::CustomLegacy,
    ];

    /// The category as NSA's timeline names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SoftwareSigning => "software and firmware signing",
            Self::WebCloud => "web browsers, servers and cloud services",
            Self::Networking => "traditional networking equipment",
            Self::OperatingSystems => "operating systems",
            Self::Niche => "niche equipment",
            Self::CustomLegacy => "custom applications and legacy equipment",
        }
    }

    /// The year by which the category is to support and prefer CNSA 2.0;
    /// `None` for custom applications and legacy equipment, which the
    /// timeline only has updated or replaced.
    #[must_use]
    pub const fn preferred_by(self) -> Option<i32> {
        match self {
            Self::SoftwareSigning | Self::WebCloud => Some(2025),
            Self::Networking => Some(2026),
            Self::OperatingSystems => Some(2027),
            Self::Niche => Some(2030),
            Self::CustomLegacy => None,
        }
    }

    /// The year by which the category is to use CNSA 2.0 exclusively.
    #[must_use]
    pub const fn exclusive_by(self) -> i32 {
        match self {
            Self::SoftwareSigning | Self::Networking => 2030,
            Self::WebCloud | Self::OperatingSystems | Self::Niche | Self::CustomLegacy => 2033,
        }
    }
}

/// When the algorithm a finding is about must be replaced, and the schedule
/// that says so. Only [`PqcMode::Deadline`] dates findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Deadline {
    /// The milestone the finding is judged against: the last day before its
    /// severity rises, or, for an Error, the last day the algorithm was
    /// allowed.
    pub date: NaiveDate,
    /// The schedule that sets it, e.g. `NIST IR 8547 Table 4`.
    pub source: String,
}

/// A calendar date, checked when the constant is built.
const fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    match NaiveDate::from_ymd_opt(year, month, day) {
        Some(d) => d,
        None => panic!("invalid calendar date"),
    }
}

/// The last day of `year`, which "by `year`" and "after `year`" turn on.
const fn end_of(year: i32) -> NaiveDate {
    date(year, 12, 31)
}

/// NIST IR 8547 Tables 2 and 4: quantum-vulnerable public-key schemes are
/// "Deprecated after 2030" and "Disallowed after 2035". SHA-1 (Table 8,
/// note 4) and the 112-bit security level (§4.1.3) are disallowed after
/// 2030 too.
const NIST_DEPRECATED_AFTER: i32 = 2030;
const NIST_DISALLOWED_AFTER: i32 = 2035;

/// EO 14412 §4(b)(ii) and (iii), OMB M-26-15: federal high value assets and
/// high impact systems use post-quantum key establishment by 2030-12-31 and
/// post-quantum signatures by 2031-12-31.
const FEDERAL_KEY_ESTABLISHMENT_BY: NaiveDate = end_of(2030);
const FEDERAL_SIGNATURES_BY: NaiveDate = end_of(2031);

/// EO 14306, OMB M-26-15: agencies "support Transport Layer Security (TLS)
/// protocol version 1.3 or a successor version as soon as practicable, but
/// not later than January 2, 2030".
const FEDERAL_TLS13_BY: NaiveDate = date(2030, 1, 2);

const FEDERAL_PQC_SOURCE_KEY_ESTABLISHMENT: &str = "EO 14412 §4(b)(ii), OMB M-26-15";
const FEDERAL_PQC_SOURCE_SIGNATURES: &str = "EO 14412 §4(b)(iii), OMB M-26-15";
const FEDERAL_TLS13_SOURCE: &str = "EO 14306, OMB M-26-15";

/// What a quantum-vulnerable public-key algorithm is used for, which picks
/// its IR 8547 table and its federal deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PkUse {
    /// A digital signature (IR 8547 Table 2).
    Signature,
    /// Key establishment: key agreement, key transport, a KEM (Table 4).
    KeyEstablishment,
    /// The SBOM does not say, as for RSA without a primitive: both tables
    /// apply, and of the federal deadlines the earlier one.
    Unstated,
}

/// A finding a schedule dates: its severity on the date judged, its
/// deadline, and what the schedule says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dated {
    pub(crate) severity: ViolationSeverity,
    pub(crate) deadline: Deadline,
    /// What the schedule says, with its source: "deprecated after 2030 and
    /// disallowed after 2035 (NIST IR 8547 Table 4)".
    pub(crate) status: String,
}

impl Dated {
    fn new(severity: ViolationSeverity, date: NaiveDate, source: &str, phrase: &str) -> Self {
        Self {
            severity,
            deadline: Deadline {
                date,
                source: source.to_string(),
            },
            status: format!("{phrase} ({source})"),
        }
    }
}

/// How deadline mode judges one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CalendarVerdict {
    /// A schedule dates it.
    Dated(Dated),
    /// No schedule dates it, for this reason: it keeps its readiness Error.
    Undated(String),
}

impl CalendarVerdict {
    /// The severity the finding takes: a dated one's, else the readiness
    /// Error.
    pub(crate) const fn severity(&self) -> ViolationSeverity {
        match self {
            Self::Dated(d) => d.severity,
            Self::Undated(_) => ViolationSeverity::Error,
        }
    }

    /// The more urgent of two verdicts, which decides a finding about
    /// several algorithms: the higher severity; between two Errors an
    /// undated one, which is due now; else the earlier deadline.
    #[must_use]
    pub(crate) fn most_urgent(self, other: Self) -> Self {
        let rank = |v: &Self| match v.severity() {
            ViolationSeverity::Error => 2,
            ViolationSeverity::Warning => 1,
            _ => 0,
        };
        match rank(&self).cmp(&rank(&other)) {
            std::cmp::Ordering::Greater => self,
            std::cmp::Ordering::Less => other,
            std::cmp::Ordering::Equal => match (&self, &other) {
                (Self::Undated(_), _) => self,
                (_, Self::Undated(_)) => other,
                (Self::Dated(a), Self::Dated(b)) => {
                    if b.deadline.date < a.deadline.date {
                        other
                    } else {
                        self
                    }
                }
            },
        }
    }
}

/// The calendar [`PqcMode::Deadline`] judges by: the profile, the CNSA 2.0
/// category and the evaluation date.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Calendar {
    profile: PqcProfile,
    cnsa_category: Option<CnsaCategory>,
    /// The evaluation date (`--as-of`, else today).
    pub(crate) today: NaiveDate,
}

impl Calendar {
    pub(crate) const fn new(
        profile: PqcProfile,
        cnsa_category: Option<CnsaCategory>,
        today: NaiveDate,
    ) -> Self {
        Self {
            profile,
            cnsa_category,
            today,
        }
    }

    /// A quantum-vulnerable public-key scheme IR 8547 lists, used for
    /// `pk_use`, at 112 bits of classical security or more (or of unknown
    /// strength), judged on `on`: NIST IR 8547 Tables 2 and 4, or the
    /// earlier federal deadline under [`PqcProfile::Federal`].
    pub(crate) fn public_key(&self, pk_use: PkUse, on: NaiveDate) -> Dated {
        match self.profile {
            PqcProfile::Nist => ir8547_public_key(pk_use, on),
            PqcProfile::Federal => federal_public_key(pk_use, on),
        }
    }

    /// SHA-1 outside a signature, judged on `on`: NIST IR 8547 Table 8,
    /// note 4, "currently deprecated for all remaining technical
    /// applications and will be disallowed for use in FIPS-validated
    /// cryptographic modules after 2030".
    pub(crate) fn sha1(on: NaiveDate) -> Dated {
        let source = "NIST IR 8547 Table 8";
        if on <= end_of(NIST_DEPRECATED_AFTER) {
            Dated::new(
                ViolationSeverity::Warning,
                end_of(NIST_DEPRECATED_AFTER),
                source,
                "SHA-1 is deprecated and disallowed after 2030",
            )
        } else {
            Dated::new(
                ViolationSeverity::Error,
                end_of(NIST_DEPRECATED_AFTER),
                source,
                "SHA-1 is disallowed since 2031",
            )
        }
    }

    /// A symmetric key of 112 to 127 bits, judged on `on`: NIST IR 8547
    /// §4.1.3, "NIST has a few symmetric cryptography standards at the
    /// 112-bit security level, which will be disallowed in 2030".
    pub(crate) fn symmetric_112(on: NaiveDate) -> Dated {
        let source = "NIST IR 8547 §4.1.3";
        if on <= end_of(NIST_DEPRECATED_AFTER) {
            Dated::new(
                ViolationSeverity::Info,
                end_of(NIST_DEPRECATED_AFTER),
                source,
                "the 112-bit security level is disallowed after 2030",
            )
        } else {
            Dated::new(
                ViolationSeverity::Error,
                end_of(NIST_DEPRECATED_AFTER),
                source,
                "the 112-bit security level is disallowed since 2031",
            )
        }
    }

    /// TLS below 1.3 under [`PqcProfile::Federal`], judged on the
    /// evaluation date: agencies support TLS 1.3 by 2030-01-02. `None`
    /// under the NIST profile, which sets no TLS deadline.
    pub(crate) fn federal_tls13(&self) -> Option<Dated> {
        if self.profile != PqcProfile::Federal {
            return None;
        }
        Some(if self.today <= FEDERAL_TLS13_BY {
            Dated::new(
                ViolationSeverity::Warning,
                FEDERAL_TLS13_BY,
                FEDERAL_TLS13_SOURCE,
                "federal agencies must support TLS 1.3 by 2030-01-02",
            )
        } else {
            Dated::new(
                ViolationSeverity::Error,
                FEDERAL_TLS13_BY,
                FEDERAL_TLS13_SOURCE,
                "federal agencies had to support TLS 1.3 by 2030-01-02",
            )
        })
    }

    /// A CNSA 1.0 algorithm or protocol, which CNSA 2.0 replaces, judged on
    /// `on` by the timeline of the configured category, else the strictest
    /// one (supported and preferred by 2025, exclusive by 2030).
    pub(crate) fn cnsa1(&self, on: NaiveDate) -> Dated {
        let (category, preferred_by, exclusive_by) = match self.cnsa_category {
            Some(c) => (c.label(), c.preferred_by(), c.exclusive_by()),
            None => ("strictest category", Some(2025), 2030),
        };
        let source = format!("CNSA 2.0 timeline: {category}");
        let exclusive = end_of(exclusive_by);
        if on > exclusive {
            let phrase = match preferred_by {
                Some(_) => format!(
                    "CNSA 2.0 is to be used exclusively since {}",
                    exclusive_by + 1
                ),
                None => format!(
                    "custom applications and legacy equipment were to be updated or \
                     replaced by {exclusive_by}"
                ),
            };
            return Dated::new(ViolationSeverity::Error, exclusive, &source, &phrase);
        }
        match preferred_by {
            Some(year) if on <= end_of(year) => Dated::new(
                ViolationSeverity::Info,
                end_of(year),
                &source,
                &format!(
                    "allowed under CNSA 1.0 until CNSA 2.0 is to be supported and preferred \
                     by {year} and used exclusively by {exclusive_by}"
                ),
            ),
            Some(year) => Dated::new(
                ViolationSeverity::Warning,
                exclusive,
                &source,
                &format!(
                    "CNSA 2.0 is to be preferred since {} and used exclusively by \
                     {exclusive_by}",
                    year + 1
                ),
            ),
            None => Dated::new(
                ViolationSeverity::Warning,
                exclusive,
                &source,
                &format!(
                    "custom applications and legacy equipment are to be updated or replaced \
                     by {exclusive_by}"
                ),
            ),
        }
    }
}

/// NIST IR 8547 Tables 2 and 4, judged on `on`.
fn ir8547_public_key(pk_use: PkUse, on: NaiveDate) -> Dated {
    let source = match pk_use {
        PkUse::Signature => "NIST IR 8547 Table 2",
        PkUse::KeyEstablishment => "NIST IR 8547 Table 4",
        PkUse::Unstated => "NIST IR 8547 Tables 2 and 4",
    };
    let deprecated = end_of(NIST_DEPRECATED_AFTER);
    let disallowed = end_of(NIST_DISALLOWED_AFTER);
    if on <= deprecated {
        Dated::new(
            ViolationSeverity::Info,
            deprecated,
            source,
            "deprecated after 2030 and disallowed after 2035",
        )
    } else if on <= disallowed {
        Dated::new(
            ViolationSeverity::Warning,
            disallowed,
            source,
            "deprecated since 2031 and disallowed after 2035",
        )
    } else {
        Dated::new(
            ViolationSeverity::Error,
            disallowed,
            source,
            "disallowed since 2036",
        )
    }
}

/// The federal deadline of `pk_use` (the earlier one when the SBOM does not
/// say), judged on `on`: a Warning until it, an Error after.
fn federal_public_key(pk_use: PkUse, on: NaiveDate) -> Dated {
    let (by, source, what) = match pk_use {
        PkUse::Signature => (
            FEDERAL_SIGNATURES_BY,
            FEDERAL_PQC_SOURCE_SIGNATURES,
            "post-quantum signatures by 2031-12-31",
        ),
        PkUse::KeyEstablishment | PkUse::Unstated => (
            FEDERAL_KEY_ESTABLISHMENT_BY,
            FEDERAL_PQC_SOURCE_KEY_ESTABLISHMENT,
            "post-quantum key establishment by 2030-12-31",
        ),
    };
    // Whether it signs or establishes keys is not said: the earlier deadline
    // applies, and the message says why.
    let unstated = if pk_use == PkUse::Unstated {
        "; the SBOM does not say whether it signs or establishes keys, so the earlier \
         deadline applies"
    } else {
        ""
    };
    if on <= by {
        Dated::new(
            ViolationSeverity::Warning,
            by,
            source,
            &format!("federal high value assets and high impact systems must use {what}{unstated}"),
        )
    } else {
        Dated::new(
            ViolationSeverity::Error,
            by,
            source,
            &format!(
                "federal high value assets and high impact systems had to use {what}{unstated}"
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("test date parses")
    }

    fn nist(on: &str) -> Dated {
        Calendar::new(PqcProfile::Nist, None, day(on)).public_key(PkUse::Signature, day(on))
    }

    /// IR 8547 Tables 2 and 4: Info through 2030, Warning through 2035,
    /// Error after; the deadline is the next milestone, then the last one.
    #[test]
    fn ir8547_public_key_milestones_turn_on_the_last_day_of_the_year() {
        let cases = [
            ("2026-10-12", ViolationSeverity::Info, "2030-12-31"),
            ("2030-12-31", ViolationSeverity::Info, "2030-12-31"),
            ("2031-01-01", ViolationSeverity::Warning, "2035-12-31"),
            ("2035-12-31", ViolationSeverity::Warning, "2035-12-31"),
            ("2036-01-01", ViolationSeverity::Error, "2035-12-31"),
        ];
        for (on, severity, deadline) in cases {
            let dated = nist(on);
            assert_eq!(dated.severity, severity, "{on}");
            assert_eq!(dated.deadline.date, day(deadline), "{on}");
            assert_eq!(dated.deadline.source, "NIST IR 8547 Table 2", "{on}");
        }
        let key = Calendar::new(PqcProfile::Nist, None, day("2026-10-12"))
            .public_key(PkUse::KeyEstablishment, day("2026-10-12"));
        assert_eq!(key.deadline.source, "NIST IR 8547 Table 4");
        assert!(
            key.status.ends_with("(NIST IR 8547 Table 4)"),
            "{}",
            key.status
        );
    }

    /// The federal deadlines: key establishment by 2030-12-31, signatures by
    /// 2031-12-31, the earlier one when the use is not stated.
    #[test]
    fn federal_deadlines_split_key_establishment_and_signatures() {
        let at = |on: &str, pk_use| {
            Calendar::new(PqcProfile::Federal, None, day(on)).public_key(pk_use, day(on))
        };
        let ke = at("2030-12-31", PkUse::KeyEstablishment);
        assert_eq!(ke.severity, ViolationSeverity::Warning);
        assert_eq!(ke.deadline.date, day("2030-12-31"));
        assert_eq!(ke.deadline.source, FEDERAL_PQC_SOURCE_KEY_ESTABLISHMENT);
        assert_eq!(
            at("2031-01-01", PkUse::KeyEstablishment).severity,
            ViolationSeverity::Error
        );
        let sig = at("2031-06-01", PkUse::Signature);
        assert_eq!(sig.severity, ViolationSeverity::Warning);
        assert_eq!(sig.deadline.date, day("2031-12-31"));
        assert_eq!(
            at("2032-01-01", PkUse::Signature).severity,
            ViolationSeverity::Error
        );
        let unstated = at("2031-06-01", PkUse::Unstated);
        assert_eq!(unstated.severity, ViolationSeverity::Error);
        assert_eq!(unstated.deadline.date, day("2030-12-31"));
        assert!(
            unstated.status.contains("does not say"),
            "{}",
            unstated.status
        );
    }

    #[test]
    fn federal_tls13_applies_only_to_the_federal_profile() {
        let nist = Calendar::new(PqcProfile::Nist, None, day("2026-10-12"));
        assert!(nist.federal_tls13().is_none());
        let before = Calendar::new(PqcProfile::Federal, None, day("2030-01-02"));
        let dated = before.federal_tls13().expect("federal profile dates TLS");
        assert_eq!(dated.severity, ViolationSeverity::Warning);
        assert_eq!(dated.deadline.date, day("2030-01-02"));
        let after = Calendar::new(PqcProfile::Federal, None, day("2030-01-03"));
        assert_eq!(
            after.federal_tls13().map(|d| d.severity),
            Some(ViolationSeverity::Error)
        );
    }

    #[test]
    fn sha1_and_the_112_bit_level_are_disallowed_after_2030() {
        assert_eq!(
            Calendar::sha1(day("2030-12-31")).severity,
            ViolationSeverity::Warning
        );
        assert_eq!(
            Calendar::sha1(day("2031-01-01")).severity,
            ViolationSeverity::Error
        );
        assert_eq!(
            Calendar::symmetric_112(day("2026-10-12")).severity,
            ViolationSeverity::Info
        );
        let after = Calendar::symmetric_112(day("2031-01-01"));
        assert_eq!(after.severity, ViolationSeverity::Error);
        assert_eq!(after.deadline.date, day("2030-12-31"));
        assert_eq!(after.deadline.source, "NIST IR 8547 §4.1.3");
    }

    /// Each category's two milestones, and the strictest when none is set.
    #[test]
    fn cnsa_categories_have_their_own_milestones() {
        let at = |category, on: &str| Calendar::new(PqcProfile::Nist, category, day(on));
        // Unset: the strictest, preferred by 2025 and exclusive by 2030.
        let strictest = at(None, "2026-10-12").cnsa1(day("2026-10-12"));
        assert_eq!(strictest.severity, ViolationSeverity::Warning);
        assert_eq!(strictest.deadline.date, day("2030-12-31"));
        assert_eq!(
            strictest.deadline.source,
            "CNSA 2.0 timeline: strictest category"
        );
        let niche = at(Some(CnsaCategory::Niche), "2026-10-12").cnsa1(day("2026-10-12"));
        assert_eq!(niche.severity, ViolationSeverity::Info);
        assert_eq!(niche.deadline.date, day("2030-12-31"));
        let niche_2031 = at(Some(CnsaCategory::Niche), "2031-06-01").cnsa1(day("2031-06-01"));
        assert_eq!(niche_2031.severity, ViolationSeverity::Warning);
        assert_eq!(niche_2031.deadline.date, day("2033-12-31"));
        let legacy = at(Some(CnsaCategory::CustomLegacy), "2026-10-12").cnsa1(day("2026-10-12"));
        assert_eq!(legacy.severity, ViolationSeverity::Warning);
        assert_eq!(legacy.deadline.date, day("2033-12-31"));
        for category in CnsaCategory::ALL {
            let after = at(Some(category), "2034-01-01").cnsa1(day("2034-01-01"));
            assert_eq!(after.severity, ViolationSeverity::Error, "{category:?}");
            assert_eq!(
                after.deadline.date,
                end_of(category.exclusive_by()),
                "{category:?}"
            );
            assert!(after.deadline.source.ends_with(category.label()));
        }
        // No category is stricter than the default.
        for category in CnsaCategory::ALL {
            assert!(category.exclusive_by() >= 2030);
            assert!(category.preferred_by().is_none_or(|year| year >= 2025));
        }
    }

    #[test]
    fn the_most_urgent_verdict_decides() {
        let dated = |on: &str| CalendarVerdict::Dated(nist(on));
        let info = dated("2026-10-12");
        let warning = dated("2031-06-01");
        let undated = CalendarVerdict::Undated("no transition".to_string());
        assert_eq!(info.clone().most_urgent(warning.clone()), warning);
        assert_eq!(warning.clone().most_urgent(info.clone()), warning);
        assert_eq!(warning.clone().most_urgent(undated.clone()), undated);
        let error = dated("2036-06-01");
        assert_eq!(error.clone().most_urgent(undated.clone()), undated);
        assert_eq!(undated.clone().most_urgent(error), undated);
        // Equal severities: the earlier deadline.
        let sha1 = CalendarVerdict::Dated(Calendar::sha1(day("2031-06-01")));
        let ir = CalendarVerdict::Dated(nist("2036-06-01"));
        assert_eq!(ir.most_urgent(sha1.clone()), sha1);
    }
}
