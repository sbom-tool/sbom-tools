"""Typed values exposed by the Python binding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TypeAlias, TypedDict

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


class ErrorCode(IntEnum):
    """Stable C ABI error codes."""

    OK = 0
    PARSE = 1
    DIFF = 2
    VALIDATION = 3
    IO = 4
    UNSUPPORTED = 5
    INTERNAL = 6


class ScoringProfile(IntEnum):
    """Stable C ABI scoring profile identifiers."""

    MINIMAL = 0
    STANDARD = 1
    SECURITY = 2
    LICENSE_COMPLIANCE = 3
    CRA = 4
    COMPREHENSIVE = 5
    AI_READINESS = 6


@dataclass(frozen=True, slots=True)
class AbiVersion:
    """Version payload returned by the C ABI."""

    abi_version: str
    crate_version: str


@dataclass(frozen=True, slots=True)
class DetectedFormat:
    """Detected SBOM format details."""

    format_name: str
    confidence: float
    variant: str | None
    version: str | None
    warnings: tuple[str, ...]


class ToolInfo(TypedDict):
    """The tool that wrote a compliance envelope or a rule catalogue."""

    name: str
    version: str


class _ComplianceResultFields(TypedDict):
    standard: str
    name: str
    applicable: bool
    compliant: bool
    score: int | None
    counts: dict[str, int]
    violations: list[dict[str, JsonValue]]
    passed: list[dict[str, JsonValue]]


class ComplianceResult(_ComplianceResultFields, total=False):
    """One standard's verdict, an entry of the envelope's ``results``.

    Each violation and passed check is a dict with its ``finding_id``,
    ``finding_key``, ``rule_id`` and the fields docs/compliance-output.md
    describes.
    """

    not_applicable_reason: str
    score_basis: dict[str, int]
    evaluated: list[dict[str, JsonValue]]
    suppressed: list[dict[str, JsonValue]]
    excluded_components: int
    conformity_summary: dict[str, JsonValue]


class DuplicateSummary(TypedDict):
    """The components a document lists more than once, merged into one each."""

    components: int
    entries: int
    conflicts: list[str]


class _ComplianceSubjectFields(TypedDict):
    sha256: str
    format: str
    spec_version: str
    components: int
    duplicates: DuplicateSummary
    timestamp_unparsed: bool


class ComplianceSubject(_ComplianceSubjectFields, total=False):
    """The SBOM a compliance envelope judges, and how its document was read.

    ``sha256`` is over exactly the content passed in; ``file_name`` is the
    ``file_name`` option without its directory, absent without one.
    """

    file_name: str


class ComplianceEnvelope(TypedDict):
    """The ``sbom-tools/compliance/v2`` envelope ``validate_json`` returns.

    ``as_of`` is the instant every standard was judged at (RFC 3339, UTC).
    """

    schema: str
    tool: ToolInfo
    as_of: str
    subject: ComplianceSubject
    results: list[ComplianceResult]


class _RuleCatalogEntryFields(TypedDict):
    id: str
    name: str
    description: str
    default_severity: str
    kind: str
    fallback: bool
    standards: list[str]
    references: list[dict[str, str]]
    remediation: str
    remediation_summary: str


class RuleCatalogEntry(_RuleCatalogEntryFields, total=False):
    """Everything the registry records about one rule."""

    help_uri: str
    advice: dict[str, dict[str, str]]


class RuleCatalog(TypedDict):
    """The ``sbom-tools/rules/v1`` document ``rule_catalog_json`` returns."""

    schema: str
    tool: ToolInfo
    rules: list[RuleCatalogEntry]


class QualityOutput(TypedDict):
    """The document ``score_with_options_json`` returns.

    It is what ``sbom-tools quality -o json`` prints: the tool and its
    version, the SBOM's file name (``"-"`` without ``file_name``), the
    profile as ``--profile`` names it, whether the profile applied, and the
    quality report, whose ``overall_score`` is ``None`` and ``grade``
    ``"N/A"`` for a profile that did not apply.
    """

    tool: str
    version: str
    sbom: str
    profile: str
    applicable: bool
    report: dict[str, JsonValue]
