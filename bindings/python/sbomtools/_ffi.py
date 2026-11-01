"""ctypes declarations and safe wrappers for the sbom-tools C ABI."""

from __future__ import annotations

import ctypes
import json
import os
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from typing import cast

from ._errors import SbomToolsNativeError
from ._loader import load_library
from .types import (
    AbiVersion,
    ComplianceEnvelope,
    DetectedFormat,
    ErrorCode,
    JsonValue,
    RuleCatalog,
    ScoringProfile,
)


class _StringResult(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_void_p),
        ("error_code", ctypes.c_uint32),
        ("error_message", ctypes.c_void_p),
    ]


def _native() -> ctypes.CDLL:
    library = load_library()

    library.sbom_tools_abi_version_json.argtypes = []
    library.sbom_tools_abi_version_json.restype = _StringResult

    library.sbom_tools_detect_format_json.argtypes = [ctypes.c_char_p]
    library.sbom_tools_detect_format_json.restype = _StringResult

    library.sbom_tools_parse_sbom_path_json.argtypes = [ctypes.c_char_p]
    library.sbom_tools_parse_sbom_path_json.restype = _StringResult

    library.sbom_tools_parse_sbom_str_json.argtypes = [ctypes.c_char_p]
    library.sbom_tools_parse_sbom_str_json.restype = _StringResult

    library.sbom_tools_diff_sboms_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.sbom_tools_diff_sboms_json.restype = _StringResult

    library.sbom_tools_score_sbom_json.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    library.sbom_tools_score_sbom_json.restype = _StringResult

    library.sbom_tools_validate_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.sbom_tools_validate_json.restype = _StringResult

    library.sbom_tools_rule_catalog_json.argtypes = [ctypes.c_char_p]
    library.sbom_tools_rule_catalog_json.restype = _StringResult

    library.sbom_tools_score_sbom_with_options_json.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    library.sbom_tools_score_sbom_with_options_json.restype = _StringResult

    library.sbom_tools_string_result_free.argtypes = [_StringResult]
    library.sbom_tools_string_result_free.restype = None
    return library


def _encode(value: str, field: str) -> bytes:
    if "\0" in value:
        raise ValueError(f"{field} must not contain NUL bytes")
    return value.encode("utf-8")


def _decode_pointer(pointer: int | None) -> str | None:
    if not pointer:
        return None
    return ctypes.string_at(pointer).decode("utf-8")


def _consume(library: ctypes.CDLL, result: _StringResult) -> JsonValue:
    try:
        try:
            code = ErrorCode(result.error_code)
        except ValueError as error:
            raise SbomToolsNativeError(
                f"native library returned unknown error code {result.error_code}"
            ) from error

        if code is not ErrorCode.OK:
            message = (
                _decode_pointer(result.error_message)
                or "native library returned no error message"
            )
            raise SbomToolsNativeError(message, code)

        payload = _decode_pointer(result.data)
        if payload is None:
            raise SbomToolsNativeError(
                "native library returned no JSON payload", ErrorCode.INTERNAL
            )
        try:
            return cast(JsonValue, json.loads(payload))
        except json.JSONDecodeError as error:
            raise SbomToolsNativeError(
                f"native library returned invalid JSON: {error}", ErrorCode.INTERNAL
            ) from error
    finally:
        library.sbom_tools_string_result_free(result)


def _mapping(value: JsonValue, operation: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise SbomToolsNativeError(
            f"{operation} returned {type(value).__name__}, expected object", ErrorCode.INTERNAL
        )
    return value


def _required_string(value: JsonValue, field: str, operation: str) -> str:
    if not isinstance(value, str):
        raise SbomToolsNativeError(
            f"{operation} returned invalid {field}", ErrorCode.INTERNAL
        )
    return value


def version() -> AbiVersion:
    """Return the ABI and Rust crate versions."""

    library = _native()
    value = _mapping(
        _consume(library, library.sbom_tools_abi_version_json()), "version"
    )
    return AbiVersion(
        abi_version=_required_string(value.get("abi_version"), "abi_version", "version"),
        crate_version=_required_string(value.get("crate_version"), "crate_version", "version"),
    )


def detect_format(content: str) -> DetectedFormat | None:
    """Detect an SBOM format from raw content."""

    library = _native()
    value = _consume(
        library,
        library.sbom_tools_detect_format_json(_encode(content, "content")),
    )
    if value is None:
        return None
    payload = _mapping(value, "detect_format")
    warnings = payload.get("warnings")
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        raise SbomToolsNativeError(
            "detect_format returned invalid warnings", ErrorCode.INTERNAL
        )
    confidence = payload.get("confidence")
    if not isinstance(confidence, (int, float)):
        raise SbomToolsNativeError(
            "detect_format returned invalid confidence", ErrorCode.INTERNAL
        )
    variant = payload.get("variant")
    detected_version = payload.get("version")
    if variant is not None and not isinstance(variant, str):
        raise SbomToolsNativeError("detect_format returned invalid variant", ErrorCode.INTERNAL)
    if detected_version is not None and not isinstance(detected_version, str):
        raise SbomToolsNativeError("detect_format returned invalid version", ErrorCode.INTERNAL)
    return DetectedFormat(
        format_name=_required_string(payload.get("format_name"), "format_name", "detect_format"),
        confidence=float(confidence),
        variant=variant,
        version=detected_version,
        warnings=tuple(warnings),
    )


def parse_path_json(path: str) -> JsonValue:
    """Parse an SBOM file and return its normalized JSON value."""

    library = _native()
    return _consume(
        library,
        library.sbom_tools_parse_sbom_path_json(_encode(path, "path")),
    )


def parse_string_json(content: str) -> JsonValue:
    """Parse raw SBOM content and return its normalized JSON value."""

    library = _native()
    return _consume(
        library,
        library.sbom_tools_parse_sbom_str_json(_encode(content, "content")),
    )


def diff_json(old_sbom_json: str, new_sbom_json: str) -> JsonValue:
    """Diff two normalized SBOM JSON strings."""

    library = _native()
    return _consume(
        library,
        library.sbom_tools_diff_sboms_json(
            _encode(old_sbom_json, "old_sbom_json"),
            _encode(new_sbom_json, "new_sbom_json"),
        )
    )


def score_json(
    sbom_json: str, profile: ScoringProfile = ScoringProfile.STANDARD
) -> JsonValue:
    """Score a normalized SBOM JSON string with an ABI scoring profile."""

    validated_profile = ScoringProfile(profile)
    library = _native()
    return _consume(
        library,
        library.sbom_tools_score_sbom_json(
            _encode(sbom_json, "sbom_json"),
            validated_profile.value,
        )
    )


def _names(value: Sequence[str], field: str) -> list[str]:
    if isinstance(value, str):
        raise TypeError(f"{field} must be a sequence of names, not a string")
    return list(value)


def _run_options(
    as_of: str | date | datetime | None,
    sidecar: Mapping[str, JsonValue] | None,
    product_class: str | None,
    pqc_mode: str | None,
    pqc_profile: str | None,
    cnsa_category: str | None,
    rules: Mapping[str, str] | None,
    include_excluded_scope: bool | None,
) -> dict[str, JsonValue]:
    """The run options as the native options object spells them."""

    options: dict[str, JsonValue] = {}
    if as_of is not None:
        # A naive datetime has no offset, so the native side takes it as UTC.
        options["as_of"] = as_of.isoformat() if isinstance(as_of, date) else as_of
    if sidecar is not None:
        options["sidecar"] = dict(sidecar)
    if product_class is not None:
        options["product_class"] = product_class
    if pqc_mode is not None:
        options["pqc_mode"] = pqc_mode
    if pqc_profile is not None:
        options["pqc_profile"] = pqc_profile
    if cnsa_category is not None:
        options["cnsa_category"] = cnsa_category
    if rules is not None:
        options["rules"] = cast(JsonValue, dict(rules))
    if include_excluded_scope is not None:
        options["include_excluded_scope"] = include_excluded_scope
    return options


def validate_json(
    content: str,
    *,
    standards: Sequence[str] | None = None,
    file_name: str | os.PathLike[str] | None = None,
    as_of: str | date | datetime | None = None,
    sidecar: Mapping[str, JsonValue] | None = None,
    product_class: str | None = None,
    pqc_mode: str | None = None,
    pqc_profile: str | None = None,
    cnsa_category: str | None = None,
    rules: Mapping[str, str] | None = None,
    include_excluded_scope: bool | None = None,
) -> ComplianceEnvelope:
    """Validate raw SBOM content against compliance standards.

    Returns the decoded ``sbom-tools/compliance/v2`` envelope: what
    ``sbom-tools validate - -o json`` writes for the same content and
    options, or ``validate <FILE>`` when ``file_name`` names the file, which
    the subject states without its directory. The subject's SHA-256 is over
    the UTF-8 bytes of ``content``, and ``as_of`` defaults to the wall clock
    when the call starts, to the second. The other options are the CLI
    flags of the same names; ``standards`` defaults to ``["ntia"]`` and
    ``sidecar`` takes the keys of a ``.cra.json`` file. Invalid options
    raise ``SbomToolsNativeError`` with ``ErrorCode.VALIDATION``.
    """

    options = _run_options(
        as_of,
        sidecar,
        product_class,
        pqc_mode,
        pqc_profile,
        cnsa_category,
        rules,
        include_excluded_scope,
    )
    if standards is not None:
        options["standards"] = cast(JsonValue, _names(standards, "standards"))
    if file_name is not None:
        options["file_name"] = os.fspath(file_name)
    library = _native()
    value = _consume(
        library,
        library.sbom_tools_validate_json(
            _encode(content, "content"),
            _encode(json.dumps(options), "options"),
        ),
    )
    return cast(ComplianceEnvelope, _mapping(value, "validate"))


def rule_catalog_json(standards: Sequence[str] | None = None) -> RuleCatalog:
    """Return the ``sbom-tools/rules/v1`` rule catalogue.

    Every rule, or the rules of the ``--standard`` names given.
    """

    filter_options: dict[str, JsonValue] = {}
    if standards is not None:
        filter_options["standards"] = cast(JsonValue, _names(standards, "standards"))
    library = _native()
    value = _consume(
        library,
        library.sbom_tools_rule_catalog_json(_encode(json.dumps(filter_options), "filter")),
    )
    return cast(RuleCatalog, _mapping(value, "rule_catalog"))


def score_with_options_json(
    sbom_json: str,
    *,
    profile: str | None = None,
    as_of: str | date | datetime | None = None,
    sidecar: Mapping[str, JsonValue] | None = None,
    product_class: str | None = None,
    pqc_mode: str | None = None,
    pqc_profile: str | None = None,
    cnsa_category: str | None = None,
    rules: Mapping[str, str] | None = None,
    include_excluded_scope: bool | None = None,
) -> dict[str, JsonValue]:
    """Score a normalized SBOM JSON string with a profile and run options.

    ``profile`` is a ``quality --profile`` name (default ``standard``); the
    other options are those of ``validate_json``. The report names the
    profile as ``--profile`` does, and its ``compliance`` is an entry of the
    validate envelope's ``results``.
    """

    options = _run_options(
        as_of,
        sidecar,
        product_class,
        pqc_mode,
        pqc_profile,
        cnsa_category,
        rules,
        include_excluded_scope,
    )
    if profile is not None:
        options["profile"] = profile
    library = _native()
    value = _consume(
        library,
        library.sbom_tools_score_sbom_with_options_json(
            _encode(sbom_json, "sbom_json"),
            _encode(json.dumps(options), "options"),
        ),
    )
    return _mapping(value, "score_with_options")
