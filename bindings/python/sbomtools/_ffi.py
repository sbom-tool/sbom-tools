"""ctypes declarations and safe wrappers for the sbom-tools C ABI."""

from __future__ import annotations

import ctypes
import json
from typing import cast

from ._errors import SbomToolsNativeError
from ._loader import load_library
from .types import AbiVersion, DetectedFormat, ErrorCode, JsonValue, ScoringProfile


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
