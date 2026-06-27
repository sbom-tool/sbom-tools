"""Typed values exposed by the Python binding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TypeAlias

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
