from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbomtools import (
    ErrorCode,
    SbomToolsNativeError,
    parse_string_json,
    score_with_options_json,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def _normalized() -> str:
    return json.dumps(parse_string_json(FIXTURE.read_text(encoding="utf-8")))


def test_score_with_options_names_levels_like_the_cli(native_library: None) -> None:
    report = score_with_options_json(_normalized(), profile="cra", as_of="2027-01-01")

    assert report["profile"] == "cra"
    compliance = report["compliance"]
    assert isinstance(compliance, dict)
    assert compliance["standard"] == "cra"
    violations = compliance["violations"]
    assert isinstance(violations, list) and violations
    for violation in violations:
        assert isinstance(violation, dict) and violation["finding_id"]


def test_score_with_options_reads_the_pinned_clock(native_library: None) -> None:
    sbom = _normalized()

    first = score_with_options_json(sbom, as_of="2027-01-01")
    second = score_with_options_json(sbom, as_of="2027-01-01")

    assert first == second
    assert first["profile"] == "standard"


def test_score_with_options_reports_invalid_options(native_library: None) -> None:
    with pytest.raises(SbomToolsNativeError) as captured:
        score_with_options_json(_normalized(), profile="strict")

    assert captured.value.code is ErrorCode.VALIDATION
