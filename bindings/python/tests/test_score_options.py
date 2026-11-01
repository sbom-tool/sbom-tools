from __future__ import annotations

from pathlib import Path

import pytest

from sbomtools import ErrorCode, SbomToolsNativeError, score_with_options_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def _content() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_score_with_options_returns_the_quality_document(native_library: None) -> None:
    output = score_with_options_json(_content(), profile="cra", as_of="2027-01-01")

    assert output["tool"] == "sbom-tools"
    assert output["profile"] == "cra"
    assert output["sbom"] == "-"
    assert output["applicable"] is True
    report = output["report"]
    assert isinstance(report["overall_score"], (int, float))
    assert isinstance(report["compliance"], dict)


def test_score_with_options_reads_the_pinned_clock(native_library: None) -> None:
    first = score_with_options_json(_content(), as_of="2027-01-01")
    second = score_with_options_json(_content(), as_of="2027-01-01")

    assert first == second
    assert first["profile"] == "standard"


def test_score_with_options_names_the_file(native_library: None) -> None:
    output = score_with_options_json(_content(), file_name=FIXTURE, as_of="2027-01-01")

    assert output["sbom"] == "minimal.cdx.json"


def test_score_with_options_reports_a_profile_that_does_not_apply(
    native_library: None,
) -> None:
    output = score_with_options_json(_content(), profile="ai-readiness", as_of="2027-01-01")

    assert output["applicable"] is False
    assert output["report"]["overall_score"] is None
    assert output["report"]["grade"] == "N/A"


def test_score_with_options_reports_invalid_options(native_library: None) -> None:
    with pytest.raises(SbomToolsNativeError) as captured:
        score_with_options_json(_content(), profile="strict")

    assert captured.value.code is ErrorCode.VALIDATION
