from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbomtools import ScoringProfile, parse_string_json, score_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def test_score_returns_quality_report(native_library: None) -> None:
    normalized = parse_string_json(FIXTURE.read_text(encoding="utf-8"))

    result = score_json(json.dumps(normalized), ScoringProfile.STANDARD)

    assert isinstance(result, dict)
    assert result["profile"] == "Standard"
    assert result["overall_score"] >= 0


def test_score_rejects_unknown_profile_before_ffi(native_library: None) -> None:
    normalized = parse_string_json(FIXTURE.read_text(encoding="utf-8"))

    with pytest.raises(ValueError):
        score_json(json.dumps(normalized), 99)  # type: ignore[arg-type]
