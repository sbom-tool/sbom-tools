from __future__ import annotations

from pathlib import Path

from sbomtools import detect_format

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def test_detect_format_reports_cyclonedx(native_library: None) -> None:
    result = detect_format(FIXTURE.read_text(encoding="utf-8"))

    assert result is not None
    assert result.format_name == "CycloneDX"
    assert result.version == "1.5"
