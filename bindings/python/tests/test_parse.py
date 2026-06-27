from __future__ import annotations

from pathlib import Path

import pytest

from sbomtools import ErrorCode, SbomToolsNativeError, parse_path_json, parse_string_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def test_parse_path_returns_normalized_payload(native_library: None) -> None:
    result = parse_path_json(str(FIXTURE))

    assert isinstance(result, dict)
    assert result["document"]["format"] == "CycloneDx"
    assert len(result["components"]) == 3


def test_parse_string_returns_normalized_payload(native_library: None) -> None:
    result = parse_string_json(FIXTURE.read_text(encoding="utf-8"))

    assert isinstance(result, dict)
    assert result["document"]["spec_version"] == "1.5"


def test_parse_string_wraps_native_errors(native_library: None) -> None:
    with pytest.raises(SbomToolsNativeError) as captured:
        parse_string_json("{not-json}")

    assert captured.value.code in {ErrorCode.PARSE, ErrorCode.UNSUPPORTED}


def test_inputs_reject_nul_bytes_before_ffi(native_library: None) -> None:
    with pytest.raises(ValueError, match="NUL"):
        parse_string_json("{}\0ignored")
