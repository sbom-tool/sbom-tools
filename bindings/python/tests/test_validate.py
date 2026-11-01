from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path

import pytest

from sbomtools import ErrorCode, SbomToolsNativeError, validate_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def _content() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_validate_returns_the_compliance_envelope(native_library: None) -> None:
    envelope = validate_json(_content(), as_of="2027-01-01")

    assert envelope["schema"] == "sbom-tools/compliance/v2"
    assert envelope["tool"]["name"] == "sbom-tools"
    assert envelope["as_of"] == "2027-01-01T00:00:00Z"
    subject = envelope["subject"]
    assert subject["sha256"] == hashlib.sha256(_content().encode("utf-8")).hexdigest()
    assert subject["format"] == "CycloneDX"
    assert "file_name" not in subject
    [ntia] = envelope["results"]
    assert ntia["standard"] == "ntia"
    assert ntia["compliant"] is False
    assert ntia["counts"]["error"] > 0
    for violation in ntia["violations"]:
        assert str(violation["finding_id"]).startswith("sbomtools:v1:")


def test_validate_names_the_file_without_its_directory(native_library: None) -> None:
    envelope = validate_json(_content(), file_name=FIXTURE, as_of="2027-01-01")

    assert envelope["subject"].get("file_name") == "minimal.cdx.json"


def test_validate_checks_a_level_named_twice_once(native_library: None) -> None:
    envelope = validate_json(
        _content(), standards=["cra", "NTIA", "cra-phase2"], as_of="2027-01-01"
    )

    assert [result["standard"] for result in envelope["results"]] == ["cra", "ntia"]


def test_validate_accepts_dates_and_datetimes(native_library: None) -> None:
    as_text = validate_json(_content(), as_of="2027-01-01T00:00:00")

    assert validate_json(_content(), as_of=date(2027, 1, 1)) == as_text
    assert validate_json(_content(), as_of=datetime(2027, 1, 1)) == as_text


def test_validate_applies_rule_settings_and_a_sidecar(native_library: None) -> None:
    envelope = validate_json(
        _content(),
        standards=["ntia", "cra"],
        as_of="2027-01-01",
        rules={"SBOM-NTIA-SUPPLIER": "warning"},
        sidecar={"manufacturerName": "Example Corp", "productClass": "important-class-1"},
    )

    ntia, cra = envelope["results"]
    suppliers = [v for v in ntia["violations"] if v["rule_id"] == "SBOM-NTIA-SUPPLIER"]
    assert suppliers
    for violation in suppliers:
        assert violation["severity"] == "Warning"
        assert violation["default_severity"] == "Error"
        assert violation["severity_source"] == "cli"
    # The sidecar's product class pins the CRA conformity route.
    assert cra["conformity_summary"]["product_class"] == "important-class-1"


@pytest.mark.parametrize(
    ("options", "needle"),
    [
        ({"standards": ["ntai"]}, "unknown compliance standard"),
        ({"standards": []}, "no compliance standard selected"),
        ({"as_of": "01/01/2027"}, "invalid as_of"),
        ({"pqc_profile": "federal"}, "apply only with `pqc_mode`"),
        ({"rules": {"SBOM-NTIA-SUPLIER": "off"}}, "did you mean SBOM-NTIA-SUPPLIER?"),
        ({"sidecar": {"security_contact": "x"}}, "unknown field `security_contact`"),
    ],
)
def test_validate_reports_invalid_options(
    native_library: None, options: dict[str, object], needle: str
) -> None:
    with pytest.raises(SbomToolsNativeError) as captured:
        validate_json(_content(), **options)  # type: ignore[arg-type]

    assert captured.value.code is ErrorCode.VALIDATION
    assert needle in str(captured.value)


def test_validate_rejects_a_string_of_standards_before_ffi(native_library: None) -> None:
    with pytest.raises(TypeError, match="not a string"):
        validate_json(_content(), standards="ntia")
