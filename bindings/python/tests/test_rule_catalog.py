from __future__ import annotations

import pytest

from sbomtools import ErrorCode, SbomToolsNativeError, rule_catalog_json


def test_rule_catalog_lists_every_rule(native_library: None) -> None:
    catalog = rule_catalog_json()

    assert catalog["schema"] == "sbom-tools/rules/v1"
    assert len(catalog["rules"]) >= 100
    ids = [rule["id"] for rule in catalog["rules"]]
    assert "SBOM-NTIA-SUPPLIER" in ids
    assert len(ids) == len(set(ids))


def test_rule_catalog_filters_by_standard(native_library: None) -> None:
    every = rule_catalog_json()
    ntia = rule_catalog_json(["ntia"])

    assert 0 < len(ntia["rules"]) < len(every["rules"])
    assert all("ntia" in rule["standards"] for rule in ntia["rules"])


def test_rule_catalog_reports_unknown_standards(native_library: None) -> None:
    with pytest.raises(SbomToolsNativeError) as captured:
        rule_catalog_json(["crab"])

    assert captured.value.code is ErrorCode.VALIDATION
