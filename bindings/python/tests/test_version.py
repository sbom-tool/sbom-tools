from __future__ import annotations

from sbomtools import version


def test_version_reports_abi_and_crate_versions(native_library: None) -> None:
    result = version()

    assert result.abi_version == "1"
    assert result.crate_version
