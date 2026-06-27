from __future__ import annotations

import json
from pathlib import Path

from sbomtools import diff_json, parse_string_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal.cdx.json"


def test_diff_reports_component_version_change(native_library: None) -> None:
    old_content = FIXTURE.read_text(encoding="utf-8")
    new_content = old_content.replace('"version": "4.17.21"', '"version": "4.18.0"')
    old_payload = parse_string_json(old_content)
    new_payload = parse_string_json(new_content)

    result = diff_json(json.dumps(old_payload), json.dumps(new_payload))

    assert isinstance(result, dict)
    assert result["summary"]["total_changes"] > 0
