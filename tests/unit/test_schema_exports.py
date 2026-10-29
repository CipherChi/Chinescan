import json
from pathlib import Path

from chinescan.core.models import Finding, Scan


def test_schema_exports_include_new_optional_fields() -> None:
    root = Path(__file__).parents[2]
    finding = json.loads((root / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
    investigation = json.loads(
        (root / "schemas" / "investigation.schema.json").read_text(encoding="utf-8")
    )
    assert "evidence" in finding["properties"]
    scan_schema = next(
        item
        for item in investigation["oneOf"]
        if "scanner" in item["properties"] and "finding_ids" in item["properties"]
    )
    assert "verdict" in scan_schema["properties"] and "coverage" in scan_schema["properties"]
    assert Finding(title="x", fingerprint="y").evidence is None
    assert Scan.model_fields["verdict"].default is None
