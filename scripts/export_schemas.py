"""Regenerate the checked-in JSON Schema exports."""

import json
from pathlib import Path

from chinescan.core.models import (
    Alert,
    Authorization,
    AuthorizationRecord,
    Case,
    Event,
    Finding,
    Indicator,
    Report,
    Scan,
    Target,
    TimelineEntry,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    (ROOT / "schemas" / "finding.schema.json").write_text(
        json.dumps(Finding.model_json_schema(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    records = [
        Event,
        Alert,
        Indicator,
        Case,
        TimelineEntry,
        Scan,
        Target,
        Report,
        Authorization,
        AuthorizationRecord,
    ]
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ChineScan investigation records",
        "oneOf": [item.model_json_schema() for item in records],
    }
    (ROOT / "schemas" / "investigation.schema.json").write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
