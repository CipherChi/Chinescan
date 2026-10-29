import hashlib
import json
from pathlib import Path

from chinescan.core.models.common import EvidenceKind
from chinescan.scanners.indicators import IndicatorScanner


def test_text_indicator_match_is_reference_only_and_stable(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.txt").write_text("observed example.invalid in a saved note", encoding="utf-8")
    indicator_file = tmp_path / "iocs.txt"
    indicator_file.write_text("domain:example.invalid\n", encoding="utf-8")
    first = IndicatorScanner([indicator_file])
    second = IndicatorScanner([indicator_file])
    finding = first.scan(root)[0]
    assert finding.evidence == EvidenceKind.REFERENCE_ONLY
    assert "does not prove the host was contacted" in finding.description
    assert finding.fingerprint == second.scan(root)[0].fingerprint
    assert finding.location == "app.txt"


def test_stix_supported_and_unsupported_patterns(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "ioc.txt").write_text("example.invalid", encoding="utf-8")
    data = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[domain-name:value = 'example.invalid']",
            },
            {"type": "indicator", "id": "indicator--2", "pattern": "[process:name = 'cmd.exe']"},
        ],
    }
    source = tmp_path / "stix.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    scanner = IndicatorScanner([source])
    findings = scanner.scan(root)
    assert findings[0].evidence == EvidenceKind.PATTERN_MATCH
    assert any(gap.code == "unsupported_pattern" for gap in scanner.coverage.gaps)


def test_misp_parse_and_malformed_indicator_are_gaps(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "reference.txt").write_text("example.invalid", encoding="utf-8")
    source = tmp_path / "misp.json"
    source.write_text(
        json.dumps(
            {
                "Event": {
                    "Attribute": [
                        {"type": "domain", "value": "example.invalid", "comment": "fixture source"},
                        {"type": "unsupported", "value": "x"},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    scanner = IndicatorScanner([source])
    assert scanner.scan(root)
    malformed = tmp_path / "bad.json"
    malformed.write_text("{broken", encoding="utf-8")
    bad_scanner = IndicatorScanner([malformed])
    bad_scanner.scan(root)
    assert any(gap.code == "indicator_parse_error" for gap in bad_scanner.coverage.gaps)


def test_protective_blocklist_is_context_only(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "reference.txt").write_text("example.invalid", encoding="utf-8")
    source = tmp_path / "misp.json"
    source.write_text(
        json.dumps(
            {
                "Event": {
                    "Attribute": [
                        {
                            "type": "domain",
                            "value": "example.invalid",
                            "Tag": [{"name": "protective_blocklist"}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    finding = IndicatorScanner([source]).scan(root)[0]
    assert finding.evidence == EvidenceKind.CONTEXT_ONLY
    assert "not a detection" in finding.title


def test_sha1_and_md5_match_file_hashes(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    payload = b"synthetic fixture bytes"
    (root / "sample.bin").write_bytes(payload)
    indicators = tmp_path / "hashes.txt"
    indicators.write_text(
        "hash:" + hashlib.md5(payload, usedforsecurity=False).hexdigest() + "\n"
        "hash:" + hashlib.sha1(payload, usedforsecurity=False).hexdigest() + "\n",
        encoding="utf-8",
    )
    findings = IndicatorScanner([indicators]).scan(root)
    assert len(findings) == 2
    assert all(finding.evidence == EvidenceKind.CONFIRMED_ARTIFACT for finding in findings)


def test_indicator_scanner_has_no_network_imports() -> None:
    source = Path(__file__).parents[2] / "chinescan" / "scanners" / "indicators.py"
    text = source.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "socket",
        "urllib.request",
        "httpx",
        "requests",
        "subprocess",
        "domain_assessment",
    ):
        assert forbidden not in text
