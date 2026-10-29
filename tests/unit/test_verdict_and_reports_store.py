import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from chinescan.core.models import Finding, Scan
from chinescan.core.models.common import EvidenceKind, ScanVerdict
from chinescan.core.models.investigation import CoverageGap, CoverageReport
from chinescan.core.report_store import ReportStoreError, _safe_id, save_scan_reports
from chinescan.core.reporting import render_report
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.core.verdict import VERDICT_CAVEAT, compute_verdict


def _scan() -> Scan:
    return Scan(
        scan_id="scan/../id", target_id="target", scanner="builtin", started_at=datetime.now(UTC)
    )


def test_verdict_outcomes_and_legacy_none() -> None:
    scan = _scan()
    assert compute_verdict(scan, []) == ScanVerdict.NO_MATCHES_IN_SCOPE
    scan.coverage = CoverageReport(gaps=[CoverageGap(code="gap", reason="Skipped")])
    assert compute_verdict(scan, []) == ScanVerdict.NO_MATCHES_WITH_GAPS
    assert (
        compute_verdict(scan, [Finding(title="Lead", fingerprint="x")]) == ScanVerdict.LEADS_FOUND
    )
    scan.failures = {"scanner": "failed"}
    assert compute_verdict(scan, []) == ScanVerdict.SCAN_FAILED
    assert _scan().verdict is None
    assert all(
        "leads rather than proof" in value and "do not prove safety" in value
        for value in VERDICT_CAVEAT.values()
    )


def test_legacy_models_allow_new_fields_to_be_absent() -> None:
    scan = _scan().model_dump(mode="json")
    scan.pop("coverage")
    scan.pop("verdict")
    assert Scan.model_validate(scan).verdict is None
    finding = Finding(title="Old", fingerprint="abc").model_dump(mode="json")
    finding.pop("evidence")
    assert Finding.model_validate(finding).evidence is None


def test_report_store_saves_redacted_files_and_collision_suffix(
    repository: SQLiteRepository, tmp_path: Path
) -> None:
    scan = _scan()
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    finding = Finding(title="Candidate", fingerprint="f", description="token=fixture-secret")
    scan.finding_ids = [finding.finding_id]
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    when = datetime(2026, 10, 29, tzinfo=UTC)
    first = save_scan_reports(repository, scan.scan_id, tmp_path / "reports", now=when)
    second = save_scan_reports(repository, scan.scan_id, tmp_path / "reports", now=when)
    assert [item.suffix for item in first] == [".json", ".md"]
    assert first[0].name == "20261029T000000Z_scan_.._id.json"
    assert second[0].stem.endswith("-1")
    assert "fixture-secret" not in first[0].read_text(encoding="utf-8")
    assert json.loads(first[0].read_text(encoding="utf-8"))["findings"]


def test_report_store_missing_scan_does_not_create_folder(
    repository: SQLiteRepository, tmp_path: Path
) -> None:
    destination = tmp_path / "not-created"
    with pytest.raises(ReportStoreError):
        save_scan_reports(repository, "missing", destination)
    assert not destination.exists()


def test_report_store_bad_location_and_id_sanitizing(
    repository: SQLiteRepository, tmp_path: Path
) -> None:
    scan = _scan()
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    blocking_file = tmp_path / "file"
    blocking_file.write_text("x", encoding="utf-8")
    with pytest.raises(ReportStoreError):
        save_scan_reports(repository, scan.scan_id, blocking_file / "child")
    assert _safe_id("../a/b....") == "_a_b"
    assert _safe_id("CON") == "scan-CON"


def test_renderers_include_verdict_coverage_and_evidence() -> None:
    scan = _scan()
    scan.verdict = ScanVerdict.NO_MATCHES_WITH_GAPS
    scan.coverage = CoverageReport(
        examined={"files_scanned": 3},
        gaps=[CoverageGap(code="symlink_skipped", reason="Linked file skipped.")],
    )
    finding = Finding(
        title="Candidate",
        fingerprint="fingerprint",
        evidence=EvidenceKind.PATTERN_MATCH,
    )
    markdown = render_report(scan, [finding], "markdown")
    html = render_report(scan, [finding], "html")
    payload = json.loads(render_report(scan, [finding], "json"))
    csv_text = render_report(scan, [finding], "csv")
    sarif = json.loads(render_report(scan, [finding], "sarif"))
    assert "Verdict" in markdown and "Coverage" in markdown
    assert "pattern_match" in markdown and "do not prove safety" in markdown
    assert "pattern_match" in html and "Coverage" in html
    assert payload["verdict"] == "no_matches_with_gaps"
    assert payload["findings"][0]["evidence"] == "pattern_match"
    assert csv_text.splitlines()[0].endswith(",evidence")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["evidence"] == "pattern_match"


def test_share_summary_omits_secret_text_and_absolute_paths() -> None:
    scan = _scan()
    scan.verdict = ScanVerdict.LEADS_FOUND
    scan.coverage = CoverageReport(examined={"files_scanned": 1})
    finding = Finding(
        title="Local reference",
        fingerprint="fingerprint",
        description="planted-secret-value",
        location="C:\\Users\\CipherChi\\repo\\secret.py:9",
        evidence=EvidenceKind.REFERENCE_ONLY,
    )
    scan.scan_options = {
        "indicator_file_name_1": "local-iocs.json",
        "indicator_sha256_1": "a" * 64,
    }
    summary = render_report(scan, [finding], "share-summary")
    assert "planted-secret-value" not in summary
    assert "C:\\Users\\CipherChi" not in summary
    assert "CipherChi" not in summary
    assert "<path>" in summary
    assert "local-iocs.json" in summary and "a" * 64 in summary
