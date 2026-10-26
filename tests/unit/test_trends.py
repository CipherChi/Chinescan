"""Tests for local scan-history aggregation and its read-only CLI view."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Alert, Scan
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.core.trends import scan_history_trends

runner = CliRunner()


def test_scan_history_trends_counts_records_by_utc_day() -> None:
    now = datetime(2026, 10, 26, 12, tzinfo=UTC)
    finding = Finding(
        finding_id="f-1", title="candidate", severity=Severity.HIGH, fingerprint="fp-1"
    )
    alert = Alert(
        alert_id="a-1",
        title="candidate alert",
        severity=Severity.MEDIUM,
        rule_id="rule-1",
        fingerprint="alert-fp-1",
    )
    yesterday = Scan(
        scan_id="s-1",
        target_id="private-target-id",
        scanner="local",
        started_at=now - timedelta(days=1),
        finding_ids=[finding.finding_id],
        alert_ids=[alert.alert_id],
    )
    old = Scan(
        scan_id="s-old",
        target_id="private-target-id",
        scanner="local",
        started_at=now - timedelta(days=5),
        finding_ids=[finding.finding_id],
    )

    result = scan_history_trends(
        [yesterday.model_dump(mode="json"), old.model_dump(mode="json")],
        [finding.model_dump(mode="json")],
        [alert.model_dump(mode="json")],
        days=3,
        now=now,
    )

    assert result["total_scans"] == 1
    assert [item["date"] for item in result["daily"]] == [
        "2026-10-24",
        "2026-10-25",
        "2026-10-26",
    ]
    yesterday_summary = result["daily"][1]
    assert yesterday_summary["scans"] == 1
    assert yesterday_summary["findings_by_severity"]["high"] == 1
    assert yesterday_summary["alerts_by_severity"]["medium"] == 1
    assert "private-target-id" not in json.dumps(result)


def test_scan_history_trends_validates_window_and_clock() -> None:
    with pytest.raises(ValueError, match="days"):
        scan_history_trends([], [], [], days=0)
    with pytest.raises(ValueError, match="timezone-aware"):
        scan_history_trends([], [], [], now=datetime(2026, 10, 26))


def test_trends_cli_reads_local_records_without_target_values(tmp_path, monkeypatch) -> None:
    database = tmp_path / "history.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    repository = SQLiteRepository(database)
    scan = Scan(
        scan_id="s-1",
        target_id="private-target-id",
        scanner="local",
        started_at=datetime.now(UTC),
    )
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.close()

    result = runner.invoke(app, ["trends", "--days", "2", "--format", "json"])

    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary["total_scans"] == 1
    assert len(summary["daily"]) == 2
    assert "private-target-id" not in result.stdout
