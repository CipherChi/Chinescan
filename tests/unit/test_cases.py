"""End-to-end regression tests for local case investigation and export."""

import json
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.cases import (
    CaseWorkflow,
    CaseWorkflowError,
    InvalidCaseTransitionError,
    UnsupportedCaseRecordError,
)
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import (
    Case,
    CaseActivity,
    CaseActivityType,
    CaseStatus,
    Event,
    Scan,
)
from chinescan.core.reporting import render_case_report
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.log_analysis.service import LogAnalysisService

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "sample-logs"


def test_case_cli_workflow_persists_and_exports_redacted_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "case-workflow.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    repository = SQLiteRepository(database)
    log_result = LogAnalysisService(repository).analyze(FIXTURE_ROOT)
    finding = Finding(
        finding_id="finding-case-fixture",
        title="Unsafe <script>alert(1)</script>",
        description="password=fixture-secret",
        severity=Severity.HIGH,
        fingerprint="case-fixture-fingerprint",
        rule_id="FIXTURE-001",
        scanner="fixture-scanner",
    )
    repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    repository.close()

    created = runner.invoke(
        app,
        [
            "--database",
            str(database),
            "case",
            "create",
            "--from-scan",
            log_result.scan_id,
            "--title",
            "Fixture investigation",
            "--description",
            "Review locally generated fixture events.",
        ],
    )
    assert created.exit_code == 0, created.output
    case_id = created.stdout.split()[2]

    linked = runner.invoke(
        app,
        ["case", "link", case_id, "--type", "finding", "--id", finding.finding_id],
    )
    assert linked.exit_code == 0, linked.output
    duplicate = runner.invoke(
        app,
        ["case", "link", case_id, "--type", "finding", "--id", finding.finding_id],
    )
    assert duplicate.exit_code == 0
    assert "Already linked" in duplicate.stdout

    note_text = "<img src=x onerror=alert(1)> password=fixture-secret"
    added = runner.invoke(
        app,
        ["case", "note", "add", case_id, "--text", note_text, "--author", "Local analyst"],
    )
    assert added.exit_code == 0, added.output
    updated = runner.invoke(app, ["case", "update", case_id, "--status", "in_progress"])
    assert updated.exit_code == 0, updated.output

    shown = runner.invoke(app, ["case", "show", case_id])
    assert shown.exit_code == 0, shown.output
    case_payload = json.loads(shown.stdout)
    assert case_payload["schema_version"] == "2.0"
    assert case_payload["status"] == "in_progress"
    assert case_payload["notes"][0]["author_label"] == "Local analyst"
    assert "fixture-secret" not in shown.stdout

    timeline = runner.invoke(app, ["case", "timeline", case_id, "--format", "json"])
    assert timeline.exit_code == 0, timeline.output
    timeline_items = json.loads(timeline.stdout)
    assert {item["category"] for item in timeline_items} >= {
        "case_activity",
        "source_event",
    }
    event_items = [item for item in timeline_items if item["category"] == "source_event"]
    assert all(
        item["event_occurred_at"] and item["record_ingested_at"] is None for item in event_items
    )
    assert [item["event_occurred_at"] for item in event_items] == sorted(
        item["event_occurred_at"] for item in event_items
    )

    exported_json = runner.invoke(app, ["case", "export", case_id, "--format", "json"])
    assert exported_json.exit_code == 0, exported_json.output
    report_data = json.loads(exported_json.stdout)
    assert report_data["schema_version"] == "1.0"
    assert report_data["summary"]["counts_by_severity"]["high"] >= 1
    assert any(
        item["record_id"] == finding.finding_id for item in report_data["records"]["finding"]
    )
    assert report_data["records"]["event"]
    assert report_data["records"]["alert"]
    assert any(link["record_id"] == finding.finding_id for link in report_data["links"])
    assert "fixture-secret" not in exported_json.stdout
    assert "[REDACTED]" in exported_json.stdout
    assert any("ingestion timestamps" in item for item in report_data["limitations"])

    markdown_path = tmp_path / "case.md"
    markdown = runner.invoke(
        app,
        ["case", "export", case_id, "--format", "markdown", "--output", str(markdown_path)],
    )
    assert markdown.exit_code == 0, markdown.output
    markdown_text = markdown_path.read_text(encoding="utf-8")
    assert "Analyst notes" in markdown_text
    assert "Other linked record details" in markdown_text
    assert '"occurred\\_at"' in markdown_text
    assert "fixture-secret" not in markdown_text

    html_path = tmp_path / "case.html"
    html_result = runner.invoke(
        app,
        ["case", "export", case_id, "--format", "html", "--output", str(html_path)],
    )
    assert html_result.exit_code == 0, html_result.output
    html_text = html_path.read_text(encoding="utf-8")
    assert "&lt;img" in html_text
    assert "<img" not in html_text
    assert "<script" not in html_text
    assert "Other linked record details" in html_text
    assert "https://" not in html_text
    assert "Counts by severity" in html_text

    reopened = SQLiteRepository(database)
    try:
        persisted = CaseWorkflow(reopened).get_case(case_id)
        assert persisted.status == CaseStatus.IN_PROGRESS
        assert persisted.notes[0].body == note_text
        assert any(item.record_id == finding.finding_id for item in persisted.links)
        assert len(persisted.activities) == 4
    finally:
        reopened.close()


def test_case_missing_records_invalid_transitions_and_unpersisted_artifacts(repository) -> None:
    workflow = CaseWorkflow(repository)
    with pytest.raises(CaseWorkflowError, match="scan record not found"):
        workflow.create_from_scan("missing-scan")

    case = Case(case_id="case-errors", title="Error cases")
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    with pytest.raises(CaseWorkflowError, match="Case not found"):
        workflow.update_status("missing-case", CaseStatus.IN_PROGRESS)
    with pytest.raises(CaseWorkflowError, match="record not found"):
        workflow.link_record(case.case_id, "finding", "missing-finding")
    with pytest.raises(UnsupportedCaseRecordError, match="not persisted"):
        workflow.link_record(case.case_id, "artifact", "sample-artifact")
    changed_case, changed = workflow.update_status(case.case_id, CaseStatus.IN_PROGRESS)
    assert changed and changed_case.status == CaseStatus.IN_PROGRESS
    _, changed_again = workflow.update_status(case.case_id, CaseStatus.IN_PROGRESS)
    assert not changed_again
    closed, _ = workflow.update_status(case.case_id, CaseStatus.CLOSED)
    with pytest.raises(InvalidCaseTransitionError, match="Cannot change"):
        workflow.update_status(closed.case_id, CaseStatus.OPEN)


def test_note_limits_and_legacy_dangling_references_are_preserved(repository) -> None:
    legacy = {
        "schema_version": "1.0",
        "case_id": "legacy-case",
        "title": "Old case",
        "description": "Old payload without workflow fields.",
        "status": "open",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
        "scan_ids": ["missing-scan"],
        "finding_ids": ["missing-finding"],
    }
    repository.save("case", "legacy-case", legacy)
    workflow = CaseWorkflow(repository)
    case = workflow.get_case("legacy-case")
    assert case.schema_version == "1.0"
    assert case.notes == [] and case.activities == [] and case.links == []
    with pytest.raises(CaseWorkflowError, match="8000 character"):
        workflow.add_note(case.case_id, "x" * 8_001)
    with pytest.raises(CaseWorkflowError, match="must not be empty"):
        workflow.add_note(case.case_id, "  ")

    context = workflow.context(case)
    assert case.scan_ids == ["missing-scan"]
    assert case.finding_ids == ["missing-finding"]
    assert len(context.warnings) == 2
    report = json.loads(render_case_report(repository, case.case_id, "json"))
    assert len(report["links"]) == 2
    assert len(report["warnings"]) == 2


def test_case_rejects_notes_owned_by_a_different_case() -> None:
    from chinescan.core.models.investigation import CaseNote

    note = CaseNote(case_id="other-case", body="must not cross case boundaries")
    with pytest.raises(ValueError, match="belong to their containing case"):
        Case(case_id="case-owner", title="Owner", notes=[note])


def test_case_timeline_stably_orders_equal_times_and_preserves_offsets(repository) -> None:
    timestamp = datetime.fromisoformat("2025-03-01T10:00:00+02:00")
    event = Event(
        event_id="event-equal-time",
        occurred_at=timestamp,
        kind="login",
        summary="Logon event",
        source="fixture",
    )
    scan = Scan(
        scan_id="scan-timeline",
        target_id="target-timeline",
        scanner="fixture",
        started_at=timestamp,
        event_ids=[event.event_id],
    )
    repository.save("event", event.event_id, event.model_dump(mode="json"))
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    case, _ = CaseWorkflow(repository).create_from_scan(scan.scan_id)
    activity_a = CaseActivity(
        activity_id="activity-a",
        activity_type=CaseActivityType.NOTE_ADDED,
        occurred_at=timestamp,
        details={"note_id": "note-a"},
    )
    activity_b = CaseActivity(
        activity_id="activity-b",
        activity_type=CaseActivityType.STATUS_CHANGED,
        occurred_at=timestamp,
        details={"from": "open", "to": "closed"},
    )
    case.activities.extend([activity_b, activity_a])
    repository.save("case", case.case_id, case.model_dump(mode="json"))

    first = CaseWorkflow(repository).timeline(case.case_id)[1]
    second = CaseWorkflow(repository).timeline(case.case_id)[1]
    assert [item.item_id for item in first] == [item.item_id for item in second]
    source_event = next(item for item in first if item.record_id == event.event_id)
    assert source_event.event_occurred_at.utcoffset().total_seconds() == 7200
    assert source_event.case_activity_at is None
    assert source_event.record_ingested_at is None


def test_case_export_refuses_existing_destination_without_partial_file(
    tmp_path: Path, repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(case_id="case-output", title="Output failure")
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    database_path = repository.path
    repository.close()
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database_path))
    target = tmp_path / "existing-directory"
    target.mkdir()

    result = runner.invoke(
        app,
        ["case", "export", case.case_id, "--format", "json", "--output", str(target)],
    )

    assert result.exit_code == 2
    assert "already exists" in result.output
    assert list(tmp_path.glob(".existing-directory.*.tmp")) == []
