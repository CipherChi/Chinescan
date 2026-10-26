"""Run an offline recovery and operator cutover drill against synthetic data."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.cases import CaseWorkflow
from chinescan.core.models.investigation import CaseStatus
from chinescan.core.storage.recovery import verify_backup
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.log_analysis.service import LogAnalysisService

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sample-logs"
ROLLBACK_NOTE = "RECOVERY-DRILL-RESTORED-ONLY-9f1a27"


def _invoke(runner: CliRunner, database: Path, *args: str) -> str:
    """Select an existing database explicitly before invoking one CLI command."""
    if not database.is_file():
        raise RuntimeError("Selected drill database does not exist; refusing CLI initialization.")
    result = runner.invoke(app, ["--database", str(database), *args])
    if result.exit_code != 0:
        raise RuntimeError(f"Drill CLI step failed ({' '.join(args)}): {result.output.strip()}")
    return result.stdout


def run_drill(root: Path) -> dict[str, str]:
    """Run a full synthetic backup, new-path cutover, and selection rollback."""
    root.mkdir(parents=True, exist_ok=False)
    original = root / "original.sqlite3"
    restored = root / "restored.sqlite3"
    bundle = root / "backup-bundle"
    repository = SQLiteRepository(original)
    try:
        analysis = LogAnalysisService(repository).analyze(FIXTURES)
        workflow = CaseWorkflow(repository)
        case, warnings = workflow.create_from_scan(analysis.scan_id, title="Offline recovery drill")
        if warnings:
            raise RuntimeError("Synthetic scan produced unexpected case-link warnings.")
        workflow.add_note(case.case_id, "Synthetic original-database note.", "Drill operator")
        workflow.update_status(case.case_id, CaseStatus.IN_PROGRESS)
        expected = workflow.get_case(case.case_id)
    finally:
        repository.close()

    original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    runner = CliRunner()
    _invoke(runner, original, "db", "backup", "--output", str(bundle))
    verification = json.loads(
        _invoke(runner, original, "db", "verify-backup", str(bundle), "--format", "json")
    )
    if not verification["verified"]:
        raise RuntimeError("Backup verification failed; cutover was not attempted.")
    backup_database_id = verification["backup_id"]
    restore_result = json.loads(
        _invoke(
            runner,
            original,
            "db",
            "restore",
            str(bundle),
            "--output",
            str(restored),
            "--format",
            "json",
        )
    )
    if restore_result["destination"] != str(restored.resolve()):
        raise RuntimeError("Restore command selected an unexpected destination.")
    if hashlib.sha256(original.read_bytes()).hexdigest() != original_hash:
        raise RuntimeError("Original database changed during backup or restore.")

    # Each command opens and closes its repository before the next database selection.
    shown = json.loads(_invoke(runner, restored, "case", "show", expected.case_id))
    notes = json.loads(_invoke(runner, restored, "case", "note", "list", expected.case_id))
    timeline = json.loads(
        _invoke(runner, restored, "case", "timeline", expected.case_id, "--format", "json")
    )
    if shown["status"] != expected.status.value or not shown["links"]:
        raise RuntimeError("Restored case status or linked records differ from expected contents.")
    if not any(note["body"] == "Synthetic original-database note." for note in notes):
        raise RuntimeError("Restored original case note is missing.")
    if not timeline:
        raise RuntimeError("Restored case timeline is empty.")
    for report_format in ("json", "markdown", "html"):
        destination = root / f"case-report.{report_format if report_format != 'markdown' else 'md'}"
        _invoke(
            runner,
            restored,
            "case",
            "export",
            expected.case_id,
            "--format",
            report_format,
            "--output",
            str(destination),
        )
        if not destination.is_file() or destination.stat().st_size == 0:
            raise RuntimeError(f"{report_format} report was not published.")

    _invoke(
        runner,
        restored,
        "case",
        "note",
        "add",
        expected.case_id,
        "--text",
        ROLLBACK_NOTE,
        "--author",
        "Drill operator",
    )

    # Rollback means selecting the original path again; it does not merge restored writes.
    original_case = json.loads(_invoke(runner, original, "case", "show", expected.case_id))
    original_notes = json.loads(_invoke(runner, original, "case", "note", "list", expected.case_id))
    restored_notes = json.loads(_invoke(runner, restored, "case", "note", "list", expected.case_id))
    if original_case["status"] != expected.status.value:
        raise RuntimeError("Original case changed during the cutover drill.")
    if any(note["body"] == ROLLBACK_NOTE for note in original_notes):
        raise RuntimeError("Restored-only note unexpectedly appeared in the original database.")
    if not any(note["body"] == ROLLBACK_NOTE for note in restored_notes):
        raise RuntimeError("Restored-only note is missing from the restored database.")
    if hashlib.sha256(original.read_bytes()).hexdigest() != original_hash:
        raise RuntimeError("Original database changed during rollback verification.")
    if not verify_backup(bundle).verified:
        raise RuntimeError("Original backup bundle changed during the drill.")
    return {
        "case_id": expected.case_id,
        "scan_id": analysis.scan_id,
        "backup_id": str(backup_database_id),
        "original_database": str(original),
        "restored_database": str(restored),
        "reports": "JSON, Markdown, and HTML generated",
        "rollback": "original intact; restored-only write remains divergent in restored copy",
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="chinescan-recovery-acceptance-") as directory:
        result = run_drill(Path(directory) / "drill")
        print(json.dumps(result, sort_keys=True, indent=2))
        print(
            "Rollback changes database selection only. Post-cutover writes remain in the restored "
            "database and are not merged into the original."
        )


if __name__ == "__main__":
    main()
