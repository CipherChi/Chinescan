import json
from pathlib import Path

from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Confidence, Severity
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    CodeScanService,
    ScannerError,
    detect_project,
    make_finding,
)
from chinescan.core.storage.sqlite import SQLiteRepository

FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_detects_python_and_node_projects() -> None:
    python_project = detect_project(FIXTURES / "sample-python-project")
    node_project = detect_project(FIXTURES / "sample-node-project")
    assert python_project.kinds == ("python",)
    assert node_project.kinds == ("node",)
    assert any(path.name == "app.py" for path in python_project.source_files)


def test_oversized_source_is_reported_as_scan_failure(tmp_path: Path) -> None:
    project = tmp_path / "large-project"
    project.mkdir()
    (project / "large.py").write_bytes(b"x" * 1_000_001)
    try:
        detect_project(project)
    except ScannerError as exc:
        assert "above the configured 1 MB limit" in str(exc)
    else:
        raise AssertionError("Oversized source was silently omitted from the scan.")


def test_builtin_scanner_does_not_return_secret_value() -> None:
    findings = BuiltinRuleScanner().scan(FIXTURES / "sample-python-project")
    assert {finding.rule_id for finding in findings} == {
        "DYNAMIC-EVAL",
        "PY-SHELL",
        "HARDCODED-CREDENTIAL",
    }
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "example-fixture-password" not in serialized
    assert all(finding.fingerprint for finding in findings)
    assert all(finding.location for finding in findings)


def test_orchestration_deduplicates_isolates_and_persists(tmp_path: Path) -> None:
    target = FIXTURES / "sample-python-project"

    class DuplicateScanner:
        name = "duplicate"

        def scan(self, scan_target: Path):
            return [
                finding.model_copy(
                    update={
                        "scanner": self.name,
                        "severity": Severity.CRITICAL,
                        "confidence": Confidence.CONFIRMED,
                    }
                )
                for finding in BuiltinRuleScanner().scan(scan_target)
            ]

    class BrokenScanner:
        name = "broken"

        def scan(self, scan_target: Path):
            del scan_target
            raise ScannerError("test failure")

    repository = SQLiteRepository(tmp_path / "scan.sqlite3")
    try:
        result = CodeScanService(
            [BuiltinRuleScanner(), DuplicateScanner(), BrokenScanner()], repository
        ).scan(target)
        assert len(result.findings) == 3
        assert all(finding.scanner == "builtin,duplicate" for finding in result.findings)
        assert all(finding.severity == Severity.CRITICAL for finding in result.findings)
        assert all(finding.confidence == Confidence.CONFIRMED for finding in result.findings)
        assert result.failures == {"broken": "test failure"}
        scan_record = repository.get("scan", result.scan_id)
        assert scan_record is not None
        assert scan_record["status"] == "partial"
        assert repository.get("target", scan_record["target_id"]) is not None
        assert repository.get("finding", result.findings[0].finding_id) is not None
    finally:
        repository.close()


def test_fingerprint_is_stable_and_severity_independent(tmp_path: Path) -> None:
    low = make_finding(
        target=tmp_path,
        scanner="one",
        rule_id="RULE-1",
        title="Candidate",
        severity=Severity.LOW,
        location="app.py:4",
    )
    high = make_finding(
        target=tmp_path,
        scanner="two",
        rule_id="rule-1",
        title="Different prose",
        severity=Severity.HIGH,
        location="app.py:4",
    )
    assert low.fingerprint == high.fingerprint


def test_code_cli_json_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    result = CliRunner().invoke(
        app,
        ["code", str(FIXTURES / "sample-node-project"), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["project_types"] == ["node"]
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["rule_id"] == "DYNAMIC-EVAL"


def test_code_cli_severity_threshold_is_configurable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "threshold.sqlite3"))
    target = str(FIXTURES / "sample-python-project")
    high = CliRunner().invoke(app, ["code", target, "--fail-on", "high", "--format", "json"])
    assert high.exit_code == 1
    assert "Failing threshold high" in high.stderr
    assert json.loads(high.stdout)["finding_count"] >= 1

    critical = CliRunner().invoke(app, ["code", target, "--fail-on", "critical"])
    assert critical.exit_code == 0

    invalid = CliRunner().invoke(app, ["code", target, "--fail-on", "blocker"])
    assert invalid.exit_code == 2


def test_dependency_cli_requires_explicit_network_consent() -> None:
    result = CliRunner().invoke(
        app,
        ["code", str(FIXTURES / "sample-python-project"), "--scanner", "pip-audit"],
    )
    assert result.exit_code == 2
    assert "require explicit --allow-network-audits consent" in result.stderr
