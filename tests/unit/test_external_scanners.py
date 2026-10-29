import io
import json
import sys
from pathlib import Path

import pytest

from chinescan.core.orchestration.code_scan import ScannerError
from chinescan.scanners.external import (
    GitleaksScanner,
    NpmAuditScanner,
    PipAuditScanner,
    SemgrepScanner,
    TrivyScanner,
    _JsonTool,
)


class _FakeProcess:
    def __init__(self, command, returncode, stdout, stderr):
        self.args = command
        self.returncode = returncode
        self.stdout = io.BytesIO(stdout.encode())
        self.stderr = io.BytesIO(stderr.encode())
        self.killed = False

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_external_adapters_normalize_json_without_evidence(tmp_path: Path, monkeypatch) -> None:
    outputs = {
        "semgrep": json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.eval-detected",
                        "path": "app.py",
                        "start": {"line": 12},
                        "extra": {"severity": "ERROR", "message": "sensitive source excerpt"},
                    }
                ]
            }
        ),
        "gitleaks": json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": "settings.py",
                    "StartLine": 3,
                    "Secret": "must-not-leak",
                }
            ]
        ),
        "trivy": json.dumps(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-2099-1234", "Severity": "HIGH"}
                        ],
                    }
                ]
            }
        ),
    }
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda exe: exe)
    monkeypatch.setenv("CHINESCAN_TEST_SECRET", "must-not-reach-scanner")
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")

    def run(args, **kwargs):
        assert kwargs["shell"] is False
        assert "PATH" in kwargs["env"]
        assert "CHINESCAN_TEST_SECRET" not in kwargs["env"]
        if Path(args[0]).name == "trivy":
            assert "--offline-scan" in args
            assert "--skip-check-update" in args
        executable = Path(args[0]).name
        return _FakeProcess(args, 0, outputs[executable], "")

    monkeypatch.setattr("chinescan.scanners.external.subprocess.Popen", run)
    semgrep = SemgrepScanner(config_path=rules, timeout_seconds=30).scan(tmp_path)
    gitleaks = GitleaksScanner(timeout_seconds=30).scan(tmp_path)
    trivy = TrivyScanner(timeout_seconds=30).scan(tmp_path)

    assert semgrep[0].location == "app.py:12"
    assert semgrep[0].severity.value == "high"
    assert "sensitive source excerpt" not in semgrep[0].model_dump_json()
    assert gitleaks[0].category == "SECRETS"
    assert "must-not-leak" not in gitleaks[0].model_dump_json()
    assert trivy[0].category == "SCA"
    assert trivy[0].severity.value == "high"


def test_external_adapter_has_safe_missing_binary_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda _: None)
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(ScannerError, match="not installed"):
        SemgrepScanner(config_path=rules).scan(tmp_path)


def test_dependency_audits_normalize_advisories(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    outputs = {
        "pip-audit": json.dumps(
            {
                "dependencies": [
                    {
                        "name": "example",
                        "vulns": [{"id": "PYSEC-2099-1", "description": "private metadata"}],
                    }
                ]
            }
        ),
        "npm": json.dumps(
            {
                "vulnerabilities": {
                    "example": {
                        "severity": "high",
                        "via": [{"name": "sample-advisory", "url": "https://example.invalid/1"}],
                    }
                }
            }
        ),
    }
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda exe: exe)

    def run(args, **kwargs):
        return _FakeProcess(args, 1, outputs[Path(args[0]).name], "")

    monkeypatch.setattr("chinescan.scanners.external.subprocess.Popen", run)
    python_findings = PipAuditScanner().scan(tmp_path)
    node_findings = NpmAuditScanner().scan(tmp_path)
    assert python_findings[0].rule_id == "PYSEC-2099-1"
    assert python_findings[0].category == "SCA"
    assert "private metadata" not in python_findings[0].model_dump_json()
    assert node_findings[0].category == "SCA"
    assert node_findings[0].confidence == "CONFIRMED"


class _PythonJsonTool(_JsonTool):
    name = "fixture-scanner"
    executable = "python"


def _run_python(tmp_path: Path, monkeypatch, code: str, timeout: float = 10.0):
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda _: sys.executable)
    return _PythonJsonTool(timeout)._run(tmp_path, ["-c", code], {0})


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_limit_kills_child_and_reports_bounded_error(tmp_path, monkeypatch, stream) -> None:
    monkeypatch.setattr("chinescan.scanners.external.MAX_OUTPUT_BYTES", 1024)
    with pytest.raises(ScannerError, match="output limit"):
        _run_python(tmp_path, monkeypatch, f"import sys; sys.{stream}.write('x' * 10000000)")


def test_external_scanner_timeout_invalid_json_and_nonzero_exit(tmp_path, monkeypatch) -> None:
    with pytest.raises(ScannerError, match="timeout"):
        _run_python(tmp_path, monkeypatch, "import time; time.sleep(10)", timeout=0.1)
    with pytest.raises(ScannerError, match="invalid JSON"):
        _run_python(tmp_path, monkeypatch, "print('not-json')")
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda _: sys.executable)
    with pytest.raises(ScannerError, match="status 7"):
        _PythonJsonTool()._run(tmp_path, ["-c", "import sys; sys.exit(7)"], {0})


def test_external_scanner_success_with_controlled_helper_process(tmp_path, monkeypatch) -> None:
    assert _run_python(tmp_path, monkeypatch, "print('{\\\"ok\\\": true}')") == {"ok": True}


def test_cancellation_kills_child_and_closes_both_pipes(tmp_path, monkeypatch) -> None:
    process = _FakeProcess(["scanner"], 0, "", "")

    def interrupted_wait(timeout=None):
        raise KeyboardInterrupt

    process.wait = interrupted_wait
    monkeypatch.setattr("chinescan.scanners.external.shutil.which", lambda _: "scanner")
    monkeypatch.setattr(
        "chinescan.scanners.external.subprocess.Popen", lambda *args, **kwargs: process
    )
    with pytest.raises(KeyboardInterrupt):
        _PythonJsonTool()._run(tmp_path, [], {0})
    assert process.killed
    assert process.stdout.closed and process.stderr.closed
