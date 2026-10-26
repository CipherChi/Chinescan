"""Opt-in checks against installed scanner binaries and local-only assets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from chinescan.core.models.investigation import Scan
from chinescan.core.orchestration.code_scan import CodeScanService
from chinescan.core.reporting import render_report
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.malware_analysis.engines import run_clamav, run_yara
from chinescan.scanners.external import GitleaksScanner, SemgrepScanner, TrivyScanner

pytestmark = pytest.mark.real_scanner
ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "fixtures" / "real-scanners"
MAX_DIRECT_OUTPUT = 1_000_000
DIRECT_TIMEOUT_SECONDS = 60.0
ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "TMP",
    "TEMP",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "SYSTEMDRIVE",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LANGUAGE",
    "TZ",
}


def _required_tool(
    name: str,
    *,
    strict: bool,
    asset_ready: bool = True,
    asset_reason: str = "",
) -> str:
    executable = shutil.which(name)
    reason = f"{name} executable is not installed or not on PATH"
    if executable is not None and not asset_ready:
        reason = f"{name} local asset unavailable: {asset_reason}"
    if executable is None or not asset_ready:
        if strict:
            pytest.fail(reason, pytrace=False)
        pytest.skip(reason)
    return executable


def _safe_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key.upper() in ENV_ALLOWLIST}
    env.update({"DO_NOT_TRACK": "1", "SEMGREP_SEND_METRICS": "off"})
    return env


def _run_bounded(argv: list[str], cwd: Path) -> tuple[int, str]:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        env=_safe_environment(),
    )
    assert process.stdout is not None
    output = bytearray()
    overflow = threading.Event()

    def drain() -> None:
        while chunk := process.stdout.read(8192):
            remaining = MAX_DIRECT_OUTPUT - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow.set()
                if process.poll() is None:
                    process.kill()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=DIRECT_TIMEOUT_SECONDS)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        reader.join(timeout=2)
        raise
    reader.join(timeout=2)
    if reader.is_alive():
        process.stdout.close()
        reader.join(timeout=2)
    if overflow.is_set():
        pytest.fail("Direct scanner output exceeded the 1 MB integration-test bound.")
    return return_code, output.decode("utf-8", errors="replace")


def _version(name: str, executable: str, args: list[str]) -> str:
    code, output = _run_bounded([executable, *args], ROOT)
    assert code == 0, f"{name} version command failed with exit {code}"
    version = output.strip().splitlines()[0] if output.strip() else ""
    assert version, f"{name} returned no version"
    return version


def _assert_ci_pin(version: str, expected: str) -> None:
    observed = version.strip().split()[-1].lstrip("v")
    assert observed == expected, (
        f"Scanner version {observed} differs from configured CI pin {expected}"
    )


def _persist_and_report(scanner, target: Path, tmp_path: Path) -> list[dict[str, object]]:
    repository = SQLiteRepository(tmp_path / f"{scanner.name}.sqlite3")
    try:
        result = CodeScanService([scanner], repository).scan(target)
        assert result.failures == {}
        scan = repository.get("scan", result.scan_id)
        assert scan is not None and scan["finding_ids"]
        persisted = [repository.get("finding", item) for item in scan["finding_ids"]]
        assert all(item is not None for item in persisted)
        report = json.loads(render_report(Scan.model_validate(scan), result.findings, "json"))
        return report["findings"]
    finally:
        repository.close()


def _trivy_db_available() -> tuple[bool, str]:
    if os.name == "nt":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        cache = local_app_data / "aquasecurity" / "trivy"
    else:
        cache = Path.home() / ".cache" / "trivy"
    database = cache / "db"
    if any((database / name).is_file() for name in ("metadata.json", "trivy.db", "trivy.db.gz")):
        return True, ""
    return False, f"no Trivy vulnerability database at {database}"


def _clamav_signatures_available() -> tuple[bool, str]:
    if os.name == "nt":
        roots = [
            Path(os.environ.get("ProgramData", "C:/ProgramData")) / "clamav",
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ClamAV",
        ]
    else:
        roots = [Path("/var/lib/clamav"), Path("/usr/local/share/clamav")]
    for root in roots:
        if root.is_dir() and (any(root.glob("*.cvd")) or any(root.glob("*.cld"))):
            return True, ""
    return False, "no local .cvd/.cld signature database in standard ClamAV locations"


def test_semgrep_real_local_positive_negative_persistence_and_report(
    tmp_path: Path, pytestconfig: pytest.Config, record_property
) -> None:
    executable = _required_tool("semgrep", strict=pytestconfig.getoption("--require-real-scanners"))
    version = _version("Semgrep", executable, ["--version"])
    rules = FIXTURES / "semgrep-local.yml"
    positive = FIXTURES / "semgrep-positive"
    negative = FIXTURES / "semgrep-clean"
    direct_code, direct_output = _run_bounded(
        [
            executable,
            "scan",
            "--config",
            str(rules),
            "--json",
            "--metrics=off",
            "--quiet",
            "--no-git-ignore",
            str(positive),
        ],
        positive,
    )
    assert direct_code in {0, 1}, f"Semgrep {version} failed with exit {direct_code}"
    assert any(
        result.get("check_id") == "chinescan.local.synthetic-eval"
        for result in json.loads(direct_output).get("results", [])
    )
    scanner = SemgrepScanner(config_path=rules, timeout_seconds=DIRECT_TIMEOUT_SECONDS)
    findings = scanner.scan(positive)
    assert len(findings) == 1
    assert findings[0].rule_id == "chinescan.local.synthetic-eval"
    assert findings[0].location == "app.py:1"
    assert findings[0].severity.value == "high"
    assert scanner.scan(negative) == []
    persisted = _persist_and_report(scanner, positive, tmp_path)
    assert persisted[0]["rule_id"] == "chinescan.local.synthetic-eval"
    assert persisted[0]["location"] == "app.py:1"
    record_property("semgrep_version", version)


def test_gitleaks_real_local_positive_negative_persistence_and_redaction(
    tmp_path: Path, pytestconfig: pytest.Config, record_property
) -> None:
    executable = _required_tool(
        "gitleaks", strict=pytestconfig.getoption("--require-real-scanners")
    )
    version = _version("Gitleaks", executable, ["version"])
    _assert_ci_pin(version, "8.30.1")
    positive = FIXTURES / "gitleaks-positive"
    negative = FIXTURES / "gitleaks-clean"
    direct_code, direct_output = _run_bounded(
        [
            executable,
            "detect",
            "--source",
            str(positive),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
        ],
        positive,
    )
    assert direct_code in {0, 1}, f"Gitleaks {version} failed with exit {direct_code}"
    direct_findings = json.loads(direct_output)
    assert any(item.get("RuleID") and item.get("StartLine") == 1 for item in direct_findings)
    scanner = GitleaksScanner(timeout_seconds=DIRECT_TIMEOUT_SECONDS)
    findings = scanner.scan(positive)
    assert len(findings) == 1
    assert findings[0].rule_id
    assert findings[0].location == "credential.txt:1"
    assert findings[0].severity.value == "high"
    assert findings[0].category == "SECRETS"
    assert scanner.scan(negative) == []
    persisted = _persist_and_report(scanner, positive, tmp_path)
    serialized = json.dumps(persisted)
    assert "ghp_0123456789abcdef0123456789abcdef0123" not in serialized
    record_property("gitleaks_version", version)


def test_trivy_real_offline_local_database_positive_negative_and_persistence(
    tmp_path: Path, pytestconfig: pytest.Config, record_property
) -> None:
    database_available, database_reason = _trivy_db_available()
    executable = _required_tool(
        "trivy",
        strict=pytestconfig.getoption("--require-real-scanners"),
        asset_ready=database_available,
        asset_reason=database_reason,
    )
    version = _version("Trivy", executable, ["--version"])
    _assert_ci_pin(version, "0.76.1")
    config = FIXTURES / "trivy-local-config"
    direct_code, direct_output = _run_bounded(
        [
            executable,
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            str(config),
        ],
        config,
    )
    assert direct_code == 0, f"Trivy {version} failed with exit {direct_code}"
    direct_results = json.loads(direct_output).get("Results", [])
    assert direct_results, "Trivy did not return a filesystem result for the local fixture"
    scanner = TrivyScanner(timeout_seconds=DIRECT_TIMEOUT_SECONDS)
    findings = scanner.scan(config)
    assert findings, "Trivy did not report the reviewed root-user Dockerfile configuration"
    assert all(item.scanner == "trivy" and item.rule_id for item in findings)
    clean = FIXTURES / "trivy-clean-config"
    assert scanner.scan(clean) == []
    persisted = _persist_and_report(scanner, config, tmp_path)
    assert persisted and all(item["scanner"] == "trivy" for item in persisted)
    record_property("trivy_version", version)


def test_yara_real_local_positive_and_negative(
    pytestconfig: pytest.Config, record_property
) -> None:
    executable = _required_tool("yara", strict=pytestconfig.getoption("--require-real-scanners"))
    version = _version("YARA", executable, ["--version"])
    rules = FIXTURES / "yara-local.yar"
    positive = FIXTURES / "yara-positive.txt"
    negative = FIXTURES / "yara-clean.txt"
    direct_code, direct_output = _run_bounded(
        [executable, "-w", str(rules), str(positive)], positive.parent
    )
    assert direct_code == 0 and "ChineScan_Local_Benign_Marker" in direct_output
    direct_negative_code, _ = _run_bounded(
        [executable, "-w", str(rules), str(negative)], negative.parent
    )
    assert direct_negative_code == 1, "YARA no-match must be distinguished from execution failure"
    positive_result = run_yara(positive, rules)
    negative_result = run_yara(negative, rules)
    assert positive_result.matches == ("ChineScan_Local_Benign_Marker",)
    assert negative_result.matches == () and negative_result.warning is None
    record_property("yara_version", version)


def test_clamav_real_local_clean_fixture(pytestconfig: pytest.Config, record_property) -> None:
    signatures_available, signature_reason = _clamav_signatures_available()
    executable = _required_tool(
        "clamscan",
        strict=pytestconfig.getoption("--require-real-scanners"),
        asset_ready=signatures_available,
        asset_reason=signature_reason,
    )
    version = _version("ClamAV", executable, ["--version"])
    clean = FIXTURES / "clamav-clean.txt"
    direct_code, direct_output = _run_bounded(
        [executable, "--no-summary", str(clean)], clean.parent
    )
    assert direct_code == 0, f"ClamAV {version} clean fixture returned exit {direct_code}"
    assert " OK" in direct_output
    result = run_clamav(clean)
    assert result.matches == () and result.warning is None
    record_property("clamav_version", version)
