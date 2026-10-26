"""Local subprocess adapters for Semgrep, Gitleaks, and Trivy JSON output."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, BinaryIO

from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.orchestration.code_scan import ScannerError, make_finding

_INHERITED_ENV_ALLOWLIST = {
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
MAX_OUTPUT_BYTES = 10_000_000
_OUTPUT_CHUNK_BYTES = 64 * 1024


def _severity(value: object, default: Severity = Severity.MEDIUM) -> Severity:
    normalized = str(value).lower()
    aliases = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "informational": Severity.INFO,
    }
    if normalized in aliases:
        return aliases[normalized]
    try:
        return Severity(normalized)
    except ValueError:
        return default


def _safe_text(value: object, fallback: str, limit: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    return value.strip()[:limit]


def _relative_location(target: Path, filename: object, line: object = None) -> str | None:
    if not isinstance(filename, str) or not filename:
        return None
    candidate = Path(filename)
    try:
        resolved = (
            candidate.resolve() if candidate.is_absolute() else (target / candidate).resolve()
        )
        relative = resolved.relative_to(target.resolve()).as_posix()
    except (OSError, ValueError):
        relative = candidate.name
    if isinstance(line, int) and line > 0:
        return f"{relative}:{line}"
    return relative


class _JsonTool:
    name: str
    executable: str

    def __init__(self, timeout_seconds: float = 120.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def _run(self, target: Path, args: list[str], accepted_codes: set[int]) -> Any:
        executable = shutil.which(self.executable)
        if executable is None:
            raise ScannerError(f"{self.name} is not installed or not available on PATH.")
        # External scanner plugins should not inherit cloud tokens, package registry
        # credentials, or other secrets from the parent process.
        env = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in _INHERITED_ENV_ALLOWLIST
        }
        env["DO_NOT_TRACK"] = "1"
        env["SEMGREP_SEND_METRICS"] = "off"
        process: subprocess.Popen[bytes] | None = None
        stdout = bytearray()
        stderr = bytearray()
        exceeded = threading.Event()

        def drain(pipe: BinaryIO, buffer: bytearray) -> None:
            try:
                while chunk := pipe.read(_OUTPUT_CHUNK_BYTES):
                    if len(buffer) + len(chunk) > MAX_OUTPUT_BYTES:
                        remaining = max(0, MAX_OUTPUT_BYTES - len(buffer))
                        buffer.extend(chunk[:remaining])
                        exceeded.set()
                        if process is not None:
                            process.kill()
                    elif not exceeded.is_set():
                        buffer.extend(chunk)
            finally:
                pipe.close()

        threads: list[threading.Thread] = []
        try:
            process = subprocess.Popen(
                [executable, *args],
                cwd=target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=env,
            )
            assert process.stdout is not None and process.stderr is not None
            threads = [
                threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
                threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                returncode = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise ScannerError(f"{self.name} exceeded its configured timeout.") from exc
            except BaseException:
                process.kill()
                process.wait()
                raise
            finally:
                for thread in threads:
                    thread.join()
        except OSError as exc:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            for pipe in (process.stdout, process.stderr) if process is not None else ():
                if pipe is not None:
                    pipe.close()
            raise ScannerError(f"{self.name} could not be started.") from exc
        if exceeded.is_set():
            raise ScannerError(f"{self.name} exceeded the configured output limit.")
        if returncode not in accepted_codes:
            raise ScannerError(f"{self.name} exited with status {returncode}.")
        try:
            return json.loads(stdout.decode("utf-8", errors="replace") or "null")
        except json.JSONDecodeError as exc:
            raise ScannerError(f"{self.name} returned invalid JSON output.") from exc


class SemgrepScanner(_JsonTool):
    """Run Semgrep locally with metrics disabled and normalize metadata only."""

    name = "semgrep"
    executable = "semgrep"

    def __init__(self, config_path: Path | None = None, timeout_seconds: float = 120.0) -> None:
        super().__init__(timeout_seconds)
        self.config_path = config_path

    def scan(self, target: Path) -> list[Finding]:
        if self.config_path is None or not self.config_path.is_file():
            raise ScannerError(
                "Semgrep requires a readable local rules file; network rules are disabled."
            )
        data = self._run(
            target,
            [
                "scan",
                "--config",
                str(self.config_path.resolve()),
                "--json",
                "--metrics=off",
                "--quiet",
                "--no-git-ignore",
                str(target),
            ],
            {0, 1},
        )
        results = data.get("results", []) if isinstance(data, dict) else []
        findings: list[Finding] = []
        for item in results if isinstance(results, list) else []:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra", {})
            start = item.get("start", {})
            if not isinstance(extra, dict):
                extra = {}
            if not isinstance(start, dict):
                start = {}
            rule_id = _safe_text(item.get("check_id"), "semgrep-unknown")
            findings.append(
                make_finding(
                    target=target,
                    scanner=self.name,
                    rule_id=rule_id,
                    title=rule_id.rsplit(".", 1)[-1][:120],
                    severity=_severity(extra.get("severity")),
                    location=_relative_location(target, item.get("path"), start.get("line")),
                    tags=["external", "local"],
                )
            )
        return findings


class GitleaksScanner(_JsonTool):
    """Run Gitleaks against the local directory and omit secret values."""

    name = "gitleaks"
    executable = "gitleaks"

    def scan(self, target: Path) -> list[Finding]:
        data = self._run(
            target,
            [
                "detect",
                "--source",
                str(target),
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--no-banner",
            ],
            {0, 1},
        )
        findings: list[Finding] = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict):
                continue
            rule_id = _safe_text(item.get("RuleID"), "gitleaks-unknown")
            findings.append(
                make_finding(
                    target=target,
                    scanner=self.name,
                    rule_id=rule_id,
                    title="Potential hard-coded secret",
                    severity=Severity.HIGH,
                    category="SECRETS",
                    confidence="LIKELY",
                    location=_relative_location(target, item.get("File"), item.get("StartLine")),
                    description="A secret pattern was detected; matched content is omitted.",
                    tags=["external", "local", "secret"],
                )
            )
        return findings


class TrivyScanner(_JsonTool):
    """Run Trivy filesystem scanners using only locally cached vulnerability data."""

    name = "trivy"
    executable = "trivy"

    def scan(self, target: Path) -> list[Finding]:
        data = self._run(
            target,
            [
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln,misconfig,secret",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                str(target),
            ],
            {0},
        )
        results = data.get("Results", []) if isinstance(data, dict) else []
        findings: list[Finding] = []
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            result_target = result.get("Target")
            for field, category in (
                ("Vulnerabilities", "SCA"),
                ("Misconfigurations", "IAC"),
                ("Secrets", "SECRETS"),
            ):
                items = result.get(field, [])
                for item in items if isinstance(items, list) else []:
                    if not isinstance(item, dict):
                        continue
                    rule_id = _safe_text(
                        item.get("VulnerabilityID") or item.get("ID") or item.get("RuleID"),
                        f"trivy-{field.lower()}",
                    )
                    findings.append(
                        make_finding(
                            target=target,
                            scanner=self.name,
                            rule_id=rule_id,
                            title=rule_id,
                            severity=_severity(
                                item.get("Severity"),
                                Severity.HIGH if category == "SECRETS" else Severity.MEDIUM,
                            ),
                            category=category,
                            confidence="LIKELY" if category == "SECRETS" else "POSSIBLE",
                            location=_relative_location(target, result_target),
                            description=(
                                "Normalized Trivy candidate finding; validate with an analyst."
                            ),
                            tags=["external", "local"],
                        )
                    )
        return findings


class PipAuditScanner(_JsonTool):
    """Audit a local requirements file; execution requires CLI network opt-in."""

    name = "pip-audit"
    executable = "pip-audit"

    def scan(self, target: Path) -> list[Finding]:
        requirements = target / "requirements.txt"
        if not requirements.is_file():
            return []
        data = self._run(
            target,
            ["-r", str(requirements), "--format", "json"],
            {0, 1},
        )
        dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
        findings: list[Finding] = []
        for dependency in dependencies if isinstance(dependencies, list) else []:
            if not isinstance(dependency, dict):
                continue
            package = _safe_text(dependency.get("name"), "unknown-package", 100)
            vulnerabilities = dependency.get("vulns", [])
            for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
                if not isinstance(vulnerability, dict):
                    continue
                advisory_id = _safe_text(vulnerability.get("id"), "unknown-advisory")
                findings.append(
                    make_finding(
                        target=target,
                        scanner=self.name,
                        rule_id=advisory_id,
                        title=f"Vulnerable dependency: {package}",
                        severity=Severity.HIGH,
                        category="SCA",
                        confidence="CONFIRMED",
                        location=f"requirements.txt:{package}",
                        description=(
                            "Installed version matches a published advisory; "
                            "review its fix guidance."
                        ),
                        tags=["external", "network-audit", "dependency"],
                    )
                )
        return findings


class NpmAuditScanner(_JsonTool):
    """Audit a local npm lockfile; execution requires CLI network opt-in."""

    name = "npm-audit"
    executable = "npm"

    def scan(self, target: Path) -> list[Finding]:
        if not (target / "package-lock.json").is_file() or not (target / "package.json").is_file():
            return []
        data = self._run(
            target,
            ["audit", "--json", "--package-lock-only", "--no-fund", "--no-progress"],
            {0, 1},
        )
        vulnerabilities = data.get("vulnerabilities", {}) if isinstance(data, dict) else {}
        findings: list[Finding] = []
        if not isinstance(vulnerabilities, dict):
            return findings
        for package, item in vulnerabilities.items():
            if not isinstance(item, dict):
                continue
            package_name = _safe_text(package, "unknown-package", 100)
            severity = _severity(item.get("severity"), Severity.HIGH)
            via_items = item.get("via", [])
            advisory_ids = (
                [
                    _safe_text(via.get("url") or via.get("name"), "npm-advisory")
                    for via in via_items
                    if isinstance(via, dict)
                ]
                if isinstance(via_items, list)
                else []
            )
            advisory_id = ",".join(advisory_ids)[:200] or package_name
            findings.append(
                make_finding(
                    target=target,
                    scanner=self.name,
                    rule_id=advisory_id,
                    title=f"Vulnerable dependency: {package_name}",
                    severity=severity,
                    category="SCA",
                    confidence="CONFIRMED",
                    location=f"package-lock.json:{package_name}",
                    description=(
                        "Installed version matches a published advisory; review its fix guidance."
                    ),
                    tags=["external", "network-audit", "dependency"],
                )
            )
        return findings
