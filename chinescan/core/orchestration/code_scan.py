"""Local project detection, scanner execution, and normalized scan persistence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from chinescan.core.models.common import EvidenceKind, ScanVerdict, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import CoverageGap, CoverageReport, Scan, Target
from chinescan.core.storage.repository import Repository
from chinescan.core.verdict import VERDICT_CAVEAT

SOURCE_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 20_000
MAX_TOTAL_SOURCE_BYTES = 250_000_000


@dataclass(frozen=True)
class ProjectProfile:
    """Detected local project traits used to describe code scan targets."""

    root: Path
    kinds: tuple[str, ...]
    source_files: tuple[Path, ...]


class FindingScanner(Protocol):
    """Adapter boundary shared by local and external finding scanners."""

    name: str

    def scan(self, target: Path) -> list[Finding]: ...


class ScannerError(Exception):
    """Expected scanner execution, availability, or output failure."""


def detect_project(target: Path) -> ProjectProfile:
    """Resolve a local project directory and identify source files and manifests."""
    try:
        root = target.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScannerError("Target directory does not exist or is inaccessible.") from exc
    if not root.is_dir():
        raise ScannerError("Code scan target must be a local directory.")

    kinds: set[str] = set()
    sources: list[Path] = []

    def walk_error(_: OSError) -> None:
        raise ScannerError("A project directory could not be read; scan aborted.")

    total_bytes = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORED_DIRS)
        current = Path(directory)
        names = set(filenames)
        if "pyproject.toml" in names or "requirements.txt" in names or "setup.py" in names:
            kinds.add("python")
        if "package.json" in names or "package-lock.json" in names:
            kinds.add("node")
        for name in sorted(filenames):
            path = current / name
            if path.suffix.lower() in SOURCE_SUFFIXES and not path.is_symlink():
                try:
                    size = path.stat().st_size
                    if size > MAX_SOURCE_BYTES:
                        raise ScannerError(
                            "Project contains a source file above the configured 1 MB limit."
                        )
                    sources.append(path)
                    total_bytes += size
                    if len(sources) > MAX_SOURCE_FILES or total_bytes > MAX_TOTAL_SOURCE_BYTES:
                        raise ScannerError("Project exceeds the configured local scan size limits.")
                except OSError:
                    continue
    return ProjectProfile(root=root, kinds=tuple(sorted(kinds)), source_files=tuple(sources))


def make_finding(
    *,
    target: Path,
    scanner: str,
    rule_id: str,
    title: str,
    severity: Severity,
    category: str = "SAST",
    confidence: str = "POSSIBLE",
    location: str | None = None,
    description: str = "Candidate finding; validate with an analyst.",
    tags: list[str] | None = None,
    evidence: EvidenceKind | None = None,
) -> Finding:
    """Build a schema-valid finding with stable target/rule/location identity."""
    normalized_target = os.path.normcase(str(target.resolve()))
    normalized_location = os.path.normcase(location or "")
    identity = json.dumps(
        [normalized_target, category.upper(), rule_id.strip().lower(), normalized_location],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint))
    return Finding(
        finding_id=finding_id,
        title=title,
        description=description,
        severity=severity,
        fingerprint=fingerprint,
        category=category.upper(),
        confidence=confidence,
        scanner=scanner,
        rule_id=rule_id,
        location=location,
        tags=tags or [],
        evidence=evidence,
    )


class BuiltinRuleScanner:
    """Small local-only heuristic ruleset; reads source without executing it."""

    name = "builtin"
    _rules: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
        (
            "DYNAMIC-EVAL",
            re.compile(r"\beval\s*\("),
            Severity.HIGH,
            "Dynamic evaluation can execute attacker-controlled input.",
        ),
        (
            "PY-SHELL",
            re.compile(
                r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*\bshell\s*=\s*True"
            ),
            Severity.HIGH,
            "Shell command construction can expose command injection risk.",
        ),
        (
            "TLS-VERIFY-DISABLED",
            re.compile(r"\bverify\s*=\s*False\b"),
            Severity.MEDIUM,
            "Disabling TLS certificate validation weakens transport security.",
        ),
        (
            "HARDCODED-CREDENTIAL",
            re.compile(
                r"(?i)\b(?:password|passwd|api[_-]?key|secret|access[_-]?token)\b"
                r"\s*[:=]\s*(['\"]).{4,}?\1"
            ),
            Severity.HIGH,
            "A credential-like literal is present; the value is intentionally omitted.",
        ),
    )

    def scan(self, target: Path) -> list[Finding]:
        profile = detect_project(target)
        findings: list[Finding] = []
        for source in profile.source_files:
            try:
                text = source.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ScannerError("A source file could not be read; scan aborted.") from exc
            relative = source.relative_to(profile.root).as_posix()
            for line_number, line in enumerate(text.splitlines(), start=1):
                if len(line) > 10_000:
                    continue
                for rule_id, pattern, severity, description in self._rules:
                    if pattern.search(line):
                        findings.append(
                            make_finding(
                                target=profile.root,
                                scanner=self.name,
                                rule_id=rule_id,
                                title=rule_id.replace("-", " ").title(),
                                severity=severity,
                                location=f"{relative}:{line_number}",
                                description=description,
                                evidence=EvidenceKind.PATTERN_MATCH,
                                tags=["heuristic", "local"],
                            )
                        )
        return findings


@dataclass
class CodeScanResult:
    """Normalized, deduplicated output and operational metadata for one scan."""

    scan_id: str
    target: str
    project_types: list[str]
    scanners: list[str]
    findings: list[Finding]
    failures: dict[str, str]
    started_at: datetime
    finished_at: datetime
    coverage: CoverageReport | None = None
    verdict: ScanVerdict | None = None
    scan_options: dict[str, str | int | float | bool] | None = None

    def summary(self) -> dict[str, object]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "project_types": self.project_types,
            "scanners": self.scanners,
            "finding_count": len(self.findings),
            "severity_counts": counts,
            "failures": self.failures,
            "findings": [finding.model_dump(mode="json") for finding in self.findings],
            "coverage": self.coverage.model_dump(mode="json") if self.coverage else None,
            "verdict": self.verdict.value if self.verdict else None,
            "caveat": VERDICT_CAVEAT.get(self.verdict) if self.verdict is not None else None,
            "scan_options": self.scan_options or {},
        }


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate locations deterministically, retaining the strongest signal."""
    severity_rank = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    confidence_rank = {"INFORMATIONAL": 0, "POSSIBLE": 1, "LIKELY": 2, "CONFIRMED": 3}
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.fingerprint, []).append(finding)

    merged: list[Finding] = []
    for duplicates in grouped.values():
        canonical = min(
            duplicates,
            key=lambda item: (item.scanner, item.title, item.description),
        )
        severity = max(duplicates, key=lambda item: severity_rank[item.severity]).severity
        confidence = max(
            duplicates,
            key=lambda item: confidence_rank[item.confidence.value],
        ).confidence
        scanners = ",".join(sorted({item.scanner for item in duplicates}))
        tags = sorted({tag for item in duplicates for tag in item.tags})
        merged.append(
            canonical.model_copy(
                update={
                    "severity": severity,
                    "confidence": confidence,
                    "scanner": scanners,
                    "tags": tags,
                }
            )
        )
    return sorted(merged, key=lambda item: (item.location or "", item.rule_id, item.scanner))


def _coverage_for_project(
    profile: ProjectProfile, scanners: list[str], failures: dict[str, str]
) -> CoverageReport:
    gaps: list[CoverageGap] = []
    long_lines = 0
    symlinks = 0
    unreadable = 0
    for directory, dirnames, filenames in os.walk(profile.root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORED_DIRS)
        current = Path(directory)
        for name in sorted(filenames):
            path = current / name
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                symlinks += 1
                continue
            try:
                if path.stat().st_size > MAX_SOURCE_BYTES:
                    continue
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if len(line) > 10_000:
                        long_lines += 1
            except OSError:
                unreadable += 1
    if long_lines:
        gaps.append(
            CoverageGap(
                code="code_line_too_long",
                reason="Lines over 10,000 characters were skipped.",
                count=long_lines,
            )
        )
    if symlinks:
        gaps.append(
            CoverageGap(
                code="symlink_skipped",
                reason="Symlinked source files were skipped.",
                count=symlinks,
            )
        )
    if unreadable:
        gaps.append(
            CoverageGap(
                code="unreadable_file", reason="Source files could not be read.", count=unreadable
            )
        )
    for name in sorted(failures):
        gaps.append(
            CoverageGap(
                code="scanner_failed",
                reason="A scanner failed; other scanner results were retained.",
                source=name,
            )
        )
    return CoverageReport(
        examined={
            "files_scanned": len(profile.source_files),
            "bytes_scanned": sum(path.stat().st_size for path in profile.source_files),
            "scanner_count": len(scanners),
        },
        gaps=gaps,
    )


class CodeScanService:
    """Run selected local scanners concurrently and persist normalized records."""

    def __init__(
        self,
        scanners: list[FindingScanner],
        repository: Repository | None = None,
        max_workers: int = 3,
        repository_lock: threading.RLock | None = None,
    ) -> None:
        self.scanners = scanners
        self.repository = repository
        self.max_workers = max(1, min(max_workers, 8))
        self.repository_lock = repository_lock

    def scan(self, target: Path) -> CodeScanResult:
        started = datetime.now(UTC)
        scan_id = str(uuid.uuid4())
        scanner_names = [scanner.name for scanner in self.scanners]
        try:
            profile = detect_project(target)
        except ScannerError as exc:
            message = str(exc)
            if "1 MB limit" in message:
                gap_code = "file_size_limit"
            elif "scan size limits" in message:
                gap_code = "file_count_or_size_limit"
            else:
                gap_code = "scan_failed"
            failure_info = {"project": message}
            coverage = CoverageReport(
                gaps=[
                    CoverageGap(
                        code=gap_code,
                        reason="Project discovery stopped before files could be scanned.",
                    )
                ]
            )
            if self.repository is not None:
                root = target.expanduser().resolve(strict=False)
                target_id = str(uuid.uuid5(uuid.NAMESPACE_URL, os.path.normcase(str(root))))
                with self.repository_lock if self.repository_lock is not None else nullcontext():
                    self.repository.save(
                        "target",
                        target_id,
                        Target(value=str(root), kind="code").model_dump(mode="json"),
                    )
                    failed_scan = Scan(
                        scan_id=scan_id,
                        target_id=target_id,
                        scanner=",".join(scanner_names) or "none",
                        started_at=started,
                        finished_at=datetime.now(UTC),
                        status="failed",
                        failures=failure_info,
                        coverage=coverage,
                        verdict=ScanVerdict.SCAN_FAILED,
                    )
                    self.repository.save("scan", scan_id, failed_scan.model_dump(mode="json"))
            raise
        findings: list[Finding] = []
        failures: dict[str, str] = {}
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, max(1, len(self.scanners)))
        ) as pool:
            tasks = {pool.submit(scanner.scan, profile.root): scanner for scanner in self.scanners}
            for task in as_completed(tasks):
                scanner = tasks[task]
                try:
                    findings.extend(task.result())
                except Exception as exc:  # isolate third-party adapters from the scan
                    failures[scanner.name] = (
                        str(exc)
                        if isinstance(exc, ScannerError)
                        else ("Scanner failed unexpectedly.")
                    )

        normalized_findings = deduplicate_findings(findings)
        coverage = _coverage_for_project(profile, scanner_names, failures)
        for scanner in self.scanners:
            scanner_coverage = getattr(scanner, "coverage", None)
            if isinstance(scanner_coverage, CoverageReport):
                coverage.gaps.extend(scanner_coverage.gaps)
                for key, count in scanner_coverage.examined.items():
                    coverage.examined[f"indicator_{key}"] = count
        scan_options: dict[str, str | int | float | bool] = {}
        for scanner in self.scanners:
            metadata = getattr(scanner, "metadata", [])
            if isinstance(metadata, list):
                for index, entry in enumerate(metadata, start=1):
                    if isinstance(entry, dict):
                        for key, value in entry.items():
                            if isinstance(value, (str, int, float, bool)):
                                scan_options[f"indicator_{key}_{index}"] = value
        finished = datetime.now(UTC)
        result = CodeScanResult(
            scan_id=scan_id,
            target=str(profile.root),
            project_types=list(profile.kinds),
            scanners=scanner_names,
            findings=normalized_findings,
            failures=failures,
            started_at=started,
            finished_at=finished,
            coverage=coverage,
            scan_options=scan_options,
        )
        from chinescan.core.verdict import compute_verdict

        verdict_scan = Scan(
            scan_id=scan_id,
            target_id="pending",
            scanner=",".join(scanner_names) or "none",
            started_at=started,
            finished_at=finished,
            status="partial" if failures else "complete",
            failures=failures,
            coverage=coverage,
        )
        result.verdict = compute_verdict(verdict_scan, normalized_findings)
        if self.repository is not None:
            target_id = str(uuid.uuid5(uuid.NAMESPACE_URL, os.path.normcase(result.target)))
            target_record = Target(value=result.target, kind="code")
            with self.repository_lock if self.repository_lock is not None else nullcontext():
                self.repository.save("target", target_id, target_record.model_dump(mode="json"))
                scan_record = Scan(
                    scan_id=scan_id,
                    target_id=target_id,
                    scanner=",".join(scanner_names) or "none",
                    started_at=started,
                    finished_at=finished,
                    status="partial" if failures else "complete",
                    project_types=list(profile.kinds),
                    finding_ids=[finding.finding_id for finding in normalized_findings],
                    failures=failures,
                    coverage=coverage,
                    verdict=result.verdict,
                    scan_options=scan_options,
                )
                self.repository.save("scan", scan_id, scan_record.model_dump(mode="json"))
                for finding in normalized_findings:
                    self.repository.save(
                        "finding", finding.finding_id, finding.model_dump(mode="json")
                    )
        return result
