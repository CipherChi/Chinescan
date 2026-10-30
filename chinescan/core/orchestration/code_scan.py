"""Local project detection, scanner execution, and normalized scan persistence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
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
DEFAULT_IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}


@dataclass(frozen=True)
class ScanBounds:
    max_files: int = 50_000
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 16_777_216
    max_depth: int = 32
    per_file_seconds: float = 2.0
    job_deadline_seconds: int = 300


@dataclass
class ProjectProfile:
    """Detected local project traits used to describe code scan targets."""

    root: Path
    kinds: tuple[str, ...]
    source_files: tuple[Path, ...]
    skipped_counts: dict[str, int] | None = None
    files_scanned: int = 0
    bytes_scanned: int = 0
    deadline_at: float | None = None


class FindingScanner(Protocol):
    """Adapter boundary shared by local and external finding scanners."""

    name: str

    def scan(self, target: Path) -> list[Finding]: ...


class ScannerError(Exception):
    """Expected scanner execution, availability, or output failure."""


def detect_project(target: Path, bounds: ScanBounds | None = None) -> ProjectProfile:
    """Resolve a local project directory and identify source files and manifests."""
    candidate = target.expanduser()
    if _contains_reparse_point(candidate):
        raise ScannerError("Code scan target changed to a link or reparse point.")
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScannerError("Target directory does not exist or is inaccessible.") from exc
    if not root.is_dir():
        raise ScannerError("Code scan target must be a local directory.")
    if _contains_reparse_point(root):
        raise ScannerError("Code scan target changed to a link or reparse point.")

    kinds: set[str] = set()
    sources: list[Path] = []

    def walk_error(_: OSError) -> None:
        raise ScannerError("A project directory could not be read; scan aborted.")

    total_bytes = 0
    skipped: dict[str, int] = {}
    files_seen = 0
    deadline = time.monotonic() + bounds.job_deadline_seconds if bounds else None
    for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        current = Path(directory)
        depth = len(current.relative_to(root).parts)
        dirnames[:] = sorted(
            name for name in dirnames if name.casefold() not in DEFAULT_IGNORED_DIRS
        )
        if bounds and depth >= bounds.max_depth:
            skipped["max_depth"] = skipped.get("max_depth", 0) + len(dirnames)
            dirnames.clear()
        for name in dirnames[:]:
            child = current / name
            if _contains_reparse_point(child):
                skipped["reparse_point"] = skipped.get("reparse_point", 0) + 1
                dirnames.remove(name)
        if bounds and deadline is not None and time.monotonic() >= deadline:
            skipped["job_deadline"] = (
                skipped.get("job_deadline", 0) + len(filenames) + len(dirnames)
            )
            dirnames.clear()
            continue
        names = set(filenames)
        if "pyproject.toml" in names or "requirements.txt" in names or "setup.py" in names:
            kinds.add("python")
        if "package.json" in names or "package-lock.json" in names:
            kinds.add("node")
        for name in sorted(filenames):
            path = current / name
            files_seen += 1
            if bounds and deadline is not None and time.monotonic() >= deadline:
                skipped["job_deadline"] = skipped.get("job_deadline", 0) + 1
                continue
            if bounds and files_seen > bounds.max_files:
                skipped["max_files"] = skipped.get("max_files", 0) + 1
                continue
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if _contains_reparse_point(path):
                if bounds:
                    skipped["reparse_point"] = skipped.get("reparse_point", 0) + 1
                continue
            try:
                resolved_file = path.resolve(strict=True)
                if os.path.commonpath(
                    (os.path.normcase(str(root)), os.path.normcase(str(resolved_file)))
                ) != os.path.normcase(str(root)):
                    skipped["containment_changed"] = skipped.get("containment_changed", 0) + 1
                    continue
                size = path.stat().st_size
                file_limit = bounds.max_file_bytes if bounds else MAX_SOURCE_BYTES
                if size > file_limit:
                    if bounds:
                        skipped["max_file_bytes"] = skipped.get("max_file_bytes", 0) + 1
                        continue
                    raise ScannerError(
                        "Project contains a source file above the configured 1 MB limit."
                    )
                if bounds and total_bytes + size > bounds.max_total_bytes:
                    skipped["max_total_bytes"] = skipped.get("max_total_bytes", 0) + 1
                    continue
                sources.append(path)
                total_bytes += size
                if not bounds and (
                    len(sources) > MAX_SOURCE_FILES or total_bytes > MAX_TOTAL_SOURCE_BYTES
                ):
                    raise ScannerError("Project exceeds the configured local scan size limits.")
            except OSError:
                continue
    return ProjectProfile(
        root=root,
        kinds=tuple(sorted(kinds)),
        source_files=tuple(sources),
        skipped_counts=skipped,
        files_scanned=len(sources),
        bytes_scanned=total_bytes,
        deadline_at=deadline,
    )


def _contains_reparse_point(path: Path) -> bool:
    """Reject links and Windows reparse points without following them."""
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                return False
            if stat.S_ISLNK(metadata.st_mode) or getattr(current, "is_junction", lambda: False)():
                return True
            if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                return True
        return False
    except (OSError, RuntimeError, ValueError):
        return True


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

    def __init__(self, bounds: ScanBounds | None = None) -> None:
        self.bounds = bounds

    def scan(self, target: Path) -> list[Finding]:
        return self.scan_profile(detect_project(target, self.bounds))

    def scan_profile(self, profile: ProjectProfile) -> list[Finding]:
        findings: list[Finding] = []
        for index, source in enumerate(profile.source_files):
            if profile.deadline_at is not None and time.monotonic() >= profile.deadline_at:
                counts = profile.skipped_counts
                if counts is not None:
                    counts["job_deadline"] = (
                        counts.get("job_deadline", 0) + len(profile.source_files) - index
                    )
                break
            started = time.monotonic()
            try:
                text = source.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ScannerError("A source file could not be read; scan aborted.") from exc
            relative = source.relative_to(profile.root).as_posix()
            for line_number, line in enumerate(text.splitlines(), start=1):
                if self.bounds and (
                    time.monotonic() - started > self.bounds.per_file_seconds
                    or (profile.deadline_at is not None and time.monotonic() >= profile.deadline_at)
                ):
                    counts = profile.skipped_counts
                    if counts is not None:
                        key = (
                            "job_deadline"
                            if profile.deadline_at and time.monotonic() >= profile.deadline_at
                            else "per_file_seconds"
                        )
                        counts[key] = counts.get(key, 0) + 1
                    profile.files_scanned = max(0, profile.files_scanned - 1)
                    try:
                        profile.bytes_scanned = max(
                            0, profile.bytes_scanned - source.stat().st_size
                        )
                    except OSError:
                        pass
                    findings = [
                        item
                        for item in findings
                        if not item.location or not item.location.startswith(relative + ":")
                    ]
                    break
                if len(line) > 10_000:
                    if self.bounds and profile.skipped_counts is not None:
                        profile.skipped_counts["long_lines"] = (
                            profile.skipped_counts.get("long_lines", 0) + 1
                        )
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
    profile: ProjectProfile,
    scanners: list[str],
    failures: dict[str, str],
    bounds: ScanBounds | None = None,
) -> CoverageReport:
    gaps: list[CoverageGap] = []
    long_lines = 0
    symlinks = 0
    unreadable = 0
    if not bounds:
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
    for reason, count in sorted((profile.skipped_counts or {}).items()):
        if count:
            if reason == "long_lines":
                gaps.append(
                    CoverageGap(
                        code="code_line_too_long",
                        reason="Lines over 10,000 characters were skipped.",
                        count=count,
                    )
                )
                continue
            gaps.append(
                CoverageGap(
                    code=f"bound_{reason}",
                    reason=f"Some files or folders were skipped at the {reason} scan bound.",
                    count=count,
                )
            )
    return CoverageReport(
        examined={
            "files_scanned": profile.files_scanned,
            "bytes_scanned": profile.bytes_scanned,
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
        bounds: ScanBounds | None = None,
        project_id: str | None = None,
    ) -> None:
        self.scanners = scanners
        self.repository = repository
        self.max_workers = max(1, min(max_workers, 8))
        self.repository_lock = repository_lock
        self.bounds = bounds
        self.project_id = project_id

    def scan(self, target: Path) -> CodeScanResult:
        started = datetime.now(UTC)
        scan_id = str(uuid.uuid4())
        scanner_names = [scanner.name for scanner in self.scanners]
        try:
            profile = detect_project(target, self.bounds)
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
                        project_id=self.project_id,
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
            tasks = {}
            for scanner in self.scanners:
                if self.bounds and hasattr(scanner, "scan_profile"):
                    task = pool.submit(scanner.scan_profile, profile)  # type: ignore[attr-defined]
                else:
                    task = pool.submit(scanner.scan, profile.root)
                tasks[task] = scanner
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
        coverage = _coverage_for_project(profile, scanner_names, failures, self.bounds)
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
            status="partial"
            if failures or any((profile.skipped_counts or {}).values())
            else "complete",
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
                    status="partial"
                    if failures or any((profile.skipped_counts or {}).values())
                    else "complete",
                    project_id=self.project_id,
                    project_types=list(profile.kinds),
                    finding_ids=[finding.finding_id for finding in normalized_findings],
                    failures=failures,
                    coverage=coverage,
                    verdict=result.verdict,
                    scan_options=scan_options,
                )
                self.repository.save("scan", scan_id, scan_record.model_dump(mode="json"))
                for finding in normalized_findings:
                    if self.project_id:
                        finding = finding.model_copy(update={"project_id": self.project_id})
                    self.repository.save(
                        "finding", finding.finding_id, finding.model_dump(mode="json")
                    )
        return result
