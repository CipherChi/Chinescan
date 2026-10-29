"""Offline matching of caller-supplied local indicators against project files."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from chinescan.core.models.common import EvidenceKind, FindingCategory, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import CoverageGap, CoverageReport, Indicator
from chinescan.core.orchestration.code_scan import (
    IGNORED_DIRS,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_SOURCE_BYTES,
    make_finding,
)
from chinescan.log_analysis.ioc_matching import MAX_INDICATORS, MAX_IOC_FILE_BYTES, load_iocs

MAX_BINARY_BYTES = MAX_SOURCE_BYTES


class IndicatorScanner:
    """Scan a local project tree and local indicator files without network access."""

    name = "indicators"

    def __init__(self, files: list[Path]) -> None:
        if not files:
            raise ValueError("At least one --indicator-file is required for indicators scanner.")
        self.files = files
        self.coverage = CoverageReport()
        self.metadata: list[dict[str, str | int]] = []

    def scan(self, target: Path) -> list[Finding]:
        root = target.expanduser().resolve(strict=True)
        indicators: list[tuple[Indicator, str]] = []
        gaps: list[CoverageGap] = []
        parse_errors = 0
        for path in self.files:
            try:
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.stat().st_size > MAX_IOC_FILE_BYTES
                ):
                    gaps.append(
                        CoverageGap(
                            code="indicator_parse_error",
                            reason="Indicator file missing or over size limit.",
                            source=path.name,
                        )
                    )
                    parse_errors += 1
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                structured: object = None
                if path.suffix.lower() == ".json":
                    try:
                        structured = json.loads(path.read_text(encoding="utf-8-sig"))
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        structured = None
                is_stix = isinstance(structured, dict) and structured.get("type") == "bundle"
                is_misp = isinstance(structured, dict) and "Event" in structured
                values, errors = ([], []) if is_stix or is_misp else load_iocs(path)
                parse_errors += len(errors)
                gaps.extend(
                    CoverageGap(
                        code="indicator_parse_error",
                        reason="Some indicator entries could not be parsed.",
                        source=path.name,
                        count=len(errors),
                    )
                    for _ in [0]
                    if errors
                )
                if path.suffix.lower() == ".json":
                    try:
                        document = structured
                        if isinstance(document, dict) and document.get("type") == "bundle":
                            objects = document.get("objects", [])
                            if len(objects) > MAX_INDICATORS:
                                gaps.append(
                                    CoverageGap(
                                        code="indicator_parse_error",
                                        reason="Indicator entry limit reached.",
                                        source=path.name,
                                        count=len(objects) - MAX_INDICATORS,
                                    )
                                )
                            for item in objects[:MAX_INDICATORS]:
                                if item.get("type") == "indicator":
                                    labels = item.get("labels", [])
                                    role = next(
                                        (
                                            label
                                            for label in labels
                                            if label
                                            in {
                                                "current_campaign",
                                                "historical_infrastructure",
                                                "protective_blocklist",
                                            }
                                        ),
                                        "",
                                    )
                                    pattern = str(item.get("pattern", ""))
                                    match = re.fullmatch(
                                        r"\[(domain-name|ipv4-addr):value = '([^']+)'\]",
                                        pattern,
                                    )
                                    file_match = re.fullmatch(
                                        (
                                            r"\[file:(?:hashes\.'(SHA-256|MD5|SHA-1)'|name) "
                                            r"= '([^']+)'\]"
                                        ),
                                        pattern,
                                    )
                                    if match:
                                        kind = "domain" if match.group(1) == "domain-name" else "ip"
                                        values.append(
                                            Indicator(
                                                kind=kind,
                                                value=match.group(2),
                                                source=str(item.get("id", path.name)),
                                                context="|".join(
                                                    filter(None, (role, "stix_pattern"))
                                                ),
                                            )
                                        )
                                    elif file_match:
                                        kind = {
                                            "SHA-256": "hash",
                                            "MD5": "hash",
                                            "SHA-1": "hash",
                                            None: "filename",
                                        }.get(file_match.group(1), "hash")
                                        values.append(
                                            Indicator(
                                                kind=kind,
                                                value=file_match.group(2).lower()
                                                if kind == "hash"
                                                else file_match.group(2),
                                                source=str(item.get("id", path.name)),
                                                context=role,
                                            )
                                        )
                                    else:
                                        gaps.append(
                                            CoverageGap(
                                                code="unsupported_pattern",
                                                reason="STIX pattern is not supported.",
                                            )
                                        )
                        elif isinstance(document, dict) and "Event" in document:
                            attrs = document.get("Event", {}).get("Attribute", [])
                            if len(attrs) > MAX_INDICATORS:
                                gaps.append(
                                    CoverageGap(
                                        code="indicator_parse_error",
                                        reason="Indicator entry limit reached.",
                                        source=path.name,
                                        count=len(attrs) - MAX_INDICATORS,
                                    )
                                )
                            for attr in attrs[:MAX_INDICATORS]:
                                typ = attr.get("type")
                                attr_kind = {
                                    "domain": "domain",
                                    "ip-dst": "ip",
                                    "sha256": "hash",
                                    "sha1": "hash",
                                    "md5": "hash",
                                    "filename": "",
                                }.get(typ)
                                if attr_kind is not None:
                                    tags = attr.get("Tag", [])
                                    role = next(
                                        (
                                            tag.get("name", "")
                                            for tag in tags
                                            if tag.get("name")
                                            in {
                                                "current_campaign",
                                                "historical_infrastructure",
                                                "protective_blocklist",
                                            }
                                        ),
                                        "",
                                    )
                                    values.append(
                                        Indicator(
                                            kind=attr_kind or "filename",
                                            value=str(attr.get("value", "")),
                                            source=str(attr.get("comment", path.name)),
                                            context=role,
                                        )
                                    )
                    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError, TypeError):
                        parse_errors += 1
                        gaps.append(
                            CoverageGap(
                                code="indicator_parse_error",
                                reason="Indicator JSON contains malformed entries.",
                                source=path.name,
                            )
                        )
                self.metadata.append(
                    {
                        "file_name": path.name,
                        "sha256": digest,
                        "entry_count": len(values),
                        "parse_error_count": len(errors),
                    }
                )
                indicators.extend((item, "") for item in values[:MAX_INDICATORS])
            except OSError:
                parse_errors += 1
                gaps.append(
                    CoverageGap(
                        code="indicator_parse_error",
                        reason="Indicator file could not be read.",
                        source=path.name,
                    )
                )
        findings: list[Finding] = []
        examined_files = examined_bytes = comparisons = 0
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames if name not in IGNORED_DIRS)
            for dirname in list(dirnames):
                linked_dir = Path(directory) / dirname
                if linked_dir.is_symlink() or getattr(linked_dir, "is_junction", lambda: False)():
                    dirnames.remove(dirname)
                    gaps.append(
                        CoverageGap(
                            code="symlink_skipped",
                            reason="Linked project directories were skipped.",
                        )
                    )
            for name in sorted(filenames):
                path = Path(directory) / name
                try:
                    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                        gaps.append(
                            CoverageGap(
                                code="symlink_skipped",
                                reason="Linked project entries were skipped.",
                            )
                        )
                        continue
                    size = path.stat().st_size
                    if size > MAX_BINARY_BYTES:
                        continue
                    examined_files += 1
                    examined_bytes += size
                    if examined_files > MAX_SOURCE_FILES or examined_bytes > MAX_TOTAL_SOURCE_BYTES:
                        gaps.append(
                            CoverageGap(
                                code="file_limit", reason="Indicator scan file or byte cap reached."
                            )
                        )
                        break
                    raw = path.read_bytes()
                    if b"\0" in raw[:8192]:
                        gaps.append(
                            CoverageGap(
                                code="binary_skipped", reason="Binary project file was skipped."
                            )
                        )
                        continue
                    text = raw.decode("utf-8", errors="replace")
                    relative = path.relative_to(root).as_posix()
                    file_hashes = {
                        hashlib.sha256(raw).hexdigest(),
                        hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
                        hashlib.md5(raw, usedforsecurity=False).hexdigest(),
                    }
                    for indicator, _role in indicators:
                        comparisons += 1
                        if comparisons > 5_000_000:
                            gaps.append(
                                CoverageGap(
                                    code="comparison_limit",
                                    reason="Indicator comparison cap reached.",
                                )
                            )
                            break
                        exact_hash = (
                            indicator.kind == "hash" and indicator.value.casefold() in file_hashes
                        )
                        exact_path = (
                            indicator.kind == "filename"
                            and indicator.value.casefold() == name.casefold()
                        )
                        value_match = (
                            indicator.value and indicator.value.casefold() in text.casefold()
                        )
                        if not (exact_hash or exact_path or value_match):
                            continue
                        protective = "protective_blocklist" in indicator.context.casefold()
                        if protective:
                            findings.append(
                                make_finding(
                                    target=root,
                                    scanner=self.name,
                                    rule_id=f"IOC-CONTEXT-{indicator.kind.upper()}",
                                    title="Protective blocklist context (not a detection)",
                                    severity=Severity.INFO,
                                    category=FindingCategory.THREAT_INTEL.value,
                                    location=relative,
                                    description=(
                                        "Protective blocklist membership is context, not a "
                                        "detection."
                                    ),
                                    tags=[
                                        f"indicator:{indicator.indicator_id}",
                                        f"source:{indicator.source}",
                                        "role:protective_blocklist",
                                    ],
                                    evidence=EvidenceKind.CONTEXT_ONLY,
                                )
                            )
                            continue
                        evidence = (
                            EvidenceKind.CONFIRMED_ARTIFACT
                            if exact_hash or exact_path
                            else EvidenceKind.PATTERN_MATCH
                            if "stix_pattern" in indicator.context
                            else EvidenceKind.REFERENCE_ONLY
                        )
                        description = (
                            "Exact local artifact match."
                            if exact_hash or exact_path
                            else (
                                "A saved reference appears in project text; this does not prove "
                                "the host was contacted."
                            )
                        )
                        findings.append(
                            make_finding(
                                target=root,
                                scanner=self.name,
                                rule_id=f"IOC-{indicator.kind.upper()}",
                                title=f"Local indicator reference ({indicator.kind})",
                                severity=Severity.MEDIUM,
                                category=FindingCategory.THREAT_INTEL.value,
                                location=relative,
                                description=description,
                                tags=[
                                    f"indicator:{indicator.indicator_id}",
                                    f"source:{indicator.source}",
                                ]
                                + ([f"role:{indicator.context}"] if indicator.context else []),
                                evidence=evidence,
                            )
                        )
                except OSError:
                    gaps.append(
                        CoverageGap(
                            code="unreadable_file", reason="A project file could not be read."
                        )
                    )
        self.coverage = CoverageReport(
            examined={
                "files_scanned": min(examined_files, MAX_SOURCE_FILES),
                "bytes_scanned": examined_bytes,
                "indicator_count": len(indicators),
                "parse_errors": parse_errors,
            },
            gaps=gaps,
        )
        return findings
