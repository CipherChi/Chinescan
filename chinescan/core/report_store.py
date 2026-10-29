"""Create immutable, redacted JSON and Markdown scan report files."""

import re
from datetime import UTC, datetime
from pathlib import Path

from chinescan.core.reporting import ReportingError, render_report, scan_data
from chinescan.core.storage.repository import Repository


class ReportStoreError(RuntimeError):
    """A scan report could not be rendered or saved."""


def _safe_id(scan_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", scan_id).strip(".-")[:64].rstrip(".-")
    if not cleaned:
        cleaned = "scan"
    if cleaned.upper() in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        cleaned = f"scan-{cleaned}"
    return cleaned


def save_scan_reports(
    repository: Repository, scan_id: str, reports_dir: Path, *, now: datetime | None = None
) -> list[Path]:
    try:
        scan, findings = scan_data(repository, scan_id)
        json_text = render_report(scan, findings, "json")
        markdown_text = render_report(scan, findings, "markdown")
        timestamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{timestamp}_{_safe_id(scan_id)}"
        reports_dir.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for extension, content in (("json", json_text), ("md", markdown_text)):
            suffix = 0
            while True:
                extra = f"-{suffix}" if suffix else ""
                path = reports_dir / f"{stem}{extra}.{extension}"
                try:
                    with path.open("x", encoding="utf-8", newline="") as stream:
                        stream.write(content)
                    paths.append(path)
                    break
                except FileExistsError:
                    suffix += 1
        return paths
    except (ReportingError, OSError) as exc:
        raise ReportStoreError(str(exc)) from exc
