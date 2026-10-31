"""Operator-configured log sources and bounded local analysis jobs."""

from __future__ import annotations

import os
import threading
import tomllib
import uuid
from collections import deque
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

from chinescan.core.log_locations import LogLocationService
from chinescan.core.projects import ProjectError
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.log_analysis.service import LogAnalysisService


class LogSourceError(ValueError):
    """A configured log source is unavailable or unsafe."""


class LogSourceRegistryStatus(TypedDict):
    status: Literal["ok", "missing", "unreadable", "invalid", "empty"]
    reason: str


def _linked(path: Path) -> bool:
    current = Path(path.absolute().anchor)
    for part in path.absolute().parts[1:]:
        current /= part
        try:
            if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                return True
        except OSError:
            return True
    return False


def _path(value: str, *, directory: bool | None = None) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or _linked(path):
        raise LogSourceError("Log source configuration contains an unsafe path.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LogSourceError("Log source configuration is unavailable.") from exc
    if directory is True and not resolved.is_dir():
        raise LogSourceError("Configured log source must be a directory.")
    if directory is False and not resolved.is_file():
        raise LogSourceError("Configured rules or IOC list must be a file.")
    return resolved


def _safe_tree(root: Path) -> bool:
    """Reject links/reparse points in the approved tree before the bounded reader walks it."""
    try:
        for directory, dirs, files in os.walk(root, followlinks=False):
            current = Path(directory).resolve(strict=True)
            for name in [*dirs, *files]:
                item = current / name
                if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
                    return False
                if item.resolve(strict=True).parent != current:
                    return False
        return True
    except (OSError, RuntimeError):
        return False


class LogSourceRegistry:
    """Read-only registry: browser requests carry only stable source IDs."""

    def __init__(self, config_path: Path | str | None, protected: Sequence[Path]) -> None:
        self.config_path = Path(config_path).expanduser() if config_path else None
        self.protected = [item.resolve(strict=False) for item in protected]

    def entries(self) -> list[dict[str, str]]:
        entries, _status = self.inspect()
        return entries

    def status(self) -> LogSourceRegistryStatus:
        """Return a path-free diagnostic for the current registry state."""
        _entries, status = self.inspect()
        return status

    def inspect(self) -> tuple[list[dict[str, str]], LogSourceRegistryStatus]:
        """Read entries and their state together so callers get a consistent snapshot."""
        if self.config_path is None or _linked(self.config_path):
            return [], {"status": "unreadable", "reason": "Registry file cannot be read safely."}
        try:
            text = self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return [], {"status": "missing", "reason": "Registry file not found."}
        except (OSError, UnicodeError):
            return [], {"status": "unreadable", "reason": "Registry file could not be read."}
        try:
            raw = tomllib.loads(text)
            if set(raw) - {"sources", "protected_paths"} or not isinstance(
                raw.get("sources"), list
            ):
                raise ValueError
            protected = [*self.protected, *self._configured_protected(raw)]
            result = []
            ids: set[str] = set()
            for item in raw["sources"]:
                if not isinstance(item, dict) or set(item) - {
                    "id",
                    "name",
                    "root",
                    "rules",
                    "iocs",
                }:
                    raise ValueError
                source_id, name = item.get("id"), item.get("name")
                if (
                    not isinstance(source_id, str)
                    or not source_id
                    or len(source_id) > 80
                    or source_id in ids
                    or not isinstance(name, str)
                    or not name
                    or len(name) > 120
                    or not isinstance(item.get("root"), str)
                    or any(
                        key in item and (not isinstance(item[key], str) or not item[key])
                        for key in ("rules", "iocs")
                    )
                ):
                    raise ValueError
                ids.add(source_id)
                try:
                    root = _path(item["root"], directory=True)
                    self._check(root, protected)
                    for key in ("rules", "iocs"):
                        if item.get(key):
                            configured = _path(
                                item[key], directory=None if key == "rules" else False
                            )
                            self._check(configured, protected)
                except LogSourceError:
                    continue
                result.append({"source_id": source_id, "display_name": name})
        except (OSError, ValueError, TypeError, KeyError, tomllib.TOMLDecodeError):
            return [], {
                "status": "invalid",
                "reason": "Registry TOML or source entries are invalid.",
            }
        if result:
            return result, {"status": "ok", "reason": "Registry loaded successfully."}
        if raw["sources"]:
            return [], {
                "status": "invalid",
                "reason": "No configured sources are available or safe.",
            }
        return [], {"status": "empty", "reason": "Registry is valid but contains no sources."}

    def resolve(self, source_id: str) -> tuple[str, Path, Path | None, Path | None]:
        raw = self._read()
        matches = [
            x for x in raw.get("sources", []) if isinstance(x, dict) and x.get("id") == source_id
        ]
        if len(matches) != 1 or source_id not in {x["source_id"] for x in self.entries()}:
            raise LogSourceError("Approved log source is unavailable.")
        item = matches[0]
        root = _path(item["root"], directory=True)
        protected = [*self.protected, *self._configured_protected(raw)]
        self._check(root, protected)
        rules = _path(item["rules"]) if item.get("rules") else None
        iocs = _path(item["iocs"], directory=False) if item.get("iocs") else None
        for configured in (rules, iocs):
            if configured:
                self._check(configured, protected)
        return str(item["name"]), root, rules, iocs

    def _read(self) -> dict[str, Any]:
        if self.config_path is None or _linked(self.config_path) or not self.config_path.is_file():
            raise LogSourceError("Log source configuration is unavailable.")
        raw = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
        if set(raw) - {"sources", "protected_paths"} or not isinstance(raw.get("sources"), list):
            raise ValueError
        return raw

    @staticmethod
    def _configured_protected(raw: dict[str, Any]) -> list[Path]:
        values = raw.get("protected_paths", [])
        if not isinstance(values, list):
            raise ValueError
        result = []
        for value in values:
            if not isinstance(value, str):
                raise ValueError
            path = Path(value).expanduser()
            if not path.is_absolute() or _linked(path):
                raise ValueError
            result.append(path.resolve(strict=False))
        return result

    @staticmethod
    def _check(path: Path, protected_paths: Sequence[Path]) -> None:
        for protected in protected_paths:
            if path == protected or path in protected.parents or protected in path.parents:
                raise LogSourceError("Configured log source overlaps protected application data.")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_diagnostics(errors: list[str]) -> list[str]:
    """Return bounded path-free categories instead of parser text or source references."""
    labels = (
        ("file count limit", "Input file count limit reached."),
        ("file exceeds size limit", "An input file exceeded the configured size limit."),
        ("total ingestion size limit", "The total input byte limit was reached."),
        ("total expanded-byte limit", "The aggregate expanded-byte limit was reached."),
        ("archive member count limit", "An archive member count limit was reached."),
        ("event count limit", "The normalized event count limit was reached."),
        ("comparison limit", "The Sigma comparison limit was reached."),
        ("unsupported condition", "A Sigma rule used an unsupported condition."),
        ("invalid Sigma rule", "A Sigma rule could not be parsed."),
        ("IOC", "The configured IOC input could not be fully processed."),
    )
    result: list[str] = []
    for error in errors:
        label = next(
            (message for needle, message in labels if needle in error),
            "Some input could not be parsed or normalized.",
        )
        if label not in result:
            result.append(label)
    return result[:20]


class LogJobManager:
    def __init__(
        self,
        repository: SQLiteRepository,
        lock: threading.RLock,
        registry: LogSourceRegistry,
        *,
        queue_limit: int = 4,
        project_locations: LogLocationService | None = None,
    ) -> None:
        self.repository, self.lock, self.registry = repository, lock, registry
        self.queue_limit = queue_limit
        self.project_locations = project_locations
        self._condition = threading.Condition()
        self._queue: deque[str] = deque()
        self._thread: threading.Thread | None = None
        self._stopping = False

    def start(self) -> None:
        with self.lock:
            for job in self.repository.list_records("log_job"):
                if job.get("status") in {"queued", "running"}:
                    job.update(
                        status="interrupted",
                        finished_at=_now(),
                        error="Server restarted before the job completed.",
                    )
                    self.repository.save("log_job", job["job_id"], job)
        self._thread = threading.Thread(target=self._run, name="chinescan-log-jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        if self._thread:
            self._thread.join()

    def submit(self, source_id: str) -> dict[str, Any]:
        name, _root, _rules, _iocs = self.registry.resolve(source_id)
        with self._condition, self.lock:
            if len(self._queue) >= self.queue_limit:
                raise OverflowError
            item: dict[str, Any] = {
                "job_id": str(uuid.uuid4()),
                "source_id": source_id,
                "source_name": name,
                "status": "queued",
                "created_at": _now(),
                "started_at": None,
                "finished_at": None,
                "scan_id": None,
                "event_count": 0,
                "alert_count": 0,
                "error_count": 0,
                "error": None,
            }
            self.repository.save("log_job", item["job_id"], item)
            self._queue.append(item["job_id"])
            self._condition.notify()
            return item

    def submit_project(
        self, project_id: str, location_ids: list[str] | None = None
    ) -> dict[str, Any]:
        if self.project_locations is None:
            raise LogSourceError("Project log analysis is unavailable.")
        available = self.project_locations.list(project_id)
        selected = (
            location_ids if location_ids is not None else [str(x["location_id"]) for x in available]
        )
        if not selected or len(selected) > 20 or len(set(selected)) != len(selected):
            raise LogSourceError("Select at least one valid log location.")
        for location_id in selected:
            self.project_locations.resolve_location(project_id, location_id)
        with self._condition, self.lock:
            if len(self._queue) >= self.queue_limit:
                raise OverflowError
            item: dict[str, Any] = {
                "job_id": str(uuid.uuid4()),
                "source_id": "project:" + project_id,
                "source_name": "Project logs",
                "project_id": project_id,
                "location_ids": selected,
                "status": "queued",
                "created_at": _now(),
                "started_at": None,
                "finished_at": None,
                "scan_id": None,
                "event_count": 0,
                "alert_count": 0,
                "error_count": 0,
                "error": None,
            }
            self.repository.save("log_job", item["job_id"], item)
            self._queue.append(item["job_id"])
            self._condition.notify()
            return item

    def list(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        with self.lock:
            return self.repository.page_records(
                "log_job",
                limit=limit,
                offset=offset,
                sort_by="created_at",
                descending=True,
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self.repository.get("log_job", job_id)

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._queue and not self._stopping:
                    self._condition.wait()
                if self._stopping:
                    return
                job_id = self._queue.popleft()
            job = self.get(job_id)
            if job is None:
                continue
            try:
                project_id = job.get("project_id")
                if project_id:
                    if self.project_locations is None:
                        raise LogSourceError("Project log analysis is unavailable.")
                    roots = [
                        self.project_locations.resolve_location(project_id, item)
                        for item in job["location_ids"]
                    ]
                    rules = iocs = None
                    if any(not _safe_tree(root) for root in roots):
                        raise ProjectError(
                            "location_denied",
                            "A selected log location now contains an unsafe path.",
                        )
                else:
                    _name, root, rules, iocs = self.registry.resolve(job["source_id"])
                    roots = [root]
                    if not _safe_tree(root):
                        raise LogSourceError(
                            "Approved log source contains a linked or unsafe path entry."
                        )
                job.update(status="running", started_at=_now())
                self._save(job)
                results = [
                    LogAnalysisService(self.repository).analyze(
                        root, rules_path=rules, ioc_path=iocs
                    )
                    for root in roots
                ]
                result = results[-1]
                for completed in results:
                    with self.lock:
                        persisted = self.repository.get("scan", completed.scan_id)
                    if persisted is None:
                        raise RuntimeError("result missing")
                    if project_id:
                        persisted["project_id"] = project_id
                        persisted["location_ids"] = list(job["location_ids"])
                        self.repository.save("scan", completed.scan_id, persisted)
                job.update(
                    status="partial" if any(item.errors for item in results) else "succeeded",
                    finished_at=_now(),
                    scan_id=result.scan_id,
                    event_count=sum(item.events for item in results),
                    alert_count=sum(len(item.alerts) for item in results),
                    error_count=sum(len(item.errors) for item in results),
                    diagnostics=_safe_diagnostics(
                        [error for item in results for error in item.errors]
                    ),
                    skipped_counts={"input_errors": sum(len(item.errors) for item in results)},
                )
                if any(item.errors for item in results):
                    job["error"] = "Analysis is partial. Some input could not be processed."
            except Exception as exc:
                job.update(
                    status="failed",
                    finished_at=_now(),
                    error=(
                        str(exc)
                        if isinstance(exc, (LogSourceError, ProjectError))
                        else "Analysis failed; details were withheld."
                    ),
                )
                if isinstance(exc, ProjectError):
                    job["error_code"] = exc.code
            self._save(job)

    def _save(self, job: dict[str, Any]) -> None:
        with self.lock:
            self.repository.save("log_job", job["job_id"], job)
