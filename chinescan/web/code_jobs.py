"""Operator-configured projects and bounded local code assessment jobs."""

from __future__ import annotations

import threading
import tomllib
import uuid
from collections import deque
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, CodeScanService
from chinescan.core.storage.sqlite import SQLiteRepository

TERMINAL = {"succeeded", "failed", "interrupted"}


class ProjectConfigurationError(ValueError):
    """Invalid or unsafe operator project configuration."""


def _canonical_directory(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ProjectConfigurationError("Project roots must be absolute local paths.")
    if _has_link_component(path):
        raise ProjectConfigurationError("Project roots may not be symlinks.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProjectConfigurationError(
            "A configured project root is missing or inaccessible."
        ) from exc
    if not resolved.is_dir():
        raise ProjectConfigurationError("A configured project root must be a directory.")
    return resolved


def _has_link_component(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                return True
        except OSError:
            return True
    return False


def _transition(job: dict[str, Any], status: str) -> None:
    allowed = {
        "queued": {"running", "interrupted"},
        "running": {"succeeded", "failed", "interrupted"},
        "succeeded": set(),
        "failed": set(),
        "interrupted": set(),
    }
    previous = str(job.get("status"))
    if status not in allowed.get(previous, set()):
        raise ValueError("Invalid code job state transition.")
    job["status"] = status
    if status == "running":
        job["started_at"] = _now()
    if status in TERMINAL:
        job["finished_at"] = _now()


class ProjectRegistry:
    def __init__(self, config_path: Path | str | None, protected: list[Path]) -> None:
        self.config_path = Path(config_path).expanduser() if config_path else None
        self.protected = [path.resolve(strict=False) for path in protected]

    def list(self) -> list[dict[str, str]]:
        if self.config_path is None or not self.config_path.is_file():
            return []
        if _has_link_component(self.config_path):
            return []
        try:
            raw = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
            if set(raw) - {"projects", "protected_paths"}:
                raise ValueError
            protected = [*self.protected, *_configured_protected(raw)]
            entries = raw.get("projects", [])
            if not isinstance(entries, list):
                raise ValueError
            result = []
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"id", "name", "root"}:
                    raise ValueError
                project_id, name = entry["id"], entry["name"]
                if (
                    not isinstance(project_id, str)
                    or not project_id
                    or len(project_id) > 80
                    or project_id in seen
                    or not isinstance(name, str)
                    or not name
                    or len(name) > 120
                ):
                    raise ValueError
                seen.add(project_id)
                try:
                    root = _canonical_directory(entry["root"])
                    self._check_protected(root, protected)
                except (TypeError, ProjectConfigurationError):
                    continue
                result.append({"project_id": project_id, "display_name": name})
            return result
        except (OSError, ValueError, TypeError):
            return []

    def resolve(self, project_id: str) -> tuple[str, Path]:
        projects = self.list()
        if (
            self.config_path is None
            or not self.config_path.is_file()
            or _has_link_component(self.config_path)
        ):
            raise ProjectConfigurationError("Approved project configuration is unavailable.")
        try:
            raw = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
            protected = [*self.protected, *_configured_protected(raw)]
            matches = [item for item in raw.get("projects", []) if item.get("id") == project_id]
            if len(matches) != 1 or project_id not in {item["project_id"] for item in projects}:
                raise ProjectConfigurationError("Approved project is unavailable.")
            root = _canonical_directory(matches[0]["root"])
            self._check_protected(root, protected)
            return str(matches[0]["name"]), root
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ProjectConfigurationError("Approved project is unavailable.") from exc

    def _check_protected(self, root: Path, protected_paths: Sequence[Path]) -> None:
        for protected in protected_paths:
            if root == protected or root in protected.parents or protected in root.parents:
                raise ProjectConfigurationError("Project overlaps protected application data.")


def _configured_protected(raw: dict[str, Any]) -> list[Path]:
    value = raw.get("protected_paths", [])
    if not isinstance(value, list):
        raise ValueError
    result: list[Path] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError
        path = Path(item).expanduser()
        if not path.is_absolute() or _has_link_component(path):
            raise ValueError
        result.append(path.resolve(strict=False))
    return result


def safe_project_tree(root: Path) -> bool:
    """Reject internal symlinks/reparse points; scanner traversal then stays root bounded."""
    try:
        canonical = _canonical_directory(root)
        import os

        for directory, dirs, files in os.walk(canonical, followlinks=False):
            current = Path(directory)
            for name in [*dirs, *files]:
                child = current / name
                if (
                    child.is_symlink()
                    or getattr(child, "is_junction", lambda: False)()
                    or child.resolve(strict=True).parent != current.resolve(strict=True)
                ):
                    return False
        return True
    except (OSError, RuntimeError, ProjectConfigurationError):
        return False


class CodeJobManager:
    def __init__(
        self,
        repository: SQLiteRepository,
        lock: threading.RLock,
        registry: ProjectRegistry,
        *,
        queue_limit: int = 4,
    ) -> None:
        self.repository, self.lock, self.registry = repository, lock, registry
        self.queue_limit = queue_limit
        self._condition = threading.Condition()
        self._queue: deque[str] = deque()
        self._thread: threading.Thread | None = None
        self._stopping = False

    def start(self) -> None:
        with self.lock:
            for item in self.repository.list_records("code_job"):
                if item.get("status") in {"queued", "running"}:
                    _transition(item, "interrupted")
                    item["error"] = "Server restarted before the job completed."
                    self.repository.save("code_job", item["job_id"], item)
        self._thread = threading.Thread(target=self._run, name="chinescan-code-jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        if self._thread:
            self._thread.join()

    def submit(self, project_id: str) -> dict[str, Any]:
        name, _root = self.registry.resolve(project_id)
        with self._condition, self.lock:
            jobs = self.repository.list_records("code_job")
            if any(
                job.get("project_id") == project_id and job.get("status") in {"queued", "running"}
                for job in jobs
            ):
                raise RuntimeError("duplicate")
            if len(self._queue) >= self.queue_limit:
                raise OverflowError
            now = _now()
            item: dict[str, Any] = {
                "job_id": str(uuid.uuid4()),
                "project_id": project_id,
                "project_name": name,
                "status": "queued",
                "created_at": now,
                "started_at": None,
                "finished_at": None,
                "scan_id": None,
                "error": None,
            }
            self.repository.save("code_job", item["job_id"], item)
            self._queue.append(item["job_id"])
            self._condition.notify()
            return item

    def list(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        with self.lock:
            jobs = sorted(
                self.repository.list_records("code_job"),
                key=lambda x: x["created_at"],
                reverse=True,
            )
        return jobs[offset : offset + limit], len(jobs)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self.repository.get("code_job", job_id)

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
                _name, root = self.registry.resolve(job["project_id"])
                if not safe_project_tree(root):
                    raise ProjectConfigurationError(
                        "Project tree contains an unsupported link or path entry."
                    )
                _transition(job, "running")
                self._save(job)
                result = CodeScanService(
                    [BuiltinRuleScanner()], self.repository, repository_lock=self.lock
                ).scan(root)
                # Scan persistence must have completed before linking it to the job.
                with self.lock:
                    persisted = self.repository.get("scan", result.scan_id)
                if persisted is None:
                    raise RuntimeError("Scan result persistence did not complete.")
                _transition(job, "succeeded")
                job["scan_id"] = result.scan_id
            except Exception as exc:
                if job.get("status") not in TERMINAL:
                    _transition(job, "failed")
                job["error"] = (
                    str(exc)
                    if isinstance(exc, ProjectConfigurationError)
                    else "Assessment failed; details were withheld."
                )
            self._save(job)

    def _save(self, item: dict[str, Any]) -> None:
        with self.lock:
            self.repository.save("code_job", item["job_id"], item)


def _now() -> str:
    return datetime.now(UTC).isoformat()
