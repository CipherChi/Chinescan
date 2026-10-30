"""Operator-configured projects and bounded local code assessment jobs."""

from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, CodeScanService, ScanBounds
from chinescan.core.projects import (
    ProjectError,
    ProjectFileRegistry,
)
from chinescan.core.projects import safe_project_tree as safe_project_tree
from chinescan.core.report_store import ReportStoreError, save_scan_reports
from chinescan.core.storage.sqlite import SQLiteRepository

TERMINAL = {"succeeded", "failed", "interrupted"}

ProjectConfigurationError = ProjectError
ProjectRegistry = ProjectFileRegistry


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


class CodeJobManager:
    def __init__(
        self,
        repository: SQLiteRepository,
        lock: threading.RLock,
        registry: ProjectRegistry,
        *,
        queue_limit: int = 4,
        reports_dir: Path | None = None,
        bounds: ScanBounds | None = None,
    ) -> None:
        self.repository, self.lock, self.registry = repository, lock, registry
        self.queue_limit = queue_limit
        self.reports_dir = reports_dir
        self.bounds = bounds
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
                _transition(job, "running")
                self._save(job)
                result = CodeScanService(
                    [BuiltinRuleScanner(self.bounds)],
                    self.repository,
                    repository_lock=self.lock,
                    bounds=self.bounds,
                    project_id=job["project_id"],
                ).scan(root)
                # Scan persistence must have completed before linking it to the job.
                with self.lock:
                    persisted = self.repository.get("scan", result.scan_id)
                    project_record = self.repository.get("project", job["project_id"])
                    if persisted is not None and project_record is not None:
                        refs = [result.scan_id, *project_record.get("last_scan_refs", [])]
                        project_record["last_scan_refs"] = list(dict.fromkeys(refs))[:10]
                        self.repository.save("project", job["project_id"], project_record)
                    if persisted is not None and self.reports_dir is not None:
                        try:
                            paths = save_scan_reports(
                                self.repository, result.scan_id, self.reports_dir
                            )
                            job["reports"] = [str(path) for path in paths]
                        except ReportStoreError:
                            job["warning"] = "Scan reports could not be saved."
                if persisted is None:
                    raise RuntimeError("Scan result persistence did not complete.")
                _transition(job, "succeeded")
                job["scan_id"] = result.scan_id
                if result.coverage and any(
                    gap.code.startswith("bound_") for gap in result.coverage.gaps
                ):
                    job["warning"] = (
                        "Assessment is partial; files or folders were skipped at configured limits."
                    )
            except Exception as exc:
                if job.get("status") not in TERMINAL:
                    _transition(job, "failed")
                job["error"] = (
                    str(exc)
                    if isinstance(exc, ProjectError)
                    else "Assessment failed; details were withheld."
                )
            self._save(job)

    def _save(self, item: dict[str, Any]) -> None:
        with self.lock:
            self.repository.save("code_job", item["job_id"], item)


def _now() -> str:
    return datetime.now(UTC).isoformat()
