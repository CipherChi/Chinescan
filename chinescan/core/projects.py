"""Project records, legacy project configuration and project-scoped operations."""

from __future__ import annotations

import builtins
import os
import stat
import tomllib
import unicodedata
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.core.fs_policy import FilesystemBrowserService, PathDecision, decide_path
from chinescan.core.storage.sqlite import SQLiteRepository


class ProjectError(ValueError):
    """Safe project operation error with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _name_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def _canonical_directory(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ProjectError("invalid_root", "Choose an absolute local directory.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProjectError(
            "root_unavailable", "The selected project folder is unavailable."
        ) from exc
    if not resolved.is_dir():
        raise ProjectError("not_a_directory", "The selected project must be a folder.")
    return resolved


class ProjectFileRegistry:
    """Read-only adapter for legacy projects.toml entries."""

    def __init__(self, config_path: Path | str | None, protected: list[Path]) -> None:
        self.config_path = Path(config_path).expanduser() if config_path else None
        self.protected = [path.resolve(strict=False) for path in protected]

    def list(self) -> list[dict[str, str]]:
        if (
            self.config_path is None
            or not self.config_path.is_file()
            or _has_link_component(self.config_path)
        ):
            return []
        try:
            raw = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
            if set(raw) - {"projects", "protected_paths"}:
                return []
            protected = [*self.protected, *_configured_protected(raw)]
            entries = raw.get("projects", [])
            if not isinstance(entries, list):
                return []
            result = []
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"id", "name", "root"}:
                    continue
                project_id, name = entry["id"], entry["name"]
                if (
                    not isinstance(project_id, str)
                    or not project_id
                    or len(project_id) > 80
                    or project_id in seen
                    or not isinstance(name, str)
                    or not 1 <= len(name) <= 120
                ):
                    continue
                seen.add(project_id)
                try:
                    root = _canonical_directory(entry["root"])
                    self._check_protected(root, protected)
                except (TypeError, ProjectError):
                    continue
                result.append(
                    {
                        "project_id": project_id,
                        "name": name,
                        "display_name": name,
                        "root": str(root),
                    }
                )
            return result
        except (OSError, ValueError, TypeError):
            return []

    def resolve(self, project_id: str) -> tuple[str, Path]:
        item = next((row for row in self.list() if row["project_id"] == project_id), None)
        if item is None:
            raise ProjectError("project_unavailable", "The configured project is unavailable.")
        return item["name"], Path(item["root"])

    def _check_protected(self, root: Path, protected: Sequence[Path]) -> None:
        for item in protected:
            if root == item or root in item.parents or item in root.parents:
                raise ProjectError(
                    "protected_root", "The project overlaps protected application data."
                )


def _has_link_component(path: Path) -> bool:
    try:
        current = Path(path.absolute().anchor)
        for part in path.absolute().parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                return True
            if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                return True
        return False
    except (OSError, RuntimeError, ValueError):
        return True


def safe_project_tree(root: Path) -> bool:
    """Reject links and reparse entries anywhere in the selected code tree."""
    try:
        canonical = _canonical_directory(root)
        for directory, dirs, files in os.walk(canonical, followlinks=False):
            current = Path(directory)
            for name in [*dirs, *files]:
                child = current / name
                if _has_link_component(child):
                    return False
                if child.resolve(strict=True).parent != current.resolve(strict=True):
                    return False
        return True
    except (OSError, RuntimeError, ProjectError):
        return False


def _configured_protected(raw: dict[str, Any]) -> list[Path]:
    value = raw.get("protected_paths", [])
    if not isinstance(value, list):
        raise ValueError
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError
        path = Path(item).expanduser()
        if not path.is_absolute() or _has_link_component(path):
            raise ValueError
        result.append(path.resolve(strict=False))
    return result


class ProjectService:
    """SQLite-backed projects and safe bridges to folder selections and code jobs."""

    def __init__(
        self,
        repository: SQLiteRepository,
        browser: FilesystemBrowserService,
        legacy: ProjectFileRegistry,
        *,
        allowed_roots: list[Path],
        hard_denied: list[Path],
        soft_denied: list[Path],
        allow_soft_denied: bool,
    ) -> None:
        self.repository = repository
        self.browser = browser
        self.legacy = legacy
        self.allowed_roots = list(allowed_roots)
        self.hard_denied = list(hard_denied)
        self.soft_denied = list(soft_denied)
        self.allow_soft_denied = allow_soft_denied

    def decision(self, path: str | Path) -> PathDecision:
        return decide_path(
            path,
            allowed_roots=self.allowed_roots,
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=self.allow_soft_denied,
        )

    def create_from_selection(self, name: str, session: str, directory_id: str) -> dict[str, Any]:
        root = self.browser.resolve_selection(session, "project_directory", directory_id)
        return self.create(name, root)

    def create(self, name: str, root: str | Path) -> dict[str, Any]:
        normalized = unicodedata.normalize("NFKC", name).strip()
        if not 1 <= len(normalized) <= 120 or any(ord(char) < 32 for char in normalized):
            raise ProjectError("invalid_name", "Project name must be 1 to 120 characters.")
        decision = self.decision(root)
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError("root_denied", "The selected folder is no longer approved.")
        if any(
            _name_key(item["name"]) == _name_key(normalized)
            for item in self._all_internal_and_file()
        ):
            raise ProjectError("duplicate_name", "A project with that name already exists.")
        project_id = str(uuid.uuid4())
        item: dict[str, Any] = {
            "project_id": project_id,
            "name": normalized,
            "kind": "local",
            "root": str(decision.path),
            "configured_by": "ui",
            "created_at": _now(),
            "last_scan_refs": [],
        }
        self.repository.save("project", project_id, item)
        return self._public(item)

    def list(self) -> list[dict[str, Any]]:
        stored = self.repository.list_records("project")
        file_items = self.legacy.list()
        by_id = {item["project_id"]: item for item in stored}
        for item in file_items:
            if item["project_id"] not in by_id:
                by_id[item["project_id"]] = {
                    "project_id": item["project_id"],
                    "name": item["name"],
                    "kind": "local",
                    "root": item["root"],
                    "configured_by": "file",
                    "created_at": "",
                    "last_scan_refs": [],
                }
        scans = self.repository.list_records("scan")
        summaries = []
        for item in sorted(by_id.values(), key=lambda p: _name_key(p["name"])):
            refs = sorted(
                (row for row in scans if row.get("project_id") == item["project_id"]),
                key=lambda row: str(row.get("started_at", "")),
                reverse=True,
            )
            summary = self._summary(item)
            summary["last_scan_refs"] = [str(row["scan_id"]) for row in refs[:10]]
            summary["last_scan"] = (
                summary["last_scan_refs"][0] if summary["last_scan_refs"] else None
            )
            summaries.append(summary)
        return summaries

    def get(self, project_id: str) -> dict[str, Any]:
        item = self._stored(project_id)
        if item is None:
            legacy = next(
                (row for row in self.legacy.list() if row["project_id"] == project_id), None
            )
            if legacy is None:
                raise ProjectError("project_not_found", "Project not found.")
            item = {
                "project_id": project_id,
                "name": legacy["name"],
                "kind": "local",
                "root": legacy["root"],
                "configured_by": "file",
                "created_at": "",
                "last_scan_refs": [],
            }
        scans = [
            row
            for row in self.repository.list_records("scan")
            if row.get("project_id") == project_id
        ]
        scans.sort(key=lambda row: str(row.get("started_at", "")), reverse=True)
        scan_ids = {str(row.get("scan_id")) for row in scans}
        findings = [
            row
            for row in self.repository.list_records("finding")
            if row.get("project_id") == project_id
        ]
        cases = [
            row
            for row in self.repository.list_records("case")
            if scan_ids.intersection(str(scan_id) for scan_id in row.get("scan_ids", []))
        ]
        jobs = [
            row
            for row in self.repository.list_records("code_job")
            if row.get("project_id") == project_id
        ]
        jobs.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
        return {
            **self._summary(item),
            "origin_label": "This device" if item.get("kind") == "local" else "GitHub",
            "last_scan_refs": [row["scan_id"] for row in scans[:10]],
            "recent_scans": [self._safe_scan(row) for row in scans[:10]],
            "recent_jobs": [self._safe_job(row) for row in jobs[:10]],
            "findings_count": len(findings),
            "findings": [self._safe_finding(row) for row in findings[:100]],
            "linked_cases": [self._safe_case(row) for row in cases[:50]],
        }

    def remove(self, project_id: str, confirmation: str) -> None:
        item = self._stored(project_id)
        if item is None:
            raise ProjectError("project_not_found", "Project not found.")
        if item.get("configured_by") != "ui":
            raise ProjectError("file_configured", "Projects configured by file are read-only.")
        if confirmation != item.get("name"):
            raise ProjectError(
                "confirmation_mismatch", "Type the project name exactly to confirm removal."
            )
        scans = [
            row
            for row in self.repository.list_records("scan")
            if row.get("project_id") == project_id
        ]
        scan_ids = {str(row.get("scan_id")) for row in scans}
        self.repository.delete("project", project_id)
        for record_type in ("scan", "finding", "code_job"):
            for row in self.repository.list_records(record_type):
                if row.get("project_id") == project_id:
                    row["project_removed"] = True
                    self.repository.save(record_type, self._record_id(record_type, row), row)
        for row in self.repository.list_records("case"):
            if scan_ids.intersection(str(scan_id) for scan_id in row.get("scan_ids", [])):
                row["project_removed"] = True
                self.repository.save("case", str(row.get("case_id")), row)

    def resolve(self, project_id: str) -> tuple[str, Path]:
        item = self._stored(project_id)
        configured_by = "ui"
        if item is None:
            name, root = self.legacy.resolve(project_id)
            configured_by = "file"
        else:
            name, root = str(item["name"]), Path(str(item["root"]))
        decision = decide_path(
            root,
            allowed_roots=self.allowed_roots if configured_by == "ui" else [root],
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=self.allow_soft_denied,
        )
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError(
                "root_denied",
                f"Project folder is no longer approved or available ({decision.reason_code}).",
            )
        return name, decision.path

    def resolve_path(self, path: str | Path) -> Path:
        decision = self.decision(path)
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError("root_denied", "Project folder is not approved.")
        return decision.path

    def code_projects(self) -> builtins.list[dict[str, str]]:
        """Legacy response shape retained for the existing Code assessments page."""
        return [
            {"project_id": str(item["project_id"]), "display_name": str(item["name"])}
            for item in self.list()
        ]

    def _stored(self, project_id: str) -> dict[str, Any] | None:
        return next(
            (
                row
                for row in self.repository.list_records("project")
                if row.get("project_id") == project_id
            ),
            None,
        )

    def _all_internal_and_file(self) -> builtins.list[dict[str, Any]]:
        stored = self.repository.list_records("project")
        names = {_name_key(str(row.get("name", ""))) for row in stored}
        return [
            *stored,
            *[row for row in self.legacy.list() if _name_key(row["name"]) not in names],
        ]

    @staticmethod
    def _record_id(record_type: str, item: dict[str, Any]) -> str:
        key = {"scan": "scan_id", "finding": "finding_id", "code_job": "job_id"}[record_type]
        return str(item[key])

    @staticmethod
    def _summary(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "project_id": str(item["project_id"]),
            "name": str(item["name"]),
            "kind": str(item.get("kind", "local")),
            "configured_by": str(item.get("configured_by", "file")),
            "origin_label": "This device",
            "created_at": str(item.get("created_at", "")),
            "last_scan_refs": list(item.get("last_scan_refs", [])),
            "last_scan": item.get("last_scan_refs", [None])[0]
            if item.get("last_scan_refs")
            else None,
        }

    @staticmethod
    def _public(item: dict[str, Any]) -> dict[str, Any]:
        return ProjectService._summary(item)

    @staticmethod
    def _safe_job(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "job_id",
                "status",
                "created_at",
                "started_at",
                "finished_at",
                "scan_id",
                "error",
                "warning",
            )
        }

    @staticmethod
    def _safe_finding(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "finding_id",
                "title",
                "severity",
                "category",
                "rule_id",
                "location",
                "description",
            )
        }

    @staticmethod
    def _safe_case(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key) for key in ("case_id", "title", "status", "severity", "updated_at")
        }

    @staticmethod
    def _safe_scan(item: dict[str, Any]) -> dict[str, Any]:
        gaps = (item.get("coverage") or {}).get("gaps", [])
        skipped = {
            str(gap.get("code", "").removeprefix("bound_")): int(gap.get("count", 0))
            for gap in gaps
            if isinstance(gap, dict) and str(gap.get("code", "")).startswith("bound_")
        }
        return {
            "scan_id": item.get("scan_id"),
            "status": item.get("status", "complete"),
            "finding_count": len(item.get("finding_ids", [])),
            "skipped_counts": skipped,
        }
