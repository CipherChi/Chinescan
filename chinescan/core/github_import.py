"""Validated, bounded public GitHub imports and their in-memory preview/job service."""

from __future__ import annotations

import hashlib
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from chinescan.core.config.settings import Settings
from chinescan.core.storage.sqlite import SQLiteRepository

JobStatus = Literal[
    "queued", "running", "verifying", "succeeded", "failed", "cancelled", "incomplete"
]
ProgressCallback = Callable[[str], None]


class GitHubImportError(ValueError):
    """Validation or operational error with a stable, user-safe code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_OWNER = re.compile(r"[A-Za-z0-9-]{1,39}\Z", re.ASCII)
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}\Z", re.ASCII)
_REF = re.compile(r"[A-Za-z0-9._/-]{1,100}\Z", re.ASCII)
_SHA = re.compile(r"[0-9A-Fa-f]{40}\Z", re.ASCII)
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.IGNORECASE)
_GIT_ERROR_MAP: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (
        (
            "repository not found",
            "not found",
            "could not read from remote repository",
            "access denied",
        ),
        "repo_not_found_or_private",
        "The public repository could not be found. Check its URL and visibility.",
    ),
    (
        (
            "could not resolve host",
            "failed to connect",
            "connection timed out",
            "network is unreachable",
            "could not resolve proxy",
        ),
        "network_unreachable",
        "GitHub could not be reached from this network. Try again later.",
    ),
    (
        ("invalid path", "unable to create file", "filename too long", "invalid argument"),
        "unsafe_entries",
        "The repository contains a file name that is unsafe on this system.",
    ),
)


@dataclass(frozen=True, slots=True)
class ValidatedSource:
    canonical_url: str
    owner: str
    repo: str


def validate_github_url(value: str) -> ValidatedSource:
    """Accept only a plain ASCII https://github.com repository URL."""
    if not isinstance(value, str) or not 1 <= len(value) <= 300:
        raise GitHubImportError("invalid_url", "Enter a valid GitHub repository URL.")
    if not value.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise GitHubImportError("invalid_url", "The repository URL must contain plain ASCII only.")
    if "\\" in value or re.search(r"%(?:2f|2e)", value, re.IGNORECASE):
        raise GitHubImportError("invalid_url", "Encoded path separators and dots are not allowed.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GitHubImportError("invalid_url", "Enter a valid GitHub repository URL.") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubImportError(
            "invalid_url", "Use an https://github.com repository URL without query or fragment."
        )
    match = re.fullmatch(
        r"/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})(?:\.git)?/?", parsed.path, re.ASCII
    )
    if match is None:
        raise GitHubImportError("invalid_url", "Use exactly https://github.com/<owner>/<repo>.")
    owner, repo = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _OWNER.fullmatch(owner) or owner.startswith("-") or owner.endswith("-"):
        raise GitHubImportError("invalid_url", "The repository owner is invalid.")
    if not _REPO.fullmatch(repo) or repo in {".", ".."}:
        raise GitHubImportError("invalid_url", "The repository name is invalid.")
    return ValidatedSource(f"https://github.com/{owner}/{repo}", owner, repo)


def validate_ref(value: str | None) -> str | None:
    """Validate a branch, tag, or full commit SHA without invoking Git."""
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not value.isascii():
        raise GitHubImportError("invalid_ref", "The branch, tag, or commit reference is invalid.")
    if _SHA.fullmatch(value):
        return value.lower()
    if (
        not _REF.fullmatch(value)
        or ".." in value
        or value.startswith(("-", "/"))
        or value.endswith(("/", ".lock"))
        or "@{" in value
        or any(part in {"", "."} for part in value.split("/"))
    ):
        raise GitHubImportError("invalid_ref", "The branch, tag, or commit reference is invalid.")
    return value


def session_binding(csrf_token: str) -> str:
    """Return a nonreversible session key for preview/job ownership checks."""
    return hashlib.sha256(csrf_token.encode("utf-8")).hexdigest()


def build_git_environment(*, test_file_transport: bool = False) -> dict[str, str]:
    """Build the complete child environment without inheriting operator credentials."""
    if test_file_transport and not _test_seam_allowed():
        raise GitHubImportError(
            "test_seam_refused", "Local transport is available only in guarded tests."
        )
    path = os.environ.get("PATH", "")
    allowed_protocols = "https:file" if test_file_transport else "https"
    environment = {
        "PATH": path,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
        "GIT_ALLOW_PROTOCOL": allowed_protocols,
    }
    return environment


def _test_seam_allowed() -> bool:
    return (
        os.environ.get("CHINESCAN_TEST_GITHUB_IMPORT") == "1"
        and "pytest" in __import__("sys").modules
    )


def build_clone_argv(
    url: str,
    target: Path,
    hooks_directory: Path,
    *,
    ref: str | None = None,
    test_file_transport: bool = False,
) -> list[str]:
    """Return a validated Git argv; caller confines cwd and target to managed storage."""
    source = _validate_test_source(url, test_file_transport)
    checked_ref = validate_ref(ref)
    options = git_config_args(hooks_directory, test_file_transport=test_file_transport)
    if checked_ref is not None and _SHA.fullmatch(checked_ref):
        return ["git", *options, "init", str(target)]
    clone = [
        "git",
        *options,
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--filter=blob:limit=16m",
    ]
    if checked_ref is not None:
        clone.extend(["--branch", checked_ref])
    return [*clone, source, str(target)]


def git_config_args(hooks_directory: Path, *, test_file_transport: bool = False) -> list[str]:
    """Return the same transport and execution restrictions for every Git subcommand."""
    options = [
        "-c",
        "core.symlinks=false",
        "-c",
        f"core.hooksPath={hooks_directory}",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "http.followRedirects=false",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "fetch.recurseSubmodules=false",
    ]
    if test_file_transport:
        options.extend(["-c", "protocol.file.allow=always"])
    return options


def _validate_test_source(url: str, test_file_transport: bool) -> str:
    if not test_file_transport:
        return validate_github_url(url).canonical_url
    if not _test_seam_allowed():
        raise GitHubImportError(
            "test_seam_refused", "Local transport is available only in guarded tests."
        )
    parsed = urlsplit(url)
    local_path = Path(parsed.path.lstrip("/")) if os.name == "nt" else Path(parsed.path)
    if parsed.scheme != "file" or parsed.netloc or not local_path.is_absolute():
        raise GitHubImportError(
            "invalid_url", "The test transport accepts only a local absolute file URL."
        )
    return local_path.as_uri()


@dataclass(slots=True)
class _Preview:
    preview_id: str
    session_id: str
    canonical_url: str
    fetch_url: str
    ref: str | None
    expires_at: float
    used: bool = False


@dataclass(slots=True)
class _Job:
    job_id: str
    owner_session: str
    name: str
    canonical_url: str
    fetch_url: str
    ref: str | None
    status: JobStatus = "queued"
    phase: str = "queued"
    error_code: str | None = None
    message: str | None = None
    commit_sha: str | None = None
    fetched_at: str | None = None
    file_count: int | None = None
    total_bytes: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    cancel_event: threading.Event = field(default_factory=threading.Event)
    process: subprocess.Popen[bytes] | None = None
    clone_path: Path | None = None
    started_monotonic: float | None = None

    def response(self) -> dict[str, Any]:
        return {
            key: getattr(self, key)
            for key in (
                "job_id",
                "status",
                "phase",
                "error_code",
                "message",
                "commit_sha",
                "fetched_at",
                "file_count",
                "total_bytes",
                "created_at",
            )
        }


class GitHubImportService:
    """Session-bound preview storage and one-worker managed clone queue."""

    QUEUE_CAPACITY = 4
    PREVIEW_TTL_SECONDS = 600
    POLL_SECONDS = 0.1
    GIT_METADATA_MIN_ALLOWANCE = 8 * 1024 * 1024
    GIT_METADATA_MAX_ALLOWANCE = 64 * 1024 * 1024

    def __init__(
        self,
        repository: SQLiteRepository,
        settings: Settings,
        managed_directory: Path,
        *,
        test_file_transport: bool = False,
        process_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        if test_file_transport and not _test_seam_allowed():
            raise GitHubImportError(
                "test_seam_refused", "Local transport is available only in guarded tests."
            )
        self.repository = repository
        self.settings = settings
        self.managed_directory = managed_directory.expanduser().absolute()
        self.test_file_transport = test_file_transport
        self.process_factory = process_factory
        self._previews: dict[str, _Preview] = {}
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.RLock()
        self._queue: queue.Queue[_Job | None] = queue.Queue(maxsize=self.QUEUE_CAPACITY)
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()

    def preview(self, session_id: str, url: str, ref: str | None) -> dict[str, Any]:
        fetch_url = (
            _validate_test_source(url, True)
            if self.test_file_transport
            else validate_github_url(url).canonical_url
        )
        checked_ref = validate_ref(ref)
        canonical = (
            "https://github.com/test-fixture/repository"
            if self.test_file_transport
            else validate_github_url(fetch_url).canonical_url
        )
        preview = _Preview(
            str(uuid4()),
            session_id,
            canonical,
            fetch_url,
            checked_ref,
            time.monotonic() + self.PREVIEW_TTL_SECONDS,
        )
        with self._lock:
            self._purge_previews()
            self._previews[preview.preview_id] = preview
        self._audit("preview", preview_id=preview.preview_id)
        return {
            "preview_id": preview.preview_id,
            "url": canonical,
            "ref": checked_ref,
            "fetch_depth": 1,
            "submodules": False,
            "lfs": False,
            "max_bytes": self.settings.github_import_max_bytes,
            "git_metadata_allowance_bytes": self._git_metadata_allowance,
            "max_files": self.settings.github_import_max_files,
            "blob_limit_bytes": 16 * 1024 * 1024,
            "expires_in_seconds": self.PREVIEW_TTL_SECONDS,
        }

    def start(self, session_id: str, preview_id: str, name: str) -> dict[str, Any]:
        safe_name = name.strip()
        if not 1 <= len(safe_name) <= 120 or any(ord(c) < 32 for c in safe_name):
            raise GitHubImportError("invalid_name", "Project name must be 1 to 120 characters.")
        with self._lock:
            preview = self._previews.get(preview_id)
            if preview is None or preview.expires_at <= time.monotonic():
                self._previews.pop(preview_id, None)
                raise GitHubImportError("preview_expired", "Preview expired. Create a new preview.")
            if preview.session_id != session_id:
                raise GitHubImportError(
                    "preview_unavailable", "Preview is not available to this session."
                )
            if preview.used:
                raise GitHubImportError("preview_used", "This preview has already been used.")
            saved_jobs = self.repository.list_records("github_import_job")
            succeeded = sum(item.get("status") == "succeeded" for item in saved_jobs)
            succeeded = max(
                succeeded,
                sum(job.status == "succeeded" for job in self._jobs.values()),
            )
            if succeeded >= self.settings.github_import_max_projects:
                raise GitHubImportError(
                    "project_limit", "The configured public import limit has been reached."
                )
            active = sum(
                job.status in {"queued", "running", "verifying"} for job in self._jobs.values()
            )
            if active >= self.QUEUE_CAPACITY + 1:
                raise GitHubImportError(
                    "queue_full", "The import queue is full. Try again shortly."
                )
            job = _Job(
                str(uuid4()),
                session_id,
                safe_name,
                preview.canonical_url,
                preview.fetch_url,
                preview.ref,
            )
            try:
                self._queue.put_nowait(job)
            except queue.Full as exc:
                raise GitHubImportError(
                    "queue_full", "The import queue is full. Try again shortly."
                ) from exc
            preview.used = True
            self._jobs[job.job_id] = job
            self._save_job(job)
            self._audit("start", job_id=job.job_id)
        return job.response()

    def get(self, session_id: str, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                if job.owner_session != session_id:
                    raise GitHubImportError("job_not_found", "Import job was not found.")
                return job.response()
            stored = self.repository.get("github_import_job", job_id)
            if stored is None or stored.get("owner_session") != session_id:
                raise GitHubImportError("job_not_found", "Import job was not found.")
            return {
                key: stored.get(key)
                for key in (
                    "job_id",
                    "status",
                    "phase",
                    "error_code",
                    "message",
                    "commit_sha",
                    "fetched_at",
                    "file_count",
                    "total_bytes",
                    "created_at",
                )
            }

    def cancel(self, session_id: str, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                stored = self.repository.get("github_import_job", job_id)
                if stored is None or stored.get("owner_session") != session_id:
                    raise GitHubImportError("job_not_found", "Import job was not found.")
                if stored.get("status") not in {"queued", "running", "verifying"}:
                    return {
                        key: stored.get(key)
                        for key in (
                            "job_id",
                            "status",
                            "phase",
                            "error_code",
                            "message",
                            "commit_sha",
                            "fetched_at",
                            "file_count",
                            "total_bytes",
                            "created_at",
                        )
                    }
                stored["cancel_requested"] = True
                self.repository.save("github_import_job", job_id, stored)
                self._audit("cancel", job_id=job_id)
                return {
                    key: stored.get(key)
                    for key in (
                        "job_id",
                        "status",
                        "phase",
                        "error_code",
                        "message",
                        "commit_sha",
                        "fetched_at",
                        "file_count",
                        "total_bytes",
                        "created_at",
                    )
                }
            if job.owner_session != session_id:
                raise GitHubImportError("job_not_found", "Import job was not found.")
            if job.status in {"succeeded", "failed", "cancelled", "incomplete"}:
                return job.response()
            job.cancel_event.set()
            self._save_job(job)
            self._audit("cancel", job_id=job.job_id)
            return job.response()

    def start_worker(self) -> None:
        if not self.settings.github_import_enabled:
            return
        self._assert_managed_directory()
        self.managed_directory.mkdir(parents=True, exist_ok=True)
        self._assert_managed_directory()
        self._worker = threading.Thread(
            target=self._work, name="chinescan-github-import", daemon=True
        )
        self._worker.start()

    def stop_worker(self) -> None:
        self._stopping.set()
        with self._lock:
            for job in self._jobs.values():
                if job.status in {"queued", "running", "verifying"}:
                    job.cancel_event.set()
        if self._worker is not None:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            self._worker.join(timeout=self.settings.github_import_timeout_seconds + 10)

    def _work(self) -> None:
        while not self._stopping.is_set():
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if job is None:
                self._queue.task_done()
                break
            try:
                self._run_job(job)
            finally:
                self._queue.task_done()

    def _run_job(self, job: _Job) -> None:
        if job.cancel_event.is_set():
            self._finish(job, "cancelled", "cancelled", "The import was cancelled.")
            return
        try:
            with self._lock:
                job.status, job.phase = "running", "fetching"
                job.started_monotonic = time.monotonic()
                job.clone_path = self._target_for(job.job_id)
                self._save_job(job)
            self._audit("running", job_id=job.job_id)
            self._fetch(job)
            with self._lock:
                if job.cancel_event.is_set():
                    raise GitHubImportError("cancelled", "The import was cancelled.")
                job.status, job.phase = "verifying", "verifying"
                self._save_job(job)
            self._verify(job)
            self._finish(job, "succeeded", None, None)
        except GitHubImportError as exc:
            if exc.code == "quarantined_or_missing_files":
                self._cleanup_job_clone(job)
                self._finish(job, "incomplete", exc.code, str(exc))
            elif exc.code == "cancelled":
                self._cleanup_job_clone(job)
                self._finish(job, "cancelled", exc.code, str(exc))
            else:
                self._cleanup_job_clone(job)
                self._finish(job, "failed", exc.code, str(exc))
        except OSError:
            self._cleanup_job_clone(job)
            self._finish(job, "incomplete", "quarantined_or_missing_files", _INCOMPLETE_MESSAGE)
        except Exception:
            self._cleanup_job_clone(job)
            self._finish(job, "failed", "network_unreachable", "The import could not be completed.")

    def _fetch(self, job: _Job) -> None:
        self.managed_directory.mkdir(parents=True, exist_ok=True)
        self._assert_managed_directory()
        target = job.clone_path
        if target is None:
            raise GitHubImportError("unsafe_entries", "The managed import location is unavailable.")
        hooks = self.managed_directory / ".empty-hooks"
        hooks.mkdir(exist_ok=True)
        argv = build_clone_argv(
            job.fetch_url,
            target,
            hooks,
            ref=job.ref,
            test_file_transport=self.test_file_transport,
        )
        environment = build_git_environment(test_file_transport=self.test_file_transport)
        if job.ref is not None and _SHA.fullmatch(job.ref):
            self._run_git(job, argv, environment)
            config_args = git_config_args(hooks, test_file_transport=self.test_file_transport)
            self._run_git(
                job,
                [
                    "git",
                    "-C",
                    str(target),
                    *config_args,
                    "remote",
                    "add",
                    "origin",
                    job.fetch_url,
                ],
                environment,
            )
            fetch = [
                "git",
                "-C",
                str(target),
                *config_args,
                "fetch",
                "--depth",
                "1",
                "--no-tags",
                "--recurse-submodules=no",
                "--filter=blob:limit=16m",
                "origin",
                job.ref,
            ]
            self._run_git(job, fetch, environment)
            self._run_git(
                job,
                ["git", "-C", str(target), *config_args, "checkout", "--detach", job.ref],
                environment,
            )
            return
        self._run_git(job, argv, environment)

    def _run_git(self, job: _Job, argv: list[str], environment: dict[str, str]) -> None:
        self._ensure_cwd()
        try:
            process = self.process_factory(  # nosec B603: validated Git argv, URL, options, and confined UUID target.
                argv,
                cwd=str(self.managed_directory),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                start_new_session=os.name != "nt",
            )
        except FileNotFoundError as exc:
            raise GitHubImportError(
                "git_missing", "Git is not installed or is unavailable on PATH."
            ) from exc
        except OSError as exc:
            raise GitHubImportError("git_missing", "Git could not be started.") from exc
        job.process = process
        stderr_data = bytearray()
        stderr_lock = threading.Lock()

        def drain_stderr() -> None:
            pipe = process.stderr
            if pipe is None:
                return
            while chunk := pipe.read(4096):
                with stderr_lock:
                    if len(stderr_data) < 16_384:
                        stderr_data.extend(chunk[: 16_384 - len(stderr_data)])

        reader = threading.Thread(target=drain_stderr, daemon=True)
        reader.start()
        deadline = (job.started_monotonic or time.monotonic()) + (
            self.settings.github_import_timeout_seconds
        )
        failure: GitHubImportError | None = None
        while process.poll() is None:
            if self._cancel_requested(job):
                failure = GitHubImportError("cancelled", "The import was cancelled.")
                self._terminate_process_tree(process)
                break
            if time.monotonic() >= deadline:
                failure = GitHubImportError("timeout", "The import exceeded its time limit.")
                self._terminate_process_tree(process)
                break
            project_bytes, git_bytes, file_count = (
                self._tree_size_parts(job.clone_path) if job.clone_path is not None else (0, 0, 0)
            )
            if (
                project_bytes > self.settings.github_import_max_bytes
                or git_bytes > self._git_metadata_allowance
                or file_count > self.settings.github_import_max_files
                or project_bytes + git_bytes
                > self.settings.github_import_max_bytes + self._git_metadata_allowance
            ):
                failure = GitHubImportError(
                    "quota_exceeded", "The import exceeded its storage limit."
                )
                self._terminate_process_tree(process)
                break
            time.sleep(self.POLL_SECONDS)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._kill_process(process)
            process.wait()
        reader.join(timeout=5)
        job.process = None
        if failure is not None:
            raise failure
        if process.returncode != 0:
            with stderr_lock:
                diagnostic = bytes(stderr_data).decode("utf-8", errors="replace").lower()
            for markers, code, message in _GIT_ERROR_MAP:
                if any(marker in diagnostic for marker in markers):
                    raise GitHubImportError(code, message)
            raise GitHubImportError(
                "network_unreachable", "The public repository could not be fetched."
            )

    def _verify(self, job: _Job) -> None:
        root = job.clone_path
        if root is None:
            raise GitHubImportError("unsafe_entries", "The managed import location is unavailable.")
        self._prove_managed_target(root)
        environment = build_git_environment(test_file_transport=self.test_file_transport)
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            cwd=str(self.managed_directory),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
        if head.returncode != 0 or not re.fullmatch(rb"[0-9a-fA-F]{40}\r?\n?", head.stdout):
            raise GitHubImportError("unsafe_entries", "The fetched commit could not be verified.")
        commit_sha = head.stdout.decode("ascii").strip().lower()
        fetched_at = datetime.now(UTC).isoformat()
        size, count, git_size, actual_files = self._verify_tree(root)
        if size > self.settings.github_import_max_bytes:
            raise GitHubImportError("quota_exceeded", "The import exceeded its storage limit.")
        if git_size > self._git_metadata_allowance:
            raise GitHubImportError(
                "quota_exceeded", "The import metadata exceeded its storage limit."
            )
        if count > self.settings.github_import_max_files:
            raise GitHubImportError("quota_exceeded", "The import exceeded its file-count limit.")
        expected_files = self._tracked_files(root, commit_sha)
        missing_files = expected_files - actual_files
        if missing_files:
            raise GitHubImportError("quarantined_or_missing_files", _INCOMPLETE_MESSAGE)
        git_dir = root / ".git"
        self._prove_managed_target(git_dir, allow_missing=False)
        self._remove_git_metadata(git_dir)
        size, count, _git_size, _actual_files = self._verify_tree(root)
        with self._lock:
            job.commit_sha, job.fetched_at = commit_sha, fetched_at
            job.file_count, job.total_bytes = count, size

    def _remove_git_metadata(self, git_dir: Path) -> None:
        canonical_git = _canonical_path(git_dir, strict=True)
        managed = _canonical_path(self.managed_directory, strict=True)
        if not canonical_git.is_relative_to(managed):
            raise GitHubImportError("unsafe_entries", "Git metadata is outside managed storage.")
        self._safe_remove_tree(git_dir, canonical_git)

    def _safe_remove_tree(self, target: Path, allowed_root: Path) -> None:
        canonical_root = _canonical_path(allowed_root, strict=True)

        def retry_removal(function: Callable[..., Any], name: str, error: BaseException) -> None:
            if not isinstance(error, OSError):
                raise error
            path = Path(name)
            canonical_path = _canonical_path(path, strict=False)
            if not canonical_path.is_relative_to(canonical_root):
                raise error
            metadata = path.lstat()
            if _is_link_or_reparse(path, metadata):
                # Remove the link/reparse entry itself without traversing its target.
                function(name)
                return
            mode = metadata.st_mode | stat.S_IWRITE | stat.S_IREAD
            if stat.S_ISDIR(metadata.st_mode):
                mode |= stat.S_IEXEC
            os.chmod(path, mode)
            function(name)

        shutil.rmtree(target, onexc=retry_removal)

    def _verify_tree(self, root: Path) -> tuple[int, int, int, set[str]]:
        try:
            canonical_root = _canonical_path(root, strict=True)
            total_bytes = 0
            git_bytes = 0
            file_count = 0
            actual_files: set[str] = set()

            def onerror(error: OSError) -> None:
                raise error

            for directory, dirs, files in os.walk(
                canonical_root, followlinks=False, onerror=onerror
            ):
                parent = Path(directory)
                for name in [*dirs, *files]:
                    path = parent / name
                    self._validate_entry_name(name)
                    if len(str(path)) >= 260:
                        raise GitHubImportError(
                            "unsafe_entries", "The repository contains a path that is too long."
                        )
                    metadata = path.lstat()
                    if _is_link_or_reparse(path, metadata):
                        raise GitHubImportError(
                            "unsafe_entries", "The repository contains a link or reparse point."
                        )
                    if _has_alternate_data_stream(path):
                        raise GitHubImportError(
                            "unsafe_entries", "The repository contains an alternate data stream."
                        )
                    try:
                        resolved = _canonical_path(path, strict=True)
                    except OSError as exc:
                        raise GitHubImportError(
                            "quarantined_or_missing_files", _INCOMPLETE_MESSAGE
                        ) from exc
                    if not resolved.is_relative_to(canonical_root):
                        raise GitHubImportError(
                            "unsafe_entries", "The repository contains an entry outside the import."
                        )
                    if stat.S_ISREG(metadata.st_mode):
                        relative = path.relative_to(canonical_root)
                        in_git_metadata = (
                            bool(relative.parts) and relative.parts[0].casefold() == ".git"
                        )
                        try:
                            with path.open("rb") as stream:
                                while chunk := stream.read(1024 * 1024):
                                    if in_git_metadata:
                                        git_bytes += len(chunk)
                                    else:
                                        total_bytes += len(chunk)
                        except OSError as exc:
                            raise GitHubImportError(
                                "quarantined_or_missing_files", _INCOMPLETE_MESSAGE
                            ) from exc
                        if not in_git_metadata:
                            file_count += 1
                            actual_files.add(_normalized_tree_name(relative.as_posix()))
                        if file_count > self.settings.github_import_max_files:
                            raise GitHubImportError(
                                "quota_exceeded", "The import exceeded its file-count limit."
                            )
                        if total_bytes > self.settings.github_import_max_bytes:
                            raise GitHubImportError(
                                "quota_exceeded", "The import exceeded its storage limit."
                            )
                    elif not stat.S_ISDIR(metadata.st_mode):
                        raise GitHubImportError(
                            "unsafe_entries",
                            "The repository contains a non-regular filesystem entry.",
                        )
            if git_bytes > self._git_metadata_allowance:
                raise GitHubImportError(
                    "quota_exceeded", "The import metadata exceeded its storage limit."
                )
            return total_bytes, file_count, git_bytes, actual_files
        except GitHubImportError:
            raise
        except OSError as exc:
            raise GitHubImportError("quarantined_or_missing_files", _INCOMPLETE_MESSAGE) from exc

    def _tracked_files(self, root: Path, commit_sha: str) -> set[str]:
        hooks = self.managed_directory / ".empty-hooks"
        argv = [
            "git",
            "-C",
            str(root),
            *git_config_args(hooks, test_file_transport=self.test_file_transport),
            "ls-tree",
            "-r",
            "-z",
            commit_sha,
        ]
        try:
            # nosec B603: argv contains only fixed Git options and a verified 40-hex commit SHA.
            result = subprocess.run(
                argv,
                cwd=str(self.managed_directory),
                env=build_git_environment(test_file_transport=self.test_file_transport),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=self.settings.github_import_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitHubImportError("quarantined_or_missing_files", _INCOMPLETE_MESSAGE) from exc
        if result.returncode != 0:
            raise GitHubImportError("unsafe_entries", "The fetched tree could not be verified.")
        records = result.stdout.split(b"\0")
        if len(records) > self.settings.github_import_max_files + 1:
            raise GitHubImportError("quota_exceeded", "The import exceeded its file-count limit.")
        tracked: set[str] = set()
        for record in records:
            if not record:
                continue
            metadata, separator, raw_name = record.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise GitHubImportError("unsafe_entries", "The fetched tree could not be verified.")
            if fields[0] == b"160000":
                continue
            try:
                name = os.fsdecode(raw_name)
            except UnicodeError as exc:
                raise GitHubImportError(
                    "unsafe_entries", "The repository has an invalid path name."
                ) from exc
            path = Path(name)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise GitHubImportError("unsafe_entries", "The repository has an unsafe path name.")
            tracked.add(_normalized_tree_name(path.as_posix()))
        return tracked

    @staticmethod
    def _validate_entry_name(name: str) -> None:
        if ":" in name or name.endswith((".", " ")) or _DEVICE.fullmatch(name):
            raise GitHubImportError(
                "unsafe_entries", "The repository contains an unsafe Windows file name."
            )

    def _tree_size(self, root: Path) -> int:
        """Compatibility total for diagnostics; quota checks use separate components."""
        project_bytes, git_bytes, _file_count = self._tree_size_parts(root)
        return project_bytes + git_bytes

    def _tree_size_parts(self, root: Path) -> tuple[int, int, int]:
        if not root.exists():
            return 0, 0, 0
        try:
            project_bytes = 0
            git_bytes = 0
            file_count = 0
            for directory, _dirs, files in os.walk(root, followlinks=False):
                for name in files:
                    path = Path(directory) / name
                    try:
                        metadata = path.lstat()
                    except FileNotFoundError:
                        # Git is creating/replacing entries during clone; final verify catches
                        # files that remain missing after Git has exited.
                        continue
                    if not _is_link_or_reparse(path, metadata) and stat.S_ISREG(metadata.st_mode):
                        relative = path.relative_to(root)
                        if relative.parts and relative.parts[0].casefold() == ".git":
                            git_bytes += metadata.st_size
                        else:
                            project_bytes += metadata.st_size
                            file_count += 1
            return project_bytes, git_bytes, file_count
        except OSError:
            # Git writes may race this poll; final verification classifies persistent failures.
            return 0, 0, 0

    @property
    def _git_metadata_allowance(self) -> int:
        return min(
            max(self.settings.github_import_max_bytes // 4, self.GIT_METADATA_MIN_ALLOWANCE),
            self.GIT_METADATA_MAX_ALLOWANCE,
        )

    def _terminate_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        if os.name == "nt":
            # Only the integer PID returned by our Popen child enters taskkill argv.
            taskkill = shutil.which("taskkill")
            if taskkill:
                try:
                    subprocess.run(
                        [taskkill, "/PID", str(process.pid), "/T", "/F"],
                        cwd=str(self.managed_directory),
                        env=build_git_environment(test_file_transport=self.test_file_transport),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        shell=False,
                        check=False,
                    )
                except OSError:
                    self._kill_process(process)
            else:
                self._kill_process(process)
        else:
            kill_process_group = getattr(os, "killpg", None)
            if callable(kill_process_group):
                try:
                    kill_process_group(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except ProcessLookupError:
                    pass
            else:
                self._kill_process(process)

    @staticmethod
    def _kill_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()

    def _target_for(self, job_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
            raise GitHubImportError("unsafe_entries", "The managed import identifier is invalid.")
        return self.managed_directory / job_id

    def _prove_managed_target(self, target: Path, *, allow_missing: bool = True) -> None:
        self._assert_managed_directory()
        managed = _canonical_path(self.managed_directory, strict=True)
        candidate = _canonical_path(target, strict=False)
        if not candidate.is_relative_to(managed):
            raise GitHubImportError(
                "unsafe_entries", "The import location is outside managed storage."
            )
        if not target.exists() and not target.is_symlink():
            if allow_missing:
                return
            raise GitHubImportError("unsafe_entries", "The import location could not be verified.")
        metadata = target.lstat()
        if _is_link_or_reparse(target, metadata):
            raise GitHubImportError(
                "unsafe_entries", "The import location is not a regular managed directory."
            )
        if not _canonical_path(target, strict=True).is_relative_to(managed):
            raise GitHubImportError(
                "unsafe_entries", "The import location is outside managed storage."
            )

    def _assert_managed_directory(self) -> None:
        directory = _canonical_path(self.managed_directory, strict=False)
        repository_root = Path(__file__).resolve().parents[2]
        canonical_repository_root = _canonical_path(repository_root, strict=True)
        if _path_overlaps(directory, canonical_repository_root):
            raise GitHubImportError(
                "unsafe_entries", "Managed imports cannot be stored in the application checkout."
            )
        for allowed in self.settings.allowed_roots:
            root = _canonical_path(allowed, strict=False)
            if _path_overlaps(directory, root):
                raise GitHubImportError(
                    "unsafe_entries", "Managed imports cannot overlap approved scan roots."
                )
        if self.managed_directory.exists():
            metadata = self.managed_directory.lstat()
            if _is_link_or_reparse(self.managed_directory, metadata) or not stat.S_ISDIR(
                metadata.st_mode
            ):
                raise GitHubImportError(
                    "unsafe_entries", "Managed import storage must be a real directory."
                )

    def _ensure_cwd(self) -> None:
        self.managed_directory.mkdir(parents=True, exist_ok=True)
        self._assert_managed_directory()
        if self.managed_directory.is_symlink() or not self.managed_directory.is_dir():
            raise GitHubImportError("unsafe_entries", "Managed import storage is unavailable.")

    def _cancel_requested(self, job: _Job) -> bool:
        if job.cancel_event.is_set():
            return True
        stored = self.repository.get("github_import_job", job.job_id)
        return bool(stored and stored.get("cancel_requested"))

    def _cleanup_job_clone(self, job: _Job) -> None:
        path = job.clone_path
        if path is None:
            return
        try:
            self._prove_managed_target(path)
            if path.exists():
                self._safe_remove_tree(path, _canonical_path(path, strict=True))
        except (OSError, GitHubImportError):
            # A poisoned target is deliberately left untouched for operator investigation.
            return

    def _finish(self, job: _Job, status: JobStatus, code: str | None, message: str | None) -> None:
        with self._lock:
            job.status, job.phase, job.error_code, job.message = status, status, code, message
            self._save_job(job)
        event = (
            "finish"
            if status == "succeeded"
            else "fail"
            if status in {"failed", "incomplete"}
            else "cancel"
        )
        self._audit(event, job_id=job.job_id, status=status, error_code=code)

    def _save_job(self, job: _Job) -> None:
        record = job.response()
        record.update(
            {
                "name": job.name,
                "origin_url": job.canonical_url,
                "ref": job.ref,
                "owner_session": job.owner_session,
                "cancel_requested": job.cancel_event.is_set(),
            }
        )
        self.repository.save("github_import_job", job.job_id, record)

    def _audit(self, event: str, **details: str | None) -> None:
        record = {"event": event, "occurred_at": datetime.now(UTC).isoformat()}
        record.update({key: value for key, value in details.items() if value is not None})
        self.repository.save("github_import_audit", str(uuid4()), record)

    def _purge_previews(self) -> None:
        now = time.monotonic()
        expired = [key for key, preview in self._previews.items() if preview.expires_at <= now]
        for key in expired:
            del self._previews[key]


_INCOMPLETE_MESSAGE = (
    "Imported files became unavailable during verification. The import is incomplete; "
    "check local file protection history and retry if the repository is available."
)


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        return True
    if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        return True
    return False


def _canonical_path(path: Path, *, strict: bool) -> Path:
    """Resolve aliases, then normalize case and Unicode identically for both operands."""
    resolved = path.resolve(strict=strict)
    normalized = unicodedata.normalize("NFC", os.path.normcase(os.path.normpath(str(resolved))))
    return Path(normalized)


def _normalized_tree_name(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _path_overlaps(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _has_alternate_data_stream(path: Path) -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    class StreamData(ctypes.Structure):
        _fields_ = [("size", ctypes.c_longlong), ("name", wintypes.WCHAR * 296)]

    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        return False
    kernel = win_dll("kernel32", use_last_error=True)
    first_stream = getattr(kernel, "FindFirstStreamW", None)
    next_stream = getattr(kernel, "FindNextStreamW", None)
    close_handle = getattr(kernel, "FindClose", None)
    if not callable(first_stream) or not callable(next_stream) or not callable(close_handle):
        return False
    first_stream.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(StreamData),
        wintypes.DWORD,
    ]
    first_stream.restype = wintypes.HANDLE
    next_stream.argtypes = [wintypes.HANDLE, ctypes.POINTER(StreamData)]
    next_stream.restype = wintypes.BOOL
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    data = StreamData()
    handle = first_stream(str(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        return False
    try:
        while True:
            if data.name not in {"::$DATA", ""}:
                return True
            if not next_stream(handle, ctypes.byref(data)):
                return False
    finally:
        close_handle(handle)
