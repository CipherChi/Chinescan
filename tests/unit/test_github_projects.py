from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from chinescan.core.fs_policy import FilesystemBrowserService
from chinescan.core.projects import ProjectError, ProjectFileRegistry, ProjectService
from chinescan.core.storage.sqlite import SQLiteRepository


def project_fixture(tmp_path: Path) -> tuple[SQLiteRepository, ProjectService, Path]:
    repository = SQLiteRepository(tmp_path / "db" / "records.sqlite3")
    managed = tmp_path / "managed-imports"
    managed.mkdir()
    projects = ProjectService(
        repository,
        FilesystemBrowserService([], [], [], False),
        ProjectFileRegistry(None, []),
        allowed_roots=[],
        hard_denied=[],
        soft_denied=[],
        allow_soft_denied=False,
        managed_import_directory=managed,
    )
    return repository, projects, managed


def register(
    projects: ProjectService,
    root: Path,
    *,
    name: str,
    job_id: str,
    max_projects: int = 20,
    replace_project_id: str | None = None,
    replace_confirmation: str | None = None,
) -> str:
    return projects.register_github_import(
        name=name,
        root=root,
        origin_url="https://github.com/example/repository",
        commit_sha="a" * 40,
        fetched_at="2026-01-01T00:00:00+00:00",
        import_job_id=job_id,
        max_projects=max_projects,
        replace_project_id=replace_project_id,
        replace_confirmation=replace_confirmation,
    )


def make_clone(root: Path, content: bytes = b"fixture") -> Path:
    root.mkdir()
    (root / "README.txt").write_bytes(content)
    return root


def test_github_project_cap_counts_projects_not_completed_jobs(tmp_path: Path) -> None:
    repository, projects, managed = project_fixture(tmp_path)
    try:
        register(projects, make_clone(managed / "first"), name="First", job_id="first")
        with pytest.raises(ProjectError, match="limit"):
            register(
                projects,
                make_clone(managed / "second"),
                name="Second",
                job_id="second",
                max_projects=1,
            )
        assert projects.github_project_count() == 1
    finally:
        repository.close()


def test_replacement_keeps_old_clone_until_verified_replacement_registers(tmp_path: Path) -> None:
    repository, projects, managed = project_fixture(tmp_path)
    try:
        old_root = make_clone(managed / "old", b"old content")
        project_id = register(projects, old_root, name="Repository", job_id="old-job")
        new_root = make_clone(managed / "new", b"verified replacement")
        with pytest.raises(ProjectError, match="Type the project name"):
            register(
                projects,
                new_root,
                name="Repository",
                job_id="new-job",
                replace_project_id=project_id,
                replace_confirmation="wrong",
            )
        assert old_root.joinpath("README.txt").read_bytes() == b"old content"
        assert projects.resolve(project_id)[1] == old_root.resolve()
        replaced_id = register(
            projects,
            new_root,
            name="Repository",
            job_id="new-job",
            replace_project_id=project_id,
            replace_confirmation="Repository",
        )
        assert replaced_id == project_id
        assert not old_root.exists()
        assert projects.resolve(project_id)[1] == new_root.resolve()
    finally:
        repository.close()


@pytest.mark.skipif(os.name != "nt", reason="NTFS directory junction containment is Windows-only.")
def test_github_project_resolution_rechecks_clone_after_junction_swap(tmp_path: Path) -> None:
    repository, projects, managed = project_fixture(tmp_path)
    try:
        root = make_clone(managed / "clone")
        project_id = register(projects, root, name="Repository", job_id="fixture-job")
        outside = make_clone(tmp_path / "outside")
        moved = managed / "original-clone"
        root.rename(moved)
        result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(root), str(outside)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        with pytest.raises(ProjectError, match="no longer approved"):
            projects.resolve(project_id)
    finally:
        if "root" in locals() and root.is_junction():
            root.rmdir()
        repository.close()
