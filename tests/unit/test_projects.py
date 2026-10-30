from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Case, Scan
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    ProjectProfile,
    ScanBounds,
    detect_project,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app


def _client(tmp_path: Path, roots: list[Path]):
    private = tmp_path / "private"
    private.mkdir()
    db = private / "records.sqlite3"
    credentials = private / "operator.json"
    create_operator(credentials, "projects@example.test", "project-test-password-123")
    settings = Settings(
        _env_file=None, database_path=db, reports_dir=private / "reports", allowed_roots=roots
    )
    app = create_app(db, credentials, settings=settings, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50131))
    response = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert response.status_code == 200
    return (
        app,
        client,
        {"Origin": "http://127.0.0.1", "X-CSRF-Token": response.json()["csrf_token"]},
    )


def _selection(client: TestClient) -> str:
    roots = client.get("/api/fs/roots?capability=project_directory")
    assert roots.status_code == 200
    return roots.json()["items"][0]["directory_id"]


def test_project_api_create_show_remove_keeps_files_scans_findings_and_cases(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    (root / "main.py").write_text("print('safe')\n", encoding="utf-8")
    before = hashlib.sha256((root / "main.py").read_bytes()).hexdigest()
    app, client, headers = _client(tmp_path, [root])
    assert client.get("/api/projects").status_code == 200
    selected = _selection(client)
    response = client.post(
        "/api/projects", json={"name": "Demo", "directory_id": selected}, headers=headers
    )
    assert response.status_code == 201
    project = response.json()
    assert project["configured_by"] == "ui"
    assert str(root) not in response.text
    detail = client.get(f"/api/projects/{project['project_id']}")
    assert detail.status_code == 200 and str(root) not in detail.text
    repository: SQLiteRepository = app.state.repository
    scan = Scan(
        scan_id="project-scan",
        target_id="internal-root",
        scanner="fixture",
        started_at=datetime.now(UTC),
        project_id=project["project_id"],
    )
    finding = Finding(
        finding_id="project-finding",
        title="Fixture finding",
        severity=Severity.LOW,
        fingerprint="fp",
        scanner="fixture",
        rule_id="fixture",
        project_id=project["project_id"],
    )
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    case = Case(
        case_id="project-case",
        title="Project case",
        project_id=project["project_id"],
        scan_ids=[scan.scan_id],
    )
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    assert (
        client.request(
            "DELETE",
            f"/api/projects/{project['project_id']}",
            headers=headers,
            json={"confirmation": "wrong"},
        ).status_code
        == 409
    )
    assert (
        client.request(
            "DELETE",
            f"/api/projects/{project['project_id']}",
            headers=headers,
            json={"confirmation": "Demo"},
        ).status_code
        == 200
    )
    assert (root / "main.py").exists()
    assert hashlib.sha256((root / "main.py").read_bytes()).hexdigest() == before
    assert repository.get("project", project["project_id"]) is None
    assert repository.get("scan", scan.scan_id)["project_removed"] is True
    assert repository.get("finding", finding.finding_id)["project_removed"] is True
    assert repository.get("case", case.case_id)["project_removed"] is True
    client.close()


def test_project_creation_and_job_start_recheck_policy_and_names_are_unique(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    app, client, headers = _client(tmp_path, [root])
    selected = _selection(client)
    created = client.post(
        "/api/projects", json={"name": "Café", "directory_id": selected}, headers=headers
    )
    assert created.status_code == 201
    duplicate = client.post(
        "/api/projects", json={"name": "CAFE\u0301", "directory_id": selected}, headers=headers
    )
    assert duplicate.status_code == 422
    app.state.project_service.allowed_roots.clear()
    rejected = client.post(
        f"/api/projects/{created.json()['project_id']}/code-jobs", headers=headers
    )
    assert rejected.status_code == 422
    assert str(root) not in rejected.text
    client.close()


def test_project_job_rejects_root_swapped_to_junction(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    app, client, headers = _client(tmp_path, [root])
    selected = _selection(client)
    created = client.post(
        "/api/projects", json={"name": "Swapped root", "directory_id": selected}, headers=headers
    )
    assert created.status_code == 201
    moved = tmp_path / "moved-root"
    root.rename(moved)
    if os.name == "nt":
        safe_root = str(root).replace("'", "''")
        safe_target = str(moved).replace("'", "''")
        command = (
            f"New-Item -ItemType Junction -Path '{safe_root}' -Target '{safe_target}' | Out-Null"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
        )
    else:
        try:
            root.symlink_to(moved, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"Could not create a temporary directory link: {type(exc).__name__}.")
    response = client.post(
        f"/api/projects/{created.json()['project_id']}/code-jobs", headers=headers
    )
    assert response.status_code == 422
    assert "root_denied" in response.text
    assert str(root) not in response.text and str(moved) not in response.text
    client.close()


def test_project_route_requires_auth_csrf_and_same_origin(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    credential = private / "operator.json"
    create_operator(credential, "projects@example.test", "project-test-password-123")
    app = create_app(
        private / "records.sqlite3",
        credential,
        settings=Settings(
            _env_file=None,
            database_path=private / "records.sqlite3",
            reports_dir=private / "reports",
            allowed_roots=[root],
        ),
        serve_frontend=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50132))
    assert client.get("/api/projects").status_code == 401
    logged = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    token = logged.json()["csrf_token"]
    assert (
        client.post(
            "/api/projects",
            json={"name": "Demo", "directory_id": "x"},
            headers={"Origin": "http://127.0.0.1"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/projects",
            json={"name": "Demo", "directory_id": "x"},
            headers={"Origin": "http://evil.test", "X-CSRF-Token": token},
        ).status_code
        == 403
    )
    client.close()


def test_legacy_file_projects_are_read_only_and_path_free(tmp_path: Path) -> None:
    root = tmp_path / "legacy-root"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    config = private / "projects.toml"
    config.write_text(
        f'[[projects]]\nid = "legacy"\nname = "Legacy"\nroot = "{root.as_posix()}"\n',
        encoding="utf-8",
    )
    credential = private / "operator.json"
    create_operator(credential, "projects@example.test", "project-test-password-123")
    app = create_app(
        private / "records.sqlite3",
        credential,
        projects_path=config,
        settings=Settings(
            _env_file=None,
            database_path=private / "records.sqlite3",
            reports_dir=private / "reports",
            allowed_roots=[],
        ),
        serve_frontend=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50133))
    logged = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert logged.status_code == 200
    listed = client.get("/api/projects")
    assert listed.status_code == 200 and listed.json()[0]["configured_by"] == "file"
    assert str(root) not in listed.text
    deleted = client.request(
        "DELETE",
        "/api/projects/legacy",
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": logged.json()["csrf_token"]},
        json={"confirmation": "Legacy"},
    )
    assert deleted.status_code == 409
    assert root.exists()
    client.close()


def test_scan_bounds_report_each_skip_reason_and_ignore_default_directories(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "code"
    (root / "nested" / "deep").mkdir(parents=True)
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "one.py").write_text("eval(input)\n", encoding="utf-8")
    (root / "two.py").write_text("exec(input)\n", encoding="utf-8")
    (root / "nested" / "deep" / "three.py").write_text("eval(input)\n", encoding="utf-8")
    (root / "node_modules" / "pkg" / "ignored.py").write_text("eval(input)\n", encoding="utf-8")
    ignored_dirs = (".git", ".venv", "venv", "dist", "build", "__pycache__")
    for name in ignored_dirs:
        ignored = root / name
        ignored.mkdir()
        (ignored / "ignored.py").write_text("eval(input)\n", encoding="utf-8")

    file_profile = detect_project(root, ScanBounds(max_files=1))
    assert file_profile.skipped_counts["max_files"] >= 1
    assert all(item.name != "ignored.py" for item in file_profile.source_files)
    assert not any(
        part in ignored_dirs for path in file_profile.source_files for part in path.parts
    )
    byte_profile = detect_project(root, ScanBounds(max_total_bytes=1))
    assert byte_profile.skipped_counts["max_total_bytes"] >= 1
    size_profile = detect_project(root, ScanBounds(max_file_bytes=1))
    assert size_profile.skipped_counts["max_file_bytes"] >= 1
    depth_profile = detect_project(root, ScanBounds(max_depth=1))
    assert depth_profile.skipped_counts["max_depth"] >= 1
    deadline_profile = detect_project(root, ScanBounds(job_deadline_seconds=0))
    assert deadline_profile.skipped_counts["job_deadline"] >= 1

    profile = ProjectProfile(
        root=root,
        kinds=("python",),
        source_files=(root / "one.py",),
        skipped_counts={},
        deadline_at=100,
    )
    times = iter([0.0, 0.0, 1.0, 1.0])
    monkeypatch.setattr(
        "chinescan.core.orchestration.code_scan.time.monotonic", lambda: next(times)
    )
    BuiltinRuleScanner(ScanBounds(per_file_seconds=0.1)).scan_profile(profile)
    assert profile.skipped_counts["per_file_seconds"] == 1
