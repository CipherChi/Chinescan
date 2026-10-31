from __future__ import annotations

import json
from pathlib import Path

import pytest
import tomli_w
from fastapi.testclient import TestClient

from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.web.app import create_app


def _configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, roots: list[Path]) -> Settings:
    config_dir = tmp_path / "private-config"
    config_dir.mkdir(exist_ok=True)
    config_path = config_dir / "config.toml"
    database = tmp_path / "database.sqlite3"
    reports = tmp_path / "reports"
    config_path.write_text(
        tomli_w.dumps(
            {
                "allowed_roots": [str(item) for item in roots],
                "database_path": str(database),
                "reports_dir": str(reports),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHINESCAN_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(reports))
    return Settings(
        _env_file=None,
        allowed_roots=roots,
        database_path=database,
        reports_dir=reports,
    )


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, roots: list[Path]):
    settings = _configuration(tmp_path, monkeypatch, roots)
    credential = tmp_path / "credential-store" / "operator.json"
    create_operator(credential, "fs-operator@example.test", "fs-test-account-password-9281")
    application = create_app(
        settings.database_path,
        credential,
        settings=settings,
        serve_frontend=False,
    )
    return application, TestClient(
        application,
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50123),
    )


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login",
        json={"email": "fs-operator@example.test", "password": "fs-test-account-password-9281"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert response.status_code == 200


def test_roots_and_directories_are_capability_scoped_selectable_and_path_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "approved"
    (root / "child").mkdir(parents=True)
    application, client = _client(tmp_path, monkeypatch, [root])
    unauthenticated = client.get("/api/fs/roots?capability=project_directory")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers.get("x-request-id")
    _login(client)

    response = client.get("/api/fs/roots?capability=project_directory")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 1
    root_entry = payload["items"][0]
    assert root_entry["selectable"] is True
    assert str(root) not in response.text
    root_page = client.get(
        "/api/fs/list",
        params={
            "capability": "project_directory",
            "directory_id": root_entry["directory_id"],
        },
    )
    assert root_page.status_code == 200
    assert root_page.json()["selectable"] is True
    assert root_page.json()["items"][0]["name"] == "child"
    assert root_page.json()["breadcrumbs"][0]["name"] == "Approved folder 1"
    assert str(root) not in root_page.text

    wrong_capability = client.get(
        "/api/fs/list",
        params={
            "capability": "log_location",
            "directory_id": root_entry["directory_id"],
        },
    )
    assert wrong_capability.status_code == 404
    forged = client.get(
        "/api/fs/list",
        params={"capability": "project_directory", "directory_id": "forged-id"},
    )
    assert forged.status_code == 422
    assert str(root) not in forged.text

    client2 = TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50124))
    _login(client2)
    cross_session = client2.get(
        "/api/fs/list",
        params={
            "capability": "project_directory",
            "directory_id": root_entry["directory_id"],
        },
    )
    assert cross_session.status_code == 404


def test_host_and_origin_guards_reject_invalid_fs_browse_origins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    _application, client = _client(tmp_path, monkeypatch, [root])
    bad_host = client.get(
        "/api/fs/roots?capability=project_directory", headers={"host": "127.0.0.1.evil.test"}
    )
    assert bad_host.status_code == 400
    assert bad_host.headers.get("x-request-id")
    assert str(root) not in bad_host.text
    bad_origin = client.get(
        "/api/fs/roots?capability=project_directory", headers={"origin": "http://evil.test"}
    )
    assert bad_origin.status_code == 403
    assert bad_origin.headers.get("x-request-id")
    assert str(root) not in bad_origin.text


def test_listing_page_cap_and_stable_opaque_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    for index in range(501):
        (root / f"folder-{index:03d}").mkdir()
    _application, client = _client(tmp_path, monkeypatch, [root])
    _login(client)
    root_id = client.get("/api/fs/roots?capability=log_location").json()["items"][0]["directory_id"]
    first = client.get(
        "/api/fs/list",
        params={"capability": "log_location", "directory_id": root_id, "limit": 500},
    )
    assert first.status_code == 200
    assert len(first.json()["items"]) == 500
    cursor = first.json()["next_cursor"]
    assert cursor
    (root / "folder-000-new").mkdir()
    second = client.get(
        "/api/fs/list",
        params={
            "capability": "log_location",
            "directory_id": root_id,
            "cursor": cursor,
            "limit": 500,
        },
    )
    assert second.status_code == 200
    assert [item["name"] for item in second.json()["items"]] == ["folder-500"]
    over_limit = client.get(
        "/api/fs/list",
        params={"capability": "log_location", "directory_id": root_id, "limit": 501},
    )
    assert over_limit.status_code == 422


def test_browse_rate_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    _application, client = _client(tmp_path, monkeypatch, [root])
    _login(client)
    responses = [client.get("/api/fs/roots?capability=project_directory") for _ in range(61)]
    assert all(item.status_code == 200 for item in responses[:60])
    assert responses[60].status_code == 429
    assert responses[60].headers.get("x-request-id")


def test_invalid_roots_are_ignored_at_settings_load_with_path_free_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = tmp_path / "approved"
    valid.mkdir()
    invalid = tmp_path / "missing"
    storage = tmp_path / "database.sqlite3"
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setenv("CHINESCAN_CONFIG_PATH", str(config_dir / "config.toml"))
    settings = Settings(
        _env_file=None,
        allowed_roots=[valid, invalid, tmp_path],
        database_path=storage,
        reports_dir=tmp_path / "reports",
    )
    assert settings.allowed_roots == [valid.resolve()]
    statuses = settings.allowed_root_validation
    assert [item.valid for item in statuses] == [True, False, False]
    assert statuses[1].reason_code == "unavailable"
    assert statuses[2].reason_code == "overlaps_chinescan_storage"
    assert str(tmp_path) not in json.dumps([item.__dict__ for item in statuses])


def test_cli_and_api_roots_and_check_have_parity_on_same_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from chinescan.cli.app import app as cli_app

    root = tmp_path / "approved"
    root.mkdir()
    _application, client = _client(tmp_path, monkeypatch, [root])
    api_roots_before_auth = client.get("/api/fs/roots?capability=project_directory")
    assert api_roots_before_auth.status_code == 401
    _login(client)
    api_roots = client.get("/api/fs/roots?capability=project_directory").json()
    runner = CliRunner()
    roots_result = runner.invoke(cli_app, ["fs", "roots", "--json"])
    check_result = runner.invoke(cli_app, ["fs", "check", str(root), "--json"])
    assert roots_result.exit_code == 0
    assert check_result.exit_code == 0
    cli_roots = json.loads(roots_result.stdout)
    cli_check = json.loads(check_result.stdout)
    assert cli_roots["count"] == len(api_roots["items"]) == 1
    assert cli_roots["roots"][0]["status"] == "valid"
    assert cli_check == {"allowed": True, "tier": "allowed", "reason_code": "allowed"}
    assert api_roots["items"][0]["selectable"] is True
    assert str(root) not in roots_result.stdout + check_result.stdout


def test_cli_denial_returns_usage_failure_without_path_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from chinescan.cli.app import app as cli_app

    root = tmp_path / "approved"
    root.mkdir()
    _configuration(tmp_path, monkeypatch, [root])
    denied = tmp_path / "outside"
    denied.mkdir()
    result = CliRunner().invoke(cli_app, ["fs", "check", str(denied), "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["reason_code"] == "outside_allowed_roots"
    assert str(denied) not in result.stdout + result.stderr
