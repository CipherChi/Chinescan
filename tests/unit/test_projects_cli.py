from __future__ import annotations

import json
from pathlib import Path

import tomli_w
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from chinescan.cli.app import app as cli_app
from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.web.app import create_app


def test_projects_cli_add_and_api_list_share_core_state(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    database = private / "records.sqlite3"
    config = private / "config.toml"
    config.write_text(
        tomli_w.dumps(
            {
                "allowed_roots": [str(root)],
                "database_path": str(database),
                "reports_dir": str(private / "reports"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHINESCAN_CONFIG_PATH", str(config))
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(private / "reports"))
    cli_result = CliRunner().invoke(
        cli_app, ["projects", "add", "--name", "Parity fixture", "--path", str(root), "--json"]
    )
    assert cli_result.exit_code == 0, cli_result.stderr
    cli_project = json.loads(cli_result.stdout)

    credential = private / "operator.json"
    create_operator(credential, "parity@example.test", "projects-parity-password-123")
    settings = Settings(
        _env_file=None,
        allowed_roots=[root],
        database_path=database,
        reports_dir=private / "reports",
    )
    application = create_app(database, credential, settings=settings, serve_frontend=False)
    client = TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50134))
    logged = client.post(
        "/api/auth/login",
        json={"email": "parity@example.test", "password": "projects-parity-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    api_items = client.get("/api/projects").json()
    assert logged.status_code == 200
    assert (
        next(item for item in api_items if item["project_id"] == cli_project["project_id"])
        == cli_project
    )
    assert str(root) not in cli_result.stdout
    client.close()
