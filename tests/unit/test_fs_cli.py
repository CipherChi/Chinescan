from __future__ import annotations

import json
from pathlib import Path

import tomli_w
from typer.testing import CliRunner

from chinescan.cli.app import app


def _config(monkeypatch, tmp_path: Path, root: Path) -> None:
    config = tmp_path / "private" / "config.toml"
    config.parent.mkdir()
    config.write_text(
        tomli_w.dumps(
            {
                "allowed_roots": [str(root)],
                "database_path": str(tmp_path / "storage" / "db.sqlite3"),
                "reports_dir": str(tmp_path / "storage" / "reports"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHINESCAN_CONFIG_PATH", str(config))
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "storage" / "db.sqlite3"))
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(tmp_path / "storage" / "reports"))


def test_fs_check_json_allowed_and_denied_exit_codes_are_path_free(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "approved"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    _config(monkeypatch, tmp_path, root)
    runner = CliRunner()

    allowed = runner.invoke(app, ["fs", "check", str(root), "--json"])
    denied = runner.invoke(app, ["fs", "check", str(outside), "--json"])

    assert allowed.exit_code == 0
    assert json.loads(allowed.stdout) == {
        "allowed": True,
        "tier": "allowed",
        "reason_code": "allowed",
    }
    assert denied.exit_code == 2
    assert json.loads(denied.stdout)["reason_code"] == "outside_allowed_roots"
    assert str(root) not in allowed.stdout + allowed.stderr
    assert str(outside) not in denied.stdout + denied.stderr


def test_fs_roots_json_reports_only_path_free_status(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    _config(monkeypatch, tmp_path, root)

    result = CliRunner().invoke(app, ["fs", "roots", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "roots": [{"index": 0, "status": "valid", "reason_code": "allowed"}],
        "count": 1,
    }
    assert str(root) not in result.stdout + result.stderr
