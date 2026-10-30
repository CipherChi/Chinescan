import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from chinescan.core.accounts import (
    create_operator,
    issue_reset_token,
    migrate_legacy_operator,
    operator_status,
)
from chinescan.web.app import create_app


def test_unknown_login_and_forgot_use_dummy_argon2id(monkeypatch, tmp_path: Path) -> None:
    import chinescan.core.accounts as accounts

    called: list[str] = []
    monkeypatch.setattr(accounts, "_verify_dummy", lambda value: called.append(value))
    credential = tmp_path / "operator.json"
    create_operator(credential, "known@example.test", "Synthetic secure passphrase 71!")
    client = TestClient(
        create_app(tmp_path / "db.sqlite3", credential, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    headers = {"Origin": "http://127.0.0.1"}
    response = client.post(
        "/api/auth/login",
        json={"email": "unknown@example.test", "password": "not-the-password"},
        headers=headers,
    )
    assert response.status_code == 401
    assert (
        client.post(
            "/api/auth/forgot-password", json={"email": "unknown@example.test"}, headers=headers
        ).status_code
        == 202
    )
    assert called == ["not-the-password", "unknown@example.test"]


def test_progressive_lockout_is_generic_and_applies_to_auth_routes(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "known@example.test", "Synthetic secure passphrase 71!")
    client = TestClient(
        create_app(tmp_path / "db.sqlite3", credential, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    headers = {"Origin": "http://127.0.0.1"}
    outcomes = []
    for _ in range(5):
        outcomes.append(
            client.post(
                "/api/auth/login",
                json={"email": "unknown@example.test", "password": "wrong"},
                headers=headers,
            )
        )
    assert [r.status_code for r in outcomes] == [401, 401, 401, 401, 429]
    assert outcomes[-1].headers["Retry-After"] == "60"
    assert "unknown@example.test" not in outcomes[-1].text

    for endpoint, body in (
        ("/api/auth/forgot-password", {"email": "forgot@example.test"}),
        (
            "/api/auth/reset-password",
            {
                "email": "reset@example.test",
                "token": "x" * 32,
                "password": "Synthetic secure passphrase 72!",
            },
        ),
        ("/api/auth/signup", {"email": "signup@example.test", "password": "password123!"}),
    ):
        isolated = TestClient(
            create_app(
                tmp_path / f"{endpoint.rsplit('/', 1)[-1]}.db",
                tmp_path / f"{endpoint.rsplit('/', 1)[-1]}.json",
                serve_frontend=False,
            ),
            base_url="http://127.0.0.1",
            client=("127.0.0.1", 50000),
        )
        for _ in range(5):
            isolated.post(endpoint, json=body, headers=headers)
        locked = isolated.post(endpoint, json=body, headers=headers)
        assert locked.status_code == 429
        assert 1 <= int(locked.headers["Retry-After"]) <= 60
        assert locked.json() == outcomes[-1].json()


def test_unknown_login_response_matches_known_failure_shape(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "known@example.test", "Synthetic secure passphrase 71!")
    client = TestClient(
        create_app(tmp_path / "db.sqlite3", credential, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    headers = {"Origin": "http://127.0.0.1"}
    known = client.post(
        "/api/auth/login",
        json={"email": "known@example.test", "password": "wrong"},
        headers=headers,
    )
    unknown = client.post(
        "/api/auth/login",
        json={"email": "unknown@example.test", "password": "wrong"},
        headers=headers,
    )
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()
    assert known.headers["content-type"] == unknown.headers["content-type"]
    assert known.headers["cache-control"] == unknown.headers["cache-control"]


def test_legacy_identity_migration_and_needs_migration_backups(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.json"
    legacy.write_text('{"username":"analyst","password_hash":"synthetic-hash"}', encoding="utf-8")
    assert operator_status(legacy) == "legacy"
    assert migrate_legacy_operator(legacy)
    assert operator_status(legacy) == "needs-migration"
    assert list(tmp_path.glob("legacy.json.*.bak"))

    email_legacy = tmp_path / "email-legacy.json"
    email_legacy.write_text(
        '{"username":" Analyst@Example.test ","password_hash":"synthetic-hash"}', encoding="utf-8"
    )
    assert migrate_legacy_operator(email_legacy)
    assert json.loads(email_legacy.read_text(encoding="utf-8"))["email"] == "analyst@example.test"
    assert list(tmp_path.glob("email-legacy.json.*.bak"))


def test_backup_listing_metadata_ignores_tampered_mtime(tmp_path: Path, monkeypatch) -> None:
    from typer.testing import CliRunner

    from chinescan.cli.app import app

    credential = tmp_path / "operator.json"
    create_operator(credential, "canary@example.test", "Synthetic secure passphrase 71!")
    token = issue_reset_token(credential, "canary@example.test")
    assert token
    backup = next(tmp_path.glob("operator.json.*.bak"))
    os.utime(backup, (1, 1))
    result = CliRunner().invoke(
        app, ["web", "restore-operator", "--credential-file", str(credential)], input="1\nno\n"
    )
    assert result.exit_code == 0
    assert "timestamp=" in result.output
    assert "email=c***@example.test" in result.output
    assert "1970" not in result.output
