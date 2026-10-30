import logging
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.accounts import create_operator, issue_reset_token
from chinescan.web.app import create_app


def test_auth_api_and_cli_do_not_emit_planted_secrets_or_paths(tmp_path: Path, caplog) -> None:
    password = "Canary-Password-Not-For-Logs-927!"
    credential = tmp_path / "canary-path-fragment" / "operator.json"
    credential.parent.mkdir()
    caplog.set_level(logging.INFO)
    client = TestClient(
        create_app(tmp_path / "private-db-fragment.sqlite3", credential, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )

    headers = {"Origin": "http://127.0.0.1"}
    signup = client.post(
        "/api/auth/signup",
        json={"email": "canary@example.test", "password": password},
        headers=headers,
    )
    assert signup.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"email": "canary@example.test", "password": password},
        headers=headers,
    )
    assert login.status_code == 200
    client.post("/api/auth/forgot-password", json={"email": "canary@example.test"}, headers=headers)
    token_canary = issue_reset_token(credential, "canary@example.test")
    reset = client.post(
        "/api/auth/reset-password",
        json={
            "email": "canary@example.test",
            "token": token_canary,
            "password": "Canary-New-Password-Not-For-Logs-72!",
        },
        headers=headers,
    )
    assert reset.status_code == 200

    cli_credential = tmp_path / "cli-operator.json"
    create_operator(cli_credential, "canary@example.test", "Canary-CLI-Password-Not-For-Logs-73!")
    cli = CliRunner().invoke(
        app,
        [
            "web",
            "reset-password",
            "--email",
            "canary@example.test",
            "--issue-link",
            "--credential-file",
            str(cli_credential),
        ],
    )
    assert cli.exit_code == 0
    retirement = CliRunner().invoke(
        app,
        ["web", "retire-operator", "--credential-file", str(cli_credential)],
        input="RETIRE OPERATOR\n",
    )
    assert retirement.exit_code == 0
    restore = CliRunner().invoke(
        app,
        ["web", "restore-operator", "--credential-file", str(cli_credential)],
        input="1\nRESTORE OPERATOR\n",
    )
    assert restore.exit_code == 0

    fake_hash = "$argon2id$v=19$m=65536,t=3,p=4$fake-canary-hash"
    logging.getLogger("chinescan").warning("password_hash=%s", fake_hash)

    captured = "\n".join(
        [
            signup.text,
            login.text,
            cli.stdout,
            cli.stderr,
            retirement.stdout,
            retirement.stderr,
            restore.stdout,
            restore.stderr,
            caplog.text,
        ]
    )
    assert password not in captured
    assert "Canary-CLI-Password-Not-For-Logs-73!" not in captured
    assert token_canary not in captured
    assert str(credential.parent) not in captured
    assert "$argon2id$" not in captured
    assert fake_hash not in captured
    assert "reset-password?token=" not in caplog.text
