import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.accounts import create_operator, issue_reset_token, operator_status
from chinescan.web.app import create_app


def test_cli_operator_status_matches_service(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    assert (
        CliRunner()
        .invoke(app, ["web", "operator-status", "--credential-file", str(credential), "--json"])
        .stdout.strip()
        == '{"status": "none"}'
    )
    create_operator(credential, "operator@example.test", "Synthetic secure passphrase 71!")
    result = CliRunner().invoke(
        app, ["web", "operator-status", "--credential-file", str(credential), "--json"]
    )
    assert json.loads(result.stdout) == {"status": operator_status(credential)}


def test_cli_bootstrap_matches_signup_service_state(tmp_path: Path, monkeypatch) -> None:
    from chinescan.cli import commands

    credential_cli = tmp_path / "cli.json"
    monkeypatch.setattr(commands, "getpass", lambda _prompt: "Synthetic secure passphrase 71!")
    cli = CliRunner().invoke(
        app,
        [
            "web",
            "bootstrap",
            "--email",
            "same@example.test",
            "--credential-file",
            str(credential_cli),
            "--json",
        ],
    )
    assert cli.exit_code == 0
    credential_api = tmp_path / "api.json"
    client = TestClient(
        create_app(tmp_path / "api.db", credential_api, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    api = client.post(
        "/api/auth/signup",
        json={"email": "same@example.test", "password": "Synthetic secure passphrase 71!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert api.status_code == 201, api.text
    assert operator_status(credential_cli) == operator_status(credential_api) == "active"


def test_cli_reset_issue_link_matches_service_reset_state(tmp_path: Path) -> None:
    cli_credential = tmp_path / "cli.json"
    create_operator(cli_credential, "same@example.test", "Synthetic secure passphrase 71!")
    cli = CliRunner().invoke(
        app,
        [
            "web",
            "reset-password",
            "--email",
            "same@example.test",
            "--issue-link",
            "--credential-file",
            str(cli_credential),
        ],
    )
    assert cli.exit_code == 0
    cli_token = cli.stdout.strip().split("token=", 1)[1]
    assert json.loads(cli_credential.read_text(encoding="utf-8"))["reset_token_hash"]
    assert cli_token not in cli_credential.read_text(encoding="utf-8")

    api_credential = tmp_path / "api.json"
    create_operator(api_credential, "same@example.test", "Synthetic secure passphrase 71!")
    api_token = issue_reset_token(api_credential, "same@example.test")
    api_record = json.loads(api_credential.read_text(encoding="utf-8"))
    assert api_token not in json.dumps(api_record)
    assert api_record["reset_token_hash"]
    assert api_record["reset_token_expires_at"] > api_record["reset_requested_at"]


def test_cli_retire_restore_round_trip_matches_service_state(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "same@example.test", "Synthetic secure passphrase 71!")
    runner = CliRunner()
    retired = runner.invoke(
        app,
        ["web", "retire-operator", "--credential-file", str(credential), "--json"],
        input="RETIRE OPERATOR\n",
    )
    assert retired.exit_code == 0
    assert operator_status(credential) == "none"
    restored = runner.invoke(
        app,
        ["web", "restore-operator", "--credential-file", str(credential), "--json"],
        input="1\nRESTORE OPERATOR\n",
    )
    assert restored.exit_code == 0
    assert operator_status(credential) == "active"
