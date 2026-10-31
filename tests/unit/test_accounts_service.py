from pathlib import Path

import pytest

from chinescan.core.accounts import (
    CredentialError,
    create_operator,
    issue_reset_token,
    normalize_email,
    operator_status,
    reset_operator_password,
    verify_operator,
)


def test_account_password_policy_and_normalized_email(tmp_path: Path) -> None:
    path = tmp_path / "operator.json"
    assert normalize_email(" Analyst@Example.test ") == "analyst@example.test"
    create_operator(path, "analyst@example.test", "T0pical!Passphrase")
    assert operator_status(path) == "active"
    assert verify_operator(path, "ANALYST@example.test", "T0pical!Passphrase")
    for password in ("password123!", "analyst", "short"):
        with pytest.raises(CredentialError):
            create_operator(tmp_path / (password[:3] + ".json"), "analyst@example.test", password)


def test_reset_token_is_single_use_and_changes_password(tmp_path: Path) -> None:
    path = tmp_path / "operator.json"
    create_operator(path, "analyst@example.test", "T0pical!Passphrase")
    token = issue_reset_token(path, "analyst@example.test")
    text = path.read_text(encoding="utf-8")
    assert token not in text
    assert not reset_operator_password(
        path, "analyst@example.test", "wrong-reset-token-value-123456", "An0ther!Passphrase"
    )
    assert reset_operator_password(path, "analyst@example.test", token, "An0ther!Passphrase")
    assert not reset_operator_password(path, "analyst@example.test", token, "Third!Passphrase")
    assert verify_operator(path, "analyst@example.test", "An0ther!Passphrase")
