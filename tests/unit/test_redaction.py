from chinescan.core.logging.redaction import redact


def test_redacts_credentials_from_text() -> None:
    assert redact("api_key=abc123") == "api_key=[REDACTED]"


def test_redacts_authorization_schemes_and_mapping_values() -> None:
    message = "Authorization: Bearer token-value"
    assert "token-value" not in redact(message)
    assert redact(message) == "Authorization: [REDACTED]"
    assert redact({"authorization": "Bearer token-value"}) == {"authorization": "[REDACTED]"}


def test_redacts_secret_mapping_values() -> None:
    assert redact({"api_token": "abc", "name": "ok"}) == {"api_token": "[REDACTED]", "name": "ok"}
