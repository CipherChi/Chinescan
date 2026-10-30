import logging
import secrets
from pathlib import Path

import pytest

from chinescan.core.logging.redaction import REDACTED, redact
from chinescan.core.logging.structured import configure_logging


@pytest.mark.parametrize(
    "text",
    [
        "password=value",
        "passwd: value",
        "pwd='value'",
        '"password_hash": "fake-hash"',
        "reset-token=<token-value>",
        "apiKey='value'",
        "sessionId=value",
        "csrf_token: value",
        "credential=value",
        "Cookie: value",
    ],
)
def test_redacts_sensitive_key_forms(text: str) -> None:
    output = redact(text)
    assert REDACTED in output
    assert "value" not in output


@pytest.mark.parametrize(
    "secret",
    [
        "$argon2id$v=19$m=65536,t=3,p=4$salt$fakehash",
        "$argon2i$v=19$m=65536,t=3,p=4$salt$fakehash",
        "$argon2d$v=19$m=65536,t=3,p=4$salt$fakehash",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjYW5hcnkifQ.signature",
        "q4w3e2r1t0y9u8i7o6p5a4s3d2f1g0h9",
    ],
)
def test_redacts_secret_value_shapes(secret: str) -> None:
    output = redact(f"unlabelled={secret}")
    assert secret not in output


def test_redacts_nested_values_and_paths_and_is_idempotent(tmp_path: Path) -> None:
    windows_path = str(tmp_path / "profile" / "private.txt")
    data = {
        "passwordHash": "$argon2id$v=19$m=65536,t=3,p=4$salt$hash",
        "nested": [{"csrfToken": "canary-token-value"}, windows_path, ("plain",)],
    }
    safe = redact(data)
    assert safe["passwordHash"] == REDACTED
    assert safe["nested"][0]["csrfToken"] == REDACTED
    assert str(tmp_path) not in str(safe)
    assert redact(safe) == safe


def test_hashes_survive_but_generated_url_safe_tokens_and_argon_hashes_do_not() -> None:
    hashes = ["a" * 32, "b" * 40, "c" * 64]
    token = secrets.token_urlsafe(32)
    argon = "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash"
    message = " ".join([*hashes, token, argon])
    output = redact(message)
    for digest in hashes:
        assert digest in output
    assert token not in output
    assert argon not in output


def test_log_messages_preserve_digests_and_scrub_token_and_argon_values(caplog) -> None:
    configure_logging()
    caplog.set_level(logging.INFO)
    hashes = ["a" * 32, "b" * 40, "c" * 64]
    token = secrets.token_urlsafe(32)
    argon = "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash"
    logging.getLogger("chinescan.ioc").info("digests %s token %s hash %s", hashes, token, argon)
    for digest in hashes:
        assert digest in caplog.text
    assert token not in caplog.text
    assert argon not in caplog.text


def test_redactor_never_raises_on_unusual_values() -> None:
    class Broken:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    class BrokenMapping(dict):
        def items(self):
            raise RuntimeError("cannot enumerate")

    assert redact(Broken()) is not None
    assert redact(BrokenMapping()) == REDACTED


def test_record_factory_redacts_uvicorn_and_third_party_logs_and_tracebacks(
    caplog, tmp_path: Path
) -> None:
    configure_logging()
    caplog.set_level(logging.INFO)
    token = "CanaryToken1234567890abcdefghijklmnopqrstuv"
    fake_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$fakehash"
    secret_path = str(tmp_path / "operator" / "credential.json")
    try:
        raise RuntimeError(f"password={token}; path={secret_path}")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception(
            "untrusted third-party message: %s", fake_hash, extra={"credential": secret_path}
        )
    captured = caplog.text
    assert token not in captured
    assert fake_hash not in captured
    assert secret_path not in captured
    assert REDACTED in captured
    assert "[PATH]" in captured


def test_logging_factory_does_not_reenter_logging_record_factory(monkeypatch, caplog) -> None:
    configure_logging()

    def unexpected_record_creation(_values):
        raise AssertionError("formatter must not recursively create log records")

    monkeypatch.setattr(logging, "makeLogRecord", unexpected_record_creation)
    caplog.set_level(logging.INFO)
    logging.getLogger("uvicorn.error").info("record factory remains responsive")
    assert "record factory remains responsive" in caplog.text
