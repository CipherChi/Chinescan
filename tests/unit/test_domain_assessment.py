import json
import socket
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.domain_assessment.authorization import (
    AuthorizationError,
    authorize_target,
    normalize_hostname,
)
from chinescan.domain_assessment.probe import (
    MAX_ADDRESSES,
    NetworkDomainProbe,
    ProbeResult,
    ProbeSettings,
    _head_request,
    _is_public_address,
)
from chinescan.domain_assessment.service import DomainAssessmentService


def test_normalize_hostname_idna_and_rejects_non_hostnames() -> None:
    assert normalize_hostname("BÜCHER.example.") == "xn--bcher-kva.example"
    for invalid in ("https://example.com", "127.0.0.1", "localhost", "host", "a.local"):
        with pytest.raises(AuthorizationError):
            normalize_hostname(invalid)


def test_ownership_assertion_requires_exact_explicit_operator() -> None:
    grant = authorize_target(
        "example.com",
        profile="light",
        operator="  analyst  ",
        assert_ownership=True,
        authorization_file=None,
    )
    assert (grant.target, grant.operator, grant.method) == (
        "example.com",
        "analyst",
        "ownership_assertion",
    )
    with pytest.raises(AuthorizationError, match="requires --operator"):
        authorize_target(
            "example.com",
            profile="light",
            operator=None,
            assert_ownership=True,
            authorization_file=None,
        )


def test_authorization_file_must_match_target_profile_and_validity(tmp_path) -> None:
    now = datetime.now(UTC)
    document = {
        "target": "example.com",
        "granted_by": "owner",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(minutes=1)).isoformat(),
        "profile": "deep",
    }
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    grant = authorize_target(
        "EXAMPLE.COM",
        profile="deep",
        operator=None,
        assert_ownership=False,
        authorization_file=path,
        now=now,
    )
    assert grant.operator == "owner"
    with pytest.raises(AuthorizationError, match="exactly match"):
        authorize_target(
            "sub.example.com",
            profile="deep",
            operator=None,
            assert_ownership=False,
            authorization_file=path,
            now=now,
        )
    expired = document | {"valid_until": (now - timedelta(seconds=1)).isoformat()}
    path.write_text(json.dumps(expired), encoding="utf-8")
    with pytest.raises(AuthorizationError, match="validity window"):
        authorize_target(
            "example.com",
            profile="deep",
            operator=None,
            assert_ownership=False,
            authorization_file=path,
            now=now,
        )


def test_cli_rejects_missing_authorization_before_database_or_network(
    monkeypatch, tmp_path
) -> None:
    database = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    monkeypatch.setattr(
        NetworkDomainProbe,
        "assess",
        lambda *_args: pytest.fail("network probe must not run without authorization"),
    )
    result = CliRunner().invoke(app, ["domain", "example.com"])
    assert result.exit_code == 2
    assert not database.exists()


def test_cli_rejects_out_of_range_limits_before_database_or_network(monkeypatch, tmp_path) -> None:
    database = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    result = CliRunner().invoke(
        app,
        [
            "domain",
            "example.com",
            "--i-own-this-target",
            "--operator",
            "analyst",
            "--timeout",
            "20",
        ],
    )
    assert result.exit_code == 2
    assert "between 0.1 and 10" in result.stderr
    assert not database.exists()


class MemoryRepository:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], dict] = {}

    def save(self, record_type: str, record_id: str, payload: dict) -> None:
        self.records[(record_type, record_id)] = payload

    def get(self, record_type: str, record_id: str) -> dict | None:
        return self.records.get((record_type, record_id))


def test_service_persists_authorization_and_running_scan_before_probe() -> None:
    repository = MemoryRepository()
    options = {"timeout_seconds": 2.0, "max_addresses": 3, "request_interval_seconds": 0.1}
    grant = authorize_target(
        "example.com",
        profile="light",
        operator="analyst",
        assert_ownership=True,
        authorization_file=None,
    )

    class Probe:
        name = "test-probe"

        def assess(self, hostname: str, profile: str) -> ProbeResult:
            assert hostname == "example.com" and profile == "light"
            assert any(key[0] == "authorization_record" for key in repository.records)
            scan = next(
                payload for (kind, _), payload in repository.records.items() if kind == "scan"
            )
            assert scan["status"] == "running"
            assert scan["scan_options"] == options
            return ProbeResult(findings=(("DAS-HTTPS-001", "Missing HSTS", "low", "No HSTS."),))

    result = DomainAssessmentService(repository, Probe(), scan_options=options).assess(grant)
    assert result.status == "complete"
    assert len(result.findings) == 1
    assert repository.get("scan", result.scan_id)["status"] == "complete"
    assert result.scan_options == options


def test_public_address_filter() -> None:
    assert _is_public_address("8.8.8.8")
    assert not _is_public_address("127.0.0.1")
    assert not _is_public_address("10.0.0.1")


def test_network_probe_caps_destinations_and_profile_requests(monkeypatch) -> None:
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"8.8.8.{i}", 0)) for i in range(1, 7)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: records)
    requests: list[tuple[str, bool]] = []

    def fake_head(address: str, hostname: str, *, tls: bool, timeout_seconds: float):
        assert hostname == "example.com"
        assert timeout_seconds == 3.0
        requests.append((address, tls))
        return 200, {"strict-transport-security": "max-age=10"}, {}

    monkeypatch.setattr("chinescan.domain_assessment.probe._head_request", fake_head)
    probe = NetworkDomainProbe()
    light = probe.assess("example.com", "light")
    assert len(light.addresses) == MAX_ADDRESSES
    assert requests == [(light.addresses[0], True)]
    requests.clear()
    probe.assess("example.com", "deep")
    assert requests == [(address, True) for address in light.addresses]


def test_probe_settings_validate_limits_and_enforce_request_spacing(monkeypatch) -> None:
    with pytest.raises(ValueError, match="max_addresses"):
        ProbeSettings(max_addresses=MAX_ADDRESSES + 1)
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"8.8.4.{i}", 0)) for i in range(1, 6)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: records)
    requests: list[str] = []
    sleeps: list[float] = []

    def fake_head(address: str, _hostname: str, *, tls: bool, timeout_seconds: float):
        assert tls and timeout_seconds == 0.5
        requests.append(address)
        return 200, {}, {}

    monkeypatch.setattr("chinescan.domain_assessment.probe._head_request", fake_head)
    monkeypatch.setattr("chinescan.domain_assessment.probe.time.sleep", sleeps.append)
    settings = ProbeSettings(
        timeout_seconds=0.5,
        max_addresses=5,
        request_interval_seconds=0.2,
    )
    NetworkDomainProbe(settings).assess("example.com", "deep")
    assert len(requests) == 5
    assert len(sleeps) == 4
    assert all(delay > 0 for delay in sleeps)


def test_head_request_stops_after_headers(monkeypatch) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.request = bytearray()
            self.response = bytearray(
                b"HTTP/1.1 204 No Content\r\nServer: test\r\n\r\nBODY MUST NOT BE READ"
            )

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendall(self, data: bytes) -> None:
            self.request.extend(data)

        def recv(self, count: int) -> bytes:
            value = self.response[:count]
            del self.response[:count]
            return bytes(value)

    fake = FakeSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: fake)
    status, headers, _ = _head_request("8.8.8.8", "example.com", tls=False)
    assert status == 204
    assert headers["server"] == "test"
    assert b"HEAD / HTTP/1.1" in fake.request
    assert bytes(fake.response).startswith(b"BODY MUST NOT BE READ")
