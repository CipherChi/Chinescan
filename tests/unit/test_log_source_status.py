from pathlib import Path

from fastapi.testclient import TestClient

from chinescan.web.app import create_app
from chinescan.web.auth import create_operator
from chinescan.web.log_jobs import LogSourceRegistry


def test_registry_status_states_are_path_free(tmp_path: Path) -> None:
    registry_path = tmp_path / "log-sources.toml"
    registry = LogSourceRegistry(registry_path, [])
    assert registry.status()["status"] == "missing"
    registry_path.write_text("not = [valid toml", encoding="utf-8")
    assert registry.status()["status"] == "invalid"
    registry_path.write_text("sources = []\n", encoding="utf-8")
    status = registry.status()
    assert status["status"] == "empty"
    assert str(tmp_path) not in status["reason"]


def test_authenticated_status_endpoint_preserves_sources_array(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    source_file = tmp_path / "log-sources.toml"
    source_file.write_text("sources = []\n", encoding="utf-8")
    create_operator(credential, "operator", "synthetic-account-password")
    client = TestClient(
        create_app(
            tmp_path / "records.sqlite3",
            credential,
            log_sources_path=source_file,
            serve_frontend=False,
        ),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    assert client.get("/api/log/sources/status").status_code == 401
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "synthetic-account-password"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    assert client.get("/api/log/sources").json() == []
    assert client.get("/api/log/sources/status").json()["status"] == "empty"
