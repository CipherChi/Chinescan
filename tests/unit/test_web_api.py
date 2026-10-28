import hashlib
import os
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from uuid import uuid4

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.config.settings import Settings
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Scan
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import COOKIE_NAME, create_app
from chinescan.web.auth import create_operator


def _fixture(tmp_path, *, ttl: int = 1800):
    database = tmp_path / "records.sqlite3"
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "analyst", "safe local password")
    repository = SQLiteRepository(database)
    finding = Finding(
        finding_id="finding-1",
        title="Unsafe evaluation",
        severity=Severity.HIGH,
        fingerprint="fingerprint-1",
        description="Candidate evidence: password=example-value",
        location="src/app.py:12",
    )
    critical = Finding(
        finding_id="finding-2",
        title="Critical local finding",
        severity=Severity.CRITICAL,
        fingerprint="fingerprint-2",
    )
    scan = Scan(
        scan_id="scan-1",
        target_id="target-1",
        scanner="builtin",
        started_at=datetime.now(UTC),
        finding_ids=[finding.finding_id, critical.finding_id],
        project_types=["python"],
    )
    repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    repository.save("finding", critical.finding_id, critical.model_dump(mode="json"))
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.close()
    app = create_app(database, credential, session_ttl_seconds=ttl, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    return app, client, credential, database


def _login(client: TestClient, username: str = "analyst", password: str = "safe local password"):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": str(client.base_url).rstrip("/")},
    )


def test_protected_reads_and_paginated_real_records(tmp_path):
    _app, client, _credential, _database = _fixture(tmp_path)
    for path in (
        "/api/auth/session",
        "/api/overview",
        "/api/scans",
        "/api/findings",
        "/api/cases",
        "/api/cases/case-x/report/json",
    ):
        assert client.get(path).status_code == 401
    for path, payload in (
        ("/api/cases", {"scan_id": "scan-1"}),
        ("/api/cases/case-x/status", {"status": "open"}),
        ("/api/cases/case-x/notes", {"body": "note"}),
        ("/api/cases/case-x/links", {"record_type": "finding", "record_id": "finding-1"}),
    ):
        assert (
            client.post(path, json=payload, headers={"Origin": "http://127.0.0.1"}).status_code
            == 401
        )
    assert (
        client.post(
            "/api/auth/logout", headers={"Origin": str(client.base_url).rstrip("/")}
        ).status_code
        == 401
    )

    submitted_secret = "x" * 1025
    invalid = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": submitted_secret},
        headers={"Origin": str(client.base_url).rstrip("/")},
    )
    assert invalid.status_code == 422 and submitted_secret not in invalid.text

    assert _login(client).status_code == 200
    assert client.cookies.get(COOKIE_NAME)
    overview_response = client.get("/api/overview")
    assert overview_response.headers["cache-control"] == "private, no-store"
    assert overview_response.headers["x-frame-options"] == "DENY"
    overview = overview_response.json()
    assert overview["scan_count"] == 1
    assert overview["finding_count"] == 2
    assert overview["findings_by_severity"]["high"] == 1
    assert overview["findings_by_severity"]["critical"] == 1
    assert overview["recent_scans"][0]["scan_id"] == "scan-1"
    assert "target_id" not in overview["recent_scans"][0]

    scans = client.get("/api/scans?limit=1&status=complete&sort=started_at").json()
    assert scans["total"] == 1 and scans["items"][0]["finding_count"] == 2
    assert client.get("/api/scans?limit=101").status_code == 422
    assert client.get("/api/scans?offset=100001").status_code == 422
    assert client.get("/api/scans?sort=target").status_code == 422
    findings = client.get("/api/findings?severity=high&limit=1").json()
    assert findings["total"] == 1 and findings["items"][0]["finding_id"] == "finding-1"
    sorted_findings = client.get("/api/findings?limit=2&sort=severity&order=desc").json()
    assert [item["finding_id"] for item in sorted_findings["items"]] == ["finding-2", "finding-1"]
    assert client.get("/api/findings?severity=urgent").status_code == 422
    detail = client.get("/api/findings/finding-1").json()
    assert "password=example-value" not in detail["description"]
    assert "target" not in detail
    scan_detail = client.get("/api/scans/scan-1").json()
    assert "target_id" not in scan_detail
    assert scan_detail["finding_ids"] == ["finding-1", "finding-2"]


def test_malware_api_fail_closed_and_redacted_case_linking(tmp_path, request):
    root = Path(tempfile.mkdtemp(prefix="chinescan-b2-api-"))
    request.addfinalizer(lambda: shutil.rmtree(root, ignore_errors=True))
    source = root / "sources" / "benign-synthetic.bin"
    source.parent.mkdir()
    source.write_bytes(b"harmless synthetic sample")
    registry = root / "operator" / "malware-samples.toml"
    registry.parent.mkdir()
    registry.write_text(
        '[[samples]]\nid = "fixture"\nname = "<script>alert(1)</script>"\n'
        f'path = "{source.as_posix()}"\n',
        encoding="utf-8",
    )
    credential = root / "private" / "operator.json"
    create_operator(credential, "analyst", "safe local password")
    database = root / "state" / "records.sqlite3"
    settings = Settings(
        _env_file=None,
        database_path=database,
        malware_managed_directory=root / "managed",
    )
    app = create_app(
        database,
        credential,
        serve_frontend=False,
        malware_registry_path=registry,
        settings=settings,
    )
    repository = app.state.repository
    sample = {
        "sample_id": "managed-sample-1",
        "registry_id": "fixture",
        "display_name": "<script>alert(1)</script>",
        "object_key": "b" * 64,
        "size_bytes": 8,
        "sha256": hashlib.sha256(b"12345678").hexdigest(),
        "availability": "available",
        "created_at": datetime.now(UTC).isoformat(),
    }
    analysis = {
        "analysis_id": "analysis-1",
        "sample_id": "managed-sample-1",
        "profile": "builtin_static",
        "status": "partial",
        "created_at": datetime.now(UTC).isoformat(),
        "result": {
            "size_bytes": 8,
            "hashes": {"sha256": hashlib.sha256(b"12345678").hexdigest()},
            "file_type": "<img src=x>",
            "printable_string_count": 1,
            "indicator_count": 1,
            "indicators": [{"kind": "url", "value": "https://example.invalid/<script>"}],
            "warnings": ["ZIP metadata inspection skipped"],
        },
        "engines": {
            "yara": {"installation": "not_checked"},
            "clamav": {"installation": "not_checked"},
        },
    }
    repository.save("malware_sample", sample["sample_id"], sample)
    repository.save("malware_analysis", analysis["analysis_id"], analysis)
    repository.save(
        "malware_job",
        "job-1",
        {
            "job_id": "job-1",
            "sample_id": sample["sample_id"],
            "status": "succeeded",
            "created_at": datetime.now(UTC).isoformat(),
            "started_at": None,
            "finished_at": None,
            "analysis_id": analysis["analysis_id"],
            "warning": None,
        },
    )
    repository.save(
        "scan",
        "scan-case",
        Scan(
            scan_id="scan-case",
            target_id="target-case",
            scanner="builtin",
            started_at=datetime.now(UTC),
        ).model_dump(mode="json"),
    )
    managed_root = app.state.malware_job_manager.manager.store.root
    (managed_root / ("b" * 64)).write_bytes(b"12345678")
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    for path in (
        "/api/malware/capability",
        "/api/malware/samples",
        "/api/malware/jobs",
        "/api/malware/analyses/analysis-1",
    ):
        assert client.get(path).status_code == 401
    assert (
        client.post(
            "/api/malware/jobs",
            json={"registry_id": "fixture"},
            headers={"Origin": "http://127.0.0.1"},
        ).status_code
        == 401
    )
    login = _login(client)
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as live:
        login = _login(live)
        headers["X-CSRF-Token"] = login.json()["csrf_token"]
        entries = live.get("/api/malware/samples").json()
        assert entries[0]["state"] == "managed"
        assert entries[0]["sha256"] == hashlib.sha256(b"12345678").hexdigest()
        assert "path" not in entries[0]
        assert (
            live.post(
                "/api/malware/jobs",
                json={"registry_id": "fixture", "path": str(source)},
                headers=headers,
            ).status_code
            == 422
        )
        assert (
            live.post(
                "/api/malware/jobs",
                json={"registry_id": "fixture"},
                headers={"Origin": "http://127.0.0.1"},
            ).status_code
            == 403
        )
        assert (
            live.post(
                "/api/malware/jobs",
                json={"registry_id": "fixture", "profile": "custom"},
                headers=headers,
            ).status_code
            == 422
        )
        assert (
            live.post(
                "/api/malware/jobs",
                json={"registry_id": "unknown"},
                headers=headers,
            ).status_code
            == 422
        )
        capability = live.get("/api/malware/capability").json()
        if os.name != "nt":
            assert capability["execution_available"] is False
            assert (
                live.post(
                    "/api/malware/jobs", json={"registry_id": "fixture"}, headers=headers
                ).status_code
                == 503
            )
        viewed = live.get("/api/malware/analyses/analysis-1")
        assert viewed.status_code == 200
        assert "internal-key-never-disclose" not in viewed.text
        assert "https://example.invalid/<script>" in viewed.text
        assert live.get("/api/malware/analyses/unknown").status_code == 404
        assert live.get("/api/malware/samples/managed-sample-1/bytes").status_code == 404
        case = live.post("/api/cases", json={"scan_id": "scan-case"}, headers=headers)
        assert case.status_code == 201
        case_id = case.json()["case"]["case_id"]
        sample_link = live.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "malware_sample", "record_id": "managed-sample-1"},
            headers=headers,
        )
        assert sample_link.status_code == 200
        linked = live.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "malware_analysis", "record_id": "analysis-1"},
            headers=headers,
        )
        assert linked.status_code == 200
        duplicate = live.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "malware_analysis", "record_id": "analysis-1"},
            headers=headers,
        )
        assert len(duplicate.json()["links"]) == len(linked.json()["links"])
        report = live.get(f"/api/cases/{case_id}/report/json").text
        assert "analysis-1" in report and "partial" in report
        assert "internal-key-never-disclose" not in report
        assert str(source) not in report
        html_report = live.get(f"/api/cases/{case_id}/report/html").text
        assert "&lt;script&gt;" in html_report
        assert "<script>alert(1)</script>" not in html_report


def test_authenticated_log_job_results_case_links_and_read_only_source(tmp_path, request):
    source = tmp_path / "approved-logs"
    source.mkdir()
    log_file = source / "auth.jsonl"
    log_file.write_text(
        '{"timestamp":"2026-10-27T10:00:00Z","event_type":"authentication",'
        '"message":"login failure password=synthetic-secret", "source_ip":"203.0.113.10",'
        '"user":"analyst", "outcome":"failure"}\n',
        encoding="utf-8",
    )
    original_hash = hashlib.sha256(log_file.read_bytes()).hexdigest()
    log_config = tmp_path / "log-sources.toml"
    log_config.write_text(
        f'[[sources]]\nid = "auth"\nname = "Synthetic auth"\nroot = "{source.as_posix()}"\n',
        encoding="utf-8",
    )
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "analyst", "safe local password")
    database = tmp_path / "state" / "records.sqlite3"
    app = create_app(database, credential, serve_frontend=False, log_sources_path=log_config)
    app.state.log_job_manager.start()
    request.addfinalizer(app.state.log_job_manager.stop)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    assert client.get("/api/log/sources").status_code == 401
    assert (
        client.post(
            "/api/log/jobs", json={"source_id": "auth"}, headers={"Origin": "http://127.0.0.1"}
        ).status_code
        == 401
    )
    login = _login(client)
    csrf = login.json()["csrf_token"]
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf}
    assert (
        client.post(
            "/api/log/jobs", json={"source_id": "auth", "path": str(source)}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post("/api/log/jobs", json={"source_id": "unknown"}, headers=headers).status_code
        == 422
    )
    assert client.get("/api/log/sources").json() == [
        {"source_id": "auth", "display_name": "Synthetic auth"}
    ]
    created = client.post("/api/log/jobs", json={"source_id": "auth"}, headers=headers)
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = client.get(f"/api/log/jobs/{job_id}").json()
        if job["status"] not in {"queued", "running"}:
            break
        time.sleep(0.02)
    assert job["status"] == "succeeded"
    assert job["event_count"] == 1
    assert source.as_posix() not in client.get(f"/api/log/jobs/{job_id}").text
    scan_id = job["scan_id"]
    events = client.get(f"/api/log/analyses/{scan_id}/events?limit=1")
    assert events.status_code == 200 and events.json()["total"] == 1
    event = events.json()["items"][0]
    assert "raw_ref" not in event and source.as_posix() not in events.text
    assert client.get(f"/api/log/analyses/{scan_id}/events?limit=101").status_code == 422
    alerts = client.get(f"/api/log/analyses/{scan_id}/alerts")
    assert alerts.status_code == 200
    case = client.post("/api/cases", json={"scan_id": scan_id}, headers=headers)
    assert case.status_code == 201
    case_id = case.json()["case"]["case_id"]
    link = client.post(
        f"/api/cases/{case_id}/links",
        json={"record_type": "event", "record_id": event["event_id"]},
        headers=headers,
    )
    assert link.status_code == 200
    assert any(item["record_id"] == event["event_id"] for item in link.json()["links"])
    assert client.get(f"/api/cases/{case_id}/report/markdown").status_code == 200
    assert hashlib.sha256(log_file.read_bytes()).hexdigest() == original_hash
    client.post("/api/auth/logout", headers=headers)
    assert client.get(f"/api/log/analyses/{scan_id}/events").status_code == 401


def test_csrf_logout_revocation_and_actual_session_expiry(tmp_path):
    _app, client, _credential, _database = _fixture(tmp_path, ttl=1)
    login = _login(client)
    csrf = login.json()["csrf_token"]
    assert (
        client.post(
            "/api/auth/logout", headers={"Origin": str(client.base_url).rstrip("/")}
        ).status_code
        == 403
    )
    assert client.get("/api/overview").status_code == 200
    logged_out = client.post(
        "/api/auth/logout",
        headers={"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": csrf},
    )
    assert logged_out.status_code == 200
    assert client.get("/api/overview").status_code == 401

    assert _login(client).status_code == 200
    time.sleep(1.1)
    assert client.get("/api/auth/session").status_code == 401


def test_origin_host_and_login_throttle(tmp_path):
    _app, client, _credential, _database = _fixture(tmp_path)
    bad_origin = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "safe local password"},
        headers={"Origin": "http://evil.example"},
    )
    assert bad_origin.status_code == 403
    oversized = client.post(
        "/api/auth/login",
        content=b"x" * 8193,
        headers={"Origin": str(client.base_url).rstrip("/"), "Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    for _ in range(5):
        assert _login(client, password="wrong-password").status_code == 401
    assert _login(client).status_code == 429
    rejected_host = client.get("/api/auth/session", headers={"Host": "example.com"})
    assert rejected_host.status_code == 400


def test_cli_bootstrap_creates_external_operator_file_without_default_password(
    tmp_path, monkeypatch
):
    external = Path(mkdtemp(prefix=f"chinescan-web-bootstrap-{uuid4().hex}-"))
    path = external / "credentials" / "operator.json"
    answers = iter(("Correct Horse Battery", "Correct Horse Battery"))
    monkeypatch.setattr("chinescan.cli.commands.getpass", lambda _prompt: next(answers))
    try:
        result = CliRunner().invoke(
            app,
            ["web", "bootstrap", "--username", "analyst", "--credential-file", str(path)],
        )
        assert result.exit_code == 0, result.output
        assert path.is_file()
        stored = path.read_text(encoding="utf-8")
        assert "Correct Horse Battery" not in stored
        assert "password_hash" in stored
    finally:
        rmtree(external, ignore_errors=True)


def test_cli_rejects_operator_credentials_inside_a_repository(tmp_path, monkeypatch):
    answers = iter(("Correct Horse Battery", "Correct Horse Battery"))
    monkeypatch.setattr("chinescan.cli.commands.getpass", lambda _prompt: next(answers))
    path = tmp_path / "must-not-be-created.json"
    result = CliRunner().invoke(
        app,
        ["web", "bootstrap", "--username", "analyst", "--credential-file", str(path)],
    )
    assert result.exit_code == 2
    assert "outside Git repositories" in result.output
    assert not path.exists()


def test_explicit_web_startup_is_fixed_to_loopback_and_single_worker(tmp_path, monkeypatch):
    external = Path(mkdtemp(prefix=f"chinescan-web-serve-{uuid4().hex}-"))
    credential = external / "operator.json"
    create_operator(credential, "analyst", "safe local password")
    captured = {}

    def record_run(application, **kwargs):
        captured["app"] = application
        captured.update(kwargs)

    monkeypatch.setattr("uvicorn.run", record_run)
    from chinescan.cli.app import app

    try:
        result = CliRunner().invoke(
            app,
            [
                "--database",
                str(tmp_path / "dashboard.sqlite3"),
                "web",
                "serve",
                "--port",
                "9876",
                "--credential-file",
                str(credential),
            ],
        )
        assert result.exit_code == 0, result.output
        assert captured["host"] == "127.0.0.1"
        assert captured["port"] == 9876
        assert captured["workers"] == 1
        assert captured["access_log"] is False
        assert captured["proxy_headers"] is False
        captured["app"].state.repository.close()
    finally:
        rmtree(external, ignore_errors=True)


def test_session_cookie_is_invalid_after_new_application_instance(tmp_path):
    _app, first_client, credential, database = _fixture(tmp_path)
    login = _login(first_client)
    cookie = first_client.cookies.get(COOKIE_NAME)
    assert login.status_code == 200 and cookie
    second_app = create_app(database, credential, serve_frontend=False)
    second_client = TestClient(second_app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    second_client.cookies.set(COOKIE_NAME, cookie)
    assert second_client.get("/api/overview").status_code == 401
    second_app.state.repository.close()


def test_case_workflow_auth_csrf_validation_timeline_and_exports(tmp_path):
    _app, client, _credential, _database = _fixture(tmp_path)
    assert (
        client.post(
            "/api/cases", json={"scan_id": "scan-1"}, headers={"Origin": "http://127.0.0.1"}
        ).status_code
        == 401
    )
    _login(client)
    missing_csrf = client.post(
        "/api/cases", json={"scan_id": "scan-1"}, headers={"Origin": "http://127.0.0.1"}
    )
    assert missing_csrf.status_code == 403
    bad_csrf = client.post(
        "/api/cases",
        json={"scan_id": "scan-1"},
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": "bad"},
    )
    assert bad_csrf.status_code == 403
    csrf = client.get("/api/auth/session").json()["csrf_token"]
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf}
    for path, payload in (
        ("/api/cases/missing/status", {"status": "open"}),
        ("/api/cases/missing/notes", {"body": "note"}),
        (
            "/api/cases/missing/links",
            {"record_type": "finding", "record_id": "finding-1"},
        ),
    ):
        assert (
            client.post(
                path,
                json=payload,
                headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": "invalid"},
            ).status_code
            == 403
        )
    assert client.get("/api/cases?limit=101").status_code == 422
    created = client.post(
        "/api/cases",
        json={"scan_id": "scan-1", "title": "Triage case", "severity": "high"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    case = created.json()["case"]
    case_id = case["case_id"]
    assert created.json()["records"] and created.json()["timeline"]
    assert client.get(f"/api/cases/{case_id}").json()["case"]["title"] == "Triage case"
    assert client.get("/api/cases?status=open&severity=high").json()["total"] == 1

    # Evidence and notes are serialized as text, redacted, and never interpreted as markup.
    note = "<script>alert(1)</script> password=must-not-leak"
    assert (
        client.post(f"/api/cases/{case_id}/notes", json={"body": note}, headers=headers).status_code
        == 201
    )
    current = client.get(f"/api/cases/{case_id}").json()
    assert "<script>" in current["case"]["notes"][0]["body"]
    assert "must-not-leak" not in current["case"]["notes"][0]["body"]
    assert (
        client.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "finding", "record_id": "finding-1"},
            headers=headers,
        ).status_code
        == 200
    )
    before = client.get(f"/api/cases/{case_id}").json()["case"]["activities"]
    assert (
        client.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "finding", "record_id": "finding-1"},
            headers=headers,
        ).status_code
        == 200
    )
    after = client.get(f"/api/cases/{case_id}").json()["case"]["activities"]
    assert len(after) == len(before)
    assert (
        client.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "artifact", "record_id": "a"},
            headers=headers,
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/cases/{case_id}/links",
            json={"record_type": "finding", "record_id": "missing"},
            headers=headers,
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/cases/{case_id}/status", json={"status": "in_progress"}, headers=headers
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/cases/{case_id}/status", json={"status": "closed"}, headers=headers
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/cases/{case_id}/status", json={"status": "open"}, headers=headers
        ).status_code
        == 422
    )
    timeline = client.get(f"/api/cases/{case_id}").json()["timeline"]
    assert [item["category"] for item in timeline][-3:] == [
        "case_activity",
        "case_activity",
        "case_activity",
    ]

    for output_format in ("json", "markdown", "html"):
        response = client.get(f"/api/cases/{case_id}/report/{output_format}")
        assert response.status_code == 200
        assert response.headers["content-disposition"].startswith("attachment;")
        assert "must-not-leak" not in response.text
        if output_format == "html":
            assert "&lt;script&gt;" in response.text
            assert "text/html" in response.headers["content-type"]
    scan_report = client.get("/api/scans/scan-1/report/html")
    assert (
        scan_report.status_code == 200
        and "attachment;" in scan_report.headers["content-disposition"]
    )
    for output_format in ("json", "markdown", "html", "csv", "sarif"):
        response = client.get(f"/api/scans/scan-1/report/{output_format}")
        assert response.status_code == 200
        assert response.headers["content-disposition"].startswith("attachment;")
    assert client.get("/api/scans/scan-1/report/../../private").status_code in {404, 422}
