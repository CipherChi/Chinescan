"""Same-origin authenticated API and production frontend serving."""

from __future__ import annotations

import json
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint

from chinescan.core.cases import (
    CaseNotFoundError,
    CaseRecordNotFoundError,
    CaseWorkflow,
    CaseWorkflowError,
)
from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Confidence, FindingCategory, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Alert, Case, CaseStatus, Event, Scan, TimelineEntry
from chinescan.core.reporting import ReportingError, render_case_report, render_report, scan_data
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.auth import LoginThrottle, Session, SessionStore, verify_operator
from chinescan.web.code_jobs import CodeJobManager, ProjectConfigurationError, ProjectRegistry
from chinescan.web.log_jobs import LogJobManager, LogSourceError, LogSourceRegistry

COOKIE_NAME = "chinescan_session"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class AuthSessionResponse(BaseModel):
    """Authenticated operator identity and in-memory CSRF token."""

    model_config = ConfigDict(extra="forbid")
    username: str
    csrf_token: str = Field(description="Keep in memory and send in X-CSRF-Token for writes.")


class ScanSummaryResponse(BaseModel):
    """Path-free persisted scan summary identified by its stable scan ID."""

    model_config = ConfigDict(extra="forbid")
    scan_id: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    scanner: str
    project_types: list[str]
    finding_count: int


class ScanDetailResponse(ScanSummaryResponse):
    finding_ids: list[str]


class FindingSummaryResponse(BaseModel):
    """Reviewed, redacted finding fields safe for dashboard display."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str
    title: str
    severity: Severity
    category: FindingCategory
    confidence: Confidence
    scanner: str
    rule_id: str


class FindingDetailResponse(FindingSummaryResponse):
    description: str = ""
    location: str | None = None
    tags: list[str] = Field(default_factory=list)


class OverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_count: int
    finding_count: int
    findings_by_severity: dict[Severity, int]
    recent_scans: list[ScanSummaryResponse]


class ScanPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[ScanSummaryResponse]
    total: int
    limit: int
    offset: int


class FindingPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[FindingSummaryResponse]
    total: int
    limit: int
    offset: int


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1, max_length=255)
    title: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIUM


class CaseNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=8000)


class CaseLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_type: str = Field(min_length=1, max_length=80)
    record_id: str = Field(min_length=1, max_length=255)


class CaseStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: CaseStatus


class CodeJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=80)


class LogJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1, max_length=80)


class CodeProjectResponse(BaseModel):
    project_id: str
    display_name: str


class CodeJobResponse(BaseModel):
    job_id: str
    project_id: str
    project_name: str
    status: Literal["queued", "running", "succeeded", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    error: str | None


class CodeJobPageResponse(BaseModel):
    items: list[CodeJobResponse]
    total: int
    limit: int
    offset: int


class LogSourceResponse(BaseModel):
    source_id: str
    display_name: str


class LogJobResponse(BaseModel):
    job_id: str
    source_id: str
    source_name: str
    status: Literal["queued", "running", "succeeded", "partial", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    event_count: int
    alert_count: int
    error_count: int
    error: str | None
    diagnostics: list[str] = Field(default_factory=list)


class LogJobPageResponse(BaseModel):
    items: list[LogJobResponse]
    total: int
    limit: int
    offset: int


class AlertResponse(BaseModel):
    alert_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    rule_id: str
    event_ids: list[str]
    indicator_ids: list[str]
    mitre_attack_techniques: list[str]


class EventResponse(BaseModel):
    event_id: str
    occurred_at: datetime
    kind: str
    summary: str
    source: str
    source_ip: str | None
    destination_ip: str | None
    user: str | None
    host: str | None
    process: str | None
    url: str | None
    event_outcome: str | None
    mitre_attack_techniques: list[str]


class TimelineResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int


def _loopback_host(host: str) -> bool:
    value = host.strip().lower()
    if value.startswith("["):
        return value.startswith("[::1]") and (len(value) == 5 or value[5] == ":")
    hostname = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    return hostname in {"127.0.0.1", "localhost", "::1"}


def create_app(
    database_path: Path | str,
    credential_path: Path | str,
    *,
    session_ttl_seconds: int = 1800,
    secure_cookie: bool = False,
    serve_frontend: bool = True,
    projects_path: Path | str | None = None,
    log_sources_path: Path | str | None = None,
) -> FastAPI:
    """Create an application instance; sessions and throttling live in this process."""
    repository = SQLiteRepository(database_path)
    db_lock = threading.RLock()
    sessions = SessionStore(session_ttl_seconds)
    throttle = LoginThrottle()
    credentials = Path(credential_path)
    registry = ProjectRegistry(
        projects_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
        ],
    )
    jobs = CodeJobManager(repository, db_lock, registry)
    log_registry = LogSourceRegistry(
        log_sources_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
            Path(log_sources_path)
            if log_sources_path
            else Path.home() / ".config" / "chinescan" / "log-sources.toml",
        ],
    )
    log_jobs = LogJobManager(repository, db_lock, log_registry)

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        jobs.start()
        log_jobs.start()
        try:
            yield
        finally:
            log_jobs.stop()
            jobs.stop()
        repository.close()

    application = FastAPI(
        title="Chinetscan local dashboard", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    application.state.repository = repository
    application.state.project_registry = registry
    application.state.log_source_registry = log_registry
    application.state.log_job_manager = log_jobs

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> Response:
        # Pydantic errors may contain submitted values (including login passwords).
        details = [
            {
                "type": item.get("type", "invalid_request"),
                "loc": item.get("loc", []),
                "msg": item.get("msg", "Invalid request."),
            }
            for item in exc.errors()
        ]
        return Response(
            content=json.dumps({"detail": details}),
            status_code=422,
            media_type="application/json",
        )

    @application.middleware("http")
    async def loopback_and_origin_guard(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        host = request.headers.get("host", "")
        client_ip = request.client.host if request.client else ""
        if not _loopback_host(host) or not _loopback_host(client_ip):
            return Response("Local loopback access required.", status_code=400)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 8192:
                    return Response("Request body is too large.", status_code=413)
            except ValueError:
                return Response("Invalid request framing.", status_code=400)
        if request.headers.get("transfer-encoding"):
            return Response("Chunked request bodies are not accepted.", status_code=400)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if not origin:
                return Response("Same-origin request required.", status_code=403)
            parsed = urlsplit(origin)
            origin_authority = parsed.netloc
            if (
                parsed.scheme != request.url.scheme
                or origin_authority.lower() != host.lower()
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                return Response("Same-origin request required.", status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "private, no-store"
        return response

    def current_session(token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> Session:
        session = sessions.get(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session

    def require_csrf(
        session: Session = Depends(current_session),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
        csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> Session:
        import secrets

        if not csrf_header or not secrets.compare_digest(session.csrf_token, csrf_header):
            raise HTTPException(status_code=403, detail="CSRF validation failed.")
        return session

    @application.get("/api/auth/session", response_model=AuthSessionResponse)
    def auth_session(session: Session = Depends(current_session)) -> dict[str, str]:  # noqa: B008
        return {"username": session.username, "csrf_token": session.csrf_token}

    @application.post("/api/auth/login", response_model=AuthSessionResponse)
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
        client_ip = request.client.host if request.client else "unknown"
        if not throttle.allowed(client_ip):
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        try:
            valid = verify_operator(credentials, payload.username, payload.password)
        except Exception:
            valid = False
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        throttle.succeeded(client_ip)
        sessions.revoke(request.cookies.get(COOKIE_NAME))
        opaque, session = sessions.create(payload.username)
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=session_ttl_seconds,
            path="/",
        )
        return {"username": session.username, "csrf_token": session.csrf_token}

    @application.post("/api/auth/logout", response_model=dict[str, str])
    def logout(
        response: Response,
        _session: Session = Depends(require_csrf),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> dict[str, str]:
        sessions.revoke(token)
        response.delete_cookie(
            COOKIE_NAME, path="/", secure=secure_cookie, httponly=True, samesite="strict"
        )
        return {"status": "logged_out"}

    @application.get("/api/overview", response_model=OverviewResponse)
    def overview(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        with db_lock:
            scan_page, scan_count = repository.page_records(
                "scan", limit=5, offset=0, sort_by="started_at", descending=True
            )
            finding_count = repository.count_records("finding")
            grouped = repository.count_records("finding", group_by="severity")
        counts = {severity.value: int(grouped.get(severity.value, 0)) for severity in Severity}
        recent = [Scan.model_validate(item) for item in scan_page]
        return {
            "scan_count": scan_count,
            "finding_count": finding_count,
            "findings_by_severity": counts,
            "recent_scans": [_scan_summary(scan) for scan in recent],
        }

    @application.get("/api/code/projects", response_model=list[CodeProjectResponse])
    def code_projects(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return registry.list()

    @application.post("/api/code/jobs", response_model=CodeJobResponse, status_code=202)
    def create_code_job(
        payload: CodeJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return jobs.submit(payload.project_id)
        except ProjectConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429, detail="The code assessment queue is full."
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409,
                detail="An assessment for this project is already queued or running.",
            ) from exc

    @application.get("/api/code/jobs", response_model=CodeJobPageResponse)
    def list_code_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/code/jobs/{job_id}", response_model=CodeJobResponse)
    def get_code_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Code assessment job not found.")
        return item

    @application.get("/api/log/sources", response_model=list[LogSourceResponse])
    def log_sources(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return log_registry.entries()

    @application.post("/api/log/jobs", response_model=LogJobResponse, status_code=202)
    def create_log_job(
        payload: LogJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            return log_jobs.submit(payload.source_id)
        except LogSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="The log analysis queue is full.") from exc

    @application.get("/api/log/jobs", response_model=LogJobPageResponse)
    def list_log_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = log_jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/log/jobs/{job_id}", response_model=LogJobResponse)
    def get_log_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = log_jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Log analysis job not found.")
        return item

    def log_scan(scan_id: str) -> Scan:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        scan = Scan.model_validate(raw)
        if scan.scanner != "chinescan-log-analysis":
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        return scan

    @application.get("/api/log/analyses/{scan_id}/alerts", response_model=AlertPageResponse)
    def log_alerts(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("alert", scan.alert_ids)
        alerts = [Alert.model_validate(records[item]) for item in scan.alert_ids if item in records]
        if severity:
            alerts = [x for x in alerts if x.severity.value == severity]
        alerts.sort(key=lambda x: (x.severity.value, x.title.casefold(), x.alert_id))
        page = alerts[offset : offset + limit]
        return {
            "items": [_alert_summary(x) for x in page],
            "total": len(alerts),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/alerts/{alert_id}", response_model=AlertResponse)
    def log_alert_detail(
        scan_id: str,
        alert_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if alert_id not in scan.alert_ids:
            raise HTTPException(status_code=404, detail="Alert not found.")
        with db_lock:
            raw = repository.get("alert", alert_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return _alert_summary(Alert.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/events", response_model=EventPageResponse)
    def log_events(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        source: Annotated[str | None, Query(max_length=100)] = None,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("event", scan.event_ids)
        events = [Event.model_validate(records[item]) for item in scan.event_ids if item in records]
        if source:
            events = [x for x in events if x.source.casefold() == source.casefold()]
        events.sort(key=lambda x: (x.occurred_at, x.event_id), reverse=True)
        page = events[offset : offset + limit]
        return {
            "items": [_event_summary(x) for x in page],
            "total": len(events),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/events/{event_id}", response_model=EventResponse)
    def log_event_detail(
        scan_id: str,
        event_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if event_id not in scan.event_ids:
            raise HTTPException(status_code=404, detail="Event not found.")
        with db_lock:
            raw = repository.get("event", event_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Event not found.")
        return _event_summary(Event.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/timeline", response_model=TimelineResponse)
    def log_timeline(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("timeline_entry", scan.timeline_entry_ids)
        timeline = [
            TimelineEntry.model_validate(records[item])
            for item in scan.timeline_entry_ids
            if item in records
        ]
        timeline.sort(key=lambda x: (x.occurred_at, x.entry_id), reverse=True)
        page = timeline[offset : offset + limit]
        values = [redact(x.model_dump(mode="json")) for x in page]
        return {"items": values, "total": len(timeline), "limit": limit, "offset": offset}

    @application.get("/api/scans", response_model=ScanPageResponse)
    def list_scans(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: Literal["complete", "partial", "failed", "running"] | None = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["started_at", "status", "scanner"] = "started_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value for key, value in {"status": status, "scanner": scanner}.items() if value
        }
        with db_lock:
            page, total = repository.page_records(
                "scan",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        scans = [Scan.model_validate(item) for item in page]
        return {
            "items": [_scan_summary(scan) for scan in scans],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
    def get_scan(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Scan not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan = Scan.model_validate(raw)
        return _scan_summary(scan) | {"finding_ids": scan.finding_ids}

    @application.get("/api/findings", response_model=FindingPageResponse)
    def list_findings(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
        category: Annotated[str | None, Query(max_length=80)] = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["severity", "title", "scanner", "category"] = "severity",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        filters = {
            key: value
            for key, value in {
                "severity": severity,
                "category": category,
                "scanner": scanner,
            }.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "finding",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        return {
            "items": [_finding_summary(Finding.model_validate(item)) for item in page],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/findings/{finding_id}", response_model=FindingDetailResponse)
    def get_finding(
        finding_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(finding_id) > 255:
            raise HTTPException(status_code=404, detail="Finding not found.")
        with db_lock:
            raw = repository.get("finding", finding_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        return _finding_summary(Finding.model_validate(raw), detail=True)

    def case_view(case_id: str) -> dict[str, Any]:
        workflow = CaseWorkflow(repository)
        stored_case = workflow.get_case(case_id)
        _enforce_case_limits(stored_case)
        context = workflow.context(stored_case)
        case = context.case
        _, timeline, warnings = workflow.timeline(case)
        severities = {item.value: 0 for item in Severity}
        linked = []
        for (record_type, record_id), record in sorted(context.records.items()):
            raw_severity = getattr(record, "severity", None)
            if raw_severity is not None and raw_severity.value in severities:
                severities[raw_severity.value] += 1
            linked.append(
                {
                    "record_type": record_type,
                    "record_id": record_id,
                    "source": str(
                        getattr(record, "source", None)
                        or getattr(record, "scanner", None)
                        or record_type
                    ),
                    "title": str(getattr(record, "title", "")),
                    "severity": raw_severity.value if raw_severity is not None else None,
                }
            )
        view = {
            "case": case.model_dump(mode="json"),
            "links": [item.model_dump(mode="json") for item in context.links],
            "records": linked,
            "timeline": [item.model_dump(mode="json") for item in timeline],
            "warnings": list(dict.fromkeys([*context.warnings, *warnings])),
            "counts_by_severity": severities,
        }
        safe_view = redact(view)
        assert isinstance(safe_view, dict)
        return safe_view

    @application.get("/api/cases")
    def list_cases(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: CaseStatus | None = None,
        severity: Severity | None = None,
        sort: Literal["created_at", "updated_at", "status", "severity", "title"] = "updated_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value.value
            for key, value in {"status": status, "severity": severity}.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "case",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        case_items = [
            {
                "case_id": item["case_id"],
                "title": item["title"],
                "description": item["description"],
                "status": item["status"],
                "severity": item["severity"],
                "created_at": item["created_at"],
                "updated_at": item["updated_at"],
                "note_count": len(item.get("notes", [])),
                "linked_record_count": len(item.get("links", [])),
            }
            for item in page
        ]
        safe_items = redact(case_items)
        return {
            "items": safe_items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.post("/api/cases", status_code=201)
    def create_case(
        payload: CaseCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                case, warnings = CaseWorkflow(repository).create_from_scan(
                    payload.scan_id,
                    title=payload.title,
                    description=payload.description,
                    severity=payload.severity.value,
                )
                result = case_view(case.case_id)
            result["warnings"] = list(dict.fromkeys([*result["warnings"], *warnings]))
            return result
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}")
    def get_case(case_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/status")
    def update_case_status(
        case_id: str,
        payload: CaseStatusRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).update_status(case_id, payload.status)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/notes", status_code=201)
    def add_case_note(
        case_id: str,
        payload: CaseNoteRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                # The session identity is deliberately not stored as a legacy author label.
                CaseWorkflow(repository).add_note(case_id, payload.body)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/links")
    def link_case_record(
        case_id: str,
        payload: CaseLinkRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).link_record(
                    case_id, payload.record_type, payload.record_id
                )
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}/report/{output_format}")
    def case_report(
        case_id: str,
        output_format: Literal["json", "markdown", "html"],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                case = CaseWorkflow(repository).get_case(case_id)
                _enforce_case_limits(case)
                body = render_case_report(repository, case_id, output_format)
            return _download_response(body, f"case-report.{output_format}", output_format)
        except (CaseWorkflowError, ReportingError) as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/scans/{scan_id}/report/{output_format}")
    def scan_report(
        scan_id: str,
        output_format: Literal["json", "markdown", "html", "csv", "sarif"],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                scan, findings = scan_data(repository, scan_id)
                if len(findings) > 10_000:
                    raise HTTPException(
                        status_code=413, detail="Scan report exceeds configured finding limits."
                    )
                body = render_report(scan, findings, output_format)
            return _download_response(body, f"scan-report.{output_format}", output_format)
        except ReportingError as exc:
            raise _case_http_error(exc) from exc

    if serve_frontend and FRONTEND_DIST.is_dir():
        application.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

    return application


def _scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "status": scan.status,
        "scanner": scan.scanner,
        "project_types": scan.project_types,
        "finding_count": len(scan.finding_ids),
    }


def _finding_summary(finding: Finding, *, detail: bool = False) -> dict[str, Any]:
    # Explicit schema allowlist: never send raw evidence or arbitrary persisted JSON to the browser.
    value: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "confidence": finding.confidence.value,
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
    }
    if detail:
        value["description"] = finding.description
        value["location"] = finding.location
        value["tags"] = finding.tags
    redacted = redact(value)
    assert isinstance(redacted, dict)
    return redacted


def _alert_summary(alert: Alert) -> dict[str, Any]:
    value = {
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "confidence": alert.confidence.value,
        "rule_id": alert.rule_id,
        "event_ids": alert.event_ids,
        "indicator_ids": alert.indicator_ids,
        "mitre_attack_techniques": alert.mitre_attack_techniques,
    }
    redacted = redact(value)
    assert isinstance(redacted, dict)
    return redacted


def _event_summary(event: Event) -> dict[str, Any]:
    # Raw refs may contain full local paths; browser schemas intentionally omit them.
    value = {
        "event_id": event.event_id,
        "occurred_at": event.occurred_at,
        "kind": event.kind,
        "summary": event.summary,
        "source": event.source,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "user": event.user,
        "host": event.host,
        "process": event.process,
        "url": event.url,
        "event_outcome": event.event_outcome,
        "mitre_attack_techniques": event.mitre_attack_techniques,
    }
    redacted = redact(value)
    assert isinstance(redacted, dict)
    return redacted


def _case_http_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, (CaseNotFoundError, CaseRecordNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


def _enforce_case_limits(case: Case) -> None:
    if len(case.links) > 2_000 or len(case.notes) > 1_000 or len(case.activities) > 5_000:
        raise HTTPException(status_code=413, detail="Case exceeds configured record limits.")


def _download_response(body: str, filename: str, output_format: str) -> Response:
    # Reports are generated in memory from bounded stored records, never via a user path.
    encoded = body.encode("utf-8")
    if len(encoded) > 2_000_000:
        raise HTTPException(status_code=413, detail="Generated report exceeds the 2 MB limit.")
    media_type = {
        "json": "application/json; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "sarif": "application/sarif+json; charset=utf-8",
    }[output_format]
    safe_name = filename.replace('"', "")
    disposition = "attachment"
    return Response(
        content=encoded,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )
