"""User-facing CLI commands."""

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path

import typer
from sqlalchemy.exc import SQLAlchemyError

from chinescan import __version__
from chinescan.core.cases import CaseWorkflow, CaseWorkflowError
from chinescan.core.config.io import init_config, load_settings, validate_config
from chinescan.core.config.settings import Settings
from chinescan.core.errors import ConfigurationError, StorageError
from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Severity
from chinescan.core.models.investigation import CaseStatus
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    CodeScanService,
    FindingScanner,
    ScannerError,
)
from chinescan.core.reporting import (
    ReportingError,
    render_case_report,
    render_report,
    scan_data,
)
from chinescan.core.storage.recovery import (
    RecoveryError,
    backup_database,
    plan_retention,
    restore_backup,
    verify_backup,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.core.trends import scan_history_trends
from chinescan.domain_assessment.authorization import AuthorizationError, authorize_target
from chinescan.domain_assessment.probe import NetworkDomainProbe, ProbeSettings
from chinescan.domain_assessment.service import DomainAssessmentService
from chinescan.log_analysis.ingest import LogIngestionError
from chinescan.log_analysis.service import LogAnalysisService
from chinescan.malware_analysis.analyzer import AnalysisError, analyze_file
from chinescan.malware_analysis.engines import EngineResult, run_clamav, run_yara
from chinescan.scanners.external import (
    GitleaksScanner,
    NpmAuditScanner,
    PipAuditScanner,
    SemgrepScanner,
    TrivyScanner,
)


def version() -> None:
    typer.echo(__version__)


_cli_config_path: Path | None = None
_cli_database_path: Path | None = None


def configure_settings(config_path: Path | None, database_path: Path | None) -> None:
    global _cli_config_path, _cli_database_path
    _cli_config_path = config_path
    _cli_database_path = database_path


def _settings() -> Settings:
    options: dict[str, object] = {}
    if _cli_database_path is not None:
        options["database_path"] = _cli_database_path
    try:
        return load_settings(_cli_config_path, cli_overrides=options)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc


config_app = typer.Typer(help="Initialize and validate local configuration.")


@config_app.command("init")
def config_init(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", help="Configuration file path."
    ),
) -> None:
    try:
        created = init_config(path)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo(f"Created configuration: {created}")


@config_app.command("validate")
def config_validate(
    path: Path = typer.Option(  # noqa: B008
        ..., "--path", help="Configuration file path."
    ),
) -> None:
    try:
        validate_config(path)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo("Configuration is valid.")


def code_scan(
    target: Path = typer.Argument(..., help="Local project directory to scan."),  # noqa: B008
    scanner_names: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--scanner",
        help="Scanner to run; repeat for multiple. Defaults to the built-in local rules.",
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
    semgrep_rules: Path | None = typer.Option(  # noqa: B008
        None, "--semgrep-rules", help="Local Semgrep YAML rules file (required for Semgrep)."
    ),  # noqa: B008
    timeout_seconds: float = typer.Option(120.0, min=0.1, max=3600.0, help="Per-engine timeout."),  # noqa: B008
    fail_on: str = typer.Option(
        "never",
        "--fail-on",
        help=("Exit 1 at this severity: critical, high, medium, low, info, or never."),
    ),  # noqa: B008
    allow_network_audits: bool = typer.Option(
        False,
        "--allow-network-audits",
        help="Allow pip-audit/npm audit to send dependency metadata to advisory services.",
    ),  # noqa: B008
) -> None:
    """Assess a local code project with the selected local scanners."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if fail_on != "never" and fail_on not in severity_order:
        raise typer.BadParameter("--fail-on must be critical, high, medium, low, info, or never")
    selected = scanner_names or ["builtin"]
    known = {"builtin", "semgrep", "gitleaks", "trivy", "pip-audit", "npm-audit"}
    unknown = sorted(set(selected) - known)
    if unknown:
        raise typer.BadParameter(f"unknown scanner(s): {', '.join(unknown)}")
    if len(set(selected)) != len(selected):
        raise typer.BadParameter("scanner names must be unique")
    if "semgrep" in selected and (semgrep_rules is None or not semgrep_rules.is_file()):
        raise typer.BadParameter("--scanner semgrep requires a readable local --semgrep-rules file")
    if {"pip-audit", "npm-audit"}.intersection(selected) and not allow_network_audits:
        raise typer.BadParameter(
            "pip-audit and npm-audit require explicit --allow-network-audits consent"
        )

    scanners: list[FindingScanner] = []
    for name in selected:
        if name == "builtin":
            scanners.append(BuiltinRuleScanner())
        elif name == "semgrep":
            scanners.append(
                SemgrepScanner(config_path=semgrep_rules, timeout_seconds=timeout_seconds)
            )
        elif name == "gitleaks":
            scanners.append(GitleaksScanner(timeout_seconds))
        elif name == "trivy":
            scanners.append(TrivyScanner(timeout_seconds))
        elif name == "pip-audit":
            scanners.append(PipAuditScanner(timeout_seconds))
        else:
            scanners.append(NpmAuditScanner(timeout_seconds))
    repository = SQLiteRepository(_settings().database_path)
    try:
        result = CodeScanService(scanners, repository).scan(target)
    except ScannerError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repository.close()

    summary = result.summary()
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(f"Scan {result.scan_id}: {len(result.findings)} candidate finding(s)")
        typer.echo(f"Target: {result.target}")
        typer.echo("Project types: " + (", ".join(result.project_types) or "unknown"))
        for severity in ("critical", "high", "medium", "low", "info"):
            count = sum(finding.severity.value == severity for finding in result.findings)
            if count:
                typer.echo(f"{severity.upper()}: {count}")
    if result.failures:
        typer.echo("Scanner failures: " + ", ".join(sorted(result.failures)), err=True)
        raise typer.Exit(code=1)
    if fail_on != "never":
        threshold = severity_order[fail_on]
        failing_findings = [
            finding
            for finding in result.findings
            if severity_order[finding.severity.value] >= threshold
        ]
        if failing_findings:
            typer.echo(
                f"Failing threshold {fail_on}: {len(failing_findings)} candidate finding(s).",
                err=True,
            )
            raise typer.Exit(code=1)


def not_implemented(phase: int, command: str) -> None:
    typer.echo(f"{command} is planned for Phase {phase} and is not implemented.", err=True)
    raise typer.Exit(code=2)


report_formats = ("json", "markdown", "html", "csv", "sarif")


def report(
    scan_id: str = typer.Argument(..., help="Persisted scan ID."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "json", "--format", help="json, markdown, html, csv, or sarif."
    ),  # noqa: B008
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", help="Write to this path instead of stdout."
    ),  # noqa: B008
) -> None:
    if output_format not in report_formats:
        raise typer.BadParameter("must be json, markdown, html, csv, or sarif")
    repository = SQLiteRepository(_settings().database_path)
    try:
        scan, findings = scan_data(repository, scan_id)
        content = render_report(scan, findings, output_format)
    except ReportingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    if output is None:
        typer.echo(content, nl=False)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="")
        typer.echo(f"Wrote {output_format} report: {output}")


def compare_scans(
    baseline_scan_id: str = typer.Argument(..., help="Earlier scan ID."),  # noqa: B008
    current_scan_id: str = typer.Argument(..., help="Later scan ID."),  # noqa: B008
) -> None:
    repository = SQLiteRepository(_settings().database_path)
    try:
        _, baseline = scan_data(repository, baseline_scan_id)
        _, current = scan_data(repository, current_scan_id)
    except ReportingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    before = {item.fingerprint: item for item in baseline}
    after = {item.fingerprint: item for item in current}
    result = {
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "added": sorted(after.keys() - before.keys()),
        "resolved": sorted(before.keys() - after.keys()),
        "unchanged": sorted(before.keys() & after.keys()),
    }
    typer.echo(json.dumps(result, sort_keys=True, indent=2))


def scan_trends(
    days: int = typer.Option(30, min=1, max=366, help="History window in days."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Summarize local scan, finding, and alert counts by day."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    repository = SQLiteRepository(_settings().database_path)
    try:
        summary = scan_history_trends(
            repository.list_records("scan"),
            repository.list_records("finding"),
            repository.list_records("alert"),
            days=days,
        )
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(summary, sort_keys=True))
        return
    typer.echo(
        f"Scan trends ({summary['start_date']} through {summary['end_date']}): "
        f"{summary['total_scans']} scan(s)"
    )
    typer.echo("Date       Scans  Findings  Alerts")
    for item in summary["daily"]:
        typer.echo(
            f"{item['date']}  {item['scans']:>5}  {item['findings']:>8}  {item['alerts']:>6}"
        )


def logs_ingest(
    target: Path = typer.Argument(..., help="Local log file, directory, or supported archive."),  # noqa: B008
    rules: Path | None = typer.Option(  # noqa: B008
        None, "--rules", help="Local directory or file of Sigma YAML rules."
    ),  # noqa: B008
    ioc_file: Path | None = typer.Option(  # noqa: B008
        None, "--ioc-file", help="Local JSON, CSV, or text IOC list."
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Analyze local exported logs without executing or uploading their contents."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    if rules is not None and not rules.exists():
        raise typer.BadParameter("--rules path does not exist")
    if ioc_file is not None and not ioc_file.is_file():
        raise typer.BadParameter("--ioc-file must be a local file")
    repository = SQLiteRepository(_settings().database_path)
    try:
        result = LogAnalysisService(repository).analyze(target, rules_path=rules, ioc_path=ioc_file)
    except LogIngestionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    summary = result.summary()
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(f"Log scan {result.scan_id}: {result.events} normalized event(s)")
        typer.echo(f"Sources: {result.source_count}; alerts: {len(result.alerts)}")
        for severity in ("critical", "high", "medium", "low", "info"):
            count = sum(alert.severity.value == severity for alert in result.alerts)
            if count:
                typer.echo(f"{severity.upper()}: {count}")
        if result.errors:
            typer.echo(f"Parser or rule warnings: {len(result.errors)}", err=True)
    if result.errors:
        raise typer.Exit(code=1)


def malware_analyze(
    sample: Path = typer.Argument(..., help="Local file for bounded static analysis."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
    yara_rules: Path | None = typer.Option(  # noqa: B008
        None, "--yara-rules", help="Explicit local YARA rules file; requires yara on PATH."
    ),  # noqa: B008
    clamav: bool = typer.Option(False, "--clamav", help="Opt in to local clamscan analysis."),  # noqa: B008
    include_indicators: bool = typer.Option(
        False, "--include-indicators", help="Include extracted indicator values in output."
    ),  # noqa: B008
) -> None:
    """Inspect one local file without executing, copying, or persisting sample bytes."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    try:
        result = analyze_file(sample)
    except AnalysisError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    engines: list[EngineResult] = []
    if yara_rules is not None:
        engines.append(run_yara(Path(result.sample_path), yara_rules))
    if clamav:
        engines.append(run_clamav(Path(result.sample_path)))
    summary = result.summary(include_indicators=include_indicators)
    summary["engines"] = [
        {"engine": engine.engine, "matches": list(engine.matches), "warning": engine.warning}
        for engine in engines
    ]
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo("Static file analysis complete; sample was not executed or retained.")
        typer.echo(f"Type: {result.file_type}; size: {result.size_bytes} bytes")
        typer.echo(f"SHA-256: {result.sha256}")
        typer.echo(f"Candidate indicators: {result.indicator_count}")
        for engine in engines:
            typer.echo(f"{engine.engine}: {len(engine.matches)} match(es)")
            if engine.warning:
                typer.echo(f"{engine.engine} warning: {engine.warning}", err=True)
    if any(engine.warning for engine in engines):
        raise typer.Exit(code=1)


def domain_assess(
    target: str = typer.Argument(..., help="Fully qualified hostname to assess."),  # noqa: B008
    profile: str = typer.Option("light", "--profile", help="Assessment profile: light or deep."),  # noqa: B008
    operator: str | None = typer.Option(
        None, "--operator", help="Operator name for ownership assertion."
    ),  # noqa: B008
    i_own_this_target: bool = typer.Option(
        False, "--i-own-this-target", help="Explicitly assert that you own this exact hostname."
    ),
    authorization_file: Path | None = typer.Option(  # noqa: B008
        None, "--authorization-file", help="Local JSON authorization for this exact hostname."
    ),  # noqa: B008
    timeout_seconds: float = typer.Option(
        3.0, "--timeout", help="DNS/connect timeout in seconds (0.1 to 10)."
    ),  # noqa: B008
    max_addresses: int = typer.Option(
        5, "--max-addresses", help="Deep-profile public address limit (1 to 5)."
    ),  # noqa: B008
    request_interval_seconds: float = typer.Option(
        0.0, "--request-interval", help="Minimum seconds between requests (0 to 5)."
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Assess one hostname only after explicit, auditable authorization."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    try:
        grant = authorize_target(
            target,
            profile=profile,
            operator=operator,
            assert_ownership=i_own_this_target,
            authorization_file=authorization_file,
        )
    except AuthorizationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    try:
        probe_settings = ProbeSettings(
            timeout_seconds=timeout_seconds,
            max_addresses=max_addresses,
            request_interval_seconds=request_interval_seconds,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    scan_options: dict[str, str | int | float | bool] = probe_settings.as_dict()
    repository = SQLiteRepository(_settings().database_path)
    try:
        result = DomainAssessmentService(
            repository,
            NetworkDomainProbe(probe_settings),
            scan_options=scan_options,
        ).assess(grant)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(result.summary(), ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(f"Domain assessment {result.scan_id}: {result.target} ({result.status})")
        typer.echo(f"Authorization record: {result.authorization_id}; profile: {result.profile}")
        typer.echo(f"Resolved public addresses: {len(result.probe.addresses)}")
        typer.echo(f"HTTP status: {result.probe.http_status or 'unavailable'}")
        typer.echo(f"Candidate findings: {len(result.findings)}")
        for error in result.probe.errors:
            typer.echo(error, err=True)
    if result.status != "complete":
        raise typer.Exit(code=1)


case_app = typer.Typer(help="Create and manage investigation cases.")
case_note_app = typer.Typer(help="Add and review append-only analyst notes.")
case_app.add_typer(case_note_app, name="note")

db_app = typer.Typer(help="Create, verify, and restore local SQLite backups.")


def _recovery_error(exc: RecoveryError) -> None:
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=exc.exit_code) from exc


@db_app.command("backup")
def database_backup(
    output: Path = typer.Option(..., "--output", help="New backup bundle directory."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    settings = _settings()
    try:
        result = backup_database(
            settings.database_path,
            output,
        )
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(
            json.dumps(
                {
                    "backup_id": result.backup_id,
                    "backup_directory": str(result.backup_directory),
                    "verification": result.verification.as_dict(),
                },
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"Created backup {result.backup_id}: {result.backup_directory}")
        typer.echo(
            "Verification: "
            + ("passed" if result.verification.verified else "application consistency issues")
        )
    if not result.verification.verified:
        raise typer.Exit(code=1)


@db_app.command("verify-backup")
def database_verify_backup(
    backup_directory: Path = typer.Argument(..., help="Backup bundle directory."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    try:
        result = verify_backup(backup_directory)
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(json.dumps(result.as_dict(), sort_keys=True))
    else:
        state = "verified" if result.verified else "verification incomplete"
        typer.echo(f"Backup {result.backup_id or 'unknown'}: {state}")
        if result.structural_errors:
            typer.echo(f"Structural errors: {', '.join(result.structural_errors)}", err=True)
        if result.unsupported_schema:
            typer.echo(f"Unsupported schema: {result.unsupported_schema}", err=True)
        if result.application_issues:
            typer.echo(
                f"Application consistency issues: {', '.join(result.application_issues)}", err=True
            )
    if not result.verified:
        raise typer.Exit(
            code=(
                1
                if result.application_issues
                and not result.structural_errors
                and result.unsupported_schema is None
                else 2
            )
        )


@db_app.command("restore")
def database_restore(
    backup_directory: Path = typer.Argument(..., help="Verified backup bundle directory."),  # noqa: B008
    output: Path = typer.Option(..., "--output", help="New SQLite database path; must not exist."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    settings = _settings()
    try:
        result = restore_backup(
            backup_directory,
            output,
            active_database_path=settings.database_path,
        )
    except RecoveryError as exc:
        _recovery_error(exc)
    payload = {
        "backup_id": result.backup_id,
        "destination": str(result.destination),
        "original_revision": result.original_revision,
        "resulting_revision": result.resulting_revision,
    }
    if output_format == "json":
        typer.echo(json.dumps(payload, sort_keys=True))
    else:
        typer.echo(
            f"Restored backup {result.backup_id} to new database {result.destination} "
            f"(schema {result.original_revision or 'unversioned'} -> "
            f"{result.resulting_revision or 'unversioned'})."
        )


@db_app.command("retention-plan")
def database_retention_plan(
    directory: Path = typer.Option(  # noqa: B008
        ..., "--directory", help="Explicit managed backup directory."
    ),  # noqa: B008
    keep_last: int = typer.Option(5, min=1, help="Retain up to this many newest verified bundles."),  # noqa: B008
    max_age_days: int = typer.Option(
        90, min=1, help="Retain bundles no older than this many days."
    ),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    try:
        plan = plan_retention(directory, keep_last=keep_last, max_age_days=max_age_days)
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(json.dumps(plan.as_dict(), sort_keys=True, indent=2))
    else:
        typer.echo(
            f"Preview only: {len(plan.entries)} entries; keep last {keep_last}, "
            f"maximum age {max_age_days} days. No files were deleted."
        )
        for entry in plan.entries:
            typer.echo(f"{entry.disposition.upper():8} {entry.name}: {entry.reason}")


def _case_repository() -> SQLiteRepository:
    try:
        return SQLiteRepository(_settings().database_path)
    except (StorageError, SQLAlchemyError, OSError) as exc:
        typer.echo("Case storage could not be opened.", err=True)
        raise typer.Exit(code=1) from exc


def _case_storage_error(exc: Exception) -> None:
    typer.echo("Case storage operation failed; no partial case update was saved.", err=True)
    raise typer.Exit(code=1) from exc


def _case_workflow_error(exc: CaseWorkflowError) -> None:
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=exc.exit_code) from exc


def _case_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        typer.echo(str(redact(warning)), err=True)


@case_app.command("create")
def case_create(
    scan_id: str = typer.Option(..., "--from-scan", help="Attach a persisted scan."),  # noqa: B008
    title: str | None = typer.Option(None, "--title", help="Case title; defaults to scan ID."),  # noqa: B008
    description: str = typer.Option("", "--description", help="Case description."),  # noqa: B008
    severity: Severity = typer.Option(Severity.MEDIUM, "--severity", help="Case severity."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        case, warnings = CaseWorkflow(repository).create_from_scan(
            scan_id, title=title, description=description, severity=severity.value
        )
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(f"Created case {case.case_id} ({case.status.value})")
    _case_warnings(warnings)


@case_app.command("show")
def case_show(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("json", "--format", help="Output format: json or human."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        workflow = CaseWorkflow(repository)
        case = workflow.get_case(case_id)
        context = workflow.context(case)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(redact(case.model_dump(mode="json")), sort_keys=True, indent=2))
    else:
        typer.echo(f"Case {case.case_id}: {redact(case.title)}")
        typer.echo(f"Status: {case.status.value}; severity: {case.severity.value}")
        typer.echo(f"Linked records: {len(context.links)}; notes: {len(case.notes)}")
        if case.description:
            typer.echo(str(redact(case.description)))
    _case_warnings(context.warnings)


@case_app.command("update")
def case_update(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    status: CaseStatus = typer.Option(  # noqa: B008
        ..., "--status", help="open, in_progress, resolved, or closed."
    ),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        case, changed = CaseWorkflow(repository).update_status(case_id, status)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    verb = "Updated" if changed else "Already at"
    typer.echo(f"{verb} case {case.case_id}: {case.status.value}")


@case_app.command("link")
def case_link(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    record_type: str = typer.Option(..., "--type", help="Persisted record type."),  # noqa: B008
    record_id: str = typer.Option(..., "--id", help="Persisted record ID."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        _, added, warnings = CaseWorkflow(repository).link_record(case_id, record_type, record_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(("Linked" if added else "Already linked") + f" {record_type} {record_id}.")
    _case_warnings(warnings)


@case_note_app.command("add")
def case_note_add(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    text: str = typer.Option(..., "--text", help="Analyst note text; maximum 8000 characters."),  # noqa: B008
    author: str | None = typer.Option(None, "--author", help="Unverified local author label."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        note = CaseWorkflow(repository).add_note(case_id, text, author)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(f"Added note {note.note_id} to case {case_id}.")


@case_note_app.command("list")
def case_note_list(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("json", "--format", help="Output format: json or human."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        case = CaseWorkflow(repository).get_case(case_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    notes = redact([note.model_dump(mode="json") for note in case.notes])
    if output_format == "json":
        typer.echo(json.dumps(notes, sort_keys=True, indent=2))
    else:
        for note in notes:
            label = (
                f" — {note['author_label']} (unverified local label)"
                if note.get("author_label")
                else ""
            )
            typer.echo(f"{note['created_at']}{label}: {note['body']}")


@case_app.command("timeline")
def case_timeline(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        _, items, warnings = CaseWorkflow(repository).timeline(case_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(
            json.dumps(
                redact([item.model_dump(mode="json") for item in items]), sort_keys=True, indent=2
            )
        )
    else:
        for item in items:
            timestamp = item.event_occurred_at or item.case_activity_at
            shown_time = timestamp.isoformat() if timestamp else "time unavailable"
            typer.echo(f"{shown_time} [{item.category}] {redact(item.description)}")
    _case_warnings(warnings)


@case_app.command("export")
def case_export(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option(
        "json", "--format", help="Output format: json, markdown, or html."
    ),  # noqa: B008
    output: Path | None = typer.Option(None, "--output", help="Write atomically to this path."),  # noqa: B008
) -> None:
    if output_format not in {"json", "markdown", "html"}:
        raise typer.BadParameter("must be json, markdown, or html")
    if output is not None and (output.exists() or output.is_symlink()):
        typer.echo("Case report destination already exists.", err=True)
        raise typer.Exit(code=2)
    repository = _case_repository()
    try:
        content = render_case_report(repository, case_id, output_format)
    except (CaseWorkflowError, ReportingError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output is None:
        typer.echo(content, nl=False)
        return
    temporary: Path | None = None
    published = False
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, output)
        published = True
        temporary.unlink()
    except OSError as exc:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        if published:
            with suppress(OSError):
                output.unlink(missing_ok=True)
        typer.echo("Case report could not be published safely.", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Wrote {output_format} case report: {output}")
