# Phase 3 plan: reporting and case management

## Scope

Render persisted scan results as JSON, Markdown, HTML, CSV, and SARIF 2.1.0; create and update
investigation cases; and compare scans by normalized finding fingerprint. Reports and cases operate
only on locally persisted metadata. The generic `scan` command remains an explicit usage-error stub.

## Security and data decisions

- Report output uses normalized finding fields; it never adds source snippets or matched secret values.
- Shared redaction is applied before serialization. HTML text is escaped and CSV uses the standard
  quoting writer. SARIF output follows version 2.1.0 and does not include source snippets.
- Report destination paths are explicitly supplied by the caller. SQLite remains local and has no
  network listener.
- Cases retain scan and finding IDs and timestamps. Status transitions are limited to `open`,
  `in_progress`, `resolved`, and `closed`; the application does not assert analyst conclusions.
- Scan comparison uses the stable finding fingerprint and reports added, resolved, and unchanged
  fingerprints.

## Acceptance

Use Python 3.12, Ruff, strict mypy, pytest with core coverage, pip-audit, JSON schema validation,
fixture code scans, report-format checks, and the container build. Record exact commands, output,
exit status, and environmental limits in `docs/reports/phase-3-report.md`.
