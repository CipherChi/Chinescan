# Architecture

The Typer CLI sits above validated Pydantic records, configuration and logging utilities, scanner adapters, orchestration, and persistence. The built-in code scanner reads local source files without executing them. Semgrep, Gitleaks, and Trivy adapters run as bounded subprocesses, without a shell, and normalize only finding metadata. Semgrep requires local rules and has metrics disabled; Trivy skips vulnerability, Java, and check database updates and runs offline. `pip-audit` and npm audit require the explicit `--allow-network-audits` CLI option because they send package metadata to advisory services.

The SQLite repository provides local persistence behind the `Repository` protocol. Its initial table stores typed record payloads as JSON with a record type and ID. Alembic owns schema evolution. Settings accept `CHINESCAN_` environment overrides and default the database under the user's data directory.

The CLI implements configuration, version, `code`, `logs`, `malware analyze`, `domain`, reports, cases, scan comparison, and explicit `web bootstrap`/`web serve` commands. Memory-image triage and sandbox detonation remain exit-2 stubs. Domain assessment validates an explicit ownership assertion or exact-host authorization file, persists the grant and running scan before network activity, resolves only public addresses, and issues bounded TLS/HTTP `HEAD` requests without redirects or body reads. DNS/connect timeouts, the deep-profile address cap, and sequential request spacing are configurable and saved on the scan. Broad scanner adapters, port scans, and subdomain enumeration are deferred. Reports read a stored scan and its normalized findings and render JSON, Markdown, HTML, CSV, or SARIF 2.1.0. Cases retain scan and finding IDs and support open, in-progress, resolved, and closed statuses. Comparison uses stable finding fingerprints. Log analysis reads local exports and compressed archives without extraction, stores normalized event/alert/timeline/IOC records in SQLite, and performs built-in detection, safe-subset Sigma evaluation, and local IOC matching.

The authenticated dashboard reuses the SQLite repository for overview, scans, findings, cases,
reports, and code-assessment jobs. FastAPI route schemas are explicit Pydantic models; finding and
job payloads are reduced to reviewed allowlists before serialization. Jobs resolve operator-owned
project IDs through a local TOML registry and run the existing built-in scanner in one bounded
worker with a four-entry queue. Opaque HttpOnly sessions and CSRF state are process-local; the
explicit server command binds to `127.0.0.1`, uses one worker, and disables forwarded-proxy trust.
React/Vite uses same-origin `/api` requests, with a loopback-only development proxy and production
static build. Filesystem validation does not eliminate time-of-check/time-of-use races.

All canonical records carry `schema_version` (currently `1.0`). Code finding fingerprints derive from normalized target, category, rule identifier, and source location; the contract is documented in [Deduplication](DEDUPLICATION.md). Finding records retain rule identifiers and locations but omit source snippets and matched secret values.

The built-in ruleset is intentionally small and heuristic. External engine availability and advisory database freshness vary by host; scanner failures are isolated and listed in the scan result. A failed scanner does not discard findings from successful scanners.

Log parsing supports JSON, JSONL, CSV, Linux auth/syslog, common nginx/Apache access logs, CEF,
LEEF, gzip, ZIP, and tar exports. Windows and cloud logs are accepted as exported JSON/CSV rather
than native EVTX or live APIs. The built-in detections and implemented Sigma selector/condition
subset are candidate logic, not a complete Sigma engine. Raw log lines are not persisted; event
records retain normalized values and source file/line references.

Malware static triage is an ephemeral local service that reads a single bounded regular file,
calculates hashes, identifies common signatures, counts but does not emit printable strings,
lists limited ZIP metadata without extraction, and extracts capped candidate IOCs. YARA and ClamAV are explicit local subprocess integrations;
their output and runtime are bounded. Sample bytes and analysis records are not persisted. This
does not implement sample intake/storage, a malware repository, memory analysis, or detonation.

Finding evidence grade is independent of confidence. Scan verdicts use `leads_found`,
`no_matches_with_gaps`, `no_matches_in_scope`, and `scan_failed`. Code scans auto-save JSON and
Markdown reports under the configured reports directory. The new indicator scanner reads local
indicator files and project files without network access; this constraint does not apply to the
existing authorized `domain_assessment/probe.py`.
