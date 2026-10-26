# ChineScan development status audit

Audit date: 2026-10-26
Repository: `C:\src\Chinescan`
Scope: initial read-only audit of the combined working tree, followed by local workflow
hardening implementation and verification on 2026-10-26.

Sections A–I preserve the baseline audit findings and recommendations. Section J records
the changes that supersede the local-workflow findings in that baseline.

## A. Executive summary

ChineScan is a **partially integrated local CLI application**, not yet the intended
self-hosted platform or a release candidate. It has exercised local vertical slices for
heuristic code assessment, SQLite persistence, reports and simple cases, exported-log
analysis, static file triage, trends, and an explicitly authorized low-impact domain
posture probe. The current test suite passes. External scanner execution and live domain
assessment were not exercised in this audit.

It can be used as a local analyst tool with important limits: built-in code rules are a
small heuristic set; log detection is a subset; domain checking is a few HTTP/TLS posture
checks rather than vulnerability scanning; and malware analysis is ephemeral metadata
triage rather than intake or quarantine. `scan`, malware memory, and detonation are
explicit exit-code-2 stubs. There is no API or dashboard. The repository instructions
prohibit a network listener, so that product area remains deferred until the instruction
changes.

The largest core gaps are the absent API/dashboard and access-control layer, limited
investigation workflows, external integrations verified only with mocked adapter tests,
no runtime migration/upgrade lifecycle, and resource bounds that need tightening in
untrusted archive and subprocess-output handling. CI configuration exists but was not
run by a remote CI service in this audit. Docker image rebuild was not attempted because
it may fetch from a registry; existing-image help was run offline.

The checkout was already substantially modified before this audit: `main` was one commit
behind `origin/main`, with tracked edits and numerous untracked Phase 2–8 modules, tests,
reports, and fixtures. Those changes were treated as user-owned and were not reset or
reverted. Findings below describe that combined worktree, not just committed code.

## B. Capability audit

| Area | Capability | Status | Evidence | Verification | Remaining work |
|---|---|---|---|---|---|
| Foundation | Installable package and CLI | VERIFIED WORKING | `pyproject.toml`; `chinescan/cli/app.py`; `chinescan/cli/commands.py` | Current `--help`, `version`, and full pytest suite passed | Keep CLI contracts and packaging checks in CI. |
| Foundation | Configuration and structured logging | PARTIAL | `chinescan/core/config/{settings,io}.py`; `chinescan/core/logging/{structured,redaction}.py` | Unit tests pass; config commands exercised by tests | Commands generally construct `Settings` from environment/defaults; no shared CLI config-file loading path. Log-level validation is a plain string. |
| Foundation | Canonical records and scanner/analyzer interfaces | PARTIAL | `chinescan/core/models/{common,finding,investigation}.py`; `chinescan/core/orchestration/protocols.py` | Model/schema tests pass | Records exist, but several are not used in workflows; `Analyzer` is an interface only. |
| Foundation | Orchestration, limits, timeout, cancellation | PARTIAL | `chinescan/core/orchestration/code_scan.py`; scanner adapters; `domain_assessment/probe.py` | Offline tests pass | Code scans isolate errors and cap workers; adapters have timeouts. No general cancellation API. External process output is not capped. |
| Foundation | SQLite persistence and migrations | PARTIAL | `chinescan/core/storage/sqlite.py`; `migrations/versions/0001_initial.py`; `tests/unit/test_migration.py` | SQLite and migration unit tests pass | Runtime repository calls `metadata.create_all`; no application migration/upgrade command or versioned upgrade lifecycle. |
| Foundation | Docker/Compose | IMPLEMENTED, NOT VERIFIED (build) | `docker/Dockerfile`; `docker-compose.yml` | Compose validation and existing local image `--help` passed | Rebuild was not run in this audit; CI's remote image build was not observed. Compose is a one-shot CLI runner, not a service. |
| Foundation | Docs, tests, lint, types, CI | PARTIAL | `docs/`; `tests/`; `.github/workflows/ci.yml`; `.gitlab-ci.yml` | 70 tests, Ruff, format, strict mypy, pip-audit, lock check passed locally | Remote CI not run. Documentation describes manual operations; automated health/readiness is absent. |
| Code | Project/language detection and local default | VERIFIED WORKING (limited) | `core/orchestration/code_scan.py:detect_project`, `BuiltinRuleScanner` | Fixture tests and full suite passed | Only selected extensions/manifests and four simple patterns; this is not full language/security coverage. |
| Code | Semgrep, Gitleaks, Trivy | IMPLEMENTED, NOT VERIFIED | `chinescan/scanners/external.py:SemgrepScanner`, `GitleaksScanner`, `TrivyScanner` | Adapter output/error tests are mocked; no real adapter binary run in this audit | Validate tool versions, actual JSON compatibility, and network behavior in isolated integration jobs. Semgrep requires local rules; Trivy uses local cache. |
| Code | Python/Node dependency audits | IMPLEMENTED, NOT VERIFIED (target workflow) | `external.py:PipAuditScanner`, `NpmAuditScanner`; `commands.py:code_scan` | Consent/adapter tests pass; pip-audit here audited the installed project dependency environment, not a target fixture | Verify real target-manifest flows. Explicit consent sends dependency metadata to advisory services. |
| Code | Normalization, severity, dedup, persistence | VERIFIED WORKING | `core/orchestration/code_scan.py:make_finding`, `deduplicate_findings`, `CodeScanService` | Fixture and repository tests pass | Improve heuristic coverage and add tested external-tool integration. |
| Domain | Explicit authorization and scope record | VERIFIED WORKING (offline) | `domain_assessment/authorization.py`; `domain_assessment/service.py`; `AuthorizationRecord` | Tests validate exact host, profile, grant window, no-probe rejection, and persist-before-probe | Ownership assertion is operator-supplied; process remains a local CLI trust boundary. |
| Domain | Built-in HTTP/TLS posture probe | IMPLEMENTED, NOT VERIFIED live | `domain_assessment/probe.py:NetworkDomainProbe` | Mocked probe tests cover address filtering, request counts and bounded headers; no live host contacted | No live verification in this audit. Narrowly checks headers/certificate; no ports, subdomains, testssl, or vulnerability templates. |
| Domain | subfinder/dnsx/httpx/nmap/testssl/Nuclei | MISSING | No such adapters found; `docs/reports/phase-6-report.md` records broader adapters deferred | Not applicable | Add only after scope and traffic policy review. |
| Logs | File/directory and archive ingestion | PARTIAL | `log_analysis/ingest.py:ingest_path`, `_ingest_zip`, `_ingest_tar` | Fixtures and traversal-safe no-extraction tests pass | Global decompression budget is checked after each member has already been decompressed; tighten it before hostile inputs. |
| Logs | JSON/JSONL/CSV, common OS/web logs, CEF/LEEF | VERIFIED WORKING (supported subset) | `log_analysis/parsers.py:parse_log_data` and format parsers | Fixture tests pass; sample fixture CLI result documented in Phase 4 report | Windows/cloud inputs are exported records, not native collectors; unsupported formats need explicit diagnostics. |
| Logs | Normalized events, timeline, Sigma, IOC, alerts | PARTIAL | `log_analysis/{normalization,detections,ioc_matching,service}.py` | Unit tests cover sample parsing, correlations, limits, persistence | Sigma evaluator supports a constrained subset; mappings/rules are small heuristic candidates, not comprehensive detections. |
| Malware | Safe intake/quarantine/access/audit | MISSING | No intake/storage module; `docs/reports/phase-5-report.md` | Not applicable | Do not claim samples are quarantined or access-controlled. |
| Malware | Hashing, type, strings count, metadata, IOC extraction | VERIFIED WORKING (ephemeral) | `malware_analysis/analyzer.py:analyze_file` | Synthetic file tests pass; no sample execution | Limited signature/metadata heuristics; results are not persisted. |
| Malware | YARA/ClamAV | IMPLEMENTED, NOT VERIFIED with real binaries | `malware_analysis/engines.py:run_yara`, `run_clamav` | Mocked binary/output/timeout tests pass | Install/configure engines separately and verify controlled fixtures in an isolated environment. |
| Malware | PE/ELF/Office/PDF/archive parser-grade triage | PARTIAL | `analyzer.py:_identify`, ZIP listing | Synthetic PE/ELF and ZIP tests pass | Signatures and markers are shallow; no rich parsers, recursive archive scanning, or memory analysis. |
| Malware | Volatility/sandbox/external enrichment | DEFERRED / OPTIONAL | `cli/app.py` memory/detonate stubs; Phase 5 report | Stub exit codes verified in existing tests | Still explicit stubs; no sample execution, upload, or enrichment. |
| Reports | JSON/Markdown/HTML/CSV/SARIF and redaction | VERIFIED WORKING for scan findings | `core/reporting.py:render_report` | Rendering, HTML escape, CSV formula handling, and redaction tests pass | Report covers scans/findings, not complete cross-source cases/timelines/evidence. |
| Investigations | Scan history and comparison | VERIFIED WORKING (basic) | `commands.py:compare_scans`, `core/trends.py` | CLI/service tests and `trends` smoke passed | Comparison is fingerprint-set comparison; trends count stored records only. |
| Investigations | Cases, notes, evidence, cross-source correlation | PARTIAL | `commands.py:case_create/show/update`; `Case` model | Case create/show/status and scan comparison tests pass | No analyst notes, evidence links, case event/alert/artifact relationships, or cross-source case correlation. |
| API/UI | Backend API, contracts, dashboard, auth/session/CSRF | MISSING / DEFERRED by repository policy | No API/frontend files; `docs/plans/phase-7.md` | Not run | A network listener is prohibited by `AGENTS.md`; policy change is a prerequisite. |
| Operations | CI thresholds and dependency management | PARTIAL | `.github/workflows/ci.yml`; `pyproject.toml`; `uv.lock` | Lock and dependency audit passed locally | CI only executes after a remote event; not verified here. |
| Operations | Health/readiness, automated backup/retention/upgrade | MISSING (manual guidance exists) | `docs/DEPLOYMENT.md`; `SQLiteRepository`; migration files | Docs inspected; no runtime checks exist | Add migration lifecycle, health checks, retention controls and tested backup/restore automation. |

## C. Completed work

### Verified in this audit

- Python 3.12.10 CLI help/version and the documented Phase 3 `scan` exit-code-2 stub.
- Full fixture/unit suite: 70 passed, 82.27% package coverage.
- Ruff lint and formatting, strict mypy, locked dependency resolution, pip-audit,
  schema JSON parsing, and Docker Compose configuration.
- Existing local image's `--help` command with `--network none`.
- The tests exercise SQLite repository behavior and initial Alembic migration, code
  normalization/deduplication, reports and cases, log ingestion/correlation, static
  malware triage, and mocked domain probe safety.

### Substantial implementation present, but live/external execution not verified

- External code scanner adapters and optional YARA/ClamAV process wrappers.
- Built-in domain DNS/HTTP/TLS probe. Tests mock network calls; this audit intentionally
  contacted no production or external target.
- Python/Node advisory integrations. Explicit consent is required because metadata leaves
  the local machine.

## D. Partial, mocked, and disconnected work

- **API and dashboard:** the workflow stops at the CLI. No backend routes, OpenAPI
  contract, frontend, authentication, session, pagination, or evidence access controls
  exist. The Phase 7 plan explicitly pauses this work because the repository prohibits a
  listener.
- **Code scanning:** the built-in scanner is a few line-based heuristics. External adapters
  launch and parse tools, but tests replace executable discovery/process results; successful
  real Semgrep/Gitleaks/Trivy runs are not established by this audit. Advisory scanners
  require explicit consent and contact upstream services.
- **Domain scanning:** authorization and persistence lead to one small built-in posture
  probe. The original named scanners and broad domain assessment workflow are absent.
  Live DNS/TLS/HTTP behavior was not verified.
- **Log analysis:** fixture inputs pass through parsing, normalization, detections, IOC
  matching, event/alert/timeline persistence. The detection set and Sigma semantics are
  intentionally constrained; this is not broad enterprise log coverage. Decompression
  limits need a global budget applied before each read.
- **Malware:** the static analyzer reads a user-selected file in memory and returns
  metadata. It does not create a quarantine, retain sample bytes, or persist results.
  YARA/ClamAV result tests are mocked; actual engine binaries were not verified.
- **Cases/reports:** report formats operate on stored scan findings. Cases attach scan and
  finding IDs and allow status changes; they do not implement notes, evidence handling, or
  cross-source investigation.
- **Persistence:** repository startup creates tables directly. Although an initial Alembic
  migration exists and is tested, there is no normal application migration or upgrade
  command.
- **Docs versus implementation:** current README and roadmap are comparatively clear about
  the lack of a web service, broad scanners and malware intake. Earlier phase reports record
  historical results; this audit's fresh results are appended to the Phase 1 report.

## E. Missing work by area

- **Foundation:** config-file consumption across commands; constrained configuration
  values; general cancellation; runtime Alembic upgrade lifecycle; stronger storage
  lifecycle and error behavior.
- **Code scanning:** broad language-aware analysis; validated live integrations; output
  bounds around third-party process capture; richer finding evidence/remediation and
  target-manifest integration checks.
- **Domain scanning:** the named recon/TLS/vulnerability scanner integrations, beyond the
  current narrow posture probe.
- **Log analysis:** broad vendor coverage and complete Sigma semantics; a pre-decompression
  global expansion budget; broader correlation quality.
- **Malware analysis:** intake/quarantine, controlled retention and access/audit; parser-grade
  document/binary analysis; memory and optional isolated sandbox integrations.
- **Reporting/cases:** notes, evidence references, richer export of events/alerts/timelines,
  and traceable cross-source correlation.
- **API/dashboard:** all backend/frontend features, authentication and access control;
  blocked by the no-listener repository rule until it changes.
- **Testing/deployment:** real external adapter integration validation; remote CI evidence;
  health/readiness, runtime migrations, automated backup/restore/retention and deployment
  lifecycle.

## F. Security and reliability gaps

Confirmed from code:

- `log_analysis/ingest.py` limits each archive and checks `MAX_TOTAL_BYTES` in
  `_parse_member`, but archive members are fully read/decompressed before that aggregate
  check. Multiple compressed inputs can therefore consume substantially more decompression
  work than the nominal global expanded-byte limit suggests. Treat this as a resource-limit
  defect for untrusted log bundles.
- `scanners/external.py:_JsonTool._run` uses `subprocess.run(capture_output=True)` with a
  timeout but no stdout/stderr size cap. A noisy or malfunctioning scanner can use
  unbounded memory before timeout. In contrast, `malware_analysis/engines.py` has an
  explicit merged output cap.
- There is no authentication or evidence access control because there is no API; the local
  CLI and database rely on operating-system account boundaries. The database is not
  encrypted, as `docs/DEPLOYMENT.md` states.
- Existing Trivy report records in `docs/reports/security-review.md` include high OS
  findings without available fixes and a review date. They are recorded as accepted in
  that worktree report, not independently rescanned in this audit.

Not established as defects by this audit:

- No live target was contacted, so real DNS/TLS/network behavior remains unverified.
- No sample was executed. Malware static tests use synthetic fixtures only.
- No confirmed credential leak or authorization bypass was found in the inspected paths;
  offline tests cover redaction and exact-host authorization. These tests do not substitute
  for a broader security review.
- Docker image rebuild and remote CI/container scans were not run now; historical phase
  reports should not be read as fresh results for this audit.

## G. Prioritized remaining backlog

| Priority | Required change | Relevant files | Dependencies | Acceptance criteria | Size |
|---|---|---|---|---|---|
| P0 blocker | Enforce a global decompressed-byte budget before reading each archive member; abort/skip further expansion deterministically. | `chinescan/log_analysis/ingest.py`; `tests/unit/test_log_analysis.py` | None | Adversarial multi-member/multi-archive fixtures never read beyond configured aggregate expanded bytes; ordinary fixture behavior remains intact. | Medium |
| P1 core | Bound stdout/stderr for external scanner processes while preserving timeout, exit-code and JSON diagnostics. | `chinescan/scanners/external.py`; `tests/unit/test_external_scanners.py` | Windows/POSIX process behavior | Oversized output is terminated or drained safely, returns a bounded diagnostic, and cannot grow captured memory without limit. | Medium |
| P1 core | Define and implement a runtime migration/upgrade path instead of relying on `create_all`. | `chinescan/core/storage/sqlite.py`; `migrations/`; `chinescan/cli/commands.py`; docs | Migration compatibility policy | Fresh and prior-version databases upgrade explicitly; normal CLI startup does not silently bypass migration state. | Medium |
| P1 core | Wire configuration file loading into supported commands and constrain/validate settings. | `chinescan/core/config/{settings,io}.py`; `chinescan/cli/commands.py`; tests | Decide config path precedence | CLI behavior follows documented file/env precedence; invalid settings fail before opening storage; secrets are never serialized. | Medium |
| P1 core | Complete the local investigation vertical slice with event/alert/timeline/artifact links and analyst notes. | `core/models/investigation.py`; `core/reporting.py`; `cli/commands.py`; tests | Schema evolution/migrations | Create/update/show a case with notes and linked evidence; report export includes selected linked records with redaction and traceable IDs. | Large |
| P1 core, policy-blocked | Build API/dashboard only after repository policy explicitly allows a listener and scope is approved. | Future API/frontend packages; `docs/plans/phase-7.md` | Change `AGENTS.md` policy; auth/session/CSRF design | Authenticated loopback service, permission checks, API contract tests, secure evidence access, and default no-service startup. | Large |
| P2 improvement | Run pinned external scanner binaries against local synthetic fixtures in isolated CI and document versions/results. | `tests/unit/test_external_scanners.py`; CI workflow; docs | Approved tools and CI network/cache policy | Each supported adapter has a real-binary fixture job and normalized expected results; no public target scanned. | Large |
| P2 improvement | Expand parser and detection conformance for supported Windows/cloud/Sigma sources. | `log_analysis/parsers.py`; `detections.py`; fixtures/tests | Representative sanitized fixtures | Documented formats/rule subset pass fixture conformance and malformed inputs remain bounded. | Large |
| P2 improvement | Add health/readiness, backup/restore validation, retention and upgrade procedures. | `core/storage`; `docs/DEPLOYMENT.md`; CI | Local service decision and data policy | Repeatable backup integrity/restore test, migration test, documented retention behavior; no listener by default. | Large |
| P3 optional | Add Volatility, isolated sandbox, richer document/binary parsers and optional enrichment. | `malware_analysis/`; docs | Explicit opt-in, isolation and data-transfer policy | Optional tools disabled by default, isolated and bounded, with no sample upload absent consent. | Large |
| P3 optional | Add broad recon and vulnerability scanner integrations. | `domain_assessment/`; `scanners/`; docs | Explicit authorization model and traffic review | Scope, rate, timeout, cancellation and failure-isolation tests; integration fixtures remain offline. | Large |

## H. Recommended next development stage

**Local workflow hardening** is the recommended next stage. It can improve the working
CLI without violating the current no-listener rule: first make archive expansion and
external subprocess output genuinely bounded, then make CLI configuration and migration
behavior explicit, and extend the case/report workflow only after persistence evolution is
defined. This fixes concrete reliability risks and closes existing local workflows before
adding additional disconnected adapters.

Exclude API/dashboard work until `AGENTS.md` changes. Exclude malware intake, sandboxing,
and wider network scanners from this stage. Verify with Python 3.12 tests that include
adversarial resource fixtures, Ruff, strict mypy, dependency audit, migration tests, local
fixture CLI smoke tests, and a documentation update. Any Docker rebuild should be a
separately authorized check when registry access is required.

## I. Ready-to-paste implementation prompt

> In `C:\src\Chinescan`, implement the next **local workflow hardening** slice. Keep all
> work scoped to this repository and preserve existing uncommitted changes. Do not commit
> or push. Do not add a network listener, API, dashboard, public-target scan, malware
> execution, sample upload, or external enrichment. Require Python 3.12+ and use
> `py -3.12` for checks. Do not install dependencies or pull/build containers unless
> separately authorized.
>
> 1. Fix archive expansion accounting in `chinescan/log_analysis/ingest.py`: enforce one
>    aggregate decompressed-byte budget before reading/decompressing each member across
>    the full ingestion job, not after the member has already been materialized. Keep
>    archives read-only and never extract paths. Add adversarial tests in
>    `tests/unit/test_log_analysis.py` for multiple compressed members/files and assert
>    no work beyond the cap while valid fixtures continue to pass.
> 2. Bound external scanner process output in `chinescan/scanners/external.py` while
>    retaining `shell=False`, the environment allowlist, and the configured timeout.
>    Add tests in `tests/unit/test_external_scanners.py` for oversized output, timeout,
>    invalid JSON, and successful normalized output. Ensure child processes are terminated
>    and pipes drained/closed on all paths.
> 3. Inspect `chinescan/core/config/{settings,io}.py` and `chinescan/cli/commands.py`.
>    Either wire config-file settings into supported commands with documented precedence
>    or clearly constrain the CLI to environment/default configuration; validate values
>    such as log level before storage is opened. Never serialize secret values.
> 4. Inspect the `metadata.create_all` startup in `chinescan/core/storage/sqlite.py` and
>    `migrations/`. Propose and implement a minimal explicit migration/upgrade path only
>    if it preserves existing SQLite data; otherwise document the exact safe boundary and
>    add an acceptance test that detects schema drift.
>
> Run the safe Python 3.12 checks available in the repository: unit suite/coverage, Ruff
> lint/format, strict mypy, pip-audit, lock check, schema validation, and Compose
> validation. Do not rebuild an image if it would fetch from a registry. Update the
> relevant report with exact command, exit code, and result. Report any unavailable tool
> or environment constraint rather than claiming verification.

## J. Local workflow hardening stage — 2026-10-26

The original findings were rechecked against the combined worktree before edits. The log
ingestor still checked aggregate expanded bytes only after decompression; scanner wrappers
still used unbounded `capture_output=True`; commands still constructed settings without
reading TOML; and SQLite initialization still used `metadata.create_all` despite one
Alembic revision (`0001_initial`).

The hardening update streams every supported input through a bounded read, shares the
expanded-byte budget across the ingestion job, and stops processing once that budget is
reached without reading a sentinel byte past the cap. A member that exhausts the remaining
budget is discarded; earlier events remain and later inputs are skipped. ZIP and tar paths
remain virtual names and are never extracted. External scanner
stdout and stderr now drain concurrently into fixed-size buffers; exceeding either cap
kills the direct child, timeout and cancellation kill it and close both pipes, and existing
nonzero/invalid-JSON semantics remain errors. Configuration precedence is explicit CLI
options, environment, TOML, then defaults; log levels are constrained and settings errors
avoid echoing invalid values. Fresh SQLite files run Alembic to head; an unversioned
database is stamped at `0001_initial` only when its records schema exactly matches that
revision; incompatible schemas fail without table recreation. Existing record payloads are
retained in the legacy upgrade test.

Fresh focused and repository-wide results, exact commands, and limitations are recorded in
the appended hardening section of `docs/reports/phase-1-report.md`. The next recommended
stage is case/report workflow completion after further schema evolution is expressed as
explicit Alembic revisions. This stage adds no API, dashboard, listener, malware intake,
scanner integration, or public-target activity.



## K. Local investigation workflow — 2026-10-26

The case workflow was checked against the current working tree before implementing this stage. The
existing `Case` model had no typed record links, notes, severity, or activity history; persisted
records already included scans, findings, alerts, events, and timeline entries. Artifacts were only
model types and were not stored. The generic record repository stores payloads in SQLite JSON, and the
initial schema migration had no case-specific tables. The audit therefore uses JSON payload evolution
rather than inventing a relational migration or claiming foreign-key enforcement.

Cases now support severity, open/in-progress/resolved/closed transitions, typed persisted-record links,
append-only local notes, and activity entries. CLI commands provide create-from-scan, show, update,
link, note add/list, timeline, and report export. Reports have JSON, Markdown, and self-contained HTML
formats; dynamic HTML is escaped, secrets are redacted, and selected direct identifiers are masked.
Report buckets retain their structure during redaction. Existing scan/SARIF renderers were not changed.
Timeline entries keep source occurrence and case-activity times distinct; ingestion is explicitly null
because the store has no ingestion timestamp. Missing legacy references are retained and reported.
Artifact links are rejected. Finding reports state that structured remediation guidance is unavailable.
Case notes and activities are saved atomically within one case payload; note ownership is validated.

Migration `0002_case_workflow` records backward-compatible payload evolution without table changes or
payload rewrites. Review found the legacy-schema initialization path stamped a compatible old database
at revision 0001 but did not proceed to head; this was fixed and regression-tested. Fresh DBs migrate to
head, the exact known legacy records schema is stamped then upgraded with its payload retained, and
incompatible schemas are rejected unchanged. This is safe for the current generic JSON storage shape but
provides no SQL-level link constraints.

The acceptance commands and exact results for this stage are recorded in the **Local investigation
workflow verification** section of `docs/reports/phase-1-report.md`: 93 tests pass at 82.78% coverage;
Ruff, strict mypy, dependency audit, Bandit medium threshold, lock check, Compose validation, schema JSON
parsing, and local CLI/config smoke commands pass. Docker image build was not run because it can fetch
images and was not authorized. The worktree remains uncommitted. No production readiness is claimed.

Remaining known limits are no persisted artifact bytes/records, no ingestion timestamps, no structured
finding remediation field, unauthenticated author labels, and no SQL foreign keys for JSON links. The
recommended next stage is local data retention and recovery: backup/restore validation on database
copies and a documented handling policy for sensitive case exports.


## L. Local data protection and recovery — 2026-10-26

Current-code inspection confirmed that SQLite repository startup migrates to Alembic head, cases
embed their notes and activities in JSON payloads, and case links have no SQL foreign keys. The
existing deployment report provided only an operator-written SQLite online-backup example. There
was no backup bundle format, verifier, new-path restore operation, or backup retention planner.
Case export staged content but used `os.replace`, which could silently overwrite an existing report.

Added `core/storage/recovery.py`: read-only source opening; SQLite online backup; bounded time, retry,
and cancellation handling; staged database-plus-manifest bundle; restricted mode requests; SHA-256,
integrity, foreign-key, supported-schema, and application-record verification; new-path staged restore;
and a manifest-validated preview-only age/count retention planner. The manifest contains no paths or
record contents and has a format version, UTC timestamp, application version, revision, size, checksum,
and verification summary. Hashes are documented as mismatch detection, not authentication. Unknown
schemas, corruption, inconsistent case and scanner relationships, and malformed payloads are reported
without repair or deletion. Supported old schemas are read-only verified; only a restored staging copy
is migrated. No database migration or record schema change was required.

Added `db backup`, `db verify-backup`, `db restore`, and `db retention-plan` CLI commands. Restore
rejects existing destinations, active database aliases, and stale WAL/SHM sidecars. Retention only
labels entries as retained/remove/skipped; it never deletes. Case exports now reject existing output
files and publish staged content without overwrite, requesting restrictive mode bits. Operator docs
cover Windows ACL limits, lack of encryption, backup/report sensitivity, non-anonymizing redaction,
manual cutover, and preview-only retention.

Verification details and exact commands are recorded under **Local data protection and recovery
verification** in `docs/reports/phase-1-report.md`: 104 tests passed with 81.85% total coverage; Ruff,
strict mypy, Bandit medium threshold, lock consistency, Compose, schema JSON parsing, CLI smoke, and
`git diff --check` passed. The recovery drill retained case IDs, links, notes, statuses, and activity
through backup/restore and generated all three report formats. Dependency audit was not run because
it would make an external advisory request without approval; the image build was not run because it
may fetch a base image. No commit or push was made.

Remaining risks: database and reports are unencrypted; checksums do not authenticate; Windows mode
bits do not enforce ACLs; relational links are not constrained by SQLite; export publication requires
same-directory hard-link support; retention is preview only; no automatic active-database cutover
exists. The recommended next stage is an operator-controlled cutover and rollback drill against a
restored copy. This implementation and local test results do not establish production readiness.


## M. Recovery acceptance and operator cutover drill — 2026-10-26

Rechecked the recovery bundle service, explicit `--database` option, CLI repository lifecycle,
migrations, case workflow, report publication, and existing tests. The supported restore path writes
to a new destination and applies supported migrations only to that staged copy. Case CLI commands
dispose their repository after each invocation. A missing database supplied to ordinary case
commands can be initialized by repository startup, so the new drill refuses to invoke a case command
unless its selected database is already a regular file.

Added `scripts/recovery_acceptance.py`, an offline synthetic drill using only the checked-in sample
logs. It prepares an original database, linked case, note, and status activity; uses CLI backup,
verification, restore, case show/note/timeline/export commands with explicit database paths; checks
all three report formats; writes a unique note only to the restored database; and selects the original
again. It compares the original database hash before and after and checks that the divergent note
stays only in the restored copy. Temporary drill data is removed at process exit. No configuration
file is rewritten and no existing database is replaced.

Added regressions for the full cutover and rollback, missing-selection refusal without accidental
database creation, failed verification blocking restore while preserving the original, and failed
report publication cleaning temporary output. Existing recovery tests also cover unsupported schema,
new-path refusal, old supported migration, original/restored distinction, and preservation of backup
bundles. Windows permission-denied destination behavior was not asserted because ACL-denial behavior
is environment and privilege dependent; current mode-bit requests do not prove ACL protection.

Exact commands and results are captured in the **Recovery acceptance and operator cutover drill**
section of `docs/reports/phase-1-report.md`. The acceptance verdict is **PASS for the bounded local
synthetic drill**: fixture records and case data survived backup/restore, explicit CLI selection
worked, exports were generated, and rollback by selection left divergent writes unmerged. This is
not a claim about unrelated OS processes, real operational cutover, backup authenticity, or production
readiness. The next recommended stage is controlled real scanner integration verification using
authorized local fixtures and isolated helper processes.


## N. Controlled real scanner integration verification — 2026-10-26

Inspected the existing Semgrep, Gitleaks, Trivy, YARA, and ClamAV adapters, settings/CLI selection,
normalization, persistence, reports, unit tests, dependencies, and CI. All five scanner executables
are absent from this Windows host's `PATH`. The standard local Trivy cache and ClamAV signature
locations checked were absent. CI declares Gitleaks `v8.30.1` and Trivy `v0.76.1`, but these do not
prove local installation or runtime compatibility. Existing adapter parser coverage uses mocked
subprocess output; no real scanner integration evidence existed.

Added local-only positive/negative fixtures where feasible and a `real_scanner` pytest group. These
tests are deselected from the default suite and run only with `--run-real-scanners` or
`--require-real-scanners`. Ordinary explicit selection skips a missing binary/database with a
specific reason. Strict mode fails on missing expected tools/assets, preventing an all-skipped
integration run from passing. Direct execution is bounded by a timeout/output cap and uses
`shell=False`, an allowlisted environment, local rule paths, and tool-level offline/telemetry flags.
The host did not enforce network isolation, and no claim that network access was blocked is made.

No real-tool execution occurred, so no adapter compatibility fix is justified. The detailed inventory,
readiness matrix, fixture inventory, actual selected/strict test results, and proposed pinned CI
provisioning/offline job design are in `docs/reports/real-scanner-integration-verification.md`.
ClamAV positive testing remains omitted because no approved signature/test fixture was present;
Trivy vulnerability scanning remains unavailable without a local DB. Proposed CI provisioning is not
activated and versions for Semgrep/YARA/ClamAV still require explicit approval and pin selection.

The milestone verdict is **BLOCKED for real-binary verification; test harness and fixtures prepared**.
The next action requires approval to provision specified scanner binaries and (for Trivy/ClamAV)
their local databases/signatures, and to select versions for the tools not pinned in current CI. Once
approved assets are available, run the strict integration group on an egress-isolated worker.
