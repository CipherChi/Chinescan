# Local dashboard API

The API is served by `chinescan web serve` on loopback only. OpenAPI and interactive docs are
disabled in this stage; response models are declared in `chinescan/web/app.py` and the stable
JSON contract is summarized here. Every route except login requires the `chinescan_session`
HttpOnly cookie. The cookie is opaque and maps to an in-memory session. Authenticated POSTs also
require a same-origin `Origin` header and `X-CSRF-Token` returned by login/session. API responses
use `Cache-Control: private, no-store`.

## Authentication

| Method and path | Access | Contract |
| --- | --- | --- |
| `POST /api/auth/login` | Public, loopback and same-origin guarded | JSON body `{ "username": string, "password": string }`; returns `{ "username": string, "csrf_token": string }` and sets an HttpOnly SameSite=Strict cookie. Failures are generic and rate limited. |
| `GET /api/auth/session` | Authenticated | Returns the operator name and CSRF token. |
| `POST /api/auth/logout` | Authenticated + CSRF | Revokes the active session and clears its cookie. |

## Persisted records

| Method and path | Access | Response |
| --- | --- | --- |
| `GET /api/overview` | Authenticated | Stored scan/finding counts, persisted finding counts grouped by severity, and up to five recent scan summaries. |
| `GET /api/scans` | Authenticated | `{ items: ScanSummary[], total, limit, offset }`; `limit` is 1–100 (default 25), `offset` is 0–100000. `status` supports `complete`, `partial`, `failed`, or `running`; `scanner` is at most 100 characters. `sort` allows `started_at`, `status`, or `scanner`; `order` allows `asc` or `desc`. |
| `GET /api/scans/{scan_id}` | Authenticated | A path-free `ScanSummary` plus linked stable `finding_ids`. |
| `GET /api/findings` | Authenticated | `{ items: FindingSummary[], total, limit, offset }`; pagination bounds match scans. `severity` must be one of `critical`, `high`, `medium`, `low`, or `info`; `category` is at most 80 characters; `scanner` is at most 100 characters. `sort` allows `severity`, `title`, `scanner`, or `category`; severity ordering follows critical, high, medium, low, info. `order` allows `asc` or `desc`. |
| `GET /api/findings/{finding_id}` | Authenticated | A reviewed `FindingDetail` schema with redacted description/location text, never a raw persisted payload. |

All unknown sort fields, unsupported severity/status values, oversized bodies, invalid page bounds,
cross-origin requests, and non-loopback Host/client values are rejected. The API does not accept
filesystem paths in requests, malware intake, domain assessment, database selection, restore, or
deletion routes.

## Local log-analysis jobs

The operator configures local sources outside the browser in `~/.config/chinescan/log-sources.toml`
or supplies `chinescan web serve --log-sources-file PATH`. The browser sends only a `source_id`.
Every route below requires the authenticated session; job creation also requires same-origin and
CSRF validation.

| Method and path | Contract |
| --- | --- |
| `GET /api/log/sources` | Available configured source IDs and display names only. Unsafe, missing, protected, or invalid roots are omitted. |
| `POST /api/log/jobs` | `{source_id}` starts bounded local analysis; unknown/unavailable source is `422`, full queue is `429`. Additional request fields are rejected. |
| `GET /api/log/jobs` | Persisted jobs, bounded `limit` 1–100 and `offset` 0–100000. States: `queued`, `running`, `succeeded`, `partial`, `failed`, `interrupted`. |
| `GET /api/log/jobs/{job_id}` | Persisted state, sanitized error, counts, and optional actual result `scan_id`. |
| `GET /api/log/analyses/{scan_id}/alerts` | Alerts belonging to that persisted log scan; optional validated `severity`; bounded pagination. |
| `GET /api/log/analyses/{scan_id}/alerts/{alert_id}` | Reviewed, redacted alert detail. The ID must belong to the given log scan. |
| `GET /api/log/analyses/{scan_id}/events` | Events belonging to that persisted log scan; optional bounded `source` filter; bounded pagination. Raw references and full paths are omitted. |
| `GET /api/log/analyses/{scan_id}/events/{event_id}` | Reviewed event detail. The ID must belong to the given log scan. |
| `GET /api/log/analyses/{scan_id}/timeline` | Persisted source timeline entries with bounded pagination. |

Log-source TOML is operator-controlled. Each source has `id`, `name`, and absolute `root`; optional
`rules` points to a local Sigma rules directory and optional `iocs` to a local IOC list. Paths are
validated against the active database directory, credentials, and registry files. Symlinks and
Windows junctions within the selected tree are rejected where detected. Ingestion is read-only and
uses existing limits: up to 10,000 files, 25 MB per file, 250 MB aggregate input/expanded data,
1,000 archive members, 100 MB per archive, and 100,000 events. Archives are never extracted.
The single worker allows one active job and four waiting jobs. Partial jobs retain available results
but are explicitly marked `partial` and include an error count; they must not be interpreted as a
clean analysis. Restart reconciliation marks unfinished jobs `interrupted`. There is no cancellation
or hard wall-clock deadline. The filesystem can change after validation, so this is not OS sandboxing.

Log alerts are candidate detections. Built-in rules are limited heuristics. The Sigma evaluator
uses safe YAML loading and supports normalized field aliases, case-insensitive glob matching,
`contains`, `startswith`, and `endswith`, optional `all` value matching, Boolean `and`/`or`/`not`,
parentheses, and `all`/`any`/`1 of` selector patterns. It does not support the full Sigma specification,
timeframes, pipelines, or arbitrary executable logic. Rule/selector work is
bounded, and unsupported conditions produce diagnostics that make the scan partial. There are no
network collectors, enrichment requests, or uploads.

## Approved local code-assessment jobs (Slice 3A)

Projects come from the operator-controlled TOML registry described in [Project operations](PROJECTS.md).
The browser submits only a project ID. Jobs use the existing `CodeScanService` with the built-in
scanner; request bodies reject additional fields. External scanners and network-backed dependency
checks cannot be selected through this API.

| Method and path | Access | Contract |
| --- | --- | --- |
| `GET /api/code/projects` | Authenticated | Approved project IDs and display names only; unavailable or invalid roots are omitted. |
| `POST /api/code/jobs` | Authenticated + CSRF | `{project_id}`; returns `202` with a queued job. Unknown/unavailable project is `422`, duplicate active project is `409`, full queue is `429`. |
| `GET /api/code/jobs` | Authenticated | Bounded page (`limit` 1–100, `offset` 0–100000) of persisted job summaries. |
| `GET /api/code/jobs/{job_id}` | Authenticated | Persisted status, timestamps, optional actual `scan_id`, and sanitized error. |

States are `queued`, `running`, and terminal `succeeded`, `failed`, or `interrupted`. Creation sets
`created_at`; transition to running sets `started_at`; any terminal transition sets `finished_at`.
On startup, previous queued/running jobs become `interrupted`; that records application state and
does not establish that any OS process was terminated. One job runs at a time, with four waiting
slots. There is no cancellation endpoint. Built-in synchronous scanning rejects a project containing
a source file over 1 MB, more than 20,000 source files, or more than 250 MB of source data; queue
bounds, concurrency, and input bounds do not impose an execution deadline. Shutdown waits for an
in-flight scan; an abrupt process loss is reconciled next start. Filesystem validation rejects
symbolic links and Windows junctions found during the preflight walk where supported, and the
scanner itself does not follow directory links and skips symlink files. A change between preflight
and file open remains a filesystem race; this is not an OS sandbox. The active database directory
(including SQLite sidecars), operator credential, and project-registry paths are excluded
automatically. Operator-selected backup or report directories can also be listed in the registry's
`protected_paths`; this dashboard has no managed backup/export directory and report downloads are
generated in memory. Raw scanner logs and source text are not sent to the browser.

## Cases and report downloads (Slice 2)

Every case route requires an authenticated session. Case creation, status changes, notes, and links
also require the same-origin `Origin` check and current `X-CSRF-Token` as logout.

| Method and path | Contract |
| --- | --- |
| `GET /api/cases` | Bounded page (`limit` 1–100, `offset` 0–100000), filters `status` and `severity`, sorts `created_at`, `updated_at`, `status`, `severity`, `title`, and `order=asc|desc`. Returns persisted case summaries with total/page metadata. |
| `POST /api/cases` | `{scan_id, title?, description?, severity?}` creates through `CaseWorkflow.create_from_scan`; title is at most 200 characters, description 8000, and severity is an enumerated value. The scan must already be persisted. |
| `GET /api/cases/{case_id}` | Case status, severity, notes, validated persisted link metadata, reviewed linked-record summaries, chronological activity/source timeline, warnings, and severity counts. Evidence is text and passed through shared redaction. |
| `POST /api/cases/{case_id}/status` | `{status}` uses the workflow transition table. Closed cases cannot transition further. |
| `POST /api/cases/{case_id}/notes` | `{body}` appends a note (1–8000 characters). The authenticated operator is not written into the legacy unverified author-label field. Notes are not editable or deleted through the API. |
| `POST /api/cases/{case_id}/links` | `{record_type, record_id}` validates supported persisted records through `CaseWorkflow`; repeating an existing link is idempotent. Artifacts are not persisted or supported. |
| `GET /api/cases/{case_id}/report/{json|markdown|html}` | Generates a redacted report in memory, capped at 2 MB, and returns it as an attachment. HTML uses `Content-Disposition: attachment` and is not rendered inline. |
| `GET /api/scans/{scan_id}/report/{json|markdown|html|csv|sarif}` | Uses the existing scan report renderer and formats. The report is a download attachment with a server-chosen filename. |

Case report generation rejects cases above configured link/note/activity limits; scan exports reject
more than 10,000 findings. All IDs are opaque record IDs, never paths. Unsupported format segments
are rejected by route validation. Case persistence still uses the existing JSON payload schema and
does not add SQL foreign keys. Missing legacy references remain warnings. No artifacts,
backup/restore controls, or malware intake are exposed.

## Session and transport limits

Sessions expire after 30 minutes and are held only in process memory. Logout revokes the current
session; a process restart discards all sessions. Run one application worker. The included server
uses plain HTTP with `Secure` cookies disabled. Setting `Secure` on an HTTP cookie would prevent
normal browsers from sending it. HTTPS termination and trusted proxy headers are not configured.
