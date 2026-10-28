# ChineScan

ChineScan is a self-hosted local security assessment and investigation application. Its CLI supports local code assessment, exported-log analysis, static malware triage, explicitly authorized domain posture checks, investigations, reporting, and database recovery. The authenticated loopback dashboard supports persisted scan/case review, code and log jobs, and operator-registered malware intake with contained static-analysis jobs, results, and case links. Malware execution, browser upload/download, external enrichment, and public deployment are not supported; process containment is not an OS sandbox.

Stage B2 Windows browser acceptance passed. Full Python acceptance remains incomplete and backup
publication reliability is unresolved; release verification is blocked. See
[`docs/reports/phase-1-report.md`](docs/reports/phase-1-report.md) for the current diagnostic status.

[![CI](https://github.com/CipherChi/Chinescan/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CipherChi/Chinescan/actions/workflows/ci.yml)

## Requirements

- Python 3.12 or newer
- `uv` for environment and dependency management
- Node.js 22.22+ and npm for frontend build and browser acceptance
- Chromium installed by Playwright for browser acceptance

## Quick start

```powershell
uv sync --locked --extra dev
uv run chinescan --help
uv run chinescan version
uv run chinescan code ./fixtures/sample-python-project
uv run chinescan logs ./fixtures/sample-logs --rules ./fixtures/sample-logs --ioc-file ./fixtures/sample-iocs.txt --format json
uv run chinescan malware analyze ./fixtures/sample-malware/synthetic-indicators.txt --format json
```

The default code scanner runs built-in checks locally without executing project files. Optional
Semgrep, Gitleaks, Trivy, pip-audit, and npm-audit adapters are available through the CLI subject
to their local-tool, rules/data, and explicit network-consent requirements. Adapter unit tests use
mocks; they do not verify behavior against real binaries. Five opt-in integration tests exercise
Semgrep, Gitleaks, Trivy, YARA, and ClamAV and require the corresponding external binaries and, for
some, local data. They are excluded from normal acceptance.

Log analysis supports local JSON, JSONL, CSV, auth/syslog, common web access logs, CEF, LEEF, and
bounded gzip/ZIP/tar archives. Static malware triage reads a bounded local file without execution
or upload and does not retain sample bytes. Domain posture checks resolve only the explicitly
authorized hostname and make bounded HTTPS/HTTP HEAD requests to its public addresses. They do not
provide port scanning, subdomain enumeration, or vulnerability-template scanning. See
[Responsible Use](docs/RESPONSIBLE_USE.md) for authorization boundaries.

Cases support workflow status, typed links, append-only notes, timelines, and redacted case and scan
reports. Local database commands provide backup creation, verification, restore to a new path,
preview-only retention planning, and recovery drill guidance. Backups contain sensitive records and
are unencrypted; store them using host-approved encrypted storage and access controls. Windows POSIX
mode bits do not establish ACL protection. Retention planning never deletes files.

## Local dashboard

Install the Python dashboard dependencies through the lockfile with `uv sync --locked --extra dev`.
Bootstrap the local operator once; the command prompts for a username and password and stores
only an Argon2id hash under the user profile (never in a project directory):

```powershell
uv run chinescan web bootstrap --username analyst
```

Build the frontend and explicitly start the single-worker loopback service:

```powershell
cd frontend
npm ci --no-audit
npm run build
cd ..
uv run chinescan web serve
```

`--username` is a username argument; bootstrap prompts securely for the password. To exercise the
browser suite, run `npm ci --no-audit`, `npx playwright install chromium`, `npm run build`, and
`npm run test:e2e` from `frontend/`. The browser harness uses synthetic temporary records and
credentials and cleans up its processes and data.

Configure approved projects outside the browser in `~/.config/chinescan/projects.toml`:

```toml
[[projects]]
id = "service-a"
name = "Service A"
root = "C:/work/service-a"
```

The dashboard sends only the stable project ID. The server resolves and validates the root again
when it accepts and begins a job. It runs built-in local checks only, with one active job and up
to four queued jobs. See [project registry and dashboard operations](docs/PROJECTS.md).

The service binds to `127.0.0.1:8765`; it does not start with other CLI commands or Docker
Compose. During development, start `uv run chinescan web serve` in one terminal and `npm run dev`
from `frontend` in another. Vite binds to `127.0.0.1:5173` and proxies `/api` to the backend.
The development browser and production app use same-origin API calls, without wildcard CORS.

The dashboard requires the local operator for every sensitive read. It uses HttpOnly,
SameSite=Strict cookies, CSRF validation for writes, login throttling, and loopback host/origin
checks. Sessions exist only in process memory and expire after 30 minutes; logging out revokes a
session, and restarting the app invalidates all sessions. Run exactly one application worker.
The bundled server serves ordinary HTTP and therefore leaves the cookie `Secure` attribute off;
ordinary HTTP cannot use a Secure cookie. HTTPS termination is not configured or supported by
this stage. Keep access local and do not put a public proxy in front of this service.

Dashboard APIs expose persisted overview counts, scans, findings, cases, reports, bounded
code-assessment and log-analysis jobs, and malware registry/sample/job/analysis views. Malware
analysis uses only the fixed built-in static profile through verified Windows Job Object
containment. Results distinguish job completion from analysis completeness; YARA and ClamAV remain
unavailable/unverified unless separately configured in another supported workflow. No sample bytes
enter SQLite backups. Raw source lines and target filesystem paths are not sent to the browser. File
browsing and domain jobs are omitted. The log detection engine supports a constrained Sigma subset
and is not comprehensive enterprise detection. Dashboard user cancellation and public deployment
are not supported.
See [the local dashboard API contract](docs/API.md) for endpoint schemas and pagination rules.
See [operator log-source configuration](docs/LOG-SOURCES.md) before enabling log jobs.

The dashboard requires one application worker. Sessions are in memory and restart-invalidated;
the backend listener is explicit and loopback-only, using plain HTTP. Do not put this service behind
a public proxy. Jobs have a fixed queue, no cancellation or hard execution deadline, and graceful
shutdown waits for active work. Project validation and scanning have a filesystem check-to-open
race and do not provide OS sandbox isolation.

Initialize a local configuration with `uv run chinescan config init`; provide `--path` to choose a location. Initialization writes no credentials. The SQLite database defaults to the platform user-data directory and can be overridden with `CHINESCAN_DATABASE_PATH`.

The built-in code scanner is local and never executes project files. Select `--scanner semgrep`, `--scanner gitleaks`, or `--scanner trivy` to use an installed engine. Semgrep requires a local rules file through `--semgrep-rules`; Trivy uses cached data without database updates. `pip-audit` and `npm-audit` are available only with explicit `--allow-network-audits` consent because they send dependency metadata to advisory services.

Generate JSON, Markdown, HTML, CSV, or SARIF 2.1.0 for a persisted scan with `chinescan report SCAN_ID --format sarif --output report.sarif`. Use `chinescan case create --from-scan SCAN_ID`, `chinescan case show CASE_ID`, and `chinescan case update CASE_ID --status in_progress` to track investigation status. Compare two stored scans with `chinescan compare BASELINE_SCAN_ID CURRENT_SCAN_ID`.

Analyze local exported logs with `chinescan logs ./logs --rules ./sigma-rules --ioc-file ./iocs.txt`. JSON, JSONL, CSV, Linux auth/syslog, common nginx/Apache/IIS access logs, CEF, and LEEF are supported, along with gzip, ZIP, and tar archives. Windows and cloud data must be exported as JSON or CSV. Archives are read without extraction; raw log lines are not stored. Built-in detections and the supported Sigma subset produce candidate alerts that require analyst review.

Run `chinescan malware analyze ./sample.bin` for ephemeral, bounded static triage. For persisted dashboard workflows, configure an operator TOML registry and explicit `CHINESCAN_MALWARE_MANAGED_DIRECTORY`, then start `chinescan web serve --malware-samples-file ...`. The dashboard accepts registry IDs only, stores a managed copy outside protected roots, and executes the built-in profile only through verified Windows Job Object containment. It exposes reviewed results and case reports but never sample bytes. See [Malware backend operations](docs/MALWARE-BACKEND.md) for configuration and guarantees. YARA and ClamAV remain unused by the dashboard profile.

Assess one domain you own with `chinescan domain example.com --i-own-this-target --operator "Analyst"`. For delegated work, pass `--authorization-file authorization.json` containing the exact `target`, `granted_by`, timezone-aware `valid_from` and `valid_until` timestamps, and `profile` (`light` or `deep`). The command records authorization and the configured limits locally before network access. Set `--timeout` from 0.1 to 10 seconds, `--max-addresses` from one to five for deep scans, and `--request-interval` from zero to five seconds. The built-in light profile resolves the exact hostname and checks one public address; deep checks up to the configured public address cap. Each address receives one HTTPS `HEAD`; if HTTPS fails for all selected addresses, the probe makes one HTTP `HEAD` fallback per selected address. It does not follow redirects, read response bodies, scan ports, enumerate subdomains, or run vulnerability templates. JSON output is available with `--format json`.

For local backup/restore guidance, upgrade precautions, and current deployment limits, see [Operations and deployment](docs/DEPLOYMENT.md).

## Guides

- [Dashboard API](docs/API.md)
- [Approved project operations](docs/PROJECTS.md)
- [Operator log-source configuration](docs/LOG-SOURCES.md)
- [Recovery runbook](docs/RECOVERY-RUNBOOK.md)
- [Deployment and operations guide](docs/DEPLOYMENT.md)
- [Development and verification guide](docs/DEVELOPMENT.md)
- [Development status audit](docs/reports/development-status-audit.md)

## Safety boundary

Only use Chinetscan against assets for which you have explicit authorization. Code, log, and static file analysis run locally; domain posture checks require explicit target authorization and contact only public addresses returned for that exact hostname. The dashboard starts only through an explicit command and binds to loopback. Malware dashboard triage is static only; samples are never executed or uploaded, and Job Object process containment is not an OS sandbox. Findings, alerts, and extracted indicators are candidates for analyst validation. See [Responsible Use](docs/RESPONSIBLE_USE.md).

The dashboard includes the existing persisted case workflow: create from a stored scan, link supported records, append notes, update case status using workflow transitions, view the timeline, and download redacted case and scan reports. It does not persist artifacts.
