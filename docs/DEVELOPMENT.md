# Development

Use Python 3.12+ and `uv`:

```powershell
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy chinescan
uv run pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80
uv run pip-audit --skip-editable
uv run chinescan code ./fixtures/sample-python-project
uv run chinescan code ./fixtures/sample-python-project --fail-on high
uv run chinescan code ./fixtures/sample-node-project --format json
uv run chinescan logs ./fixtures/sample-logs --rules ./fixtures/sample-logs --ioc-file ./fixtures/sample-iocs.txt --format json
uv run chinescan malware analyze ./fixtures/sample-malware/synthetic-indicators.txt --format json
uv run chinescan domain your-owned-domain.example --i-own-this-target --operator "Analyst" --profile light
uv run chinescan report SCAN_ID --format sarif --output report.sarif
uv run chinescan case create --from-scan SCAN_ID
uv run chinescan case show CASE_ID
uv run chinescan case link CASE_ID --type finding --id FINDING_ID
uv run chinescan case note add CASE_ID --text "Analyst observation"
uv run chinescan case timeline CASE_ID --format json
uv run chinescan case export CASE_ID --format html --output case-report.html
uv run chinescan db backup --output D:/restricted-backups/chinescan-2026-10-26
uv run chinescan db verify-backup D:/restricted-backups/chinescan-2026-10-26
uv run chinescan db restore D:/restricted-backups/chinescan-2026-10-26 --output D:/recovery/chinescan-restored.sqlite3
uv run chinescan db retention-plan --directory D:/restricted-backups --format json
uv run chinescan compare BASELINE_SCAN_ID CURRENT_SCAN_ID
uv run chinescan trends --days 30 --format json
```

Dashboard frontend development additionally requires Node.js 22.12+ and npm. The frontend uses
React, TypeScript, Vite, Vitest, Testing Library, and Playwright; install its locked dependencies
with `npm ci --no-audit` from `frontend/`. Run the backend explicitly with
`uv run chinescan web serve` and the development UI with `npm run dev`. Both bind to loopback;
Vite proxies `/api` to port 8765.

The operator identity is an email address. ChineScan trims and lowercases it for case-insensitive
lookup. With no credential file, open the Vite loopback URL and choose **Create operator account**.
Signup creates the sole local operator and signs it in immediately. Passwords require at least 12
characters and are stored as Argon2id hashes. Signup returns a generic conflict after an account
exists.

Passwords cannot be recovered; they can only be reset. **Forgot password?** gives generic local
instructions. Run `uv run chinescan web reset-password --email operator@example.com`; the CLI
prints a one-time token locally. Enter it with the email and new password at `/reset-password`
within 15 minutes. The raw token is never returned by the API or written to logs; only its SHA-256
digest is stored. Tokens are single-use, a later reset request replaces an earlier token, and
repeat CLI requests are limited to one per minute. Reset invalidates existing sessions.

`uv run chinescan web recover-operator` first creates and names a timestamped credential backup,
then asks whether to reset/migrate or retire the local operator. The `retire` choice removes only
the credential file after explicit confirmation; database scans, settings, and other data remain.
The reset/migrate choice asks for an email, preserves the old password hash until the operator
completes the new-token reset flow, and prints a reset token locally. A legacy `username`
credential already containing a valid email is backed up and migrated on app startup. A non-email
legacy value is backed up, marked as requiring recovery, and cannot sign in until the guided
recovery flow replaces it.

`uv run chinescan web bootstrap` remains the terminal setup path and refuses to overwrite an
existing account. The public `POST /api/auth/signup` accepts `email` and `password`; `POST
/api/auth/forgot-password` and `POST /api/auth/reset-password` follow the same loopback and
same-origin guards. See [API](API.md) for request details. Backend coverage is in
`tests/unit/test_web_api.py` (`uv run pytest tests/unit/test_web_api.py`). The Playwright flow in
`frontend/e2e/operator-recovery.spec.ts` covers signup, logout, local reset-token use, login, and
dashboard access with synthetic credentials. Its Playwright trace and screenshots are disabled so
the synthetic one-time token is not retained in test artifacts.

To disable an existing operator without creating another one, run
`uv run chinescan web retire-operator`. The command makes a timestamped copy beside the active
credential file (`operator.json.bak-YYYYMMDD-HHMMSS`), shows only the username/email-field
presence and file paths, then requires the exact phrase `RETIRE OPERATOR`. On confirmation, it
renames the active file to `operator.json.retired-YYYYMMDD-HHMMSS`. It touches no scan records,
application settings, or other files. Pass `--credential-file PATH` if bootstrap/serve uses a
custom credential path. A missing active file is a successful no-op.

To restore an archived credential, run `uv run chinescan web restore-operator`, select a listed
backup or retired file, and type `RESTORE OPERATOR`. If an active credential exists, it is first
copied to a timestamped `.bak-*` file before the selected archive is restored. These commands
never print password hashes or create a replacement account. Passwords and Argon2id hashes cannot
be recovered from the credential file; the backup preserves the hash for restoring the old login.
After retirement, manually start the backend and use browser signup or `uv run chinescan web
bootstrap` when you are ready to create an operator.

For production browser acceptance, first build the frontend and install Playwright's Chromium
browser locally (no global package or system browser installation):

```powershell
cd frontend
npm ci --no-audit
npx playwright install chromium
npm run build
npm run test:e2e
```

The Playwright harness launches the production build served by the authenticated Python app on
an ephemeral loopback port. It creates synthetic SQLite records, a randomly generated temporary
operator account, and temporary credential/data directories. It does not use the configured
operator account, personal database, or assessment commands. Temporary server processes and
fixture data are removed after the run. Traces and screenshots are retained only for failures
under `frontend/test-results/`; do not commit these generated artifacts. The suite requires
Python 3.12+ and the project Python environment available to `py -3.12`.

Create the single operator account in the browser or with `uv run chinescan web bootstrap`. The
default credential file is `%USERPROFILE%\.config\chinescan\operator.json`; it contains the
operator email and Argon2id password hash. To inspect only the email in PowerShell, run:

```powershell
(Get-Content "$env:USERPROFILE\.config\chinescan\operator.json" | ConvertFrom-Json).email
```

On Windows, protect this file through the user's profile ACL; POSIX mode bits do not prove Windows
ACL protection. A custom path can be supplied with `--credential-file`.

The dashboard uses one Uvicorn worker, volatile sessions, 30-minute expiry, HttpOnly and
SameSite=Strict cookies, CSRF validation, loopback host/origin checks, and a five-attempt
per-process login throttle. Logout revokes the current session; process restart invalidates all
sessions. The included service is plain HTTP with `Secure` cookies disabled. A Secure cookie is
not sent over ordinary HTTP; local HTTPS termination is not configured in this stage.

Run the CLI with `uv run chinescan --help`. The test suite uses temporary configuration and SQLite files. Do not point tests at personal data. Keep dependency changes in `pyproject.toml` and regenerate `uv.lock` with `uv lock`.

Configuration precedence is explicit root CLI options (`--database`, `--config`), then
`CHINESCAN_DATABASE_PATH` / other `CHINESCAN_` settings, then the selected TOML file,
then defaults. The TOML path defaults to `~/.config/chinescan/config.toml` and can be
selected with `--config` or `CHINESCAN_CONFIG_PATH`. Settings are validated before a
command opens SQLite or launches scanner tools. `api_token` is accepted as a secret
environment/config value but is not written by `config init` or printed by validation.

Code scanning reads local files and does not execute them. Built-in scanning is the default. Semgrep requires a local rules file; Trivy requires locally cached databases. pip-audit and npm audit require `--allow-network-audits` because they submit dependency metadata to advisory services.

Use `chinescan code <project> --fail-on high` to make a CI job exit with status 1 when candidate findings meet or exceed HIGH severity. Supported thresholds are `critical`, `high`, `medium`, `low`, `info`, and `never`; `never` is the default. These findings remain candidates for analyst validation.

`chinescan trends` reads stored scans, findings, and alerts from local SQLite and reports daily counts for the requested 1–366 day window. It does not include target names or raw evidence.

Log analysis reads local exports and bounded archives without extraction or network access. Raw log lines are not persisted; normalized records are retained in the configured SQLite database. The Sigma evaluator supports a safe, documented subset, not the entire Sigma language.

Malware static triage reads one regular file up to 64 MiB and never executes it. The `malware analyze` CLI remains ephemeral; the backend-only Stage B1 library supports explicit registry-based managed copies and persists sample metadata, jobs, bounded results, and audit records. Managed sample bytes remain outside database backups. See [Malware backend operations](MALWARE-BACKEND.md) for its required storage configuration, limits, worker controls, recovery, and remaining boundaries. Neither path is a malware sandbox, memory analysis, or dynamic analysis. YARA and ClamAV remain opt-in local tools and are not called by the managed B1 job path.

Domain assessment is the sole built-in network posture command. Use it only with explicit ownership or a matching local authorization file. Unit tests mock all domain network operations; do not add live targets to acceptance checks.

Case workflow stores status, severity, typed links, append-only notes, and activity in the
existing local JSON record. Links must resolve to persisted records; Artifact records are
not persisted and cannot be attached. Case exports support JSON, Markdown, and self-contained
HTML, redact secrets and selected direct identifiers, and do not change scan reports or SARIF.
Timeline output distinguishes source event occurrence time from case activity time. Record
ingestion timestamps are not available. Notes and activities are embedded in the Case record,
so a single SQLite transaction saves each workflow update. Case author labels are unverified.

Database backups use SQLite's online backup API and publish a verified database plus manifest
bundle at a new path. Verification never migrates or repairs a backup. Restore only creates a new
database file, upgrading that restored copy when its schema is an older supported revision.
`db retention-plan` is a dry-run preview and never deletes files. Case report output paths must not
exist already; export does not overwrite prior reports.

The dashboard exposes this same `CaseWorkflow` through authenticated, same-origin API routes. For
local code-assessment jobs it reads an operator-controlled TOML project registry and runs the
existing `CodeScanService` with only `BuiltinRuleScanner`; details and path limits are in
[Project operations](PROJECTS.md).
Case creation starts from an existing scan; status updates, link validation/idempotency, and
append-only notes remain enforced by the workflow layer. The UI displays case activity and source
timelines and downloads redacted JSON, Markdown, or HTML case reports, plus supported scan reports.
HTML reports are attachments. Evidence and analyst notes are rendered as text, and legacy author
labels remain unverified. Job requests accept only a stable project ID, and responses contain no
full local project path. There is no cancellation or safe hard wall-clock timeout for the built-in
synchronous scan; graceful shutdown waits for active work.

Dashboard log jobs use the same authenticated single-worker loopback service. The operator maintains
an ID-based local source registry with optional local Sigma rules and IOC list paths; browser requests
cannot submit file paths or detection logic. Alerts, events, and source timelines are paginated and
scoped to a persisted log scan. Partial ingestion is represented as a partial job with path-free
diagnostic categories. See the [log-source operator guide](LOG-SOURCES.md) and [API contract](API.md).
# Authentication throttling

Login, signup, password reset, and forgot-password throttles are held in process memory and keyed by client IP and normalized email. Five failures begin a one minute lockout; repeated groups of five increase the delay to five and fifteen minutes, capped at fifteen minutes. Restarting the local service clears these counters. Locked requests return a generic response and `Retry-After` header.

## Local environment troubleshooting

Use the repository's uv-managed environment for development commands. If `uv run` reports a missing `pyvenv.cfg`, confirm `UV_PROJECT_ENVIRONMENT` and `VIRTUAL_ENV` are unset or point to this repository's `.venv`, then run `uv sync --all-groups --all-extras`. Run pytest with `--basetemp` under the operating system temporary directory so SQLite handles are not removed while the repository is in use.
