# Phase 1 verification report

Recorded 2026-10-25. Python 3.12.10 was newly installed after the user authorized installation. The standalone repository is `C:\src\Chinescan`; the parent repository was not staged or changed.

## Outcome

Platform foundation implemented: package metadata and lock, versioned records and schemas, config, redaction and JSON logging, protocols and fake scanner, SQLite repository and Alembic migration, Typer CLI, tests, project policies/docs, Compose, and CI workflow.

The initial acceptance run had a Docker wheel-install failure and left the base image tag unpinned. On 2026-10-25, the Dockerfile was corrected to preserve the built wheel's filename and pinned to the verified Python image manifest digest. The complete Docker build and container CLI smoke check now pass. The latest Python acceptance rerun also passes lint, formatting, type checks, unit tests, dependency audit, CLI checks, and Compose validation. Exact rerun results are recorded below.

## Tasks and verification

| Plan task | Result | Verification / note |
| --- | --- | --- |
| 1. Python gate, standalone Git repository, conventions | PASS | `py -0` and `py -3.12 --version` passed; nested `git init` and status passed. |
| 2. Project metadata and lock | PASS | `uv lock --check`; `uv sync --locked --extra dev`; `pyproject.toml` and `uv.lock` committed as `50d04e9`. |
| 3. Typed errors, canonical models, schemas | PASS | Pydantic model tests and both JSON Schema JSON parse checks passed. |
| 4. TOML config, environment overrides, safe init | PASS | Configuration tests passed, including environment override and no-secret initialization. |
| 5. Redaction, structured logging, focused tests | PASS | Redaction and JSON formatter tests passed. |
| 6. Protocols, fake adapter, SQLite, Alembic | PASS | Fake adapter and temporary SQLite repository tests passed; migration created the `records` table. |
| 7. Typer CLI and future stubs | PASS | CLI tests, help, version, config commands, and Phase 3 stub exit code 2 passed. |
| 8. Example config, docs, decisions, license, policies | PASS | Files created; reviewed as source artifacts. |
| 9. Docker, Compose, `.dockerignore`, CI | PASS | `docker compose ... config --quiet` passed; digest-pinned Docker build and container `--help` smoke check passed. |
| 10. Acceptance checks and report | PASS | Python 3.12.10 checks, CLI/config, tests, lint/format, mypy, pip-audit, schemas, migration, Compose, and Docker build passed; see rerun results below. |

## Exact verification commands and results

### Python gate

`py -0` — exit 0:

```text
 -V:3.13 *        Python 3.13 (64-bit)
 -V:3.12          Python 3.12 (64-bit)
 -V:3.11          Python 3.11 (64-bit)
 -V:3.10          Python 3.10 (64-bit)
```

`py -3.12 --version` — exit 0:

```text
Python 3.12.10
```

### Python checks

| Command | Exit | Output |
| --- | ---: | --- |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | `Using CPython 3.12.10`; `Resolved 54 packages`; installed locked project and development dependencies, including pytest 9.1.1. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms` |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\mypy.exe chinescan` | 0 | `Success: no issues found in 23 source files` |
| `\.venv\Scripts\pytest.exe --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 0 | 17 passed; total coverage 89.26%; required 80% reached. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable local `chinescan` distribution skipped. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed `version`, `scan`, `report`, and `config`. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `.\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `.\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |

The first audit found `PYSEC-2026-1845` in pytest 8.4.2 (fix listed as 9.0.3). The dev dependency upper bound was widened from `<9` to `<10`, the lock was upgraded to pytest 9.1.1, and the audit then passed.

### Persistence and container configuration

| Command | Exit | Output |
| --- | ---: | --- |
| Temporary Alembic upgrade script using `alembic.command.upgrade(cfg, 'head')` | 0 | `migration upgrade head: OK; records table present` |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No errors. |
| `docker info` | 0 | Docker Engine 29.9.2 server responded; daemon available. |
| `docker image inspect python:3.12-slim --format '{{json .RepoDigests}}'` | 1 | `Error response from daemon: No such image: python:3.12-slim` |
| Docker build | NOT RUN | Registry fetch was not attempted because network use is limited to package indexes. Therefore Docker daemon unavailability is not claimed. |

## Deviations and decisions

- The planned pytest `<9` range was unsafe per the audit result; it is now `>=8.3,<10`, with 9.1.1 locked.
- An existing `.venv` using Python 3.13.15 was unintentionally replaced by `uv sync` with the Python 3.12.10 project environment. `.venv312` contains the uv executable used for environment management. This local environment change is recorded in `docs/ENVIRONMENT.md`.
- The initial pytest runs used pytest's default system temporary directory for `tmp_path` fixtures. Before the final run, pytest was configured with `--basetemp=tests/.pytest-tmp` so subsequent test files are confined to the project. No cleanup was attempted outside the project directory.
- The initial Docker build failed because the built wheel was copied to `/tmp/chinescan.whl`, which is not a valid wheel filename. The Dockerfile now copies the wheel to `/tmp/` without renaming it. The Python 3.12 slim Bookworm base was resolved from Docker Hub and pinned by manifest digest in both stages; the digest-pinned build passes.
- Only `pyproject.toml` and `uv.lock` were committed, as directed by plan task 2. No other files were committed or pushed.

## Latest acceptance rerun — 2026-10-25

All commands below were run from `C:\src\Chinescan` after the Dockerfile fix and Ruff formatting. Exit 0 indicates success.

| Command | Exit | Result |
| --- | ---: | --- |
| `\.venv312\Scripts\python.exe --version` | 0 | `Python 3.12.10` |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | `Resolved 54 packages in 2ms`; `Checked 54 packages in 35ms` |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms` (recorded in the earlier run; lock unchanged) |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed `version`, `scan`, `report`, and `config` |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `49 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 23 source files` |
| `\.venv\Scripts\pytest.exe --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `17 passed`; total coverage `91.05%` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; configuration valid |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Build succeeded; base `python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`; image `chinescan:0.1.0` created |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container displayed CLI help |
| Config initialization, duplicate initialization, validation, and malformed TOML validation using a temporary `tests\phase1-config-check.toml` | 0 / 2 / 0 / 2 | Outputs respectively: created; already exists; valid; parse error. Error cases return documented application exit code 2. Temporary file removed. |

The earlier formatter failure has been corrected by applying Ruff formatting to the five reported files. Docker registry access was available for this rerun, so the prior package-index-only limitation no longer applies to the current verification.

## Rerun commands

From `C:\src\Chinescan` in PowerShell:

```powershell
\.venv312\Scripts\uv.exe sync --locked --extra dev
\.venv312\Scripts\uv.exe lock --check
\.venv\Scripts\ruff.exe check .
\.venv\Scripts\mypy.exe chinescan
\.venv\Scripts\pytest.exe --cov=chinescan --cov-report=term-missing --cov-fail-under=80
\.venv\Scripts\pip-audit.exe --skip-editable
\.venv\Scripts\chinescan.exe --help
\.venv\Scripts\chinescan.exe version
docker compose -f docker-compose.yml config --quiet
```

Run the Alembic migration check through the pytest suite; pytest writes temporary databases under `tests/.pytest-tmp/`. The Docker image build command, after an authorized immutable base digest and registry access are available, is:

```powershell
docker build -f docker/Dockerfile -t chinescan:0.1.0 .
```

## Security and acceptance rerun — 2026-10-25

The following checks were rerun from `C:\src\Chinescan` with Python 3.12.10 after the secret-redaction and config-initialization fixes. The worktree also contains uncommitted Phase 2–4 code; results below describe that combined local worktree and do not make those features part of Phase 1.

| Command | Exit | Result |
| --- | ---: | --- |
| `py -0` | 0 | Registered interpreters: Python 3.13 (64-bit, default), 3.12 (64-bit), 3.11 (64-bit), 3.10 (64-bit) |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev --python 3.12` | 0 | `Resolved 57 packages`; `Checked 57 packages` |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 3ms` |
| `uv run --locked --extra dev ruff check .` | 0 | `All checks passed!` |
| `uv run --locked --extra dev ruff format --check .` | 0 | `72 files already formatted` |
| `uv run --locked --extra dev mypy --strict chinescan` | 0 | `Success: no issues found in 33 source files` |
| `uv run --locked --extra dev pytest --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `44 passed`; core coverage `94.08%` |
| `uv run --locked --extra dev pip-audit --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped |
| `uv run --locked --extra dev bandit --severity-level medium -r chinescan` | 0 | No medium/high issues; three low-severity items are triaged in `docs/reports/security-review.md` |
| PyYAML parse of `.github/workflows/ci.yml` and `.github/dependabot.yml` | 0 | Both YAML documents parsed; GitHub workflow execution remains pending a push |
| `actionlint -color .github/workflows/ci.yml` (actionlint 1.7.12) | 0 | Workflow syntax and expressions passed local validation |
| JSON parse of `schemas/*.json` | 0 | Both schemas valid |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration |
| `docker build -f docker/Dockerfile -t chinescan:security-review .` | 0 | Built using Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`; runtime packages installed from hashed `uv.lock` export |
| `docker run --rm chinescan:security-review --help` | 0 | Container CLI help rendered |
| `trivy config --severity HIGH,CRITICAL --exit-code 1 .` | 0 | No high/critical Dockerfile misconfiguration; Trivy detected one config file (Dockerfile) |
| Trivy image scan with `--ignore-unfixed --severity HIGH,CRITICAL --exit-code 1` | 0 | No fixable high/critical image vulnerabilities |
| Trivy full image report without `--ignore-unfixed` | 0 (report-only) | 44 high OS findings: 43 `affected`, one `fix_deferred`, none had a fixed version; no critical or Python-library findings. See the temporary acceptance in `docs/reports/security-review.md`. |
| `gitleaks git . --log-opts=--all --redact --no-banner` | 0 | Two Git commits scanned; no leaks |
| Gitleaks scans of tracked/unignored source paths | 0 | No leaks in source paths. A broad scan including ignored `.venv` produced 202 potential matches, all under that generated environment; they were not confirmed as credentials and were not staged. |

The full Bandit run still reports three low-severity items in uncommitted later-phase code. The Trivy workflow reports all high/critical image findings and fails only when a fix is available; the accepted no-fix OS findings have owner `CipherChi` and review date `2026-11-25` in the security review report. No repository settings, visibility, commits, pushes, pull requests, or deployments were changed or created in this run.

Exact `py -0` output:

```text
 -V:3.13 *        Python 3.13 (64-bit)
 -V:3.12          Python 3.12 (64-bit)
 -V:3.11          Python 3.11 (64-bit)
 -V:3.10          Python 3.10 (64-bit)
```

## Acceptance rerun — 2026-10-26

This rerun validates the current combined worktree, which includes uncommitted later-phase modules;
it does not expand Phase 1's scope. Python commands explicitly used the 3.12 launcher. `PYTHONPATH`
was pointed at the repository virtual environment's installed dependencies because system Python
3.12 does not have the project dependencies installed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `69 passed`; total coverage `82.26%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChineScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; four low-severity subprocess findings are outside this threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 2ms` |
| JSON parsing for `schemas\finding.schema.json` and `schemas\investigation.schema.json` | 0 | Both schema files valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:phase1-acceptance .` | 0 | Image built successfully using pinned Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`. |
| `docker run --rm chinescan:phase1-acceptance --help` | 0 | Container CLI help rendered and listed commands. |
| `docker build -f docker/Dockerfile -t chinescan:phase8-trends .` | 0 | Updated image containing scan-history trends built from the pinned Python base. |
| `docker run --rm -e CHINESCAN_DATABASE_PATH=/tmp/chinescan-trends.sqlite3 chinescan:phase8-trends trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from a fresh local SQLite database. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help rendered; lists version, code, logs, scan, report, compare, domain, config, case, and malware. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `\.venv\Scripts\chinescan.exe trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from an empty temporary local database. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` |
| Config init, validation, then malformed TOML validation using `tests\phase1-rerun-config.toml` | 0 / 0 / 2 | `Created configuration: tests\phase1-rerun-config.toml`; `Configuration is valid.`; `Unable to load configuration: Expected ']' at the end of a table declaration (at end of document)`. Temporary file removed. |

The initial Phase 1 report above retains its original dated results for audit history. This is the
latest full acceptance snapshot. No production target or external domain was contacted.

### Parser update acceptance — 2026-10-26

The full acceptance suite was rerun after adding support for classic syslog-prefixed CEF records.
This remains later-phase parser functionality in the combined worktree; Phase 1 scope is unchanged.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `70 passed`; total coverage `82.50%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChineScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; four low-severity subprocess findings are outside this threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 70ms`. |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| Python 3.12 JSON parsing of `schemas\finding.schema.json` and `schemas\investigation.schema.json` | 0 | Both schema files valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker run --rm chinescan:phase1-acceptance --help` | 0 | Container CLI help rendered and listed commands. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed version, code, logs, scan, report, compare, trends, domain, config, case, and malware. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `\.venv\Scripts\chinescan.exe trends --days 2 --format json` | 0 | Returned two daily buckets with `total_scans: 1` from the existing local database. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` |
| Config init, validation, and malformed TOML validation under `tests\phase1-rerun-config-continue.toml` | 0 / 0 / 2 | Created config; `Configuration is valid.`; `Unable to load configuration: Invalid value (at end of document)`. Temporary file removed. |
| `docker build -f docker/Dockerfile -t chinescan:phase4-syslog-cef .` | 0 | Image built from pinned Python 3.12.15 slim Trixie base. |
| `docker run --rm -v C:\src\Chinescan\fixtures\sample-logs:/logs:ro chinescan:phase4-syslog-cef logs /logs --format json` | 0 | `event_count: 21`, `source_count: 9`, `alert_count: 8`, `parse_error_count: 0`. |
| `docker run --rm -e CHINESCAN_DATABASE_PATH=/tmp/chinescan-trends.sqlite3 chinescan:phase1-acceptance trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from a fresh local SQLite database. |

No production target or external domain was contacted.

## Current audit acceptance rerun — 2026-10-26

These results were collected during the read-only development-status audit of the current
combined worktree. No application code was edited. Tests used the existing installed
environment; no dependency installation or image build was performed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `70 passed`; total coverage `82.27%`; 80% threshold reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChineScan distribution skipped. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 8ms`. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; configuration valid. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `py -3.12 -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |
| `.\.venv\Scripts\chinescan.exe --help` | 0 | Help lists version, code, logs, scan, report, compare, trends, domain, config, case, and malware. |
| `.\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `.\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` Expected explicit stub usage exit code. |
| `docker run --rm --network none chinescan:phase4-syslog-cef --help` | 0 | Existing local image rendered CLI help with no network. |

Not run: Docker image build (may fetch base/build dependencies from a registry), live domain
assessment, actual external-scanner binaries, YARA/ClamAV binaries, GitHub/GitLab remote CI,
and Bandit in this specific rerun. No production target or external domain was contacted.

## Local workflow hardening verification — 2026-10-26

The implementation run used the existing Python 3.12 environment and local tools. No
dependencies were installed and no images were fetched or built. The focused regression
suite first reported one test expectation error after missing explicitly selected config
files were made fatal; the test was corrected to cover the default-config-absent case. The
final full suite below passed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `86 passed in 12.27s`; total coverage `82.86%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `93 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChineScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; five low-severity findings remain below the requested threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 2ms`. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `py -3.12 -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; valid Compose configuration. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help includes global `--config` and `--database` options and existing commands. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | PowerShell `$LASTEXITCODE` was `2`; expected Phase 3 explicit stub. |
| `docker run --rm --network none chinescan:phase4-syslog-cef --help` | 0 | Existing local image rendered CLI help offline. The image was not rebuilt and does not include this worktree's new global options. |

Regression coverage added for shared archive expansion limits across multiple gzip inputs,
strict per-read byte bounds, an understated ZIP size declaration, malformed archives,
output overflow on both scanner streams, subprocess timeout/cancellation/JSON/exit paths,
settings precedence and secret redaction, validation before database creation, fresh and
legacy SQLite schemas, retained records, and incompatible-schema preservation. Ordinary
log fixture tests continue to pass. When the expanded-byte cap is reached, the member
using the remaining budget is rejected and all later inputs are skipped; previously parsed
events are retained.

Not run: Docker image build, remote CI, live domain probing, actual third-party scanner
binaries, or optional YARA/ClamAV binaries. The Docker build was skipped because it may
fetch images; no external targets or services were contacted. The timeout/cancel/output
tests use controlled local Python helpers or process doubles.

Known limits: output caps apply separately to stdout and stderr, and process termination
targets the direct scanner child (not an independently daemonized descendant). A legacy
database is accepted only for the exact initial table shape; other versions require an
explicit future migration. The migration downgrade in `0001_initial` still drops the
records table, so downgrade commands must not be used on data-bearing databases.


## Local investigation workflow verification — 2026-10-26

The local case workflow stage adds persisted case status and severity, typed links to existing
records, append-only notes and activity, ordered timelines, and redacted JSON/Markdown/HTML case
reports. `0002_case_workflow` is an application-payload revision over the existing generic JSON
record table; it does not rewrite payloads or change physical tables. Legacy unversioned stores
with the exact recognized initial schema are stamped at `0001_initial` and then upgraded to head.
Incompatible schemas are rejected without recreation. The report and schema are updated. No
production readiness is claimed.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `93 passed in 30.80s`; total coverage `82.78%`; required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `96 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 42 source files`. |
| `& .\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project skipped. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high findings; six low-severity findings remain below the selected threshold. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 112ms`; lock unchanged. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` and same for `investigation.schema.json` | 0 | Both schema files parse as JSON. |
| `& .\.venv\Scripts\chinescan.exe --help` and `case --help` | 0 | Existing CLI help and the new case commands render. |
| `& .\.venv\Scripts\chinescan.exe config init --path tests/.pytest-tmp/workflow-acceptance.toml` | 0 | Wrote local test configuration. |
| `& .\.venv\Scripts\chinescan.exe config validate --path tests/.pytest-tmp/workflow-acceptance.toml` | 0 | `Configuration is valid.` |

A direct `py -3.12 -m chinescan.cli.app --help` attempt returned exit 1 because the standalone
Python 3.12 interpreter does not have the project dependencies on its import path (`ModuleNotFoundError:
No module named 'typer'`). The equivalent existing-environment entry point, `& .\.venv\Scripts\chinescan.exe
--help` and `case --help`, passed as listed above. No JSON Schema metaschema validator was configured;
only JSON parsing was run.

The suite covers ordinary fixture-driven local ingestion, persisted/missing/dangling links, unsupported
non-persisted artifacts, invalid status transitions, note bounds, redaction and HTML escaping, deterministic
timelines and missing ingestion times, atomic report-write failures, fresh database creation, retained
legacy payloads through the supported upgrade, and incompatible schema preservation.

Docker image build was **NOT RUN** because it may fetch base images and the user did not authorize image
fetches. No live scanner, public target, malware execution, or upload was used. JSON parsing does not
establish full JSON Schema metaschema conformance. The migration stores notes/activity inside one JSON
case record; it has no relational foreign keys, and ingestion timestamps and structured remediation
content remain unavailable. Case author labels are unverified. This is local workflow validation, not a
production-readiness assessment.

Recommended next stage: define and test local data retention, backup/restore, and export handling for
case records, including recovery against a copied database and explicit policy for sensitive report files.


## Local data protection and recovery verification — 2026-10-26

Implemented a local recovery bundle and a dry-run backup retention planner. Backups use SQLite's
online backup API through a read-only source connection, stage a standalone database plus a
versioned manifest, verify them, and publish only at a new path. Manifest SHA-256 detects a mismatch
with the manifest; it is not authentication. Verification is read-only and distinguishes structural
errors, unsupported schema, and application consistency issues. It explicitly checks case links,
note/activity references, typed records, scan relationships, and other persisted links because case
links do not have SQL foreign keys. Restore requires a fully verified bundle, stages to a new file,
and runs existing Alembic migrations only on that staged copy. No database migration revision or
stored record format changed in this stage.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `104 passed in 20.87s`; total coverage `81.85%`; required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `98 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; six low-severity items remain below the configured threshold. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 2ms`; no lock changes. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas/finding.schema.json > $null` and `schemas/investigation.schema.json` | 0 | Both schema documents parse as JSON. |
| `git diff --check` | 0 | No whitespace errors; Git emitted its existing LF-to-CRLF working-copy notices. |

The recovery drill created local log-analysis records, a linked case, notes and status activity; created
and verified a backup; restored to a new path; reopened it through `SQLiteRepository`; compared case
IDs, status, links, notes, and activities; and rendered JSON, Markdown, and HTML reports. Separate
tests cover committed WAL data, missing source without accidental creation, existing destinations,
active database and hard-link aliases, cancellation and timeout staging cleanup, truncated/corrupt and
checksum-mismatched files, unsupported revisions, unversioned and 0001 legacy schemas, retained
payloads, dangling/invalid case relationships, invalid payloads, symlink-safe retention preview, and
case export no-overwrite behavior. CLI smoke checks completed `trends`, `db backup`, `db verify-backup`,
`db restore`, and `db retention-plan` using a temporary database; each exited 0 and the backup reported
`verified: true` at revision `0002_case_workflow`.

External dependency audit was **NOT RUN** because it would contact an advisory service and the request
forbids external requests without approval. No packages were installed. Docker image build was **NOT
RUN** because it may fetch images. No network target, external scanner, or malware sample was used.

Known limits: backups and exports are not encrypted. Checksums do not authenticate a bundle. Windows
mode-bit requests do not establish ACL protections; operators must review ACLs. Redaction is not
anonymization. Backup bundles preserve original sensitive records. Case links are checked at verify
time but remain without SQL foreign keys. Retention only previews; no backups or records are deleted.
A restore is published as a new file; active database replacement/cutover remains operator-controlled.
Case export publication uses same-directory hard links to prevent overwrite, so filesystems without
hard-link support fail closed. No production readiness is claimed.

Recommended next stage: conduct an operator-controlled cutover and rollback drill using a restored
copy, with documented downtime, database-path change, user verification, and recovery checkpoints.


## Recovery acceptance and operator cutover drill — 2026-10-26

Added `scripts/recovery_acceptance.py` and the operator sequence in `docs/RECOVERY-RUNBOOK.md`.
The script creates synthetic scan/log records and a case inside a temporary directory, closes the
repository before backup, creates and verifies a bundle, restores to a new database, and runs case
show, note list, timeline, and JSON/Markdown/HTML exports through the CLI with an explicit
`--database` path for each invocation. It adds a unique note only to the restored copy, selects the
original again, and verifies the original hash and case data remain intact. The restored-only note
remains divergent in the restored database; selecting the original does not merge it. The configuration
file is not changed, and neither the original nor backup bundle is replaced.

The drill refuses to invoke case commands against a missing selected file because ordinary
repository startup may initialize a database. This preflight prevents accidental creation within
the acceptance script; it does not change general CLI initialization behavior.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed in 26.30s`; total coverage `82.44%`; required 80% reached. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_migration.py tests/unit/test_recovery.py -q` | 0 | `17 passed in 9.08s`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 scripts/recovery_acceptance.py` | 0 | Completed; backup/case IDs emitted; JSON, Markdown, HTML generated; original intact; restored-only note stayed divergent. Temporary drill directory removed at process exit. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `100 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; six low-severity findings remain below threshold. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 trends --days 1 --format json` | 0 | Empty temporary database returned zero scans. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 db backup --output tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --format json` | 0 | Created bundle at revision `0002_case_workflow`; verification true. |
| `& .\.venv\Scripts\chinescan.exe db verify-backup tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --format json` | 0 | `verified: true`, no structural/application issues. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 db restore tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --output tests/.pytest-tmp/cli-smoke-acceptance-20261026a/restored.sqlite3 --format json` | 0 | Restored to a distinct path; source/result revisions both `0002_case_workflow`. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/restored.sqlite3 trends --days 1 --format json` | 0 | Restored database opened and returned zero scans. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 4ms`; no lock changes. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` and `schemas\investigation.schema.json` | 0 | Both schema files parse as JSON. |
| `git diff --check` | 0 | No whitespace errors; existing LF-to-CRLF worktree notices were emitted. |

The suite also verifies a failed/corrupt backup cannot be restored, missing drill database selection
does not create a file, restored-only notes are absent from the original, original and restored paths
are not confused, and failed case-report publication removes its temporary file. Supported migration
behavior is covered by the focused migration/recovery tests. A permission-denied destination test was
not run because reliable ACL denial is environment and privilege dependent on this Windows host.

**Recovery acceptance verdict: PASS for the bounded local synthetic drill.** This verifies local
application behavior only. It does not prove that unrelated processes have closed the database, that
a backup is authentic or encrypted, or that an operational cutover is production ready. Backup and
reports remain unencrypted, Windows ACLs require separate review, links lack SQL foreign keys, report
publication needs same-directory hard-link support, retention is preview-only, and divergent writes
are not merged. No network-backed audit or image build was run; no dependency was installed or
external service contacted.

Recommended next stage: controlled real scanner integration verification with authorized local
fixtures and isolated helper processes.

## Separate-project scanning guide verification — 2026-10-26

Added `docs/SCANNING-ANOTHER-PROJECT.md` after inspecting the current CLI, code scanner, external adapters, settings/configuration, SQLite path handling, reporting, and development documentation. Verification used only `fixtures/sample-python-project`; no real separate project, external scanner, domain, advisory service, or downloaded database was used. The database and generated report were placed under `C:\scan-results\my-application`.

| Exact command | Exit | Exact relevant result |
| --- | ---: | --- |
| `& .\.venv\Scripts\chinescan.exe --help` | 0 | CLI help lists `code`, `report`, and global `--database`. |
| `& .\.venv\Scripts\chinescan.exe code --help` | 0 | Help confirms target argument, repeatable `--scanner`, `--semgrep-rules`, `--timeout-seconds`, `--fail-on`, and `--allow-network-audits`. |
| `& .\.venv\Scripts\chinescan.exe --database "C:\scan-results\my-application\chinescan.sqlite3" code .\fixtures\sample-python-project --format json` | 0 | Returned scan ID `62cacaf8-e059-4893-8c40-a1af6da186cd`; `finding_count: 3`; `failures: {}`; scanner `builtin`; target is the synthetic Python fixture. |
| `& .\.venv\Scripts\chinescan.exe --database "C:\scan-results\my-application\chinescan.sqlite3" report 62cacaf8-e059-4893-8c40-a1af6da186cd --format markdown --output "C:\scan-results\my-application\scan-62cacaf8-e059-4893-8c40-a1af6da186cd.md"` | 0 | Wrote Markdown report to the external results folder; file size 687 bytes. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 23.05s`; coverage `82.44%`, required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `104 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 3ms`. |
| `Get-Command semgrep,gitleaks,trivy,pip-audit,npm -ErrorAction SilentlyContinue | Format-Table Name,Source -AutoSize` | 0 | Only `npm.ps1` was found at `C:\Program Files\nodejs\npm.ps1`; Semgrep, Gitleaks, Trivy, and pip-audit were not found by this check. No external scanner was run. |

NOT RUN: dependency advisory audit because it contacts external advisory services; Docker build because it may fetch images; all actual external scanner executions; scanning from a separate live target; and runtime web assessment. The CLI invocations and outputs above verify local scan and Markdown report mechanics only. No application code was changed for this guide.

Additional exact working-directory check: from `C:\src\Chinescan\fixtures\sample-python-project`, `& $exe --database $db code . --format json` exited 0 and returned scan ID `0176dc24-673a-4472-b4ed-802104760390`, three findings, and no failures (`$exe` was the absolute ChineScan executable and `$db` the external database path). From that same working directory, `& $exe --database $db report 0176dc24-673a-4472-b4ed-802104760390 --format markdown --output 'C:\scan-results\my-application\scan-0176dc24-673a-4472-b4ed-802104760390.md'` exited 0 and wrote a 687-byte report outside the fixture.

## Offline verification — 2026-10-26

Commands ran from `C:\src\Chinescan` with Python 3.12.10. To use the existing Python 3.12
environment's installed tools without installing dependencies, PowerShell set
`$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'` before the commands below.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `py -3.12 -m ruff format --check .` | 0 | `105 files already formatted` |
| `py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 43 source files` |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 31.59s`; total coverage `82.44%`, required 80% reached. |

No dependencies were installed. Gitleaks was unavailable, so a local credential-pattern scan examined
147 intended files without printing matched contents. It reported three expected synthetic patterns
under `fixtures/real-scanners/gitleaks-positive/credential.txt`,
`fixtures/sample-python-project/app.py`, and `tests/integration/test_real_scanners.py`; no operational
database, backup, environment-secret, or investigation-export filenames were found. This pattern
scan is not a substitute for Gitleaks. Docker, external scanner, and network-backed checks were not
run.

## Merge verification — 2026-10-26

After resolving the merge of upstream `f06d43a`, checks ran from `C:\src\Chinescan` with Python
3.12.10 and the existing `.venv\Lib\site-packages` on `PYTHONPATH`. No dependencies were installed.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `py -3.12 -m ruff format --check .` | 0 | `106 files already formatted` |
| `py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 43 source files` |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 22.65s`; total coverage `82.44%`, required 80% reached. |
| PyYAML parse of `.github/workflows/ci.yml` and `.github/dependabot.yml` | 0 | `YAML parse passed`. |
| `git diff --check` and `git diff --cached --check` | 0 | Both passed. |

## Authenticated dashboard Slice 1 verification — 2026-10-26

Added FastAPI, Uvicorn, argon2-cffi, and the Starlette-compatible `httpx2` API test transport to
the existing `uv` project environment. Added React/React DOM, Vite, TypeScript, React typings,
Vitest, jsdom, and Testing Library to `frontend/`. Direct dependencies are recorded in
`pyproject.toml` and `frontend/package.json`; exact resolutions are recorded in `uv.lock` and
`frontend/package-lock.json`. A lock comparison confirmed that no previously locked Python package
version changed; only dashboard dependencies and their transitive packages were added.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `115 passed, 5 deselected in 30.36s`; total coverage `83.05%`, required 80% reached. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff format --check .` | 0 | `111 files already formatted`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 2ms`. |
| `npm ci --no-audit; npm run typecheck; npm test -- --reporter=dot; npm run build` (from `frontend/`) | 0 | Clean lockfile install; TypeScript check passed; `1` Vitest file and `2` tests passed; Vite production build passed (`index.html` 0.47 kB, CSS 17.64 kB, JS 239.27 kB). |
| `& .\.venv\Scripts\chinescan.exe --help; ... web --help; ... web bootstrap --help; ... web serve --help` | 0 | Help lists explicit `web bootstrap` and `web serve`; server options have no host override. |
| Live loopback HTTP harness using `uvicorn.Server` on an ephemeral `127.0.0.1` socket | 0 | Served the built production shell; unauthenticated overview returned 401; sign-in set HttpOnly/SameSite=Strict cookie; persisted empty overview returned zero scans/findings; logout revoked access (subsequent request returned 401). Temporary credentials/database were removed. |
| `git diff --check` | 0 | Passed; Git emitted line-ending conversion notices only. |

The API tests exercise CLI bootstrap and repository-path rejection, protected reads, real SQLite
summary/detail data, bounded pagination and allowlisted filters/sorts, severity ordering, body and
validation limits, CSRF rejection, login throttling, host/origin rejection, session expiry, logout
revocation, new-application session invalidation, and fixed loopback/single-worker startup options.
The component tests exercise unauthorized login, backend-loaded metrics, and honest empty states.
Browser-level verification was **NOT RUN**; no browser binaries were downloaded. Domain probes,
external scanners, and other external services were not run.

`pip-audit` was **NOT RUN** because it queries an external advisory service, outside the approved
package-download scope. During initial npm package installation, npm also emitted its default
registry audit output (`0 vulnerabilities`); the final acceptance install used `--no-audit`.

## Chinetscan dashboard Slice 2 verification — 2026-10-26

The authenticated dashboard now exposes persisted cases and report downloads through the existing
`CaseWorkflow` and reporting renderers. No dependencies were installed or upgraded for Slice 2; the
existing lockfiles remain consistent.

| Exact command or check | Exit | Actual result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `116 passed, 5 deselected in 194.36s`; total coverage `83.28%`, above 80%. |
| `& .\\.venv312\\Scripts\\uv.exe run --offline ruff check .` | 0 | `All checks passed!` |
| `& .\\.venv312\\Scripts\\uv.exe run --offline ruff format --check .` | 0 | `111 files already formatted`. |
| `$env:PYTHONPATH='C:\\src\\Chinescan;.venv\\Lib\\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\\.venv312\\Scripts\\uv.exe lock --check` | 0 | `Resolved 76 packages`. |
| `npm --prefix frontend run typecheck` | 0 | TypeScript project build passed. |
| `npm --prefix frontend test -- --reporter=dot` | 0 | `2` test files, `5` tests passed (3 new case workflow tests plus the existing 2 dashboard tests). |
| `npm --prefix frontend run build` | 0 | Vite production build passed; CSS 20.43 kB and JS 248.96 kB (uncompressed). |
| Temporary live Uvicorn service bound to `127.0.0.1:8765`; HTTPX2 local smoke harness | 0 | Verified production shell, unauthenticated denial, sign-in, scan detail, filtered case listing, create/link/note/status, all case and scan report formats as attachments, logout revocation. Synthetic credentials/database were created under the user temp directory and removed afterward. |
| `git diff --check` | 0 | Passed; Git emitted line-ending conversion notices only. |

The five deselected tests are marked `real_scanner` by `tests/integration/test_real_scanners.py` and
are intentionally excluded by `tests/conftest.py`; they require external scanner binaries and
integration conditions that were not part of this local dashboard verification. No external
services were contacted.

Browser verification was **NOT PERFORMED**. The in-app browser control was available, but its local
browser view attach timed out. Checks for installed Chrome, Edge, Firefox, and Chromium executables
returned none. No browser binary was downloaded. To run the requested full browser smoke, approval is
needed to install a compatible Chromium-based browser binary and, if the existing browser control
remains unavailable, a Playwright-compatible browser test runtime and its browser package. The live
HTTP harness is API verification and is not represented as browser testing.

## Chinetscan dashboard browser acceptance — 2026-10-26

This section supersedes the earlier NOT PERFORMED note above. The user approved only the npm
registry packages required for `@playwright/test` and Playwright's official Chromium assets. The
frontend lockfile now resolves `@playwright/test` 1.64.1. `npx playwright install chromium` downloaded
Chrome for Testing 156.0.8078.4 and the matching Playwright headless shell from Playwright's official
distribution. No package or browser was installed globally. The `npm install` and clean `npm ci`
commands both used `--no-audit`.

The browser harness serves the actual built `frontend/dist` from `create_app` using a temporary
SQLite database containing synthetic scans, findings, and an event. It generates random operator
credentials under a unique temporary directory, starts two Python services on ephemeral
`127.0.0.1` ports, uses only loopback requests, and removes the services and temporary directories
after each run. Credential values, cookies, browser profiles, and Playwright artifacts are not
tracked. Browser traces and screenshots are configured for failures only; the successful run
produced no failure artifacts.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `npm install --save-dev @playwright/test --no-audit` (from `frontend/`) | 0 | Added 3 packages; lockfile updated with `@playwright/test` 1.64.1. |
| `npx playwright install chromium` (from `frontend/`) | 0 | Installed official Chrome for Testing 156.0.8078.4 and matching headless shell. |
| `npm ci --no-audit` (from `frontend/`) | 0 | Clean lockfile install; added 106 packages. |
| `npm run test:e2e` (from `frontend/`) | 0 | Chromium: `3 passed` (production dashboard workflow, finding detail/XSS text handling, and a scan request held in flight until session expiry); `34.3s`. No tests skipped. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `116 passed, 5 deselected in 96.02s`; total coverage `83.28%`, above 80%. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff format --check .` | 0 | `112 files already formatted`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 60ms`; Python lockfile consistent. |
| `npm run typecheck` (from `frontend/`) | 0 | `tsc -b --pretty false` passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | `2` component-test files and `5` tests passed. Vitest's test timeout was raised to tolerate this host's slow jsdom startup. |
| `npm run build` (from `frontend/`) | 0 | Production build passed; CSS 20.43 kB, JS 249.11 kB (uncompressed). |
| `git diff --check` | 0 | Passed; only existing LF-to-CRLF notices were printed. |

The five Python tests deselected by `tests/conftest.py` carry the `real_scanner` marker and require
external scanner binaries; they were not part of this local browser acceptance. No assessment job,
external target, advisory service, or external upload was used. The browser suite explicitly checked
that its intentional pre-login/session-expiry 401s and invalid-scan 404 were the only failed API
responses, with no unexpected browser console errors or server errors.

**Browser acceptance verdict: PASS** for the requested dashboard Slices 1 and 2 workflows against
the production frontend and local authenticated backend.

## Dashboard Slice 3A — local code-assessment jobs — 2026-10-26

Implemented an operator TOML project registry, authenticated and CSRF-protected job creation,
persisted job state, one worker with four waiting slots, startup interruption reconciliation, bounded
job listing/detail, and a dashboard form/list with two-second polling while active jobs are present.
The dashboard uses only `BuiltinRuleScanner` through `CodeScanService`; optional engines and
network-backed dependency checks cannot be requested. Jobs return a scan ID only after the service
has persisted the scan and result records. The UI opens the persisted scan and finding IDs and uses
the existing case workflow. Project IDs, names, and roots are operator configured outside the
browser; API responses omit full paths and raw logs.

Path validation resolves configured roots strictly and excludes the database directory, operator
credential file, and registry file. It rejects symlinked path components and symlink/junction entries
found during a preflight tree walk. The existing scanner does not follow directory symlinks and skips
symlink files. This remains vulnerable to a time-of-check/time-of-use change after validation; it is
not OS filesystem isolation. Built-in scanning has file-count and byte bounds but no safely
interruptible wall-clock timeout. Graceful shutdown waits for active work. A restarted server marks
persisted queued/running jobs interrupted without asserting that an OS process was terminated.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | Final isolated run: `123 passed, 5 deselected in 193.86s`; total coverage `83.59%`, threshold 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `115 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files`. |
| `npm run typecheck` (from `frontend/`) | 0 | TypeScript project check passed. |
| `npm test` (from `frontend/`) | 0 | `3` test files and `7` component tests passed. |
| `npm run build` (from `frontend/`) | 0 | Final Vite production build passed; CSS `21.21 kB`, JavaScript `254.67 kB` (uncompressed). |
| `npm run test:e2e` (from `frontend/`) | 0 | Full run after the case-selection race fix: `4 passed` in `2.3m`, including the complete job/result/case/refresh path and session-expiry coverage. A later run after registry hardening produced `3 passed, 1 failed` because the 15-second expiry fixture expired before the Overview page finished signing in on this slow host. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 3ms`; no lock changes. |
| `& .\.venv\Scripts\chinescan.exe web serve --help` | 0 | Help includes `--projects-file`, port, and credential options. |
| `git diff --check` | 0 | Passed; Git printed existing LF-to-CRLF working-copy notices. |

The five deselected Python tests require real optional scanner binaries. They were not run. No
dependency was installed, scanner or rules database downloaded, external target contacted, or
network-backed audit performed. Queue bounds, duplicate active project submission, failed scanner
and persistence outcomes, auth/CSRF, unknown project, missing/protected roots, symlink rejection,
restart reconciliation, and no fixture modification have focused backend tests. Browser acceptance
used only synthetic local fixture source and the existing Playwright installation.

Known limitations: queue depth is fixed at four waiting jobs; there is no cancellation or progress
percentage; built-in scans have no hard elapsed-time limit; abrupt filesystem changes can race the
preflight walk; scan writes are existing per-record repository operations rather than a new atomic
multi-record transaction. This slice does not claim comprehensive security coverage or production
readiness. Recommended next stage: design and verify a cancellable, resource-limited worker boundary
with atomic scan-result publication before adding additional assessment types.

The final isolated Playwright retry `npx playwright test -c playwright.config.ts --project=chromium-session-expiry`
exited 1 before executing tests: the Python dashboard fixture did
not start within its 60-second harness startup window (no server stderr was emitted). This is an
harness-level startup timeout with undetermined cause, separate from the 15-second session expiry
observed in the preceding full-suite rerun. The complete job workflow itself passed in both
full-suite reruns.

## Dashboard Slice 3A stabilization — 2026-10-26

Root cause separation: the earlier expiry failure happened in the dedicated 15-second session
fixture while the Overview transition was still in progress. The standard dashboard fixture has its
own 1,800-second TTL. The existing captured output does not establish why the separate local Python
fixture failed to announce readiness within 60 seconds; it emitted no stderr, so that event is
classified as an undiagnosed fixture startup failure, not attributed to the host. No authentication
bypass, retry, or longer production session lifetime was introduced.

The browser harness now captures bounded diagnostics (last 4,000 characters per output stream),
checks early process exit, confirms Python 3.12 and repository-root working directory through its
explicit `py -3.12` launch, uses the server's OS-assigned loopback port, and requires an actual HTTP
401 from `/api/auth/session` before declaring readiness. One reproduction printed its URL just after
the previous 60-second announcement bound; the bounded announcement window is now 120 seconds, with
a separate 10-second HTTP readiness bound. Failed setup and normal teardown terminate only the
test-owned process tree and remove its temporary data. The existing real 15-second expiry and
server-side 401 behavior are unchanged; expiry uses observable request/session conditions, not a
fixed sleep. Playwright retries remain disabled.

A later browser failure snapshot showed the production page still displaying `Signing in…` when the
test asserted Overview content. The production browser test now waits for a successful login
response and the visible Overview heading before checking stored records; it does not expand global
expectation or session timeouts.

Project roots automatically exclude the active SQLite parent directory (database and sidecars),
operator credentials, and registry. Operator `protected_paths` remains available for additional
backup/report storage. This dashboard has no managed backup or report/export directory; reports are
generated in memory. Roots are strictly resolved, link/junction entries are rejected where
supported, overlap checks work in both directions, and registry/tree checks run again before
execution. The filesystem check/open race remains and this is not sandbox isolation.

The scanner previously omitted individual source files over 1 MB, which could look like a clean
result. It now reports that input-limit exhaustion as a scan failure. Existing limits are 1 MB per
source, 20,000 source files, and 250 MB aggregate source bytes. The queue allows four waiting jobs;
one worker executes at a time. These are separate from elapsed-time limits and cancellation, neither
of which exists. Graceful shutdown waits for an active scan. Restart reconciliation marks unfinished
jobs interrupted but does not prove process termination. Failed scan-result persistence produces a
sanitized failed job record. A hard deadline needs a worker-process boundary and is outside this
stabilization.

The five deselected tests are the opt-in tests in `tests/integration/test_real_scanners.py`; they
require the actual Semgrep, Gitleaks, Trivy, YARA, and ClamAV executables, plus local Trivy/ClamAV
database assets. These are deliberately not installed or fetched during this run.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `set PYTHONPATH=C:\src\Chinescan;.venv\Lib\site-packages&& py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `126 passed, 5 deselected in 156.59s`; total coverage `83.62%` (80% threshold met). |
| `.venv\Scripts\ruff.exe check . && .venv\Scripts\ruff.exe format --check .` | 0 | `All checks passed!`; `115 files already formatted`. |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files`. |
| `node_modules\.bin\tsc -b --pretty false` (from `frontend/`) | 0 | TypeScript project check passed. |
| `node_modules\.bin\vitest run` (from `frontend/`) | 0 | `3` files and `7` tests passed. |
| `node_modules\.bin\vite build` (from `frontend/`) | 0 | Production build passed; JS `254.67 kB`, CSS `21.21 kB`. |
| `node_modules\.bin\playwright test -c playwright.config.ts` (from `frontend/`), run 1 | 0 | `4 passed` in `2.4m`; expiry case `33.4s`. |
| Same complete Playwright command, run 2 | 0 | `4 passed` in `1.4m`; expiry case `24.7s`. |
| Same complete Playwright command, run 3 | 0 | `4 passed` in `53.6s`; expiry case `20.6s`. |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 4ms`; lock unchanged. |
| `git diff --check` | 0 | Passed; Git emitted existing LF-to-CRLF working-copy notices. |

No dependencies were installed, no external service was contacted, and no real scanner was run.
Browser acceptance is qualified to the local synthetic fixture and these three consecutive clean
suite runs. Worker execution still has no hard deadline or cancellation, and filesystem path checks
do not provide an OS sandbox.

## Dashboard release verification — 2026-10-26

Current local verification for the stabilized dashboard release scope. The five real-scanner tests
remain deselected; they require Semgrep, Gitleaks, Trivy, YARA, and ClamAV binaries (and local Trivy
or ClamAV data where applicable). No real scanner or remote target was used.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `set PYTHONPATH=C:\src\Chinescan;C:\src\Chinescan\.venv\Lib\site-packages && py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `126 passed, 5 deselected in 160.08s`; total coverage `83.62%`, above 80%. |
| `.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `.venv\Scripts\ruff.exe format --check .` | 0 | `115 files already formatted` |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files` |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 250ms`; Python lock unchanged. |
| `npm ci --dry-run --no-audit` (from `frontend/`) | 0 | `up to date in 13s`; npm lockfile and manifest are consistent. No packages were installed. |
| `npm ls --depth=0` (from `frontend/`) | 0 | All 13 declared direct frontend dependencies resolved to the installed versions. |
| `npm run typecheck` (from `frontend/`) | 0 | `tsc -b --pretty false` passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | `3` files and `7` component tests passed. |
| `npm run build` (from `frontend/`) | 0 | Production build passed; CSS `21.21 kB`, JavaScript `254.67 kB` (uncompressed). |
| `npm run test:e2e` (from `frontend/`) | 0 | `4 passed` in `1.3m` using local synthetic data and Chromium. |
| `.venv\Scripts\chinescan.exe web serve --help` | 0 | Confirms explicit startup, one worker on `127.0.0.1`, default port `8765`, and optional credential/project file paths. |
| `.venv\Scripts\chinescan.exe web bootstrap --help` | 0 | Confirms explicit operator bootstrap and required `--username`; password is entered interactively. |
| `.venv\Scripts\chinescan.exe code --help` | 0 | Confirms local project target, built-in default scanner, optional scanner selection, and network-audit consent flag. |
| `.venv\Scripts\chinescan.exe db --help` | 0 | Confirms backup, verify-backup, restore, and retention-plan commands. |

The first browser acceptance attempt failed before tests because the Windows Python launcher did not
inherit the project environment's Uvicorn dependency. The harness now adds the local Windows
environment only when using `py`; CI supplies its locked `.venv` interpreter explicitly. The
complete browser run above passed after that correction. Failure diagnostics omit the harness
stdout because it contains generated login credentials. `npm ci --no-audit` remains enforced in
CI; local verification used the already installed dependencies and did not reinstall packages.
