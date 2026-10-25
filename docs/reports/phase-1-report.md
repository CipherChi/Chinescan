# Phase 1 verification report

Recorded 2026-10-25. Python 3.12.10 was newly installed after the user authorized installation. The standalone repository is `C:\src\Chinescan`; the parent repository was not staged or changed.

## Outcome

Platform foundation implemented: package metadata and lock, versioned records and schemas, config, redaction and JSON logging, protocols and fake scanner, SQLite repository and Alembic migration, Typer CLI, tests, project policies/docs, Compose, and CI workflow.

All available code checks passed. The Docker acceptance build was not run: the daemon is available, but no Python base image is cached. The environment instructions limit network use to package indexes, so fetching an image from a container registry was not permitted. As a result, the Docker base is version-tagged but not digest-pinned, and Phase 1's Docker acceptance criterion remains incomplete. This is a deviation from the Docker plan and must be resolved by supplying/verifying an immutable digest within an authorized registry workflow.

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
| 9. Docker, Compose, `.dockerignore`, CI | PARTIAL | Compose config passed. Docker daemon is running, but Python base image is absent locally; build not run because registry access is outside the documented network scope. Dockerfile base digest requirement is unmet. |
| 10. Acceptance checks and report | PARTIAL | All listed non-container checks passed and are recorded below. Docker build remains incomplete. |

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
- Docker build was not run despite daemon availability because the required Python base image was not cached and registry access is outside the recorded network scope. The Dockerfile consequently lacks the immutable base digest required by the plan; Docker acceptance is not complete.
- Only `pyproject.toml` and `uv.lock` were committed, as directed by plan task 2. No other files were committed or pushed.

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
