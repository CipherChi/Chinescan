# Phase 6 verification report

Recorded 2026-10-26 in `C:\src\Chinescan` with Python 3.12.10.

## Outcome and boundary

This is a partial Phase 6 delivery. `chinescan domain <hostname>` supports an explicit
`--i-own-this-target --operator ...` ownership assertion or a local JSON authorization grant with
an exact normalized hostname, granting operator, timezone-aware validity window, and matching
profile. The authorization record and a running scan record are saved in the configured local
SQLite database before the probe is called.

The built-in assessor resolves the exact hostname and connects only to public addresses, capped at
five. The light profile sends one HTTPS HEAD request to one selected address. Deep sends one HTTPS
HEAD request to each selected address. If every HTTPS request fails, the probe makes one HTTP HEAD
fallback per selected address. It reads only bounded response headers, does not follow redirects,
and does not read response bodies. DNS and connect/TLS/HTTP timeouts are configurable from 0.1 to
10 seconds (default three seconds); the deep-profile address cap is configurable from one to five,
and sequential request spacing from zero to five seconds. These values are persisted in the scan
record before probing. No ports, subdomains, or vulnerability templates are scanned.

Broader external scanner adapters from the original Phase 6 scope are deferred. Their traffic and
scope need a separate review. They have not been represented as implemented here.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `85 files already formatted`. |
| `\.venv\Scripts\mypy.exe chinescan` | 0 | `Success: no issues found in 40 source files`. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `60 passed`; total coverage `81.64%` (required 80%). |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChineScan distribution skipped. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 5ms`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON; schema includes `AuthorizationRecord`. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built using the pinned Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help lists the `domain` command. |
| `\.venv\Scripts\chinescan.exe domain example.com` | 2 | Rejected for missing explicit authorization before database creation or network access. |
| `docker run --rm chinescan:0.1.0 domain example.com` | 2 | Rejected for missing explicit authorization; no live target was contacted. |
| `git diff --check` | 0 | No whitespace errors; Git printed standard LF-to-CRLF working-tree notices. |

The offline domain tests cover IDNA normalization and invalid targets, ownership assertions,
authorization-file scope and expiry, rejection before database/network access, audit persistence
before probing, public-address filtering, the five-address ceiling, profile request counts,
configurable limits and request spacing, and header-only HTTP parsing. All network functions are
mocked; no live domain was assessed.

## Definition of done

- [x] Add exact-host authorization inputs and persist authorization before network activity.
- [x] Add a bounded DNS/TLS/HTTP HEAD assessor with public-address filtering and no body reads.
- [x] Make timeouts, request spacing, and the address cap configurable and persist them with scans.
- [x] Add JSON/human CLI output and reject unauthorized requests with usage exit code 2.
- [x] Add offline tests, schema, docs, and roadmap updates.
- [x] Python 3.12, Ruff, strict mypy, tests/coverage, pip-audit, lock, schema, Compose, and Docker
  checks pass.
- [ ] Broad external scanner adapters remain deferred pending a separate scope and traffic review.

## Public GitHub import work — 2026-11-01

This is an incomplete implementation checkpoint on `hardening/github-import`, based on main at
`1548986`. The required Phase 5A report cleanup was committed separately as `82b2989`; the Phase 1
report now matches commit `ac1a6f4`, and the moved notes are in `phase-5a-report.md`.

Implemented in this checkpoint: a pure ASCII URL/ref validator with rejection coverage for unsafe
schemes, hosts, credentials, ports, encoded path separators/dots, Unicode, extra path segments,
malformed owners/repositories, and Git reference syntax; bounded configuration fields; authenticated
API paths and CLI commands that return `feature_disabled` while the default flag is false; and a
diagnostics check for the flag and local Git availability. No network or subprocess is used by URL
preview validation.

The feature is not complete and must remain disabled. With the flag set true, API/CLI import paths
return `import_unavailable`; there is no clone runner, background job store, session-bound preview
registry, project creation/removal integration, or frontend dialog. Therefore clone options and
redirect behavior have not been verified, and this branch must not be enabled or treated as ready
for import. There are no frontend or E2E results or screenshots for this checkpoint.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `uv run pytest tests/unit/test_github_import.py tests/unit/test_projects.py::test_github_import_api_is_stably_disabled_by_default -q --basetemp <OS-temp>` | 0 | 41 passed. |
| `uv run pytest --cov=chinescan --cov-report=term --cov-fail-under=80 --basetemp <OS-temp>` | 0 | 381 passed, 5 deselected; 81.62% total coverage. |
| `uv run ruff check .` | 0 | All checks passed. |
| `uv run ruff format --check .` | 0 | 158 files already formatted. |
| `uv run mypy --strict chinescan` | 0 | No issues in 65 source files. |
| `uv run bandit --severity-level medium -r chinescan` | 0 | No medium/high findings; 12 low findings remain; no `nosec` exclusions. |
| `uv run python -m compileall -q chinescan` | 0 | Passed. |

No frontend/E2E, Git flag/redirect verification, gitleaks, push, or pull request was completed for
this checkpoint. Remaining work includes the full managed-copy lifecycle and all Phase 6 acceptance
gates in the task request.
