# Phase 2 verification report

Recorded 2026-10-25. Implementation and acceptance checks were run from
`C:\src\Chinescan` with Python 3.12.10.

## Outcome

The code assessment path is implemented. `chinescan code <local-directory>` detects
Python and Node project markers, runs a built-in local heuristic scanner by default,
normalizes and merges findings, and stores target/scan/finding records in configured SQLite.
Semgrep, Gitleaks, Trivy, pip-audit, and npm audit adapters are available by explicit
selection. Non-networking scanner adapters are timeout-bounded; advisory checks require
the explicit `--allow-network-audits` option.

## Architecture decisions

- No new Python dependencies were added. External tools are called through argument
  arrays with `shell=False`.
- Built-in rules inspect local source only and never execute project files. Source
  files are capped at 1 MB each, 20,000 files per project, and 250 MB total.
- Semgrep accepts a local rules file only, with metrics disabled. Trivy skips
  vulnerability, Java, and check updates and disables remote lookups.
- pip-audit and npm audit send dependency metadata to advisory services only after
  explicit CLI consent. Python auditing needs `requirements.txt`; npm auditing needs
  both `package.json` and `package-lock.json`.
- Finding fingerprints use normalized target/category/rule/location. Duplicate
  findings merge scanner attribution, tags, maximum severity, and strongest
  confidence deterministically. Source snippets and matched secret values are omitted.

## Installation and use

```powershell
uv sync --locked --extra dev
uv run chinescan code ./fixtures/sample-python-project
uv run chinescan code ./fixtures/sample-node-project --format json
```

The Python fixture produced three candidate findings (three HIGH). The Node fixture
produced one candidate finding. Human output shows counts only; JSON
output includes normalized metadata and omits matched credential values.

Optional local scanners can be selected with repeated `--scanner` options. Semgrep
requires `--semgrep-rules PATH`. Example advisory use is
`chinescan code ./project --scanner pip-audit --allow-network-audits`; this sends
dependency metadata to the advisory service and was not run during this verification.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | Resolved and checked 54 packages. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 4ms`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `56 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 25 source files`. |
| `\.venv\Scripts\pytest.exe --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `26 passed`; total coverage `92.72%`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped. |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON; schema generated from `Finding`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built from pinned Python digest `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help lists `code` and Phase 1 commands. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `\.venv\Scripts\chinescan.exe code .\fixtures\sample-python-project` | 0 | `3 candidate finding(s)`; project type `python`; three HIGH. |
| `\.venv\Scripts\chinescan.exe code .\fixtures\sample-node-project --format json` | 0 | JSON summary: `finding_count: 1`; project type `node`; no failures. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | Explicit future-phase stub message; expected usage exit code. |

The fixture commands used `CHINESCAN_DATABASE_PATH=tests\phase2-acceptance.sqlite3`;
the temporary database was removed. `Get-Command semgrep,gitleaks,trivy,npm` found npm
but not Semgrep, Gitleaks, or Trivy. Their JSON adapters and subprocess constraints
were verified with mocked processes; no live external scanner execution was available.

## Security and known limitations

- Built-in checks are a small heuristic ruleset and can miss vulnerabilities or flag
  safe code. Treat every result as a candidate for analyst validation.
- Semgrep has no bundled ruleset. Trivy needs pre-populated local databases; an empty
  or stale cache can yield scanner errors or incomplete dependency coverage.
- Python advisory analysis currently reads `requirements.txt`; npm advisory analysis
  reads the lockfile. Both contact upstream services only with explicit consent.
- External scanner binaries were not installed in this environment, so only adapter
  parsers and command construction were tested here.
- Malware intake, reports/cases, domain assessments, log analysis, and web services
  remain out of scope.

## Definition of Done

- [x] Python and Node project types detected; sample code commands return normalized findings.
- [x] Built-in local scanner, Semgrep/Gitleaks/Trivy adapters, and opt-in package audit adapters implemented.
- [x] Finding category/confidence schema, stable fingerprints, deterministic deduplication, and SQLite persistence implemented.
- [x] Scanner failures are isolated; subprocesses are shell-free and bounded by timeout.
- [x] Tests cover fixtures, adapters, failure isolation, storage, CLI consent, and deduplication.
- [x] Ruff, strict mypy, test suite, dependency audit, CLI fixtures, and Docker build pass.
- [ ] Validate live Semgrep/Gitleaks/Trivy adapters in an environment with those binaries and suitable local rules/cache.

## Next recommended phase

Phase 3: report generation and case management.
