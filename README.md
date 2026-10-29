# ChineScan

ChineScan is a local security assessment and investigation tool. It scans local code, analyzes exported logs and local malware samples, performs domain posture checks only with explicit authorization, and supports investigations and reports. Findings need analyst review; this tool does not establish that a system is safe.

## What Chinescan does

ChineScan helps operators collect and review leads from local assessment workflows. Code scanning reads source files without executing project code. The indicator scanner compares project files with indicator data supplied from local files and operates offline. Other capabilities include exported-log analysis, static malware triage, explicitly authorized domain posture checks, cases, reporting, and database backup and recovery.

## Workable features

- Code scanning with built-in heuristic rules and optional scanner integrations. The `indicators` scanner matches local project files against local indicator files.
- Optional finding evidence grades: `confirmed_artifact`, `pattern_match`, `reference_only`, and `context_only`. Evidence grade is separate from confidence; existing findings may omit a grade.
- Code-scan coverage accounting records examined files and coverage gaps. Verdicts are `leads_found`, `no_matches_with_gaps`, `no_matches_in_scope`, and `scan_failed`.
- Code scans automatically save JSON and Markdown reports. Log, malware, and domain scans do not currently auto-save JSON or Markdown reports.
- A local authenticated web dashboard provides sign-in only. There is no sign-up or registration flow.

## CLI quick start

Install Python 3.12 or newer and [uv](https://docs.astral.sh/uv/), then install the project:

```powershell
uv sync --extra dev
uv run chinescan --help
```

Initialize local configuration and inspect it:

```powershell
uv run chinescan config init
uv run chinescan config validate --path "$HOME/.config/chinescan/config.toml"
```

Commands and their options are also available through `chinescan <command> --help`. Configuration initialization does not write secret values.

## Code scan examples

Run built-in rules against a local project. JSON and Markdown reports are saved automatically:

```powershell
uv run chinescan code .
```

Add local indicator matching (see the next section), disable automatic report saving, or return a failure status when coverage gaps are recorded:

```powershell
uv run chinescan code . --scanner builtin --scanner indicators --indicator-file .\indicators.json
uv run chinescan code . --no-save-report
uv run chinescan code . --fail-on-gaps
```

`--fail-on-gaps` exits with status 1 when the scan records coverage gaps. Scanner failures also produce a nonzero exit. A verdict summarizes findings and coverage; it is not a safety determination.

## Indicator scanning examples

The `indicators` scanner requires one or more local files passed with `--indicator-file`. It reads supported JSON, CSV, or text IOC formats, plus supported STIX 2.1 bundle indicator entries and MISP event attributes. Support is limited to the formats and entry types implemented by the parser; unsupported entries may be reported as coverage gaps. Input files are not fetched from URLs, and the scanner does not resolve or contact indicator values. Indicator matching is strictly offline and accepts only local indicator files.

```powershell
uv run chinescan code . --scanner indicators --indicator-file .\indicators.json
uv run chinescan code . --scanner indicators --indicator-file .\domains.txt --indicator-file .\hashes.csv
```

## Reports and share summaries

Only code scans automatically save JSON and Markdown reports. The default directory is `~/.local/share/chinescan/reports`; set it with the global `--reports-dir` option or `CHINESCAN_REPORTS_DIR`. You can also set `reports_dir` in the local TOML configuration. Use `--no-save-report` to opt out for a code scan.

Reports for persisted scans can be rendered as JSON, Markdown, HTML, CSV, SARIF, or `share-summary`:

```powershell
uv run chinescan report <scan-id> --format share-summary --output .\share-summary.md
```

A share summary contains the verdict and caveat, evidence and severity counts, coverage gaps, indicator-file names and hashes when recorded, and up to ten lead titles with evidence grades and locations. It omits finding descriptions and absolute paths, redacts sensitive values, and masks indicator IDs in lead titles. Review a generated summary before sharing; redaction is not a substitute for checking its contents.

Log, malware, and domain scans do not currently auto-save JSON or Markdown reports. This does not prevent supported explicit report commands from rendering stored scan records.

## Web dashboard sign-in

Prepare local operator sign-in credentials with the CLI bootstrap command, then start the dashboard:

```powershell
uv run chinescan web bootstrap
uv run chinescan web serve
```

The bootstrap command prompts for a username and password and stores local sign-in credentials outside the repository. The dashboard has sign-in only; it has no sign-up or registration flow. The server binds to `127.0.0.1` by default.

The dashboard shows recent scans, verdicts and coverage gaps, scan details, failures and warnings, and JSON/Markdown report downloads for code scans. Access to scans, cases, evidence, reports, and job controls requires authentication.

## Configuration

Configuration can come from the local TOML file and `CHINESCAN_` environment variables. CLI settings take precedence where supported. The reports directory can be set with:

```powershell
$env:CHINESCAN_REPORTS_DIR = "$HOME/chinescan-reports"
uv run chinescan --reports-dir "$HOME/chinescan-reports" code .
```

The default SQLite database and report locations are local user-data paths. Config initialization never writes secret values; logs redact secret-like values.

## Security and responsible use

Use ChineScan only on assets and data you own or are explicitly authorized to assess. Code and indicator scans operate on local files; code scanning does not execute project code. The indicator scanner is offline. Domain posture checks perform network activity and require explicit target authorization. Optional package audit integrations can send dependency metadata to advisory services only when explicitly enabled with `--allow-network-audits`.

Malware analysis is static triage: samples are not executed or uploaded. It is not an OS sandbox. The dashboard is local and authenticated; do not expose it publicly. Matches are leads, not proof; no matches do not prove safety. Coverage gaps and scanner failures limit what a scan can say. ChineScan does not provide protection, threat removal, or complete detection coverage.

## Development and tests

Install development dependencies and run the local checks:

```powershell
uv sync --extra dev
uv run --locked --extra dev ruff check .
uv run --locked --extra dev mypy --strict chinescan
uv run --locked --extra dev pytest -q
```

The frontend checks are run from `frontend/`:

```powershell
npm ci
npm run typecheck
npm test -- --run
```
