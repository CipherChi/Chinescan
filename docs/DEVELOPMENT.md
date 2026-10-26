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

Malware static triage reads one regular file up to 64 MiB, never executes it, and does not copy or persist sample bytes or analysis results. It counts printable strings but never returns their contents. By default, CLI summaries omit indicator values; `--include-indicators` explicitly displays them. YARA rules and ClamAV scanning are opt-in local tools with timeouts; they do not enable a network service or sandbox. This is not malware intake/storage, memory analysis, or dynamic analysis.

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
