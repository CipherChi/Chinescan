# ChineScan

ChineScan is an authorization-first security investigation platform. Implemented capabilities include local code assessment, reports and cases, exported-log analysis, ephemeral static malware triage, and a bounded authorized domain posture check. Malware sample intake/storage, memory analysis, dynamic sandboxing, and the web service remain unimplemented.

## Requirements

- Python 3.12 or newer
- `uv` for environment and dependency management

## Quick start

```powershell
uv sync --extra dev
uv run chinescan --help
uv run chinescan version
uv run chinescan code ./fixtures/sample-python-project
uv run chinescan code ./fixtures/sample-python-project --fail-on high
uv run chinescan code ./fixtures/sample-node-project --format json
uv run chinescan logs ./fixtures/sample-logs --rules ./fixtures/sample-logs --ioc-file ./fixtures/sample-iocs.txt --format json
uv run chinescan malware analyze ./fixtures/sample-malware/synthetic-indicators.txt --format json
```

Initialize a local configuration with `uv run chinescan config init`; provide `--path` to choose a location. Initialization writes no credentials. The SQLite database defaults to the platform user-data directory and can be overridden with `CHINESCAN_DATABASE_PATH`.

The built-in code scanner is local and never executes project files. Select `--scanner semgrep`, `--scanner gitleaks`, or `--scanner trivy` to use an installed engine. Semgrep requires a local rules file through `--semgrep-rules`; Trivy uses cached data without database updates. `pip-audit` and `npm-audit` are available only with explicit `--allow-network-audits` consent because they send dependency metadata to advisory services.

Generate JSON, Markdown, HTML, CSV, or SARIF 2.1.0 for a persisted scan with `chinescan report SCAN_ID --format sarif --output report.sarif`. Use `chinescan case create --from-scan SCAN_ID`, `chinescan case show CASE_ID`, and `chinescan case update CASE_ID --status in_progress` to track investigation status. Compare two stored scans with `chinescan compare BASELINE_SCAN_ID CURRENT_SCAN_ID`.

Analyze local exported logs with `chinescan logs ./logs --rules ./sigma-rules --ioc-file ./iocs.txt`. JSON, JSONL, CSV, Linux auth/syslog, common nginx/Apache/IIS access logs, CEF, and LEEF are supported, along with gzip, ZIP, and tar archives. Windows and cloud data must be exported as JSON or CSV. Archives are read without extraction; raw log lines are not stored. Built-in detections and the supported Sigma subset produce candidate alerts that require analyst review.

Run `chinescan malware analyze ./sample.bin` for bounded, non-executing local static triage. It calculates MD5, SHA-1, and SHA-256, identifies common file signatures, counts printable strings without displaying them, lists bounded ZIP member metadata without extraction, and extracts candidate network/email indicators. Indicator values are hidden unless `--include-indicators` is passed. YARA and ClamAV are opt-in through `--yara-rules` and `--clamav` and require locally installed tools. The command does not copy, retain, encrypt, or persist sample bytes; malware intake/storage, memory analysis, and dynamic detonation are not implemented.

Assess one domain you own with `chinescan domain example.com --i-own-this-target --operator "Analyst"`. For delegated work, pass `--authorization-file authorization.json` containing the exact `target`, `granted_by`, timezone-aware `valid_from` and `valid_until` timestamps, and `profile` (`light` or `deep`). The command records authorization and the configured limits locally before network access. Set `--timeout` from 0.1 to 10 seconds, `--max-addresses` from one to five for deep scans, and `--request-interval` from zero to five seconds. The built-in light profile resolves the exact hostname and checks one public address; deep checks up to the configured public address cap. Each address receives one HTTPS `HEAD`; if HTTPS fails for all selected addresses, the probe makes one HTTP `HEAD` fallback per selected address. It does not follow redirects, read response bodies, scan ports, enumerate subdomains, or run vulnerability templates. JSON output is available with `--format json`.

For local backup/restore guidance, upgrade precautions, and current deployment limits, see [Operations and deployment](docs/DEPLOYMENT.md).

## Safety boundary

Only use ChineScan against assets for which you have explicit authorization. Code, log, and static file analysis run locally; domain posture checks require explicit target authorization and contact only public addresses returned for that exact hostname. Malware sample intake/storage and a network service are not implemented. Findings, alerts, and extracted indicators are candidates for analyst validation. See [Responsible Use](docs/RESPONSIBLE_USE.md).
