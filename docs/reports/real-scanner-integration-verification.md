# Real scanner integration verification

Date: 2026-10-26
Platform: Windows, Python 3.12.10
Status: **No real scanner binary was available; real-binary verification is blocked.**

## Local inventory

Executable discovery used PowerShell `Get-Command` for each adapter executable. None were on
`PATH`, so no version command could be run and no direct or adapter invocation against a real
binary was performed.

| Tool | Local version/path | Adapter | Local assets | Readiness / result |
| --- | --- | --- | --- | --- |
| Semgrep | Not installed/on PATH | `SemgrepScanner`; local rules required; accepts exit 0/1 | Added local YAML rule and positive/clean Python fixtures | Blocked by missing binary; no network rules are used by the adapter. |
| Gitleaks | Not installed/on PATH | `GitleaksScanner`; built-in rules; accepts exit 0/1; omits matched secret value | Added synthetic GitHub-token-like positive fixture and clean negative fixture; no custom-config option exists in adapter | Blocked by missing binary. Synthetic value is not a credential. |
| Trivy | Not installed/on PATH | `TrivyScanner`; filesystem vuln/misconfig/secret; database-update flags disabled and offline mode selected; accepts exit 0 | Added local Dockerfile fixtures. No cache found under the standard Windows cache path; `TRIVY_CACHE_DIR` was unset. No vulnerability DB available to the adapter. | Blocked by missing binary and local database. No vulnerability coverage can be claimed. |
| YARA | Not installed/on PATH | `run_yara`; local rules; only exit 0 is currently treated as success | Existing `fixtures/sample-malware/marker.yar`, plus a separate harmless positive and negative fixture/rule | Blocked by missing binary. The integration test requires a clean no-match with no warning and will expose exit-code incompatibility if observed. No defect is claimed without execution. |
| ClamAV (`clamscan`) | Not installed/on PATH | `run_clamav`; local scan; accepts exit 0/1 | Added benign clean-file fixture. No `.cvd` or `.cld` signatures found in standard Windows locations. No positive signature fixture was introduced. | Blocked by missing binary and signatures. Positive scan not run. |

CI currently declares Gitleaks `v8.30.1` and Trivy `v0.76.1`; these are configuration pins only,
not local binary versions or integration evidence. There are no current Semgrep, YARA, or ClamAV pins
in the repository. The repository does not contain a Trivy DB or ClamAV signatures. YARA's local
rule is user-controlled and needs no signature database.

## Direct and adapter invocation evidence

The test module contains the bounded commands below. Each command is **not run** because its binary
was absent; version commands were likewise not run. This table is a reproducible plan, not execution
evidence.

| Tool | Direct command against local fixture | Adapter/service invocation and expected check | Result |
| --- | --- | --- | --- |
| Semgrep | `semgrep scan --config fixtures/real-scanners/semgrep-local.yml --json --metrics=off --quiet --no-git-ignore fixtures/real-scanners/semgrep-positive` | `SemgrepScanner(config_path=local_rule).scan(positive)` and `CodeScanService` persistence/JSON report; expected local rule ID and `app.py:1`; clean fixture expected empty | Not run; binary missing. |
| Gitleaks | `gitleaks detect --source fixtures/real-scanners/gitleaks-positive --report-format json --report-path - --no-banner` | `GitleaksScanner().scan(positive)` plus persistence/JSON report; expected rule/file/line, synthetic token absent from report; clean fixture expected empty | Not run; binary missing. |
| Trivy | `trivy fs --format json --scanners vuln,misconfig,secret --skip-db-update --skip-java-db-update --skip-check-update --offline-scan fixtures/real-scanners/trivy-local-config` | `TrivyScanner().scan(local_config)` plus persistence/JSON report; reviewed root-user configuration expected; clean fixture expected empty | Not run; binary and DB missing. |
| YARA | `yara -w fixtures/real-scanners/yara-local.yar fixtures/real-scanners/yara-positive.txt` (and the clean fixture) | `run_yara(positive, local_rules)` and `run_yara(negative, local_rules)`; expected marker then clean no-match without warning | Not run; binary missing. |
| ClamAV | `clamscan --no-summary fixtures/real-scanners/clamav-clean.txt` | `run_clamav(clean_fixture)`; expected clean result, no positive test | Not run; binary and signatures missing. |

The integration tests assert normalized metadata for scanner fields that their adapters expose.
Semgrep/Gitleaks/Trivy support persisted code findings and JSON reports. YARA/ClamAV are optional
malware-analysis engine summaries and do not currently persist normalized findings or render scan
reports; this output is not invented by the integration harness.

## Controlled fixtures and test selection

Added reviewed local fixtures under `fixtures/real-scanners/`: a Semgrep rule and matching/clean
source, an obviously synthetic Gitleaks-like token and clean text, a harmless YARA marker rule and
positive/negative text, Trivy root-user and non-root Dockerfiles, and a ClamAV clean text file. No
fixture is executed. No malware, EICAR string, real credential, signature update, remote rule, or
network service was used.

`tests/integration/test_real_scanners.py` is separately selectable. Default unit runs deselect these
tests. `--run-real-scanners` runs them and reports missing binaries/assets as skips. Strict
`--require-real-scanners` fails on each missing required binary or local database so an all-skipped
run cannot be called successful. Direct invocations use `shell=False`, an environment allowlist,
tool-specific offline/telemetry options, a 60-second timeout, and a 1 MB output cap. This is
tool-level configuration only: the Windows environment did not enforce network isolation, so
absence of network access was **not** verified.

Commands:

```powershell
$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'
py -3.12 -m pytest tests/integration -m real_scanner --run-real-scanners -q
py -3.12 -m pytest tests/integration -m real_scanner --require-real-scanners -q
```

The first command skips when tools/assets are absent. The strict command fails until required local
tools and assets have been provisioned. Actual results on this host:

| Command | Result |
| --- | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/integration -m real_scanner --run-real-scanners -q -rs` | Exit 0; `5 skipped in 0.96s`. Each skip names the missing executable: Semgrep, Gitleaks, Trivy, YARA, and clamscan. No scanner process ran. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/integration -m real_scanner --require-real-scanners -q` | Exit 1 as intended; `5 failed in 0.79s`, one for each missing executable. This confirms strict mode blocks an all-missing run from passing. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | Exit 0; `108 passed, 5 deselected in 26.18s`; total coverage `82.44%`. Default tests do not invoke real scanners. |
| `& .\.venv\Scripts\ruff.exe check .` | Exit 0; `All checks passed!`. |
| `& .\.venv\Scripts\ruff.exe format --check .` | Exit 0; `104 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | Exit 0; `Success: no issues found in 43 source files`. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | Exit 0; no medium/high issues; six low-severity issues remain below the threshold. |
| `& .\.venv\Scripts\chinescan.exe code --help` and `& .\.venv\Scripts\chinescan.exe malware analyze --help` | Exit 0; both installed CLI help commands rendered successfully. |
| `git diff --check` | Exit 0; no whitespace errors. Existing LF-to-CRLF notices remain. |

## Evidence classification

| Adapter | Real binary | Existing non-integration evidence | Fields covered when real tests can run |
| --- | --- | --- | --- |
| Semgrep | Blocked; not run | Mock-only parser/error checks | Rule ID, file/line, severity, negative result, persisted finding, JSON report. |
| Gitleaks | Blocked; not run | Mock-only parser/error checks | Rule ID, file/line, severity/category, negative result, secret redaction, persistence/report. |
| Trivy | Blocked; not run | Mock-only parser/error checks | Offline filesystem result, normalized rule/category, clean fixture, persistence/report; DB-dependent checks require local DB. |
| YARA | Blocked; not run | Mock-only engine checks | Local rule match, clean negative, exit status and warning behavior. |
| ClamAV | Blocked; not run | Mock-only engine checks | Local clean-file exit and adapter result; no positive fixture. |

No compatibility defect was demonstrated because no scanner process ran. In particular, YARA
no-match exit handling remains an explicit integration check rather than a claimed fix. Canonical
severity and confidence were not changed.

## CI job design (proposal only)

Do not enable a remote job until the user approves scanner provisioning and runner isolation.

1. **Provisioning job:** use an ephemeral, isolated runner to obtain exact pinned binaries and
   verify their release checksums. Reuse the repository's current Gitleaks `v8.30.1` and Trivy
   `v0.76.1` pins only after compatibility is exercised. Select and approve exact Semgrep, YARA, and
   ClamAV versions before provisioning; none are currently pinned. Provision Trivy vulnerability
   DB and ClamAV signatures in this stage only from approved sources; record their creation date,
   upstream version, and digest. Do not update assets in the execution stage.
2. **Offline integration job:** use a separate disposable worker with enforced egress denial at the
   worker/network layer. Verify binary versions and asset digests before tests; run
   `pytest tests/integration -m real_scanner --require-real-scanners`. Keep tool telemetry/update
   switches disabled as an additional control, not as proof of isolation.
3. **Artifacts:** retain JUnit results with scanner version properties, DB/signature versions and
   digests, and a sanitized summary. Never retain raw scanner JSON, matched secret values, user
   source, credentials, or full environment dumps. Cache freshness must be visible; a stale local
   DB limits vulnerability/signature coverage even when the job passes.

This design has not been activated or run remotely. No dependency, image, scanner, or signature
database was downloaded for this verification stage.
