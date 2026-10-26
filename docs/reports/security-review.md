# Security review notes

Recorded 2026-10-25 against the current worktree. This review includes uncommitted files; it does not imply they comply with the Phase 1 scope or are approved for commit.

## Static analysis

Bandit 1.9.4 scanned 3,024 lines in `chinescan/` and reported no medium or high severity issues. The default all-severity run reported three low-severity findings:

| Finding | Location | Assessment | Owner / review date |
| --- | --- | --- | --- |
| B101 `assert_used` | `chinescan/log_analysis/service.py:151` | Resolved 2026-10-26: persistence now raises an explicit `RuntimeError` if called without a repository. |
| B404 `subprocess` import | `chinescan/scanners/external.py:8` | Expected for the external-scanner adapter. Review the full argument construction and timeout before enabling the feature. | CipherChi / 2026-11-25 |
| B603 subprocess call | `chinescan/scanners/external.py:78` | Low generic alert. The inspected call uses an argument vector, `shell=False`, an execution timeout, controlled environment, and accepted exit-code checks. Keep these controls and validate scanner paths/configuration before release. | CipherChi / 2026-11-25 |

The subprocess findings are not suppressed: CI fails on Bandit medium/high findings, while the full local scan and low-severity triage remain recorded here. The subprocess findings concern explicit scanner integrations and should be reassessed against their final interfaces.

## Application changes

- **Credential redaction gap (high):** `Authorization: Bearer <value>` previously redacted only the word `Bearer`, leaving the credential visible. Authorization-keyed mappings also bypassed mapping redaction. The redactor now consumes common bearer/basic schemes and treats authorization keys as secret; regression coverage checks both forms.
- **Config initialization race (low):** initialization previously checked for an existing path and then wrote non-exclusively, allowing a concurrent file to be overwritten. Creation now uses exclusive mode and reports a conflict without replacing the file; a regression check simulates the race.
- **Child-process environment exposure (moderate):** external scanner processes previously inherited the complete parent environment, including possible cloud or registry credentials. They now receive only an OS/runtime environment allowlist. A regression check ensures a secret-like variable is not forwarded.
- **CSV formula injection (moderate):** exported finding fields could begin with spreadsheet formula markers. CSV exports now prefix formula-like and control-character-leading cells with an apostrophe; a regression check covers formula and tab-prefixed cells.

## GitHub alerts

On 2026-10-25, GitHub verified the repository is public. Secret scanning and push protection are enabled, with zero open secret-scanning alerts; non-provider patterns are disabled. Code-scanning alerts returned “no analysis found”; Dependabot security alerts are disabled; private vulnerability reporting is disabled; branch `main` has no protection. One collaborator is listed (the owner). These results describe the current public repository state and do not carry over automatically if visibility or plan eligibility changes.

The latest remote CI run (run `40195117001`, commit `6e7c002`) passed `quality` and failed `container` because the committed Dockerfile renamed its wheel to the invalid filename `/tmp/chinescan.whl`. The local Dockerfile now preserves the generated wheel filename, installs runtime dependencies from the hash-locked export, and builds successfully. The updated workflow has only been syntax-checked locally; it cannot be verified on GitHub until changes are approved and pushed.

Gitleaks 8.30.1 (release archive checksum verified) scanned the two-commit Git history with no findings. A scan of tracked and unignored worktree source paths also found no leaks. A broad scan that included the local ignored `.venv` reported 202 pattern matches, all located under `.venv`; those generated environment matches were not confirmed as credentials and the directory is ignored. The virtual environment was not staged or cleaned.

Trivy 0.76.1 (release archive checksum verified) scanned the Dockerfile for high/critical misconfigurations and found none. Its default config discovery did not identify `docker-compose.yml`; Compose syntax was checked separately with `docker compose config --quiet`.

The initial Bookworm image scan reported 63 high/critical OS package advisories. The base was moved to the newer, digest-pinned Python 3.12.15 Trixie image and runtime dependencies now install from the hashed `uv.lock` export. The rebuilt image scan reported 44 high findings: 43 with status `affected`, one `fix_deferred`, and no fixed version; no critical or Python library findings were returned. No available package fix was identified by Trivy 0.76.1 on 2026-10-25. These OS findings are temporarily accepted in the scanned base image; CI prints the full findings and fails when a high/critical fix becomes available. Owner: CipherChi. Review by 2026-11-25, and after each base-image refresh.

## Phase 5 static-analysis addendum

Recorded 2026-10-26. The assertion in `log_analysis/service.py` was replaced with explicit invariant handling. The all-severity `bandit -r chinescan` run now exits 1 for four low findings: subprocess import/call in `scanners/external.py` and subprocess import/call in `malware_analysis/engines.py`. These are explicit scanner integrations; both select executables from `PATH`, pass argument lists with `shell=False`, use timeouts and controlled environments, and bound output. The malware integration's timeout is 30 seconds. No Bandit finding was suppressed.
