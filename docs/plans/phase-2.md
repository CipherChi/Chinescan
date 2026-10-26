# Phase 2 plan: local codebase assessment

## Scope

Implement local-only code project detection, a built-in heuristic scanner, explicit
Semgrep/Gitleaks/Trivy adapters, finding normalization and stable fingerprints,
failure-isolated concurrent orchestration, and SQLite target/scan/finding persistence. The
CLI accepts a local directory and emits a redacted summary or JSON. Future domain,
log, malware, report, and case workflows remain out of scope.

## Decisions

- Only the built-in scanner runs by default. External engines run only when selected
  by name; executables are invoked without a shell and with bounded timeouts.
- Static adapters do not upload source or findings. Semgrep uses local rules with
  metrics disabled; Trivy skips vulnerability, Java, and check database updates and
  disables remote dependency lookups.
- Findings contain rule identifiers and source locations, never source snippets or
  secret values. Human output contains counts and severities only.
- Findings deduplicate by normalized target, category, rule identifier, and location.
  Each scanner failure is reported without discarding successful results.
- Package-manager audits that require remote advisory services are available only
  behind `--allow-network-audits`, which makes the package metadata transfer explicit.
  Python auditing requires `requirements.txt`; npm auditing requires both `package.json`
  and `package-lock.json`.

## Implementation order

1. Add project type detection, the local rule scanner, finding metadata, and stable
   fingerprint helpers.
2. Add subprocess adapters and parsers for Semgrep, Gitleaks, Trivy, pip-audit, and
   npm audit JSON output.
3. Add bounded orchestration, failure isolation, normalization, deduplication, and
   storage of scan and finding records.
4. Replace the Phase 2 `code` stub with a local-only CLI command; leave other future
   commands as usage-error stubs.
5. Add deterministic Python and Node fixtures, adapter/orchestration/CLI tests, and
   update architecture, roadmap, and Phase 2 verification report.
6. Run acceptance using Python 3.12, Ruff, mypy, pytest, pip-audit, CLI fixtures,
   and Docker build.

## Security boundaries and limitations

The implementation does not execute project code, install dependencies, scan Git
history, or analyze binaries. Package advisory checks contact their upstream services
only when explicitly enabled; they submit dependency metadata, not source files.
Built-in rules are heuristics and produce candidate findings that require analyst
validation. External scanner output is treated as untrusted input; only normalized
metadata is persisted.
