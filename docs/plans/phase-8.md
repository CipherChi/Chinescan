# Phase 8 plan: CI/CD and operational readiness

## Scope

Complete the portions that do not require a deployment target or network service: full-package
coverage enforcement, configurable severity-based CLI exit thresholds, GitHub Actions and GitLab
CI examples, local scan-history trends, and accurate deployment limitations. No image publishing,
production deployment, secret provisioning, or rollback automation will be enabled without a
configured environment.

## Implementation

1. Enforce the existing 80% coverage floor across the full package in GitHub Actions.
2. Add `chinescan code --fail-on` with `critical`, `high`, `medium`, `low`, `info`, and `never`.
   Keep `never` as the default to preserve existing CLI behavior.
3. Add an offline benchmark for code scanning and log parsing, then store revision-keyed results
   as CI artifacts for comparison.
4. Add a read-only `chinescan trends` command that summarizes daily local scan/finding/alert counts.
5. Add a GitLab CI example with the same lock, lint, formatting, type, coverage, dependency-audit,
   and Bandit checks. Pin its Python image to the verified digest.
6. Document local database backup/restore, upgrade, retention, and incident-handling limitations.
7. Keep deployment disabled until hosting, registry, credentials, health checks, backup, migration,
   and rollback details are approved and available.
8. Run Python 3.12 tests, Ruff, strict mypy, CLI threshold checks, lock/schema checks, GitLab YAML
   parsing, Compose validation, and a Docker build.

## Limits

Production deployment is not completed in this phase slice. The repository has no configured remote
environment or release credentials. The Phase 7 dashboard remains constrained by the no-listener
repository instruction.
