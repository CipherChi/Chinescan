# Operator log-source registry

Log-analysis jobs read local exports only. Configure the registry before starting the dashboard;
the browser can select a source ID but cannot submit a path or modify detection inputs.

By default the server reads `~/.config/chinescan/log-sources.toml`. Override it with:

```powershell
chinescan web serve --log-sources-file C:/secure/config/log-sources.toml
```

Example:

```toml
# Optional additional exclusions for local exports, backups, or sensitive inputs.
protected_paths = ["C:/scan-data/backups", "C:/scan-data/private"]

[[sources]]
id = "auth-export"
name = "Authentication export"
root = "C:/scan-data/auth-logs"
rules = "C:/scan-data/rules"
iocs = "C:/scan-data/iocs.txt"

[[sources]]
id = "web-export"
name = "Web server export"
root = "C:/scan-data/web-logs"
```

Each entry requires a unique stable `id` (1–80 characters), a display `name` (1–120 characters),
and an absolute local `root`. Optional `rules` must be a local Sigma rules file/directory; optional
`iocs` must be a local IOC file. These paths are operator-owned and never accepted through the API.
Do not put the source tree, rules, IOC file, credentials, or registry in the active database
directory. Roots overlapping the database directory, credentials, project registry, or log-source
registry are rejected. Keep source and rules files locally controlled while a job runs.

Jobs perform read-only ingestion. Gzip, ZIP, and tar members are streamed and never extracted.
Existing bounds cap ingestion at 10,000 files, 25 MB per file, 250 MB total input/expanded data,
1,000 archive members, 100 MB per archive, and 100,000 normalized events. One job runs at a time
with four waiting slots. There is no cancellation or hard elapsed-time deadline. Symlinks and
Windows junctions are rejected where the platform exposes them, but path checks cannot prevent a
filesystem change between validation and open; this is not an OS sandbox.

Inspect `partial` jobs and scan diagnostics as incomplete. Parsing errors, unsupported content,
archive exhaustion, event/file/byte limits, invalid IOC/rule inputs, or unsupported Sigma conditions
must not be treated as complete results. Raw input lines are not persisted or returned to the browser;
normalized events can still contain sensitive evidence and remain in local SQLite. Protect the DB
and backups using host controls. Windows POSIX mode bits do not establish ACL protections.

Detection rules are operator-configured. Built-in detections are small candidate heuristics. The
Sigma subset uses safe YAML parsing, field alias normalization, case-insensitive glob matching,
`contains`, `startswith`, and `endswith` modifiers, optional `all` value matching, and Boolean
`and`/`or`/`not`, parentheses, and `all`/`any`/`1 of` selector patterns. Timeframes, pipelines,
correlation semantics, arbitrary modifiers, and general Sigma specification behavior are not
implemented. It is not comprehensive enterprise detection. The dashboard makes no network calls,
uses no remote collectors or enrichment, and uploads no logs.
