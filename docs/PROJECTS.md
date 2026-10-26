# Approved project registry and dashboard operation

The dashboard accepts code assessments only for projects configured by the local operator. The
browser cannot add or edit registry entries and never submits an arbitrary path.

## Configure approved projects

Create `~/.config/chinescan/projects.toml` (or choose a file with `chinescan web serve
--projects-file PATH`) with one `[[projects]]` entry per project:

```toml
protected_paths = ["C:/scan-data/backups", "C:/scan-data/reports"]

[[projects]]
id = "service-a"           # stable ID, unique in this file
name = "Service A"         # browser display name
root = "C:/work/service-a" # explicit local directory
```

Use absolute local roots. The server resolves each directory strictly, rejects missing/non-directory
roots, duplicate or malformed IDs, and roots overlapping protected application data. The active
SQLite database directory (including its database and sidecar files), operator credential file,
and project registry file are excluded automatically; this also rejects a project containing one
of those locations. Add operator-selected backup or report storage directories to `protected_paths`.
There is no separately configured dashboard report/export directory in this slice: dashboard
reports are generated in memory. Backup storage is not managed by this dashboard.
Invalid entries do not appear in the project selector; a root is resolved again when a job is
submitted and immediately before scanning.

## Start and review assessments

Run `chinescan web serve` explicitly. The service remains a single worker bound to loopback. Sign in,
open **Code assessments**, choose an approved project, and start the assessment. One job runs at a
time; four more can wait. Repeated submissions for the same queued or active project are rejected.
The browser polls every two seconds only while visible jobs are queued or running. Jobs remain in
SQLite across refreshes and link to their actual persisted scan and finding IDs. Create a case from
the persisted scan using the existing case form. Session expiry returns the dashboard to sign-in.

Only built-in local source checks run from the dashboard. They do not execute project code, package
scripts, or install dependencies. Optional scanners are unavailable through this interface. No
network-backed dependency checks run. The scanner bounds source files to 20,000, each to 1 MB, and
aggregate source bytes to 250 MB. There is no hard wall-clock timeout or cancellation because the
built-in synchronous scan cannot be safely stopped in its current execution model. The server waits
for an in-flight assessment during graceful shutdown. Abrupt server loss is marked `interrupted`
when the next server starts; this state does not prove an operating-system process was terminated.

The server rejects symlinks and Windows junctions found during validation where the platform exposes
them, and the scanner does not follow directory symlinks or read symlink files. It revalidates the
project registry and tree before execution. A filesystem entry can still change after validation and
before it is opened; ordinary path checks cannot close that race. This design is not filesystem
isolation. Use roots that are stable and locally controlled during assessment. Dashboard responses
do not include full roots, source text, or raw logs. This feature is a local workflow, not a claim of
comprehensive security coverage or production readiness.
