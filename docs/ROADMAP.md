# Roadmap

- Phase 1: platform foundation, canonical records, local config/logging/storage, and CLI contracts. Complete.
- Phase 2: codebase assessment with project detection, local and explicit scanner adapters, normalization, deduplication, and scan storage. Implemented with the limits below.
- Phase 3: JSON, Markdown, HTML, CSV, and SARIF reporting; case workflows and scan comparison. Implemented; see the Phase 3 verification report.
- Phase 4: log ingestion, normalized events, timelines, detections, and IOC correlation. Implemented; see the Phase 4 verification report.
- Phase 5: static triage and Stage B1 backend managed-copy intake, bounded persistence, and a Windows Job Object worker are implemented. There are no malware dashboard routes, browser transfers, case links, retention/deletion controls, memory analysis, or dynamic analysis. See the Phase 5 report and `MALWARE-BACKEND.md`.
- Phase 6: bounded authorized domain posture assessment implemented; broader external scanner adapters deferred. See the Phase 6 verification report.
- Phase 7: Slice 1 authenticated loopback dashboard implemented; cases/reports/jobs remain deferred. See the Phase 7 plan.
- Phase 8: partial CI and operational-readiness work implemented; local scan-history trends and revision-keyed offline benchmark artifacts are available. Cross-revision performance analysis and deployment remain pending. See the Phase 8 plan and report.

Phase 2's built-in rules are a small heuristic ruleset, not a comprehensive SAST engine. Semgrep requires a local rules file. Trivy runs with its local cache and skips database and policy updates. Python and Node advisory scans require explicit `--allow-network-audits` consent and send dependency metadata to advisory services. All findings are candidate results that require analyst validation.
