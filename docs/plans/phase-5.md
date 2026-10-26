# Phase 5 plan: local malware static triage

## Scope and repository guardrail

Implement `chinescan malware analyze <path>` as a bounded, non-executing static analyzer for one
local regular file. Report hashes, best-effort file identification, a count of printable strings,
and candidate IP/domain/URL/email indicators. Recognize PE, ELF, PDF, OLE/Office, ZIP/Office Open XML,
and common archive signatures; list bounded archive members without extracting or recursively
opening them. Optional YARA and ClamAV adapters may run only when explicitly selected with a local
rules file or executable already installed.

The repository instructions prohibit claiming malware intake or sample storage is implemented.
Accordingly, this phase will not copy, quarantine, retain, encrypt, or persist submitted sample
bytes; the analyzer reads the supplied path transiently and stores no sample or analysis payload.
The summary will display hashes and bounded indicator metadata only. No submitted bytes or
extracted content will be printed. No file is executed, uploaded, or sent to a network service.

Memory-image analysis and dynamic sandbox integration remain explicit exit-2 stubs. This phase
does not claim the overall Phase 5 acceptance criteria for sample intake/storage are complete.

## Safety limits

- Accept one non-symlink regular file up to a documented maximum size; reject directories,
  device paths, symlinks, and oversized files before reading.
- Bound string and IOC extraction counts/lengths and cap archive listings at 1,000 members; do not decompress archives or follow archive
  member paths.
- Hash the exact bytes read and compare file metadata before and after processing; report a
  changed-file error if the source changed during the read.
- External YARA/ClamAV adapters use argument arrays, no shell, controlled environment, explicit
  timeout, bounded output, and no network flags. They are opt-in and never modify the sample.
- Treat all identified file types, extracted indicators, and signatures as candidate evidence,
  not a malware verdict. Redact secrets and avoid emitting raw strings by default.

## Implementation and acceptance

1. Add a pure local analyzer with bounded streaming hash calculation, signature identification,
   PE/ELF metadata hints, safe archive member listing, and candidate IOC extraction.
2. Add opt-in, timeout-bounded YARA and ClamAV adapters with mockable subprocess boundaries.
3. Add `malware analyze` JSON/human output and explicit `malware memory` and `malware detonate`
   stubs returning usage exit code 2.
4. Add synthetic fixture files and tests proving sample bytes are never executed, copied, or
   persisted; cover malformed and oversized inputs, signatures, IOCs, archives, and scanner
   failures/timeouts.
5. Update CLI, architecture, development/security documentation, schemas if records change,
   roadmap, and this phase's verification report. Avoid schema changes if results remain ephemeral.
6. Run Python 3.12, Ruff, strict mypy, pytest with coverage, pip-audit, lock/schema checks, CLI
   fixture analysis, Compose validation, and Docker build; record exact results.
