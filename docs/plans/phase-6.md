# Phase 6 plan: explicitly authorized domain assessment

## Scope

Implement `chinescan domain <hostname>` with a mandatory authorization gate and auditable local
record. Support two authorization inputs: the explicit `--i-own-this-target` assertion paired
with an operator identity, or a local JSON authorization file with exact hostname scope, operator,
grant time, optional expiry, and profile. Record authorization before any network request.

The initial built-in light profile performs bounded DNS resolution and checks one resolved public
address with one HTTPS HEAD request; if HTTPS fails, it makes one HTTP HEAD fallback. It does not
follow redirects or read response bodies. Deep performs one HTTPS HEAD per resolved public
address (capped at five), with one HTTP HEAD fallback per address only if every HTTPS check fails.
It reports address records, certificate dates/subject/issuer, HTTP status and selected security
headers. No default port sweep, subdomain brute force, exploit/test templates,
credential attempts, or broad crawling.

Use an injectable probe protocol. Do not invoke subdomain enumeration, Nmap port scans, testssl,
or Nuclei vulnerability templates in this phase: they expand scope or run broader active checks
than the exact-host posture probe. Tests mock all network operations; acceptance will not contact
a real target.

## Authorization and safety requirements

- Reject URLs, IP literals, localhost/single-label names, malformed IDNA, and targets outside the
  exact authorized hostname. Do not implicitly widen file authorization to subdomains.
- Require explicit ownership flag plus operator identity or a readable local authorization file;
  never prompt and infer consent silently.
- Authorization JSON must match the normalized requested host exactly, be within its validity
  window, have a nonempty operator, and use a recognized `light`/`deep` profile.
- Persist an `AuthorizationRecord` with target, method, operator, timestamp, scan profile, and scan
  ID before starting any scanner. Failed or interrupted scans retain that record and scan status.
- Enforce timeouts, response/output caps, request/connect ceilings, no redirects, and low default
  concurrency. No network listener or external evidence service is added.
- Expose DNS/connect timeout (0.1–10 seconds), deep-profile address cap (1–5), and sequential
  request interval (0–5 seconds) as CLI options. Persist these settings with the scan before
  network activity.
- Do not silently fetch templates/rules or update databases.

## Implementation and acceptance

1. Extend typed records for `AuthorizationRecord` and persist authorization with domain scans.
2. Add injectable DNS/HTTP/TLS probe protocols and a low-impact default assessor that can be
   tested entirely with fakes.
3. Keep the built-in probe independent of vendor tooling; broad external scanning adapters are
   deferred until a separately reviewed policy can constrain their traffic and scope.
4. Add `chinescan domain` JSON/human CLI requiring authorization and recording authorization
   evidence before network activity.
5. Add tests for authorization rejection/scope, no-network-on-rejection, persisted audit records,
   mocked probe output, public-address filtering, bounded headers, no body reads, and configurable
   resource limits.
6. Update schemas, docs, roadmap, and this phase report; run Python 3.12, Ruff, strict mypy,
   pytest/coverage, pip-audit, schema/lock, Compose, fixture/mock CLI, and Docker checks. No live
   domain will be scanned during acceptance. Phase completion is partial until broader scanner
   adapters receive separate traffic and scope review.
