# Phase 7 plan: local dashboard

## Slice 1 status — authenticated local dashboard

The repository owner explicitly approved a loopback-only web API and dashboard. Slice 1 is
implemented in `chinescan/web/` and `frontend/`. It is started only by the explicit
`chinescan web serve` command, binds to `127.0.0.1`, and uses one Uvicorn worker. The frontend
uses a same-origin `/api` development proxy; a production build is served by the API process.
No CORS middleware, public binding option, background jobs, or domain assessment route is added.

One operator is bootstrapped explicitly with `chinescan web bootstrap`. Credentials are stored
outside project workspaces in the user's profile, passwords are hashed with Argon2id, and opaque
HttpOnly/SameSite cookies map to process-local sessions. Writes require a CSRF token, login
attempts are throttled, and host/origin requests are constrained to loopback and same-origin.
Restarting the process invalidates sessions; one application worker is required.

Authenticated APIs currently cover only overview counts, paginated scans, and paginated findings.
Finding responses use a reviewed field allowlist and shared text redaction; target paths and raw
payloads are not returned. Cases, report actions, evidence file access, assessment jobs, malware
intake, and remote deployment remain deferred.

Acceptance: `tests/unit/test_web_api.py` exercises bootstrap, sign-in, protected reads, page/filter
bounds, CSRF, logout revocation, real session expiry, throttling, and host/origin validation.
React component tests cover unauthorized login, real-data overview rendering, and empty states.
Browser-level testing is not yet performed.
