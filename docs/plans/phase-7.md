# Phase 7 plan: local dashboard

## Current constraint

The product brief calls for a FastAPI dashboard. The repository instructions explicitly prohibit
exposing a network listener. A FastAPI server, including one bound to loopback, would add a
listener, so implementation is paused under the current guardrail. SQLite remains local and no
web/API process is added.

## Implementation boundary if the guardrail changes

Before adding the dashboard, the repository owner must revise the listener restriction to define
whether loopback-only binding is permitted. Any implementation should default to `127.0.0.1`,
reject non-loopback binding unless separately configured, and retain the CLI's authorization gate
for domain scans. It should use authentication and CSRF protections before any non-loopback mode,
avoid serving raw evidence by default, and keep the database path local/configurable.

Acceptance must include API authorization tests, loopback binding checks, CSRF tests, rate limits,
and confirmation that the service does not start from the CLI or Docker Compose by default.
