# ADR 0001 — Keep the validation engine dependency-free

**Status:** accepted (2026-11-03)

## Context

The engine needs an HTTP client, TLS inspection and a policy layer. The obvious
choice is `httpx`/`requests`, which the repository already depends on. But the
engine must also: connect to a validated IP rather than re-resolve a hostname,
refuse redirects unless each hop is re-authorized, and run identically in a
worker, in CI and from a CLI with no service dependencies.

## Decision

Implement the client on `http.client` + `socket` + `ssl` behind a small
`GuardedHttpClient`. The engine imports nothing outside the standard library.

## Consequences

- DNS-rebinding protection is possible at all: we control the socket target.
- Tests for the engine run with `python -m unittest` on a bare interpreter.
- We own redirect semantics, header parsing and TLS error handling — roughly 200
  lines that a library would have provided.
- If we later adopt a library, it must expose a custom resolver and per-hop
  redirect hooks; `GuardedHttpClient` remains the only egress path either way.
