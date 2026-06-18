# ADR-0022: Siege crisis response — token revocation, siege-declared event, UI tile

**Status:** accepted (2026-06-18, retrospective for M9)

## Context

M7 introduced `OperatingMode.SIEGE` as a value that the SecurityCommander sets
when multiple high-confidence incidents converge. But Siege mode previously only
changed containment thresholds (ADR-0014) — it did not do anything visibly
different that an operator could point to as "the system reacted." For the demo
and for real incident response, Siege mode needs concrete, auditable actions.

Three gaps were identified:

1. **Token revocation** — a compromised session's JWT remains valid across
   processes after quarantine (the breaker blocks it locally, but a different
   gateway or a forged client presenting the same token would accept it). Hard
   revocation is the only reliable containment for credential-level compromise.
2. **Siege-declared event** — departments and the UI cannot distinguish a mode
   reaching SIEGE from any generic mode change; a distinct bus event lets
   subscribers react specifically (e.g., freeze operations, notify operators).
3. **Observable UI signal** — the Command Center had no visible indication of
   how many sessions were frozen in a Siege, making the UI unhelpful during an
   active crisis.

## Decision

### 1. Token revocation via `jti` claim

The MockCA (`identity/tokens.py`) now includes a `jti` (JWT ID, UUID v4) in
every token it issues. `IdentityClaims` carries `jti`. A new
`RevokedTokenCache` (`identity/tokens.py`) holds revoked jtis in:
- An in-memory set (O(1) lookup on the hot path)
- A `revoked_tokens` table in the SQLite store (persists across restarts)

`OliveTokenVerifier` checks the jti against the cache after signature and expiry
verification. A revoked token is rejected even if its signature is valid and its
expiry has not elapsed.

`POST /admin/revoke` (HTTP transport, `olive:command` capability gate) accepts
`{"jti": "..."}` and adds the jti to both the in-memory cache and the store.
The store loads all revoked jtis at startup to seed the cache.

**Scope:** MockCA only (the only issuer in the current system). The interface is
forward-compatible with a real CA that also issues `jti` claims.

### 2. `siege-declared` bus object

When `SecurityCommander.set_mode` transitions to `SIEGE`, it publishes a
distinct `siege-declared` `IncidentObject` on the bus (in addition to the
existing generic `mode-change` object). The envelope carries:
- `kind = "siege-declared"`
- `evidence` — bounded string (≤200 chars, rule 3): quarantined session count
  at the moment of Siege declaration
- No raw arguments or session content

Departments that need to react to Siege specifically subscribe to
`kind="siege-declared"` rather than polling mode. The `UIBroker` subscribes
and forwards a `UIEvent` to connected dashboards.

### 3. Frozen session count badge in the Command Center header

The web dashboard (`ui/static/index.html`) adds a `#hc-frozen` badge in the
header. It is hidden in Normal/Suspicious mode; it appears in red in Siege mode.
The badge value is parsed from the `siege-declared` event's evidence field
(the quarantined count). `CircuitBreaker.quarantined_count()` is the new method
that provides that snapshot.

The badge is read-only and display-only; it does not expose any write surface.

### 4. Scope

**IN:** `jti` in MockCA + `IdentityClaims`; `RevokedTokenCache`;
`revoked_tokens` DB table; startup cache seeding; `POST /admin/revoke` endpoint;
`siege-declared` bus event; `quarantined_count()` on breaker; frozen-session
badge in dashboard; `test_siege_response.py` (254-line test, covers revocation
round-trip, cross-restart cache seeding, siege event, UI badge).

**OUT:** Automatic bulk revocation on Siege (human still decides which jtis
to revoke; the endpoint accepts one jti at a time); cross-gateway revocation
propagation (still per-process; a revoked jti is not pushed to other gateway
instances — that is M11 fleet scope); real CA integration.

## Consequences

- A token whose session is quarantined can be hard-revoked in one HTTP call;
  the revocation survives gateway restarts.
- The `siege-declared` event gives the remediation cycle a clear trigger point
  for incident correlation.
- The frozen-session badge makes Siege mode visually unambiguous in the demo
  and in production monitoring.
- New residual risk: the `revoked_tokens` table grows unboundedly if jtis are
  never pruned. Expired-token pruning (delete rows where token expiry has
  elapsed) is deferred to a maintenance task.

## Required doc updates

- `docs/ARCHITECTURE.md` — add `RevokedTokenCache` and `revoked_tokens` table
  to the Identity section; add `POST /admin/revoke` to the HTTP transport
  section; add `siege-declared` kind to the Incident Bus section.
- `docs/THREAT_MODEL.md` — update "token revocation" from a gap to a guarantee
  (within a single gateway process); note cross-gateway revocation propagation
  as a remaining non-guarantee until M11.
