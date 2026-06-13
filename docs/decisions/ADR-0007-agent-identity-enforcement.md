# ADR-0007: Agent identity is verified, not asserted

**Status:** accepted (2026-06-13)

## Context
Through M2-so-far the gateway derives identity — `agent_id`, `role`, `org` —
from the static policy file. That is fine for single-tenant stdio (the gateway
is spawned by a client that already trusts it), but it means **role is
self-asserted**: nothing stops a process from running as `role: admin`. The
vision requires answering "who is this agent, who authorized it, what role" with
cryptographic backing, and one gateway eventually fronting many agents/orgs over
HTTP. The mock-CA JWT module (`identity/tokens.py`) already does real RS256
verification but is not yet on the enforcing path.

## Decision
Establish identity from a **cryptographically verified token**, not from config
or an unauthenticated client claim.

- **`IdentityClaims`** (`identity/claims.py`): a transport-independent value —
  `agent_id`, `organization`, `role`, `session_id`, `capabilities`, and a
  `verified` flag. The gateway is built around this object; on the enforcing
  path it no longer reads identity from config.
- **Authoritative source is a signed token.** `claims_from_token` reuses
  `verify_token` (signature, expiry, audience, pinned RS256) and maps claims to
  `IdentityClaims(verified=True)`. Verification failure is **fail-closed**: the
  call/connection is refused, never served under a fallback identity.
- **Role is identity-bound.** The token's `role` selects the `RolePolicy`.
  Default-deny still applies — a role with no policy is blocked — so an agent
  cannot escalate to a role it has no CA-signed token for.
- **Config's job narrows.** It keeps role *policies* (allowed/forbidden tools),
  trust labels, patterns, containment, rate limits — "what each role may do",
  not "who is connecting".
- **Transport supplies the token.** HTTP via `Authorization: Bearer` using the
  SDK's bearer-auth + `TokenVerifier` (slice 2). Stdio falls back to a
  config-derived **unverified** identity (`verified=False`) for local dev —
  acceptable only because stdio is single-tenant and spawned by a trusting
  client.
- **Capabilities** are carried now, enforced later as **capability attenuation**
  (effective tools = role ∩ token capabilities) — a detection-logic change that
  will go through red-team + corpus.

## Slice plan
1. **Identity binding** (this slice): `IdentityClaims`, `claims_from_token`,
   gateway built around verified identity, role-bound policy. No transport
   change yet.
2. **HTTP transport**: streamable HTTP + bearer auth feeds the token per
   connection; cross-process release admin surface.
3. **Capability attenuation**: enforce token capabilities ∩ role.

## Consequences
- Role spoofing is prevented cryptographically once tokens are required; audit
  `agent_id`/`role` become *attested*, not merely asserted.
- Multi-tenant HTTP becomes possible (per-connection identity).
- Until HTTP lands, stdio identity is unverified (`verified=False`); this is
  recorded in the threat model as a known non-guarantee.
- `SecurityContext`'s schema is unchanged this slice (identity is a
  construction-time concern), so the store and existing tests are untouched.
