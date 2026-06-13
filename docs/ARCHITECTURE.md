# Architecture

Olive is a **transparent MCP proxy**. To the agent's MCP client it looks
like a normal MCP server; to the real tool server it looks like a normal MCP
client. Everything that crosses it is inspected in both directions.

```
                        ┌──────────────────────────────────────────────┐
                        │                OLIVE                   │
  ┌──────────┐  MCP     │  ┌──────────────────────────────┐    MCP     │  ┌────────────┐
  │  Agent   │ ───────► │  │     FAST PATH (inline)       │  ────────► │  │  Upstream  │
  │ (client) │          │  │  SecurityContext per call    │            │  │ MCP server │
  │          │ ◄─────── │  │  Inspector pipeline:         │  ◄──────── │  │  (tools)   │
  └──────────┘          │  │   outbound: policy, …        │            │  └────────────┘
                        │  │   inbound:  patterns, …      │            │
                        │  │  Decision: allow|block|hold  │            │
                        │  └───────────┬──────────────────┘            │
                        │              │ telemetry (async)             │
                        │  ┌───────────▼──────────────────┐            │
                        │  │   PARALLEL PATH (M3)         │            │
                        │  │   LLM sentinels (advisory)   │            │
                        │  │   → circuit breaker (M2)     │            │
                        │  │   → session quarantine       │            │
                        │  └──────────────────────────────┘            │
                        │              │                               │
                        │        SQLite audit store                    │
                        │        (events + incidents)                  │
                        └──────────────────────────────────────────────┘
```

Two paths, one rule: the **fast path is deterministic and enforces**; the
**parallel path is intelligent and advises** (ADR-0005). LLM sentinels can
only signal the circuit breaker, which applies deterministic quarantine.

## Components

### Gateway proxy — `src/olive/gateway/proxy.py`
- Presents an MCP server (stdio transport first; streamable HTTP in M2).
- Holds an MCP `ClientSession` to the upstream server (spawned subprocess).
- Forwards `initialize`, `tools/list`, `tools/call`.
- On `tools/call`:
  1. Build `SecurityContext` (outbound).
  2. Run outbound pipeline → block returns a sanitized error result to the
     client; the upstream server is never contacted.
  3. Forward to upstream, await result.
  4. Build inbound context, run inbound pipeline over result content →
     block returns a sanitized error result; the poisoned content never
     reaches the agent.
  5. Log events (and incident if blocked) either way.
- `tools/list` responses are also recorded; description-poisoning inspection
  is roadmapped (M4 corpus category exists from day one).

### SecurityContext — `src/olive/gateway/context.py`
One frozen object per inspected message. Fields: `agent_id`, `session_id`,
`role`, `declared_goal`, `tool`, `arguments_hash` (SHA-256, never raw),
`direction` (`outbound`/`inbound`), `call_number`, `session_tool_history`,
`source_trust` (`trusted`/`untrusted`), `timestamp`. This is the object the
whole system reasons about — "can *this* agent use *this* tool at *this*
point in the session", not just "is the tool allowlisted".

### Inspector pipeline — `src/olive/gateway/pipeline.py`
- `Inspector` protocol: `async inspect(ctx, content) -> Verdict`.
- `Verdict(decision, rule, evidence, confidence)`;
  decisions: `allow | block | hold | quarantine`.
- Pipeline runs inspectors matching the message direction, in order; first
  non-allow verdict wins (short-circuit).
- **Fail closed**: any inspector exception → `block` verdict with the error
  recorded as evidence.
- Inspectors are pure plugins; adding one never requires touching the proxy.

### Inspectors — `src/olive/inspectors/`
- `policy.py` (outbound): allowed/forbidden tool check per role from
  `policies/*.yaml`. Unknown tools are blocked (default deny).
- `patterns.py` (inbound): deterministic injection-phrase matching,
  case/whitespace-normalized. **Layer zero only** — documented as trivially
  bypassable by encoding/semantics; exists for speed and as the floor the
  eval harness measures everything else against.
- M3 adds LLM sentinels on the parallel path (never inline, never enforcing).

### Trust labeling
Every upstream (and optionally per-tool) carries `trusted | untrusted` in
policy. Labels tune inspection *depth*, never disable it (threat model rule 1):
untrusted sources always get full content inspection; trusted sources still
get layer-zero checks.

### Identity — `src/olive/identity/`
- `tokens.py` — Mock CA: local RSA keypair, real JWT signing/verification
  (RS256, algorithm pinned, expiry + audience checked). Payload: agent_id, org,
  role, session_id, capabilities, expiry.
- `claims.py` — `IdentityClaims`, the transport-independent identity the gateway
  is built around (ADR-0007). `claims_from_token` verifies a signed token and
  maps it to claims (`verified=True`); `unverified_from_config` is the stdio
  local-dev fallback (`verified=False`). Verification failure is fail-closed.

The gateway enforces *as* an `IdentityClaims`: **role comes from identity, not
config**, so once tokens are required a role cannot be self-asserted (a forged
`role: admin` is rejected at verification; an unbacked role hits default-deny).
Config now holds role *policies*, not *who is connecting*. HTTP feeds the token
from the `Authorization: Bearer` header via the SDK's bearer auth (next slice);
stdio uses the unverified config fallback.

### Event store — `src/olive/store/events.py`
SQLite via `aiosqlite` (ADR-0004), behind a small interface so it can be
swapped later.

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL, session_id TEXT NOT NULL,
    organization_id TEXT NOT NULL, role TEXT NOT NULL,
    tool TEXT NOT NULL, direction TEXT NOT NULL,
    decision TEXT NOT NULL, policy_rule TEXT,
    arguments_hash TEXT, latency_ms INTEGER, incident_id TEXT
);
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL, session_id TEXT NOT NULL,
    attack_type TEXT NOT NULL, evidence TEXT NOT NULL,
    confidence REAL, detection_method TEXT NOT NULL,
    decision TEXT NOT NULL, status TEXT NOT NULL
);
```

Raw payloads are never stored — hashes + bounded evidence excerpts only.

### Session state — `src/olive/gateway/session.py`
One mutable `SessionState` per session: status (`active`/`quarantined`), call
counter, tool history, block count, first/last seen, and the quarantine reason
+ tripping incident id. Pure data; the circuit breaker is the only mutator.

### Circuit breaker — `src/olive/gateway/breaker.py`
The single concurrency authority over session state: it owns the in-memory
session map and one lock, so advancing a call (next call number + history
snapshot) and deciding whether to trip are atomic together. Checked **before
any pipeline work or upstream contact**; a quarantined session's calls are
denied with `Decision.QUARANTINE`. Trips deterministically when a session
reaches `max_blocks_before_quarantine` security blocks (config); the same
`trip()` entry point is what M6 sentinel signals will call. **Reversible human
release** resets the session to active. Quarantined calls are logged as
`quarantine` events referencing the tripping incident — no incident-per-call
spam, but never a silent decision (ADR-0006).

In-memory and per-process for now: in stdio mode that is exactly one session.
A cross-process admin surface for release lands with the HTTP transport (M2);
today release is an in-process method.

### Rate limiter — `src/olive/gateway/ratelimit.py`
Deterministic per-session sliding-window throttle; the limit value comes from
the role policy (`max_calls_per_minute`, omit for unlimited). Checked after the
quarantine check and before the pipeline/upstream. A throttle is **not** an
attack: an over-limit call is denied and audited as a `ratelimit.exceeded`
event, but mints **no incident** and does **not** count toward the breaker's
quarantine threshold — a chatty-but-legitimate agent must not be contained as
if hostile. Its own lock, never nested with the breaker's, so the two cannot
deadlock.

## Layering rule (keeps the business split clean — ADR-0003)

`src/olive/` (gateway core) must never import from intelligence/fleet
layers. Telemetry flows out through a queue; quarantine signals flow back in
through the circuit breaker's narrow interface. That seam is the potential
open-core boundary.

## What deliberately does not exist yet

- Streamable HTTP transport, wire JWT enforcement, multi-upstream
  aggregation/namespacing, cross-process release (rest of M2).
- Tool-description/schema inspection and rug-pull diffing (M3).
- LLM sentinels, incident reporter (M6).
- Larger corpus + CI regression gate (M5). Dashboard (M5/showable).
