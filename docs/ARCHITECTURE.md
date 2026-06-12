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

### Identity — `src/olive/identity/tokens.py`
Mock CA: local RSA keypair, real JWT signing/verification (RS256). Payload:
agent_id, org, role, session_id, capabilities, expiry. In stdio mode (M1) the
gateway is configured per-agent via policy file; cryptographic enforcement on
the wire lands with HTTP transport (M2). The module is real and unit-tested
from day one so the enforcement wiring is a transport change, not a redesign.

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

### Circuit breaker (M2) — `src/olive/gateway/breaker.py`
In-memory session blocklist checked before any pipeline work; trip on
sentinel signal or repeated blocks; reversible human release. Quarantined
sessions get `quarantined` responses to every call.

## Layering rule (keeps the business split clean — ADR-0003)

`src/olive/` (gateway core) must never import from intelligence/fleet
layers. Telemetry flows out through a queue; quarantine signals flow back in
through the circuit breaker's narrow interface. That seam is the potential
open-core boundary.

## What deliberately does not exist yet

- Streamable HTTP transport, multi-upstream aggregation/namespacing (M2).
- LLM sentinels, incident reporter (M3).
- CI regression gate on eval corpus (M4). Dashboard (M5).
