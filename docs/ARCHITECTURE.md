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
- Presents an MCP server over **stdio** (`olive run`) or **streamable HTTP**
  (`olive serve`, see transport below).
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
- The **whole MCP surface** is inspected (M3), not just tool calls: `*/list`
  declarations (tools, resources, prompts) are screened per item — poisoned or
  rug-pulled (ADR-0009) declarations are withheld and logged; and `resources/read`
  + `prompts/get` content is inspected like a tool response (poison → sanitized
  result). The shared `_screen_declaration` / `_screen_inbound_content` helpers
  keep every surface enforcing identically.

### SecurityContext — `src/olive/gateway/context.py`
One frozen object per inspected message. Fields: `agent_id`, `session_id`,
`role`, `declared_goal`, `tool`, `arguments_hash` (SHA-256, never raw),
`direction` (`outbound`/`inbound`), `call_number`, `session_tool_history`,
`source_trust` (`trusted`/`untrusted`), `timestamp`, plus (M4, ADR-0010)
`requested_resource` (a `ResourceRef` = `type`/`id`/`classification`, the
structured target lifted by a per-tool extractor — never the payload) and
`task_resources` (resource ids the attested identity's current task is scoped
to). This is the object the whole system reasons about — "can *this* agent use
*this* tool on *this* resource at *this* point in the session", not just "is
the tool allowlisted".

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
- `context_policy.py` (outbound, M4/ADR-0010): runs **after** `policy.py` and
  is **refine-only** — it can `block` or `hold` an already-allowed call, never
  grant one. Ordered deterministic rules over `SecurityContext` structured
  fields: explicit task binding (`resource.id_in: task.resources`),
  classification ceilings, and approval requirements (`hold`). No regex over
  arguments, no LLM. A `hold` is released out-of-band by a capability-gated
  (`olive:approve`) operator via the `ApprovalRegistry` (`gateway/approvals.py`).
- `patterns.py` (inbound): deterministic injection-phrase matching,
  case/whitespace-normalized. **Layer zero only** — documented as trivially
  bypassable by encoding/semantics; exists for speed and as the floor the
  eval harness measures everything else against.
- M3 adds LLM sentinels on the parallel path (never inline, never enforcing).

### Multi-upstream — `src/olive/gateway/upstreams.py`
One gateway can front several upstream servers (ADR-0008). `MultiplexUpstream`
presents them to the proxy as a single upstream: tools are aggregated and
namespaced `"<name>.<tool>"`, and each `tools/call` is routed to the owning
server (prefix split on the first separator, then stripped). The proxy is
unchanged — it still sees "one upstream", so all enforcement runs over the
namespaced names; policy `allowed_tools` therefore reference `server.tool`.
A single upstream with an empty name yields bare tool names (single-upstream
back-compat). Upstreams are declared in the policy file (`upstreams:`), or via
the CLI command for the single-upstream case. Unroutable names fail closed.

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

Identity is resolved **per call**: `handle_call_tool` takes the request's
`IdentityClaims` (stdio falls back to the construction identity). The breaker
and rate limiter key on `IdentityClaims.session_key` — the namespaced
**(org, agent, session_id)** triple, so a reused session id across tenants can't
share containment state — and the rate limit is resolved from that identity's
role. One gateway can thus front many agents with independent containment and
per-role throttles. The limiter is a pure keyed sliding window; the limit is
supplied per call.

### HTTP transport — `src/olive/transport/http.py`
`olive serve` exposes the gateway over streamable HTTP with **bearer-token
identity enforcement on the wire** (ADR-0007):
- `OliveTokenVerifier` (an SDK `TokenVerifier`) verifies the `Authorization:
  Bearer` token against the CA public key and maps it to claims. The MCP
  endpoint sits behind the SDK's bearer auth + `RequireAuthMiddleware`, so a
  missing/invalid token is **401 before the gateway is reached** (fail closed).
- `build_server(upstream, identity_resolver=...)` lets the transport feed each
  request's verified identity (read from the auth contextvar); the gateway then
  enforces as that identity. Stdio passes no resolver and uses its construction
  identity.
- A capability-gated admin endpoint `POST /admin/release/{session_id}` performs
  reversible session release (requires the `olive:release` capability in the
  token) — the cross-process release surface for quarantined sessions.
- Core gateway code holds no SDK-auth imports; that coupling lives only here,
  keeping the layering rule (ADR-0003) intact.

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

Plus a `tool_baselines` table (tool_name, declaration_hash, first/last seen)
backing trust-on-first-use rug-pull detection (ADR-0009).

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

In-memory and per-process for now: in stdio mode that is exactly one session;
over HTTP, release is reachable via the capability-gated admin endpoint. Idle
**active** sessions are evicted past a TTL (lazy sweep + `evict_idle`) to bound
memory; **quarantined sessions are never evicted** (idling must not clear a
quarantine).

### Remediation cycle ledger — `src/olive/intelligence/remediation.py`
The first department loop (ADR-0013): a deterministic, auditable state machine
that walks one incident through `reproduced → fix-proposed → verified → approved
→ learned` (+ terminal `rejected`). It is driven by the `olive cycle` CLI and
backs the back half of the security cycle (Reproduce → Repair → Verify → Learn).

The two consequential transitions cannot be reached by an LLM: **verify** is
writable only from the real `evals/run_evals.py` gate result (the CLI runs it as
a subprocess; there is no path to inject a pass), and **learn** refuses unless a
capability-gated (`olive:remediate`) human approval is already recorded. This
extends ADR-0005 to the remediation loop.

Lives on the **intelligence side of the open-core seam** (ADR-0003): it owns its
own `aiosqlite` access to the same DB file and references the incident by its
`incident_id` string only — it never imports `IncidentReport` into core, and the
gateway core never imports it. `cli.py` (the composition root) wires it in with a
local import, like `serve_http` does for the HTTP stack. Rule 3 holds: the table
stores the proposed diff's SHA-256 + a bounded ≤200-char summary, never the diff
body.

### Operating mode — `src/olive/gateway/mode.py` + the breaker
`OperatingMode` (`normal | suspicious | siege`, ADR-0014) is the fleet-wide
enforcement posture. It lives in **core** (pure data, no intelligence imports)
and the circuit breaker **owns the value** behind its existing lock. The breaker
gains two methods that mirror `trip`/`release`: `set_mode(mode, reason,
incident_id)` — the **second narrow inward seam crossing**, the only way the
intelligence-side Commander delivers a posture change — and `mode()` for the
fast-path read. Mode tunes deterministic inline behavior the core already owns:
suspicious halves the containment threshold (quarantine sooner); siege collapses
it to one block. Inline enforcement only ever *reads* the mode; it never imports
the orchestration layer.

### Security Commander — `src/olive/intelligence/commander.py`
The runtime org's coordinator (ADR-0014), **deterministic code, not an LLM**. Its
only authorities are deciding the operating mode and routing incident objects. It
is the **sole caller of `breaker.set_mode`** (just as `SentinelRunner` is the
sole caller of `trip`) — two state machines, one writer each, so there are never
two places claiming to be "the one place." It escalates the mode from the
deterministic detection stream via a pure `target_mode()` policy (monotonic up;
only a capability-gated human `force_mode` with `olive:command` de-escalates),
and audits every change as a signed `mode-change` object on the bus.

### Incident bus — `src/olive/intelligence/bus.py`
How runtime departments collaborate — "structured incident objects, never group
chat" (ADR-0014). An in-process async pub/sub for live fan-out plus an
append-only `incident_events` table (own `aiosqlite`, same DB file, the
`RemediationLedger` precedent) for audit + replay. The `IncidentObject` envelope
wraps the existing `IncidentReport`, so it carries only bounded, hashed evidence —
it has **no `content`/`arguments` field**, and raw `TelemetryEvent` payloads
never reach it (rule 3, tested). Objects are HMAC-signed and verified: an unsigned
or tampered object is rejected fail-closed, so a compromised LLM agent cannot
forge a `mode-change` or `verified` object. The two first-slice departments are
**Defense** (the `SentinelRunner`'s `on_report` hook publishes `detection`
objects) and **Remediation** (the `RemediationLedger` subscribes; a `reproduced`
object opens a cycle). Wired by `build_runtime_org`, sharing one breaker.

### Red-team engine — `src/olive/redteam/`
The autonomous attacker (ADR-0015), offline and deterministic — same category as
the eval runner, not a runtime sentinel. `olive redteam run` applies pure
`AttackStrategy` mutators (base32, double-base64, chunked-base64, capital-homoglyph
— the set mapped to existing `known-miss` cases) to seed malicious intents and
runs every variant through the **real** `build_pipeline`; a variant the pipeline
*allows* is a bypass. Two structural guarantees: it **proves the pipeline is live**
(every seed's plain trigger must block, else it refuses to run — no finding bypasses
against a mock), and it has **no enforcement-write path** — its only outputs are a
report and `known-miss` candidate cases, so it can never weaken detection to fake a
win. The loop closes through the existing human gates (review→commit known-miss,
then `olive cycle` → human approval → baseline). Imports core one-directionally
(like `run_evals.py`); **core never imports it**.

### Runtime Red-Team department — `src/olive/intelligence/redteam_dept.py`
VISION department 2 as a runtime component (ADR-0016): on a trigger (on-demand
`run_once()` or a scheduled interval loop, mirroring `SentinelRunner.start/stop`)
it runs the deterministic engine and publishes bypass findings onto the bus as a
**distinct `redteam-finding` kind**. Three structural guarantees: **sandbox-only**
(its only attack primitive is `run_campaign`, which targets `build_pipeline`; the
module cannot import the proxy/upstreams/`ClientSession`/live breaker, so it can
never reach live traffic — a test asserts the import set); **a drill never
escalates** (the Commander only reads `detection`, so a `redteam-finding` cannot
move the mode — no self-inflicted Siege); and **no feedback loop** (it publishes
but subscribes to nothing). Advisory-only: it never calls `trip`/`set_mode`, only
publishes deduped novel findings, which Remediation records as intents awaiting
human triage. Wired as an optional department in `build_runtime_org` (default off).

### Runtime Builder department — `src/olive/intelligence/builder_dept.py`
VISION department 3 as a runtime component (ADR-0018): it subscribes to
**confirmed weaknesses** on the bus (`redteam-finding` + `reproduced`) and turns
each *novel* one into a bounded, auditable **fix-proposal** — a `builder_proposals`
row (own aiosqlite, same DB; rule-3: hashes + ≤200-char summary, never a diff body)
plus a published **`fix-proposed`** object. **Propose-only by construction**: it
cannot import the proxy/upstreams/breaker/`ClientSession` and never calls
`trip`/`set_mode`/`olive cycle`/baseline update (a test asserts the import set *and*
that no enforcement method is called); at runtime it authors **no diff**
(`patch_hash` is null — the diff stays the build-time `.claude/agents/builder.md`,
ADR-0013). **No self-trigger** (it subscribes only to the two confirmed-weakness
kinds, never to its own `fix-proposed`) and a proposal carries `confidence=0.0`, so
it can never move the mode. Promotion is unchanged: a proposal is inert until a
human walks the fix through `olive cycle` (the eval gate + `olive:remediate`
token). Spam is bounded by **novelty dedup** (`finding_key` UNIQUE → one proposal
per weakness). Wired as an optional department in `build_runtime_org` (off unless an
opened `ProposalLedger` is supplied); `olive builder-dept run` is the on-demand
operator/CI trigger (replays the bus, proposes for novel weaknesses).

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
layers. Telemetry flows **out** through a queue; two narrow signals flow back
**in** through the circuit breaker's interface — `trip` (contain a session) and,
since ADR-0014, `set_mode` (set the fleet-wide posture). Both are the same shape:
the intelligence side passes a plain value inward; core imports nothing outward.
That seam is the potential open-core boundary.

## What deliberately does not exist yet
- The full Command & Coordination hierarchy (Security Commander → department
  *supervisors* → specialists). The runtime org now ships the deterministic
  Commander, operating modes, the incident bus, and **four** departments (Defense,
  Remediation, Red-Team, Builder); the **supervisor tier** is still deferred (no
  specialists to supervise yet — ADR-0018).
- Runtime Red-Team / Builder **autonomy** — a *scheduled* runtime Red-Team
  department (ADR-0016) attacks only the sandboxed `build_pipeline`, **never the
  live gateway**; a runtime Builder department (ADR-0018) now reacts to confirmed
  weaknesses but only **proposes** (it authors no diff and never applies one).
  Event-triggering ("after every incident") and the supervisor tier remain
  deferred. The build-time `.claude/agents` remain the only LLM-creative
  attack/fix authors — runtime departments are deterministic orchestration.
- Auto-apply/auto-deploy of a proposed fix — permanently human-gated by design.
- Credential/token freezing in Siege; cross-process / fleet mode propagation;
  durable mode/bus across restarts (mode is in-memory/per-process for now).
- Cross-session/fleet behavioral baselines and the enterprise control plane.
- Dashboard (showable).
