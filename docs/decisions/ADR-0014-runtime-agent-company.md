# ADR-0014: The runtime agent company — Security Commander, operating modes, and the incident-object bus

**Status:** accepted (2026-06-15)

## Context
VISION describes Olive's end state as a **runtime security organization**: a
hierarchy of specialized agents (Defense, Red-Team, Builder, Verification)
coordinated by a Security Commander, cooperating through structured incident
objects — *never uncontrolled group chat* — and shifting between operating modes
(Normal / Suspicious / Siege) as an attack unfolds. ADR-0013 built the first
department *loop* (Reproduce → Repair → Verify → Learn) but explicitly deferred
"operating modes and the Command & Coordination hierarchy" to a later slice.
This ADR is that slice's foundation.

The hard part is doing this **without breaking the two laws that make Olive a
security product rather than an attack surface**:

- **ADR-0005 (the architectural law):** agents provide intelligence; only
  deterministic code and humans enforce. A runtime "company of agents" must not
  put an LLM anywhere it can *decide* an enforcement action — otherwise an
  attacker who prompt-injects a tool response could talk the security
  organization into standing down, or into attacking its own company. That an
  autonomous security org **cannot be subverted this way, by construction**, is
  the moat — not a limitation.
- **ADR-0003 (the open-core seam):** the gateway core (`gateway/`, `store/`)
  must never import the intelligence/orchestration layer. Today exactly two
  crossings exist: telemetry **out** (`TelemetrySink`) and a quarantine signal
  **in** (`CircuitBreaker.trip`).

## Decision

The runtime org is built on a parallel plane beside the deterministic wall.
Agents observe, reason, simulate, propose, and **communicate through signed,
structured incident objects**; deterministic code (the Commander, the breaker,
the policy engine) and humans hold all enforcement authority.

### 1. The Security Commander is deterministic code, not an LLM
A new `intelligence/commander.py` (intelligence side). Its authority is limited
to **operating-mode decisions** and **routing** incident objects between
departments. It never runs inline on a request, never calls an LLM to decide,
and never calls `breaker.trip`. The Commander being deterministic is the whole
point: command authority in a security org cannot be an injectable LLM.

### 2. Operating modes live in core; the breaker owns the value
`OperatingMode` (`StrEnum`: `normal | suspicious | siege`) is defined in a new
**core** module `gateway/mode.py` — pure data, no intelligence imports, the same
posture as `gateway/session.py`. The `CircuitBreaker` holds the current mode
behind its existing lock and gains two methods that mirror `trip`/`release`:

- `set_mode(mode, reason, incident_id)` — **the one inward crossing for mode**,
  structurally identical to `trip()`. The deterministic Commander is its only
  caller (just as `SentinelRunner` is the only caller of `trip`).
- `mode()` — a fast-path read for inline enforcement.

Mode tunes **deterministic inline behavior the core already owns**:

- **Suspicious** — the breaker's effective quarantine threshold drops; the
  `SentinelRunner` action threshold lowers (already anticipated in its code); more
  context rules escalate from allow to `hold`.
- **Siege** — a policy-flagged set of sensitive tools is denied inline; new
  sessions default to `hold`. (Credential/token freezing is **out** — it touches
  live secrets, deferred like ADR-0013.)

This is the key seam result: **mode changes inline behavior with zero new
core→intelligence coupling.** Core defines and stores the value; the
intelligence-side Commander only *delivers* a new value through the same narrow,
already-shaped inward call as `trip`. The breaker is already injected into the
gateway, so the composition root constructs **one** breaker and hands it to both
the gateway and the Commander.

Every `set_mode` is audited (a `mode-change` row with reason + triggering
incident id) and reversible (`set_mode(normal, ...)` is de-escalation, exactly
like `release`). Mode is in-memory / per-process for this slice — the same honest
non-guarantee as quarantine state.

### 3. Commander vs. SentinelRunner — one writer each
The Commander is a **sibling above**, not a rename of, `SentinelRunner`:

- `SentinelRunner` keeps its exclusive title — **the only place a signal becomes
  a `breaker.trip`** (one session contained).
- The Commander is **the only place an incident stream becomes a `set_mode`**
  (fleet-wide inline posture reshaped).

Two different deterministic authorities over two different state machines, each
with exactly one writer. No overlap, no "two places that are the one place."

### 4. The incident-object bus
A new `intelligence/bus.py`: in-process async pub/sub over an `asyncio.Queue`
(the `QueueSink` pattern) for live fan-out, **plus** an append-only
`incident_events` table for audit + replay. The table lives on the intelligence
side with its **own** `aiosqlite` access to the same DB file — the precedent
`RemediationLedger` set. Core never imports the bus.

The message is a typed `IncidentObject` envelope **extending the existing
`IncidentReport`** (never a parallel evidence type):

```
IncidentObject:
  object_id    str            # 'IOB-NNNN', single-statement-derived (like INC-/CYC-)
  incident_id  str | None     # string ref into the store incidents row
  kind         str            # detection | reproduced | fix-proposed | verified | mode-change
  source_dept  str            # defense | remediation | commander
  target_dept  str | None     # routing hint; None = broadcast
  report       IncidentReport # the existing structured evidence
  signature    str            # over the canonical object (see below)
  created_at   str
```

**Rule 3 is the hardest-guarded property here.** `IncidentReport` already carries
only confidence, attack types, bounded evidence excerpts, and ids — never raw
payloads. `TelemetryEvent.content` / `arguments` (in-memory, for sentinel
analysis) **must never be copied into a bus object or a table row**. A test
asserts no raw-payload field exists on `IncidentObject`.

**Signing.** Objects are signed and verified so a compromised LLM agent cannot
forge a `mode-change` or a `verified` object onto the bus — an unsigned or
wrongly-signed object is rejected (fail-closed). The first slice may ship an
HMAC-over-canonical-JSON with a per-process key (the honest reduction); the
target is per-department CA-signed identities reusing `identity/tokens.py`.

### 5. Two departments first
- **Defense** = the existing `SentinelRunner` + sentinels, adapted to also
  *publish* an `IncidentObject` to the bus when it acts (its `on_report` hook is
  the integration point). Its `trip` authority is unchanged.
- **Remediation** = the existing `RemediationLedger` driven as a bus subscriber
  that opens a cycle in `reproduced` when a confirmed-incident object arrives.
  Its human-gated transitions (ADR-0013) are unchanged.

### 6. Capability gate for human-forced mode
A new distinct capability `olive:command` gates a human-forced mode change
(mirrors `olive:release` / `olive:approve` / `olive:remediate`; capabilities
never imply one another). An LLM agent may publish *evidence* to the bus; only
the deterministic Commander rules/thresholds, or a capability-gated human, move
the mode.

### 7. The open-core seam is preserved
Core imports nothing from `intelligence/`. The Commander and bus are additive and
removable: the gateway enforces with the org entirely absent (`NullSink`, default
`normal` mode). The Commander imports core (one-directional, allowed); never the
reverse.

## Scope — IN / OUT

**IN (first slice):** `gateway/mode.py` + breaker `set_mode`/`mode`; mode-aware
inline tuning in the existing inspectors/breaker/runner thresholds;
`intelligence/bus.py` (async pub/sub + `incident_events`); the `IncidentObject`
envelope + signing/verification; `intelligence/commander.py` (deterministic mode
state machine + router); wiring Defense and Remediation as the first two bus
departments; `olive:command` capability; composition-root wiring in `cli.py` via
local imports with one shared breaker; tests + doc updates.

**OUT (deferred, named honestly):** runtime Red-Team and Builder *autonomy* (the
build-time `.claude/agents` versions remain the only ones); the full Supervisor
hierarchy (first slice has Commander + two departments only); credential/token
freezing in Siege; cross-process / fleet mode propagation and durable mode/bus
across restarts; any auto-apply of a fix (permanently human-gated).

## Consequences
- The runtime organization becomes real and auditable: every mode change and
  every agent-to-agent message is reproducible from `incident_events` plus the
  deterministic thresholds. Departments collaborate through structured objects,
  never group chat.
- ADR-0005 is extended, not bent: the Commander is deterministic; LLM agents only
  publish evidence; mode and quarantine each have exactly one deterministic
  writer; no LLM is ever inline.
- The open-core seam (ADR-0003) holds: mode is a core-owned value delivered
  through a second narrow inward call of the same shape as `trip`; the org is
  additive and removable.
- New residual risks (THREAT_MODEL update): operating-mode integrity (a forged
  mode-change could stand the org down or wedge it into Siege), mode state being
  in-memory/per-process, and the bus's integrity resting on the signing key.

## Supersession note
This ADR delivers the "operating modes and Command & Coordination" slice that
ADR-0013's "what stays out of scope" clause deferred. The full Supervisor
hierarchy and runtime attack/build agents remain future work.

## Required doc updates
- `docs/ARCHITECTURE.md` — the "What deliberately does not exist yet" bullet
  (modes + a minimal Commander + a two-department bus now exist; full hierarchy
  + runtime Red-Team/Builder still deferred) and the "Layering rule" (the inward
  crossing is now two narrow breaker methods of the same shape: `trip` and
  `set_mode`); plus new component subsections.
- `docs/THREAT_MODEL.md` — operating-mode integrity as a protected asset; the
  in-memory/per-process and bus-signing-key non-guarantees.
- `docs/ROADMAP.md` — M7 second slice (modes + Commander + bus); Supervisors +
  runtime attack/build agents deferred.
