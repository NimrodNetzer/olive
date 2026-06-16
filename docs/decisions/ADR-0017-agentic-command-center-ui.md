# ADR-0017: The Agentic Command Center — read-side UI for the runtime agent company

**Status:** accepted (2026-06-16)

## Context
ADR-0014 built the runtime agent company (Security Commander, operating modes,
the incident bus, Defense + Remediation departments); ADR-0015/0016 added the
offline and scheduled red-team engine/department. All of this is currently only
observable through logs, `incident_events`, and CLI commands. ARCHITECTURE.md's
"What deliberately does not exist yet" lists a "Dashboard (showable)" as
explicitly deferred. This ADR delivers a minimal, optional, observability-only
TUI (the "Agentic Command Center", built on Textual) that visualizes the runtime
org and lets an operator fire `evals/corpus/` attack cases at the sandbox
red-team pipeline — without adding any new enforcement authority, writer, or
inward seam crossing.

## Decision

### 1. Placement: `olive/ui` is an intelligence-side sibling (ADR-0003)
`src/olive/ui/` lives on the **intelligence side** of the open-core seam, in the
same category as `olive/intelligence`, `olive/redteam`. It imports core
one-directionally (`gateway/telemetry.py` types, `gateway/pipeline.py` `Verdict`)
and the intelligence-side `intelligence/bus.py` — both allowed for an
intelligence-side module. **Core never imports `olive/ui`.** It is additive and
removable: the gateway enforces identically with the UI absent, exactly the
`NullSink` default (ADR-0012).

### 2. `UIBroker` — read-only projection, two inbound subscriptions, zero writes
`ui/broker.py` defines `UIBroker`:
- Implements `TelemetrySink` (`gateway/telemetry.py`) — registered as an
  *additional* sink alongside whatever sink is already configured (`NullSink` or
  `QueueSink`), never a replacement. A dropped/slow UI sink must never apply
  backpressure to the fast path (same drop-on-full contract as `QueueSink`).
- Calls `IncidentBus.subscribe()` (`intelligence/bus.py`) for live fan-out, and
  may read `IncidentBus.history()` / the `incident_events` table for replay on
  startup.
- Translates both input types into a single bounded `UIEvent` DTO carrying only:
  `Verdict.decision`, `Verdict.rule`, `Verdict.evidence` (already ≤200 chars,
  rule 3), `ctx.agent_id`/`session_id`/`tool`/`direction`/`timestamp`, and — for
  bus objects — `kind`, `source_dept`, `object_id`, `report.confidence`,
  `report.attack_types`.
- **`UIBroker` reads `TelemetryEvent.content`/`arguments` for NOTHING.** Those
  fields exist on `TelemetryEvent` only for in-memory sentinel analysis
  (`telemetry.py`); `UIBroker` must not reference them. A test asserts `UIEvent`
  has no `content`/`arguments`/raw-payload field (same shape as the existing
  `IncidentObject` rule-3 test, ADR-0014 §4).
- `UIBroker` calls **no** breaker, policy, mode, or Commander method, directly
  or indirectly. It is read-only by construction — a test asserts its import set
  excludes `gateway.breaker`, `gateway.proxy`, `intelligence.commander`
  (mirroring the ADR-0016 import-set test pattern).

### 3. `app.py` — Textual App, deployed as its own process
The TUI (`olive ui` CLI entry point, wired like `olive cycle`/`olive redteam` via
a local-import handler in `cli.py`) runs as its **own process**, connecting to
the same DB file as the gateway (read-only access to `incident_events` for
history) and to a live `IncidentBus`/telemetry sink registered by the gateway's
composition root if co-located. Running it as a separate process is the default
recommendation: it keeps "additive and removable" crisp, avoids Textual's
asyncio loop ever sharing a thread with the fast path, and means a UI crash or
slow redraw cannot affect gateway latency. (Co-locating in the same process as
`build_runtime_org` remains possible — `UIBroker` is just another sink/subscriber
— but is not the default.)

Panels: department status (idle/thinking/executing, reactive, driven by
`UIEvent.kind`/`source_dept` from bus objects), a central gateway node (driven by
telemetry `UIEvent`s), an attack-theater sidebar (`evals/corpus/` case list), and
a mitigation/audit log (`UIBroker.stream()`).

### 4. Attack theater = the existing ADR-0015/0016 sandbox primitive, nothing new
"Fire a corpus case at a sandbox gateway instance" means: invoke
`redteam.engine.run_campaign` / `intelligence.redteam_dept.run_once()` against an
in-process `build_pipeline(load_config(...))` — the **same** sandbox primitive
ADR-0015/0016 already define, with the same structural guarantees (no
`Proxy`/`ClientSession`/upstream/live-breaker reachable; no enforcement-write
path). This ADR adds **no new live-traffic seam** and **no new sandbox
infrastructure**. A literal second running gateway process ("sandbox
deployment") is explicitly out of scope — if wanted later, it needs its own ADR
and threat-model entry, since it would be new infrastructure with its own attack
surface.

The UI must visually distinguish "sandbox/drill" output from anything resembling
live gateway state (e.g. a persistent banner/border), so an operator never
mistakes a drill result for a live incident.

### 5. UI-initiated control actions: a new `operator-request` kind, announce-only
A new `IncidentObject` `kind="operator-request"`, `source_dept="ui"`, extending
the ADR-0014 envelope (still no `content`/`arguments` field — rule 3 holds
unchanged). It carries a bounded `action` string (`report.action`, reusing the
existing field) drawn from a small closed set:

- `"force-mode-request"` — **announce-only**. Publishing this object does
  **not** change the operating mode. A human with the `olive:command`
  capability still must invoke `Commander.force_mode` (ADR-0014 §6) through its
  existing path (CLI/admin). No subscriber may translate an `operator-request`
  into `breaker.trip`/`breaker.set_mode` — doing so would create a second writer
  to a state machine ADR-0014 §3 defines as having exactly one writer. The bus
  object exists purely so the UI's audit log shows "operator asked for mode X at
  time T" alongside whether/when it was actually actioned via the existing path.
- `"run-campaign-request"` and `"toggle-redteam-dept-request"` — **may** be acted
  on directly by `intelligence/redteam_dept.py` as an additional on-demand
  trigger, because `run_once()`/`start()`/`stop()` already have no
  enforcement-write path and no escalation capability (ADR-0015 §3, ADR-0016
  §§2-4, §7). This is a minor additive extension to ADR-0016 §6's trigger
  surface ("on-demand `run_once()`" already in scope) — not a new authority.

Pausing/resuming Defense, Remediation, or the Commander itself is **out of
scope** for this ADR (those *are* enforcement-adjacent) and is not part of the
`operator-request` action set.

The UI signs `operator-request` objects with the same per-process bus key
(ADR-0014 §4 precedent) — it must hold the signing key to publish at all, same
as any other department.

### 6. No new inward seam crossing
The two inward crossings remain exactly `CircuitBreaker.trip` and
`CircuitBreaker.set_mode` (ADR-0003/0014), each with its existing single writer
(`SentinelRunner`, `SecurityCommander`). `olive/ui` adds zero writers to either.
Telemetry-out and bus-subscribe are both *already* sanctioned crossing shapes
(ADR-0012, ADR-0014) — the UI reuses them, it does not add new ones.

## Scope — IN / OUT

**IN:** `src/olive/ui/broker.py` (`UIBroker`, `UIEvent`), `src/olive/ui/app.py`
(Textual `App`), `textual` dependency, `olive ui` CLI entry point; the
`operator-request` bus kind (announce-only for mode, actionable-but-harmless for
redteam-dept triggers); attack-theater sidebar wired to `run_campaign`/
`run_once()` over `evals/corpus/`; tests (import-set exclusions for `UIBroker`,
`UIEvent` rule-3 shape test, `operator-request` never reaches `trip`/`set_mode`).

**OUT (deferred/forbidden):** a second live "sandbox gateway" process (separate
ADR if wanted); pausing Defense/Remediation/Commander from the UI; any UI path
that calls `breaker`, policy engine, or Commander methods directly (permanently
forbidden — would violate ADR-0003/0005/0014); generalizing `operator-request`
beyond the three named actions.

## Consequences
- ARCHITECTURE.md's "Dashboard (showable)" deferred-bullet is resolved for the
  observability case; a true multi-tenant/fleet dashboard remains future work.
- The open-core seam (ADR-0003) gains a third intelligence-side consumer of the
  same two sanctioned crossings (telemetry-out, bus-subscribe); core is
  unchanged and the UI is additive/removable.
- ADR-0014's "one writer each" invariant is preserved: `operator-request` is
  either announce-only (mode) or targets an authority that already has no
  enforcement-write path (redteam-dept triggers).
- New dependency `textual` — UI-process only; does not appear in core's
  dependency graph.

## Required doc updates
- `docs/ARCHITECTURE.md` — new "Agentic Command Center" component section under
  intelligence-side components; update "What deliberately does not exist yet"
  (observability dashboard now exists; fleet/multi-tenant dashboard still
  deferred).
- `docs/ROADMAP.md` — M7 note: optional runtime-org visualization shipped.
