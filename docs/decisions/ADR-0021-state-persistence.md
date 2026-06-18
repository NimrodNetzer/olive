# ADR-0021: Durable session and mode state — quarantine and posture survive restarts

**Status:** accepted (2026-06-18, retrospective for M8)

## Context

Through M7 the `CircuitBreaker`'s session map and `OperatingMode` value were
purely in-memory. A gateway restart during an active incident silently reset all
containment state: quarantined sessions became active again, Siege mode dropped
to Normal, and the audit trail had no record of the gap. For a production
gateway this is unacceptable — an attacker who can force a restart (OOM, crash,
deploy) can escape quarantine.

M8 closes this gap by persisting the two pieces of containment state that matter
across restarts: per-session quarantine records and the current operating mode.
The existing `events` + `incidents` SQLite store (ADR-0004) is extended with two
new tables rather than introducing a new persistence layer.

## Decision

### 1. Two new tables in the existing SQLite store

`sessions` — one row per quarantined session:
- `session_id` (PK), `agent_id`, `organization_id`, `role`, `block_count`,
  `quarantine_reason`, `incident_id`, `first_seen`, `last_seen`, `status`
- Written on every `CircuitBreaker.trip`; deleted on human release
- Only quarantined sessions are persisted (active sessions are transient;
  persisting them would add write overhead for zero recovery value)

`runtime_state` — single-row key/value slab for scalar gateway state:
- `key` (`operating_mode`), `value` (enum name string), `updated_at`
- Written on every `SecurityCommander.set_mode`; read once at startup

Both tables follow security rule 3: no raw arguments or response content stored,
only structural metadata.

### 2. Startup hydration sequence

On gateway start (`run_gateway` and `serve_http_live` in `cli.py`), before the
first MCP call is served:
1. `EventStore.load_sessions()` → list of `SessionState` objects
2. `CircuitBreaker.restore(sessions)` → rebuilds in-memory map; quarantined
   sessions are quarantined immediately, not re-evaluated
3. `EventStore.load_mode()` → `OperatingMode` (defaults to `NORMAL` if absent)
4. `CircuitBreaker.restore_mode(mode)` → sets mode before any request is served

The hydration is synchronous in the lifespan startup path. If the store is
corrupt or unreadable the gateway starts in NORMAL with an empty session map and
logs an error — it does not fail to start (fail-open on startup is acceptable
here because no traffic has flowed yet; the alternative, refusing to start
because of a corrupt DB, would itself be an availability attack vector).

### 3. Write path remains the same two single writers

`CircuitBreaker.trip` remains the sole writer of session quarantine state. The
proxy calls `store.persist_session` immediately after `breaker.trip`; the
SentinelRunner does the same after its sentinel-triggered trip. `set_mode`
remains the SecurityCommander's sole authority; it calls `store.persist_mode`
after updating the breaker.

No new inward crossing is introduced. The store is passed to the Commander and
accessed from the proxy — both already had store references.

### 4. Scope

**IN:** `sessions` + `runtime_state` tables; 5 new store methods
(`persist_session`, `load_sessions`, `delete_session`, `persist_mode`,
`load_mode`); `restore()` + `restore_mode()` on `CircuitBreaker`; hydration in
`cli.py`; `test_persistence.py` (10 tests, full round-trip).

**OUT:** Persisting active (non-quarantined) session state; persisting the
in-memory incident bus (`IncidentBus` already has its own `incident_events`
table from ADR-0014); cross-process session sharing (still per-gateway).

## Consequences

- A gateway restart during an active Siege no longer resets containment.
  Quarantined agents stay quarantined; operating mode is restored before the
  first call is served.
- The SQLite write path for `persist_session` is on the hot path (every
  `trip`), but trips are rare events — the overhead is negligible.
- The `delete_session` call on human release ensures the DB does not accumulate
  stale quarantine rows indefinitely.
- Hydration failure is logged but non-fatal; the gateway starts clean rather
  than refusing to serve.

## Required doc updates

- `docs/ARCHITECTURE.md` — note `sessions` + `runtime_state` tables in the
  Event Store section; update CircuitBreaker description to mention startup
  hydration.
- `docs/THREAT_MODEL.md` — remove "containment state lost on restart"
  non-guarantee bullet (it is now a guarantee within a single gateway process).
