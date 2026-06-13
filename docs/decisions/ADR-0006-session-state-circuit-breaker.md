# ADR-0006: Session state and the circuit breaker

**Status:** accepted (2026-06-13)

## Context
M1 enforces per-message: each tool call and each response is judged on its own.
But an attack is rarely one message — a compromised session probes, gets one
payload blocked, and immediately tries the next bypass. Blocking messages while
letting the *session* continue unbounded is the wrong containment posture.

The vision and ARCHITECTURE.md call for a **circuit breaker**: deterministic
containment that quarantines a whole session and supports reversible human
release. It is also the component the future LLM sentinels (M6, ADR-0005) will
*signal* but never control — so its enforcement must be pure deterministic code.

## Decision
Introduce session state and a circuit breaker as core-gateway components.

- **`gateway/session.py`** — `SessionState` (mutable): status, call counter,
  tool history, block count, first/last seen, quarantine reason + the incident
  id that caused the quarantine. Pure data, no I/O.
- **`gateway/breaker.py`** — `CircuitBreaker`: the single concurrency authority
  over session state. It owns the in-memory session map and one `asyncio.Lock`,
  so call-sequencing and trip decisions are atomic together (no two-lock
  ordering hazard). API: `begin_call` (atomically returns a `CallTicket` with
  call number + history snapshot + quarantine status — a quarantined session is
  *not* advanced), `record_allowed_call`, `record_block` (increments and trips
  at threshold in one atomic step), `release`, `status`, `snapshot`.
- **Trip policy (M2):** auto-quarantine when a session accumulates
  `max_blocks_before_quarantine` blocks (config, default 3). In M6 the same
  `trip()` entry point is what a sentinel signal will call. Enforcement stays
  deterministic either way.
- **Containment is checked first.** The proxy asks the breaker before any
  pipeline work or upstream contact; a quarantined session's calls are denied
  with `Decision.QUARANTINE` and never reach an inspector or the upstream.
- **Quarantine does not spam incidents.** The block that trips the breaker
  creates the incident; subsequent quarantined calls are logged as
  `quarantine` *events* referencing that same incident id — every decision is
  still auditable (rule 5) without a new incident per denied call.
- **Layering (ADR-0003).** The breaker imports nothing from store/intelligence.
  It returns plain values; the proxy does the logging. This keeps the core free
  of the eventual commercial layers.

## Scope / deferral
State is **in-memory and per-process**. In stdio mode that is exactly one
session, so quarantine is fully effective for the lifetime of the run. **Human
release is implemented and tested as a method**, but an *admin surface* to
release a session in another process (CLI/HTTP endpoint) requires shared state
and lands with the **HTTP transport** later in M2. Persisting session/quarantine
state across restarts is deferred until there is a reason to (it would reuse the
existing store interface, ADR-0004).

## Consequences
- Containment becomes real: a probing session is stopped wholesale, not just
  message-by-message — the `Contain` step of the product loop.
- The trip entry point is ready for M6 sentinel signals with no redesign.
- Until the HTTP admin surface exists, release is reachable only in-process
  (and in tests); this limitation is recorded in ARCHITECTURE.md and ROADMAP.md.
- Reproducibility holds: a quarantine is explainable from the block events that
  preceded it plus the configured threshold.
