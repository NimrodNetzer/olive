# ADR-0024: Fleet Foundation — control plane architecture for multi-gateway deployments

**Status:** accepted (2026-06-18)

## Context

Milestones M1–M10 deliberately scoped Olive to a single-gateway deployment. The
in-memory `CircuitBreaker`, `IncidentBus`, and `OperatingMode` are per-process;
the SQLite audit store is a local file. That model is production-correct for one
gateway instance. It cannot address enterprise deployments where N gateway
processes front different agent teams, environments, or tenants.

ADR-0020 explicitly deferred cross-process/fleet mode propagation and a fleet
dashboard to a future ADR. This is that ADR.

Three constraints dominate every choice:

1. **ADR-0003 (layering rule):** gateway core (`src/olive/`) must never import
   fleet or intelligence layers. No new inward coupling beyond the two
   already-sanctioned `CircuitBreaker` crossings (`trip` / `set_mode`).
2. **Security rule 4 (fail closed):** if the control plane is unreachable, each
   gateway continues at its current operating mode — it does not degrade to
   Normal and does not fail enforcement. The control plane is a management
   overlay, not a dependency of the fast path.
3. **ADR-0006 (breaker authority):** `CircuitBreaker` remains the sole
   session-state and operating-mode authority within a gateway process. The
   control plane may instruct a mode change, but it executes through
   `breaker.set_mode` via the Commander — the single-writer rule is preserved.

## Decision

### 1. Control plane storage: separate process, own DB, gateways push event summaries

**Option A (shared SQLite)** introduces write contention at N > 2 concurrent
writers and conflates gateway audit integrity with fleet aggregation — a locked
shared file takes both down simultaneously.

**Option C (control plane reads N gateway DB files)** requires filesystem access
to every gateway's SQLite path, which is impossible in networked or containerised
deployments and violates the spirit of ADR-0003.

**Chosen: Option B.** The control plane runs as a separate process
(`olive control-plane`) with its own SQLite DB (ADR-0004 interface; swappable to
Postgres later). Gateways own their audit DB (unchanged) and push event
summaries to the control plane over HTTPS.

What gateways push: structured event summaries (event_id, agent_id, org,
session_id, tool, decision, timestamp, policy_rule) and incident summaries
(incident_id, attack_type, confidence, decision, status). No raw arguments, no
response bodies — the same bounded evidence rule (security rule 3) the local
store already enforces.

The gateway push is fire-and-forget over an async queue with drop-on-full: a
slow or unavailable control plane never blocks the fast path (same contract as
`QueueSink` for the UIBroker).

### 2. Mode propagation: hybrid heartbeat (gateway polls, mode piggy-backed on response)

**Option A (push — control plane calls each gateway)** requires the control
plane to maintain a live registry of gateway endpoints and authenticate outbound
calls, adding operational surface for a feature that needs to be simple first.

**Option B (pure pull)** introduces a hard latency floor: Siege escalation
during an active attack should not wait 30 seconds.

**Chosen: Option C (hybrid).** The gateway sends a heartbeat `POST
/fleet/heartbeat` every N seconds (default 10 s, minimum 5 s) and reads the
`mode` field in the response. The round-trip happening anyway carries the mode
instruction at no additional cost. Maximum fleet-wide mode-propagation lag is N
seconds — acceptable for a management overlay.

The mode field in the heartbeat response is advisory to the control plane only.
The gateway passes it to `SecurityCommander.force_mode` (which calls
`breaker.set_mode`), not to the breaker directly. The existing `olive:command`
capability gate on `force_mode` is reused. This preserves the single-writer rule
(ADR-0006): the Commander remains the only code that calls `set_mode`.

Fail-closed: if a heartbeat fails (network error, 4xx/5xx, TLS error, auth
error), the gateway logs a warning and retains its current mode. Three
consecutive heartbeat failures trigger a local escalation to `SUSPICIOUS` (not
Siege; that requires a confirmed incident stream) to account for the possibility
the control plane is unreachable due to an attack.

### 3. Policy distribution: control plane serves YAML over HTTP, local-disk fallback

The control plane exposes `GET /fleet/policy/{role}` (bearer-auth gated,
`olive:fleet` capability). Gateways fetch their role policy on startup and on
`SIGHUP`. The fetched YAML is byte-for-byte compatible with the existing local
format; `PolicyLoader` is called identically regardless of source.

Local YAML files remain the authoritative fallback: if the control plane is
unreachable at startup the gateway loads from disk and logs a warning. Fetches
over plaintext HTTP are rejected when `--control-plane-url` is `http://` without
an explicit `--allow-insecure` flag (fail-closed).

### 4. Fleet dashboard: reads from control plane API

The control plane exposes a read-only fleet API: `GET /fleet/events`, `GET
/fleet/incidents`, `GET /fleet/gateways` (heartbeat-derived liveness), `GET
/fleet/mode` (last-reported mode per gateway). The existing web dashboard
(`olive ui --web`) is extended with a fleet tab when `--control-plane-url` is
configured. Same Starlette/static-HTML approach; no new framework.

The fleet dashboard is read-only. There is no `POST /fleet/operator` in this
ADR; fleet-wide mode commands go through the control plane's own authenticated
admin surface, not the gateway's unauthenticated `POST /operator` endpoint.

## New component: `src/olive/fleet/`

The fleet layer lives at `src/olive/fleet/` — inside the repo but on the
intelligence/fleet side of the ADR-0003 seam. Core (`gateway/`, `store/`,
`identity/`) must never import from `fleet/`. A test asserts the import set.

Sub-modules:
- `fleet/client.py` — async HTTP client for heartbeat, policy fetch, and event
  push. Drop-on-full queue for event push; never blocks the fast path. Accepts a
  pre-built `httpx.AsyncClient`.
- `fleet/heartbeat.py` — heartbeat loop: sends every N seconds, reads the
  response `mode` field, calls `SecurityCommander.force_mode` if mode differs.
  Counts failures toward the three-failure `SUSPICIOUS` escalation.
- `fleet/gateway_registry.py` — control plane side: receives heartbeats, tracks
  liveness, stores last-known mode per gateway id.
- `fleet/control_plane.py` — lightweight Starlette app assembling the control
  plane endpoints. Launched via `olive control-plane` CLI subcommand.

## New capability: `olive:fleet`

A distinct `olive:fleet` capability gates gateway-to-control-plane bearer
tokens. It grants: heartbeat, event push, policy fetch. It does not imply
`olive:command`, `olive:approve`, `olive:release`, or `olive:remediate`.
Capabilities still never imply one another.

## Audit (security rule 5)

Every mode change received via heartbeat is logged at the gateway as a
`mode-change` event with `source=fleet-control-plane`, the gateway's current
`incident_id` context, and a timestamp. The control plane logs every mode
instruction it issues (to which gateway, from which operator, when). Neither
log replaces the other.

## Scope — IN / OUT

**IN (M11):**
- `src/olive/fleet/` (client, heartbeat, registry, control-plane app)
- `olive control-plane` CLI subcommand
- Heartbeat loop wired into `olive serve` lifespan (off by default, enabled
  with `--control-plane-url`)
- Policy fetch in `PolicyLoader` with local-disk fallback
- Event push queue (fire-and-forget, drop-on-full)
- Fleet tab in `olive ui --web` (read-only)
- `olive:fleet` capability
- Three-failure escalation to `SUSPICIOUS`
- Import-set test: `gateway/` must not import `fleet/`
- Tests: heartbeat fail-closed (mode retained), policy-fetch fallback,
  event-push drop-on-full, three-failure escalation, fleet-tab read-only

**OUT (deferred / forbidden):**
- Cross-process incident bus federation (each gateway's bus remains per-process
  and per-HMAC-key; aggregation is event-summary push, not live bus fan-out)
- Durable quarantine state across gateway restarts within one gateway (still
  the ADR-0021 per-gateway DB guarantee; cross-fleet sync is out of scope)
- Auth on the `olive ui --web` dashboard (stays loopback-default, ADR-0020)
- `POST /fleet/operator` (fleet commands go through control-plane admin surface)
- Fleet-level policy write from the dashboard (git is the authoring mechanism)
- Automatic policy rollback (git is the rollback mechanism)
- Postgres backend for control plane (ADR-0004 interface allows it later)
- Cross-gateway revocation propagation for `jti` (ADR-0022 revocation is
  per-gateway; fleet-level revocation push is unblocked by this ADR but deferred)
- Any mechanism by which the control plane writes to a gateway's SQLite DB

## Consequences

- Fleet operators get a single pane for incidents and mode state across N
  gateways, with at most N-second mode-propagation lag.
- An unreachable control plane is a management degradation, not an enforcement
  failure. Every gateway continues enforcing at its last known mode.
- The ADR-0003 seam is respected: `gateway/` imports nothing from `fleet/`.
- The ADR-0006 single-writer rule is respected: `fleet/heartbeat.py` calls
  `commander.force_mode`, not `breaker.set_mode` directly.
- New residual risk: the `olive:fleet` credential is a new secret; compromise
  allows fleet-wide mode-change instructions (still mediated through the
  Commander's deterministic `target_mode` policy). The fleet client must support
  hot-reload of the credential from an environment variable without restart.
- The control plane is a new network surface; all endpoints are TLS-only with
  certificate validation enforced by the fleet client.

## Required doc updates

- `docs/ARCHITECTURE.md` — add `fleet/` component section; update the
  "What deliberately does not exist yet" bullet (cross-process fleet propagation
  now exists in M11); update the layering rule paragraph to name `fleet/`
  alongside `intelligence/` as a one-directional importer.
- `docs/THREAT_MODEL.md` — add "Fleet control plane" as a protected asset; add
  non-guarantee bullet for the N-second propagation lag and the `olive:fleet`
  credential as a new secret; add cross-gateway jti revocation propagation as a
  remaining non-guarantee.
- `docs/ROADMAP.md` — M11: Fleet Foundation; note that per-gateway bus
  federation and cross-fleet jti revocation propagation remain future work.
