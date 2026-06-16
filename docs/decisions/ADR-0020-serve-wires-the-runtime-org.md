# ADR-0020: Wire the runtime org into `olive serve` and co-mount the Command Center

**Status:** accepted (2026-06-16)

## Context

ADR-0014 built the runtime agent company (Commander, operating modes, incident
bus, departments); ADR-0017/0019 added the read-only Command Center (TUI + web
dashboard); ADR-0018 added the runtime Builder department. To date `olive serve`
(`cli.py:serve_http`) builds only the bare gateway — no telemetry sink, no bus,
no runtime org, no sentinels — and the UI runs as a *separate* `olive ui` process.

Because the incident bus is in-process by design (in-memory async pub/sub +
per-process HMAC key + SQLite persistence, ADR-0014 §4), a separate UI process
cannot receive live bus events from a running `serve`; it sees only persisted
`history()` and live-fans-out only events published in its own process. A live
demo of "the gateway is defending an agent and the Command Center shows it
happening in real time" therefore requires the gateway and the UI to share one
process, one bus, one breaker, one event loop.

This slice is demo-driven (UNIC, ~23–24 June 2026): the whole live loop must work
with **no `ANTHROPIC_API_KEY`** — the deterministic decode/pattern inspectors and
the deterministic-first sentinels produce real incidents, the breaker quarantines,
the Commander escalates, and a sandbox red-team drill → finding → Builder
fix-proposal all run key-free. Sentinels still degrade to "no signal" for the
semantic path without a key (ADR-0012), unchanged.

## Decision

### 1. Cross-process question: one process (Option A)
`olive serve --ui` (or `--web`) builds the gateway AND co-mounts the Command
Center on the SAME uvicorn/Starlette app, sharing ONE `IncidentBus`, ONE
`CircuitBreaker`, ONE `UIBroker`, and ONE event loop. This is the only option
that yields true in-process live fan-out. DB-tailing and a real cross-process
broker are rejected: tailing reintroduces polling latency and a per-process
HMAC-key mismatch that breaks cross-process signature verification; a real broker
is speculative generality. Bus, breaker, and mode remain in-memory/per-process
(unchanged from ADR-0014); cross-process / fleet propagation stays deferred.

### 2. Wiring lives at the composition root; no new inward seam crossing
All new wiring is in `cli.py` (the composition root) and the transport lifespan.
The gateway is constructed with an injected `QueueSink` (`telemetry=`) and an
explicit shared `CircuitBreaker` (`breaker=`) — both already supported by
`OliveGateway.__init__`. `build_runtime_org` (intelligence side) is given that
same breaker, queue, bus, sentinels, and the Builder `ProposalLedger`. Telemetry
flows OUT through the queue; the only inward crossings remain
`CircuitBreaker.trip` (sole caller `SentinelRunner`) and `CircuitBreaker.set_mode`
(sole caller `SecurityCommander`), exactly as ADR-0003/0014. Core imports nothing
intelligence-side; `transport/http.py` stays free of `olive.ui` — the UI routes
are injected into `build_http_app` from the composition root.

### 3. MultiSink (the one new core primitive)
`UIBroker` must be registered as an *additional* telemetry sink alongside the
`QueueSink` (ADR-0017 §2), but `OliveGateway` takes a single `telemetry=` sink.
This ADR introduces a small `MultiSink` in `gateway/telemetry.py` that publishes
to each wrapped sink under that sink's own drop/never-block contract: a slow or
full UI sink never blocks the `QueueSink` or the fast path, and one sink raising
never stops the others. `MultiSink` lives in core but imports nothing
intelligence-side (sinks are passed in as the `TelemetrySink` protocol), so the
layering rule holds.

### 4. Lifespan: runtime org starts/stops as background tasks, never blocking
The serving lifespan starts `org.start()` (SentinelRunner drain loop) after the
session manager is running, and `await org.stop()` + bus/ledger close on
shutdown. The drain loop and (if ever enabled) the red-team scheduler spawn
background asyncio tasks, mirroring the existing start/stop contract — neither
blocks the uvicorn serve loop. The bare `serve` lifespan path is unchanged and
selected when the flag is off.

### 5. UI routes co-mounted, NOT behind the gateway's bearer auth
The dashboard routes (`GET /ws`, `GET /corpus`, `POST /operator`, static) are
added to the app alongside `/mcp` + `/admin/*` but are NOT wrapped in the
gateway's `RequireAuthMiddleware`. `POST /operator` keeps its ADR-0017 §5 /
ADR-0019 §4 semantics exactly: announce-only / on-demand-trigger-only, the closed
`OPERATOR_ACTIONS` set, 400 on anything else, never a path to `trip`/`set_mode`.
The UI's read-only-by-construction property (import-set exclusion of
`gateway.breaker`, `gateway.proxy`, `intelligence.commander`) is unchanged; a
test asserts the assembled app exposes the UI routes without bearer auth and the
MCP route still behind it.

### 6. On-demand drills (presenter-driven), not a timer
A red-team drill fires when the presenter clicks "fire drill" in the dashboard:
the browser `POST /operator {"action": "run-campaign-request"}` publishes an
`operator-request` object; a deterministic **operator bridge** subscribed to
`kind="operator-request"` turns `run-campaign-request` into
`RedTeamDepartment.run_once()` (a sandbox campaign, ADR-0015/0016). This is the
ADR-0017 §5 sanctioned on-demand-trigger path, now wired. The bridge subscribes
only to `operator-request` (never to `redteam-finding`/`fix-proposed`), so there
is no feedback loop; `force-mode-request` remains announce-only (audited, never
auto-applied — a human with `olive:command` still must act). The red-team
*scheduler interval* stays off by default (deferred); single-flight in `run_once`
already guards re-entrancy.

### 7. Additive, reversible, default-off
Bare `olive serve` is byte-for-byte unchanged when the flag is absent (NullSink
default, no org, no UI) — the same "additive and removable" property as
ADR-0012/0017. The Builder department is enabled (a `ProposalLedger` is opened)
when the UI is on, so fix-proposals appear in the demo.

## Scope — IN / OUT

**IN:** `--ui`/`--web`/`--host`/`--port` flags on `olive serve`; the org-aware
serving-lifespan branch; `MultiSink` in `gateway/telemetry.py`; a
`build_sentinels(config)` helper (intelligence side) constructing the three
deterministic-capable sentinels; the operator bridge
(`operator-request:run-campaign-request → run_once`); UI routes injected into
`build_http_app` (no bearer auth) + a "fire drill" control in the dashboard;
tests (bare-serve-unchanged-when-off, MultiSink fan-out + drop isolation, the
operator bridge, UI-routes-not-behind-bearer-auth on the assembled app).

**OUT (deferred / forbidden):** cross-process/fleet bus or mode propagation;
durable bus/mode across restart; auth on the dashboard or `POST /operator`;
default non-loopback bind; the red-team scheduler interval on by default; any
UI/lifespan/bridge path that calls `breaker.trip`/`breaker.set_mode`/policy or a
Commander method directly (permanently forbidden — ADR-0003/0005/0014);
auto-applying a `force-mode-request` (stays announce-only).

## Consequences

- One impressive single-process live demo; no new framework, one tiny new core
  primitive (`MultiSink`), no new inward seam crossing, and no API key required.
- A co-mounted unauthenticated dashboard shares an origin and event loop with the
  bearer-protected gateway — a new local surface, mitigated by loopback-only
  default + announce-only `POST /operator` + drop-on-full isolation.
- Bus/breaker/mode remain per-process/in-memory; a restart loses live state.

## Required doc updates
- `docs/ARCHITECTURE.md` — the `olive serve --ui` co-mount path under the Command
  Center section.
- `docs/THREAT_MODEL.md` — the co-mounted-dashboard non-guarantee bullet.
- `docs/ROADMAP.md` — M7: runtime org wired into `serve`, live Command Center.

## Threat-model bullet to add
- **Co-mounted Command Center (M7, ADR-0020):** running `olive serve --ui` mounts
  the read-only dashboard on the same Starlette app and event loop as the
  bearer-protected gateway. The dashboard and `POST /operator` are NOT behind the
  gateway's bearer auth; their safety rests on the ADR-0017 §5 announce-only
  closed action set and the UI's import-set exclusion (no `trip`/`set_mode`/
  Commander reachable), not on authentication. Default bind is loopback;
  `--host 0.0.0.0` would expose the unauthenticated dashboard and `POST /operator`
  to the network and must be explicit. A UI WebSocket flood cannot apply
  backpressure to the fast path (drop-on-full on `MultiSink`, the per-client WS
  sub-queue, and `QueueSink`). Bus/breaker/mode remain in-memory/per-process; a
  restart loses live containment and posture (same non-guarantee as ADR-0006/0014).
