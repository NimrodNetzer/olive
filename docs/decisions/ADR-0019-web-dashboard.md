# ADR-0019: Web Dashboard for the Agentic Command Center

**Status:** accepted (2026-06-16)

## Context

ADR-0017 delivered the Agentic Command Center as a Textual TUI (`olive ui`), fed by `UIBroker`
(`src/olive/ui/broker.py`), which projects both `TelemetryEvent`s and `IncidentBus` objects into
rule-3-safe `UIEvent` DTOs. The TUI is read-only by construction and additive/removable from the
gateway. Starlette is already a core dependency (`olive serve`, `src/olive/transport/http.py`); no
new framework is needed for a WebSocket layer.

ARCHITECTURE.md's "What deliberately does not exist yet" continues to defer a "true
multi-tenant/fleet dashboard." This ADR delivers the next smallest step: a single-deployment,
browser-rendered view of the same `UIEvent` stream the TUI already consumes — without adding any
new enforcement authority, any new inward seam crossing, or any new framework dependency.

## Decision

### SS1. Placement: `src/olive/ui/` alongside `broker.py` and `app.py`

The WebSocket server (`src/olive/ui/web.py`) and its bundled static frontend
(`src/olive/ui/static/`) live in the existing `src/olive/ui/` package. This is correct by the same
reasoning as ADR-0017 §1: `olive/ui` is an intelligence-side sibling; it may import core types
one-directionally (`gateway/telemetry.py`, `gateway/pipeline.py`, `intelligence/bus.py`) and is
never imported by core. No new package boundary is needed; the web component is a second consumer
of `UIBroker`, not a separate subsystem.

`UIBroker` is the single source of truth for all subscribers. Both the Textual `App` and the
WebSocket server subscribe to the same `UIBroker.stream()` async generator. They may run
simultaneously or independently; `UIBroker` already handles multiple concurrent readers by the
drop-on-full fan-out contract inherited from ADR-0017 §2.

### SS2. Transport: Starlette WebSocket, no new dependency

The web server is a small Starlette `Application` defined in `src/olive/ui/web.py`. It exposes:

- `GET /` — serves `src/olive/ui/static/index.html` (and sibling assets) via `StaticFiles`.
- `GET /ws` — a Starlette `WebSocket` endpoint that subscribes to `UIBroker`, serialises each
  `UIEvent` as JSON, and pushes it to all connected clients. Slow or disconnected clients are
  dropped, mirroring `UIBroker`'s own drop-on-full contract; they must never apply backpressure to
  the broker or to the gateway fast path.
- `POST /operator` — the single inbound write surface (see SS4).

Starlette is already present in the dependency graph (`transport/http.py`). No new dependency is
introduced. `uvicorn` is already the assumed ASGI runner for `olive serve`; the web dashboard
reuses the same runner under `olive ui --web`.

### SS3. Read-only guarantee: same import-set test as ADR-0017

`src/olive/ui/web.py` must not import `gateway.breaker`, `gateway.proxy`, or
`intelligence.commander`, directly or transitively. A test asserts this import-set exclusion,
mirroring the existing test for `UIBroker` (ADR-0017 §2). The WebSocket endpoint is structurally
incapable of calling `trip`, `set_mode`, policy engine methods, or Commander methods, for the same
reason the Textual `App` is: the code that would let it do so is not importable from this module.

Any WebSocket message arriving on `GET /ws` that is not a valid `operator-request` payload is
silently dropped and logged; it is never forwarded to any bus or enforcement path.

### SS4. Inbound messages: operator-request via POST /operator, announce-only

The browser may send an `operator-request` by `POST /operator` with a JSON body
`{"action": "<action>"}`. The permitted action set is the same closed set defined in ADR-0017 §5:

- `"force-mode-request"` — announce-only. The web server publishes an `IncidentObject` of
  `kind="operator-request"`, `source_dept="ui"` onto the `IncidentBus`. It does not call
  `breaker.set_mode` or any Commander method.
- `"run-campaign-request"` and `"toggle-redteam-dept-request"` — may be acted on by
  `intelligence/redteam_dept.py` as an on-demand trigger (ADR-0016 §6). The web server only
  publishes; it does not call `run_once()` or `start()`/`stop()` directly.

Any body that does not parse as valid JSON, or whose `action` field is not in the above closed set,
is rejected `400 Bad Request`. No other inbound path exists. ADR-0014's "one writer each" invariant
for `trip` and `set_mode` is unchanged.

WebSocket inbound messages are not a supported write path. The `GET /ws` endpoint is read-only by
construction; any received WebSocket frame is dropped and logged.

### SS5. Frontend: static files bundled in `src/olive/ui/static/`, no build step

The frontend is plain HTML, CSS, and vanilla JavaScript, served by Starlette's `StaticFiles` mount
from `src/olive/ui/static/`. No npm, no bundler, no CDN dependency at runtime. Assets are
committed to the repo and served from disk; the dashboard must be fully functional in an air-gapped
environment. If the frontend grows to require a build step, that is a separate ADR decision.

### SS6. CLI surface: `--web` flag on `olive ui`

The existing `olive ui` subcommand gains an optional `--web` flag:
`olive ui --web [--host 127.0.0.1] [--port 7700]`. When `--web` is absent, behaviour is identical
to ADR-0017 (Textual TUI). When `--web` is present, the Textual TUI is not launched; instead
`uvicorn` serves the Starlette app on the specified host/port.

Default bind address is `127.0.0.1` (loopback only). Binding to `0.0.0.0` requires an explicit
`--host` flag. The dashboard has no authentication of its own and must be placed behind a network
boundary or reverse proxy if exposed beyond localhost.

### SS7. No new inward seam crossing

The two inward crossings sanctioned since ADR-0003/0014 remain exactly `CircuitBreaker.trip` (sole
caller: `SentinelRunner`) and `CircuitBreaker.set_mode` (sole caller: `SecurityCommander`). This
ADR adds zero new crossings. The web server is a third publisher of `operator-request` objects onto
the bus — the same announce-only surface introduced in ADR-0017 §5 — and a second subscriber to
`UIBroker.stream()`.

## Scope — IN / OUT

**IN:** `src/olive/ui/web.py` (Starlette app, WebSocket push, `POST /operator`),
`src/olive/ui/static/` (HTML/CSS/JS, no build step), `--web`/`--host`/`--port` flags on
`olive ui`, import-set exclusion test for `web.py`, `POST /operator` validation test (closed action
set, 400 on invalid), WebSocket drop-on-full test.

**OUT (deferred/forbidden):** authentication on the dashboard; binding to `0.0.0.0` as default; a
JS build step or CDN dependency; multi-tenant/fleet dashboard (deferred in ARCHITECTURE.md,
unchanged); pausing/stopping Commander/Defense/Remediation from the browser; any path from
`web.py` to `breaker.trip`, `breaker.set_mode`, or any policy engine method (permanently
forbidden).

## Consequences

**Positive:**
- Browser-rendered view with no new framework dependency and no new inward seam crossing.
- `UIBroker` reused without modification; the web component is additive and removable.
- Rule 3 inherited from `UIEvent` — the WebSocket stream carries only the bounded projection.
- Fail-closed: if the Starlette app errors, the WebSocket connection closes; gateway unaffected.
- Plain-HTML/JS frontend ships inside the Python wheel with no build toolchain.

**Negative:**
- Loopback `POST /operator` is a new local attack surface (compromised co-process could send
  requests). Mitigation: closed action set, announce-only semantics, loopback-only default.
- `olive ui --web` does not run the Textual TUI simultaneously; operators wanting both run two
  processes (both share `UIBroker`'s drop-on-full fan-out).
- No auth on `POST /operator`; multi-user/remote use requires a network boundary.
- Static frontend capability is limited by the no-build-step constraint; complex animated
  visualisations that require a JS framework are deferred.
