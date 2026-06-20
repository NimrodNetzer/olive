"""Agentic Command Center — web dashboard (ADR-0019).

A small Starlette app that pushes `UIEvent`s to browsers over WebSocket and
serves the static HTML/CSS/JS frontend from `src/olive/ui/static/`.

Read-only by construction (ADR-0019 SS3): this module must not import
`gateway.breaker`, `gateway.proxy`, or `intelligence.commander`. A test asserts
the import set, mirroring the test for `UIBroker` (ADR-0017 SS2).

The single inbound write path is `POST /operator` (ADR-0019 SS4): the browser
may publish an announce-only `operator-request` bus object from the same closed
action set defined in ADR-0017 §5. The `GET /ws` endpoint is push-only; any
received WebSocket frame is dropped.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

from olive.intelligence.bus import IncidentBus
from olive.ui.broker import OPERATOR_ACTIONS, UIBroker, make_operator_request

_STATIC = Path(__file__).parent / "static"
_LOG = logging.getLogger(__name__)

_CORPUS: list[str] = []  # set by build_app via corpus_dir arg


def _event_json(event) -> str:
    return json.dumps(dataclasses.asdict(event))


async def _ws_endpoint(websocket: WebSocket) -> None:
    """Push UIEvents to this client. Receives nothing — any inbound frame is
    dropped per ADR-0019 SS3 (GET /ws is a read-only push channel)."""
    broker: UIBroker = websocket.app.state.broker
    await websocket.accept()
    # Fan-out: each client gets its own async task that reads from broker.stream().
    # UIBroker.stream() is a shared generator and must not be consumed by multiple
    # callers — so we subscribe via a per-client sub-queue instead.
    client_q: asyncio.Queue = asyncio.Queue(maxsize=128)
    dropped = 0

    async def _drain() -> None:
        nonlocal dropped
        async for event in broker.stream():
            try:
                client_q.put_nowait(event)
            except asyncio.QueueFull:
                dropped += 1

    drain_task = asyncio.create_task(_drain())
    try:
        while True:
            recv_task = asyncio.create_task(websocket.receive_text())
            send_task = asyncio.create_task(client_q.get())
            done, pending = await asyncio.wait(
                [recv_task, send_task], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            for t in done:
                if t is send_task and not t.cancelled():
                    try:
                        await websocket.send_text(_event_json(t.result()))
                    except (WebSocketDisconnect, RuntimeError):
                        return
                elif t is recv_task and not t.cancelled():
                    # Re-raise if the receive itself failed (disconnect or
                    # "already disconnected" RuntimeError) so the outer
                    # except can clean up instead of looping into another
                    # receive_text() on a closed socket.
                    exc = t.exception()
                    if exc is not None:
                        raise exc
                    _LOG.debug("ws: inbound frame dropped (read-only channel)")
    except (WebSocketDisconnect, asyncio.CancelledError, RuntimeError):
        pass
    finally:
        drain_task.cancel()
        if dropped:
            _LOG.debug("ws: dropped %d events for slow client", dropped)


async def _corpus_endpoint(request: Request) -> JSONResponse:
    """Return the list of corpus case stems for the attack-theater UI."""
    return JSONResponse(request.app.state.corpus)


async def _events_recent_endpoint(request: Request) -> JSONResponse:
    """Return the last N gateway decision events for UI history replay."""
    store = getattr(request.app.state, "store", None)
    if store is None:
        return JSONResponse([])
    try:
        limit = min(int(request.query_params.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50
    return JSONResponse(await store.recent_events(limit))


async def _incidents_list_endpoint(request: Request) -> JSONResponse:
    """Return the last N incidents for the UI incidents panel."""
    store = getattr(request.app.state, "store", None)
    if store is None:
        return JSONResponse([])
    try:
        limit = min(int(request.query_params.get("limit", 20)), 100)
    except (ValueError, TypeError):
        limit = 20
    return JSONResponse(await store.recent_incidents(limit))


async def _metrics_endpoint(request: Request) -> JSONResponse:
    """Return eval/test metrics so the dashboard badge is never hardcoded."""
    corpus_dir: Path | None = getattr(request.app.state, "corpus_dir_path", None)
    baseline: dict = {}
    corpus_size = 0
    if corpus_dir and corpus_dir.is_dir():
        baseline_path = corpus_dir.parent / "baseline.json"
        try:
            baseline = json.loads(baseline_path.read_text())
        except Exception:
            pass
        corpus_size = sum(1 for _ in corpus_dir.glob("*.yaml"))
    return JSONResponse({
        "detected": baseline.get("detected", 0),
        "malicious_total": baseline.get("malicious_total", 0),
        "false_positives": baseline.get("false_positives", 0),
        "benign_total": baseline.get("benign_total", 0),
        "corpus_size": corpus_size,
        "test_count": getattr(request.app.state, "test_count", 0),
    })


async def _stats_summary_endpoint(request: Request) -> JSONResponse:
    """Aggregate allow/block/hold/quar counts and latency percentiles."""
    store = getattr(request.app.state, "store", None)
    if store is None:
        return JSONResponse({})
    events = await store.recent_events(200)
    counts: dict[str, int] = {"allow": 0, "block": 0, "hold": 0, "quarantine": 0}
    latencies: list[int] = []
    for ev in events:
        dec = ev.get("decision", "")
        if dec in counts:
            counts[dec] += 1
        lat = ev.get("latency_ms")
        if lat is not None:
            latencies.append(int(lat))
    latencies.sort()
    n = len(latencies)
    p50 = latencies[n // 2] if n > 0 else 0
    p95 = latencies[min(int(n * 0.95), n - 1)] if n > 0 else 0
    summary = await store.summary()
    return JSONResponse({
        "allow": counts["allow"],
        "block": counts["block"],
        "hold": counts["hold"],
        "quarantine": counts["quarantine"],
        "incidents": summary.incidents,
        "latency_p50": p50,
        "latency_p95": p95,
    })


async def _agents_summary_endpoint(request: Request) -> JSONResponse:
    """Per-agent aggregated stats for the trust panel."""
    store = getattr(request.app.state, "store", None)
    if store is None:
        return JSONResponse([])
    events = await store.recent_events(200)
    agents: dict[str, dict] = {}
    for ev in events:
        aid = ev.get("agent_id") or ""
        if not aid:
            continue
        if aid not in agents:
            agents[aid] = {
                "agent_id": aid, "calls": 0, "blocked": 0,
                "quarantined": 0, "last_seen": "", "last_tool": "",
            }
        a = agents[aid]
        a["calls"] += 1
        dec = ev.get("decision", "")
        if dec in ("block", "hold"):
            a["blocked"] += 1
        elif dec == "quarantine":
            a["quarantined"] += 1
        ts = ev.get("timestamp", "")
        if ts > a["last_seen"]:
            a["last_seen"] = ts
            a["last_tool"] = ev.get("tool", "")
    result = []
    for a in agents.values():
        total = a["calls"]
        a["block_rate"] = round((a["blocked"] + a["quarantined"]) / total, 3) if total else 0.0
        result.append(a)
    result.sort(key=lambda x: x["last_seen"], reverse=True)
    return JSONResponse(result)


async def _tools_hotspot_endpoint(request: Request) -> JSONResponse:
    """Top-5 most-called tools with block counts, for the gateway center."""
    store = getattr(request.app.state, "store", None)
    if store is None:
        return JSONResponse([])
    events = await store.recent_events(200)
    tools: dict[str, dict] = {}
    for ev in events:
        tool = ev.get("tool") or ""
        if not tool:
            continue
        if tool not in tools:
            tools[tool] = {"tool": tool, "calls": 0, "blocked": 0}
        tools[tool]["calls"] += 1
        if ev.get("decision") in ("block", "quarantine"):
            tools[tool]["blocked"] += 1
    result = sorted(tools.values(), key=lambda x: x["calls"], reverse=True)[:5]
    return JSONResponse(result)


async def _llm_status_endpoint(request: Request) -> JSONResponse:
    """Return current LLM (SemanticAnalyzer) enabled/available/provider state."""
    bridge = getattr(request.app.state, "operator_bridge", None)
    return JSONResponse({
        "available": bridge.llm_available if bridge else False,
        "enabled": bridge.llm_enabled if bridge else False,
        "provider": bridge.llm_provider if bridge else None,
    })


async def _operator_endpoint(request: Request) -> JSONResponse:
    """The single inbound write surface (ADR-0019 SS4). Accepts
    `{"action": "<action>"}` from the browser and publishes an announce-only
    `operator-request` bus object. Rejects unknown actions with 400."""
    bus: IncidentBus | None = request.app.state.bus
    if bus is None:
        return JSONResponse({"error": "no bus configured"}, status_code=503)
    try:
        body = await request.json()
        action = body.get("action", "")
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if action not in OPERATOR_ACTIONS:
        return JSONResponse(
            {"error": f"unknown action {action!r}; must be one of {sorted(OPERATOR_ACTIONS)}"},
            status_code=400,
        )
    evidence = str(body.get("evidence", ""))[:200]
    obj = make_operator_request(bus, action=action, evidence=evidence)
    published = await bus.publish(obj)  # publish returns the persisted object with object_id set
    _LOG.info("operator-request published: action=%s object_id=%s", action, published.object_id)
    return JSONResponse({"ok": True, "object_id": published.object_id, "action": action})


def _corpus_stems(corpus_dir: Path | None) -> list[str]:
    return (
        sorted(p.stem for p in corpus_dir.glob("*.yaml"))
        if corpus_dir and corpus_dir.is_dir()
        else []
    )


def ui_routes() -> list:
    """The dashboard's routes, for co-mounting onto the gateway's Starlette app
    (ADR-0020). The endpoints read `broker`/`bus`/`corpus` from
    `request.app.state`, which the host app's lifespan must set. Returned WITHOUT
    any auth middleware: the dashboard is read-only and `POST /operator` is
    announce-only (ADR-0017 §5). The static Mount is last so the specific gateway
    routes (`/mcp`, `/admin/*`) and UI routes match first."""
    return [
        WebSocketRoute("/ws", _ws_endpoint),
        Route("/corpus", _corpus_endpoint, methods=["GET"]),
        Route("/metrics", _metrics_endpoint, methods=["GET"]),
        Route("/llm-status", _llm_status_endpoint, methods=["GET"]),
        Route("/stats/summary", _stats_summary_endpoint, methods=["GET"]),
        Route("/agents/summary", _agents_summary_endpoint, methods=["GET"]),
        Route("/tools/hotspot", _tools_hotspot_endpoint, methods=["GET"]),
        Route("/events/recent", _events_recent_endpoint, methods=["GET"]),
        Route("/incidents/list", _incidents_list_endpoint, methods=["GET"]),
        Route("/operator", _operator_endpoint, methods=["POST"]),
        Mount("/", StaticFiles(directory=str(_STATIC), html=True)),
    ]


def build_app(
    broker: UIBroker,
    bus: IncidentBus | None = None,
    corpus_dir: Path | None = None,
    store=None,
    test_count: int = 0,
    operator_bridge=None,
) -> Starlette:
    """Build the standalone Starlette ASGI app (`olive ui --web`, a separate
    process). `broker` is required (stream source); `bus` is optional (enables
    POST /operator — without it the endpoint returns 503); `corpus_dir` populates
    the GET /corpus list for the attack-theater. `test_count` is embedded in the
    /metrics response so the eval badge in the UI stays current."""
    app = Starlette(routes=ui_routes())
    app.state.broker = broker
    app.state.bus = bus
    app.state.corpus = _corpus_stems(corpus_dir)
    app.state.store = store
    app.state.corpus_dir_path = corpus_dir
    app.state.test_count = test_count
    app.state.operator_bridge = operator_bridge
    return app
