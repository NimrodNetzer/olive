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
        Route("/operator", _operator_endpoint, methods=["POST"]),
        Mount("/", StaticFiles(directory=str(_STATIC), html=True)),
    ]


def build_app(
    broker: UIBroker,
    bus: IncidentBus | None = None,
    corpus_dir: Path | None = None,
) -> Starlette:
    """Build the standalone Starlette ASGI app (`olive ui --web`, a separate
    process). `broker` is required (stream source); `bus` is optional (enables
    POST /operator — without it the endpoint returns 503); `corpus_dir` populates
    the GET /corpus list for the attack-theater."""
    app = Starlette(routes=ui_routes())
    app.state.broker = broker
    app.state.bus = bus
    app.state.corpus = _corpus_stems(corpus_dir)
    return app
