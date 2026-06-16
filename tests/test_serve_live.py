"""`olive serve --ui` — the live Command Center wiring (ADR-0020).

Properties under test (the safety-relevant ones):
  - MultiSink fans one telemetry event to every sink and ISOLATES a failing sink
    (one broken/slow sink never stops the others or the fast path);
  - the OperatorBridge turns ONLY a `run-campaign-request` into a sandbox drill,
    subscribes to nothing it emits (no feedback loop), and has no enforcement path;
  - `build_sentinels` yields the three deterministic-capable sentinels (so the demo
    works with no API key);
  - co-mounting the dashboard onto the gateway app leaves UI routes reachable
    WITHOUT a bearer token while `/mcp` stays behind auth (ADR-0020 §5).
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.telemetry import MultiSink, QueueSink
from olive.identity.tokens import MockCA
from olive.intelligence.bus import IncidentBus
from olive.intelligence.departments import OperatorBridge, build_runtime_org, build_sentinels
from olive.intelligence.redteam_dept import RedTeamDepartment
from olive.intelligence.remediation import RemediationLedger
from olive.transport.http import build_http_app
from olive.ui.broker import UIBroker, make_operator_request
from olive.ui.web import ui_routes

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evals" / "corpus"
_KEY = b"test-process-key"


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


# ---- MultiSink (the one new core primitive, ADR-0020 §3) ---------------------


async def test_multisink_fans_out_to_every_sink():
    a, b = QueueSink(), QueueSink()
    multi = MultiSink(a, b)
    event = object()  # neither MultiSink nor QueueSink inspects the event
    await multi.publish(event)
    assert a.queue.qsize() == 1
    assert b.queue.qsize() == 1


async def test_multisink_isolates_a_failing_sink():
    # A broken/slow sink must never stop the others or perturb the fast path.
    before, after = QueueSink(), QueueSink()

    class Boom:
        async def publish(self, event):
            raise RuntimeError("sink down")

    multi = MultiSink(before, Boom(), after)
    await multi.publish(object())
    assert before.queue.qsize() == 1
    assert after.queue.qsize() == 1  # the sink AFTER the failing one still got it
    assert multi.errors == 1  # the failure is counted, never silently swallowed


# ---- build_sentinels (deterministic, no API key, ADR-0020 §7) ----------------


def test_build_sentinels_returns_three_deterministic_sentinels():
    config = SimpleNamespace(injection_patterns=["ignore previous instructions"])
    sentinels = build_sentinels(config)
    names = {s.name for s in sentinels}
    assert names == {"prompt-injection", "data-leak", "behavior"}


# ---- OperatorBridge: the on-demand drill path (ADR-0020 §6) ------------------


async def test_run_campaign_request_triggers_a_sandbox_drill(bus):
    redteam = RedTeamDepartment(bus, corpus_dir=CORPUS)
    bridge = OperatorBridge(bus, redteam)
    bridge.subscribe()
    await bus.publish(make_operator_request(bus, action="run-campaign-request"))
    assert bridge.campaigns_triggered == 1
    # the drill ran and published findings onto the bus
    assert any(row["kind"] == "redteam-finding" for row in await bus.history())


async def test_bridge_ignores_non_campaign_actions(bus):
    redteam = RedTeamDepartment(bus, corpus_dir=CORPUS)
    bridge = OperatorBridge(bus, redteam)
    bridge.subscribe()
    # force-mode-request is announce-only — the bridge must NOT run a drill.
    await bus.publish(make_operator_request(bus, action="force-mode-request"))
    assert bridge.campaigns_triggered == 0
    assert not any(row["kind"] == "redteam-finding" for row in await bus.history())


async def test_bridge_subscribes_only_to_operator_request_no_feedback(bus):
    # A redteam-finding (which a drill emits) must never re-enter the bridge.
    redteam = RedTeamDepartment(bus, corpus_dir=CORPUS)
    bridge = OperatorBridge(bus, redteam)
    bridge.subscribe()
    await bus.publish(make_operator_request(bus, action="run-campaign-request"))
    triggered = bridge.campaigns_triggered
    assert triggered == 1  # the findings it just published did not re-trigger it


async def test_build_runtime_org_wires_operator_bridge_end_to_end(bus, tmp_path):
    ledger = RemediationLedger(tmp_path / "led.db")
    await ledger.open()
    try:
        import asyncio

        org = build_runtime_org(
            breaker=CircuitBreaker(),
            bus=bus,
            ledger=ledger,
            queue=asyncio.Queue(),
            sentinels=[],
            redteam_corpus_dir=CORPUS,
            operator_bridge=True,
        )
        assert org.operator_bridge is not None
        await bus.publish(make_operator_request(bus, action="run-campaign-request"))
        assert org.operator_bridge.campaigns_triggered == 1
        assert any(row["kind"] == "redteam-finding" for row in await bus.history())
    finally:
        await ledger.close()


async def test_operator_bridge_off_by_default(bus, tmp_path):
    ledger = RemediationLedger(tmp_path / "led.db")
    await ledger.open()
    try:
        import asyncio

        org = build_runtime_org(
            breaker=CircuitBreaker(),
            bus=bus,
            ledger=ledger,
            queue=asyncio.Queue(),
            sentinels=[],
        )
        assert org.operator_bridge is None
    finally:
        await ledger.close()


# ---- co-mount: UI reachable without auth, /mcp still protected (ADR-0020 §5) -


async def test_ui_routes_co_mounted_without_bearer_auth():
    ca = MockCA()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        app.state.broker = UIBroker()
        app.state.bus = None
        app.state.corpus = ["inj-0001"]
        yield

    app = build_http_app(ca.public_key_pem(), lifespan, extra_routes=ui_routes())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://olive.test") as client:
            # UI route reachable with NO token...
            r = await client.get("/corpus")
            assert r.status_code == 200
            assert r.json() == ["inj-0001"]
            # ...but /mcp still rejects an unauthenticated request.
            r2 = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert r2.status_code == 401


def test_build_http_app_has_no_ui_routes_when_not_co_mounted():
    # Bare serve is unchanged: without extra_routes the app exposes only /mcp + admin.
    ca = MockCA()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        yield

    app = build_http_app(ca.public_key_pem(), lifespan)
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/corpus" not in paths and "/operator" not in paths
    assert "/mcp" in paths
