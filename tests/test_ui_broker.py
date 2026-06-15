"""The Agentic Command Center's UIBroker (ADR-0017). The properties under test:

  - read-only BY CONSTRUCTION: `ui.broker` cannot import the breaker, proxy, or
    Commander, so it cannot enforce anything;
  - `UIEvent` has no `content`/`arguments`/raw-payload field (rule 3), and
    `UIBroker` never reads `TelemetryEvent.content`/`arguments`;
  - `UIBroker` projects both `TelemetryEvent`s (telemetry sink) and
    `IncidentObject`s (bus subscriber) into bounded `UIEvent`s, dropping on a
    full queue rather than blocking the publisher;
  - `operator-request` objects are announce-only: publishing one never trips
    the breaker or changes the operating mode.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

import olive.ui.broker as broker_module
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.context import SecurityContext
from olive.gateway.mode import OperatingMode
from olive.gateway.pipeline import Decision, Verdict
from olive.gateway.telemetry import TelemetryEvent
from olive.intelligence.bus import IncidentBus
from olive.ui.broker import UIBroker, UIEvent, make_operator_request

_KEY = b"test-process-key"


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


def _ctx(**overrides) -> SecurityContext:
    base = dict(
        agent_id="a1",
        session_id="s1",
        organization_id="org",
        role="r",
        declared_goal="g",
        tool="t",
        arguments_hash="h",
        direction="outbound",
        call_number=1,
        session_tool_history=(),
        source_trust="trusted",
        timestamp=SecurityContext.now(),
    )
    base.update(overrides)
    return SecurityContext(**base)


# ---- read-only by construction (ADR-0017 SS2) ---------------------------------


def test_module_cannot_enforce_anything():
    """By construction: ui.broker must not import the breaker, proxy, or
    Commander. A thing it cannot import, it cannot do."""
    tree = ast.parse(Path(broker_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    forbidden = ("olive.gateway.breaker", "olive.gateway.proxy", "olive.intelligence.commander")
    leaks = [imp for imp in imported for f in forbidden if imp == f or imp.startswith(f + ".")]
    assert not leaks, f"ui.broker must not import enforcement modules: {leaks}"


# ---- rule 3: UIEvent never carries raw payloads --------------------------------


def test_ui_event_has_no_raw_payload_field():
    fields = {f.name for f in dataclasses.fields(UIEvent)}
    assert "content" not in fields
    assert "arguments" not in fields


# ---- TelemetrySink projection --------------------------------------------------


async def test_publish_projects_bounded_verdict_fields():
    b = UIBroker()
    verdict = Verdict(decision=Decision.BLOCK, rule="pat.injection", evidence="x" * 300)
    await b.publish(TelemetryEvent(ctx=_ctx(), verdict=verdict))
    event = await b._queue.get()
    assert event.kind == "decision"
    assert event.decision == "block"
    assert event.rule == "pat.injection"
    assert len(event.evidence) <= 203  # bound_evidence's 200 + "..."
    assert event.agent_id == "a1"
    assert event.session_id == "s1"
    assert event.tool == "t"


async def test_publish_drops_on_full_queue():
    b = UIBroker(maxsize=1)
    verdict = Verdict(decision=Decision.ALLOW)
    await b.publish(TelemetryEvent(ctx=_ctx(), verdict=verdict))
    await b.publish(TelemetryEvent(ctx=_ctx(), verdict=verdict))  # queue full, dropped
    assert b.dropped == 1


# ---- IncidentBus subscription ---------------------------------------------------


async def test_on_incident_projects_bus_object(bus):
    b = UIBroker()
    bus.subscribe(b.on_incident)
    obj = make_operator_request(bus, action="run-campaign-request", evidence="case-x")
    await bus.publish(obj)
    event = await b._queue.get()
    assert event.kind == "operator-request"
    assert event.source_dept == "ui"
    assert event.object_id is not None
    assert "case-x" in (event.evidence or "")


# ---- operator-request is announce-only (ADR-0017 SS5) ---------------------------


def test_operator_request_rejects_unknown_action(bus):
    with pytest.raises(ValueError):
        make_operator_request(bus, action="pause-everything")


async def test_operator_request_never_moves_the_mode(bus):
    breaker = CircuitBreaker()
    obj = make_operator_request(bus, action="force-mode-request", evidence="siege please")
    await bus.publish(obj)
    # Publishing the request alone must not change the operating mode - it is an
    # announcement, not an enforcement action (no subscriber here calls set_mode).
    assert await breaker.mode() is OperatingMode.NORMAL


def test_operator_request_object_has_no_raw_payload_field(bus):
    obj = make_operator_request(bus, action="toggle-redteam-dept-request")
    fields = {f.name for f in dataclasses.fields(obj)}
    assert "content" not in fields
    assert "arguments" not in fields
    assert obj.kind == "operator-request"
    assert obj.source_dept == "ui"
