"""Fleet layer tests (ADR-0024).

Properties under test:
  - heartbeat fail-closed: mode retained on any network error
  - three-failure escalation to SUSPICIOUS (upward only, never downgrade)
  - event-push queue is drop-on-full: never blocks the fast path
  - FleetClient refuses http:// without allow_insecure (fail-closed)
  - GatewayRegistry heartbeat liveness + commanded_mode round-trip
  - control plane endpoints: bearer-auth gated, read-only GETs, POST /fleet/mode
  - fleet/control_plane.py blocks path-traversal attempts on /fleet/policy/{role}
  - import-set: gateway/ must not import fleet/
  - FleetSink never includes raw content or arguments (rule 3)
"""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

# ── helpers ────────────────────────────────────────────────────────────────


def _make_commander(breaker=None):
    """Minimal SecurityCommander stand-in with force_mode_fleet tracked."""
    from olive.gateway.breaker import CircuitBreaker
    from olive.gateway.mode import OperatingMode
    from olive.intelligence.bus import IncidentBus

    if breaker is None:
        breaker = CircuitBreaker(max_blocks=3)
    # We use a real IncidentBus backed by :memory: so the bus can sign objects.
    bus = IncidentBus(":memory:", b"k" * 32)

    from olive.intelligence.commander import SecurityCommander
    return SecurityCommander(breaker, bus), breaker


# ── FleetClient ────────────────────────────────────────────────────────────


def test_fleet_client_refuses_http_without_allow_insecure():
    from olive.fleet.client import FleetClient, FleetClientError

    with pytest.raises(FleetClientError, match="plaintext"):
        FleetClient(
            base_url="http://localhost:9090",
            gateway_id="gw-1",
            org_id="org",
            token="tok",
        )


def test_fleet_client_allows_http_with_allow_insecure():
    from olive.fleet.client import FleetClient

    client = FleetClient(
        base_url="http://localhost:9090",
        gateway_id="gw-1",
        org_id="org",
        token="tok",
        allow_insecure=True,
    )
    assert client.gateway_id == "gw-1"


def test_fleet_client_enqueue_drop_on_full():
    """Queue full → drop counted, never raises, never blocks."""
    from olive.fleet.client import FleetClient

    client = FleetClient(
        base_url="https://cp.example.com",
        gateway_id="gw-1",
        org_id="org",
        token="tok",
        max_queue_size=2,
    )
    client.enqueue_event({"tool": "a"})
    client.enqueue_event({"tool": "b"})
    client.enqueue_event({"tool": "c"})  # should drop, not raise
    assert client.dropped == 1
    assert client._queue.qsize() == 2


# ── HeartbeatLoop ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_heartbeat_applies_commanded_mode():
    """A heartbeat response with a new mode calls force_mode_fleet."""
    from olive.gateway.mode import OperatingMode
    from olive.fleet.client import FleetClient
    from olive.fleet.heartbeat import HeartbeatLoop

    commander, breaker = _make_commander()

    client = MagicMock(spec=FleetClient)
    client.gateway_id = "gw-1"
    client.heartbeat = AsyncMock(return_value="suspicious")

    loop = HeartbeatLoop(client=client, commander=commander, breaker=breaker, interval=5.0)

    called = []
    original = commander.force_mode_fleet

    async def mock_force(mode, *, gateway_id):
        called.append((mode, gateway_id))

    commander.force_mode_fleet = mock_force
    loop._interval = 0.01
    loop.start()
    await asyncio.sleep(0.05)
    await loop.stop()

    assert any(mode == OperatingMode.SUSPICIOUS for mode, _ in called)


@pytest.mark.asyncio
async def test_heartbeat_fail_closed_mode_retained():
    """Network errors never downgrade the mode; consecutive_failures counts up."""
    from olive.fleet.client import FleetClient
    from olive.fleet.heartbeat import HeartbeatLoop

    commander, breaker = _make_commander()

    client = MagicMock(spec=FleetClient)
    client.gateway_id = "gw-1"
    client.heartbeat = AsyncMock(side_effect=ConnectionError("refused"))

    mode_changes = []
    async def mock_force(mode, *, gateway_id):
        mode_changes.append(mode)
    commander.force_mode_fleet = mock_force

    loop = HeartbeatLoop(client=client, commander=commander, breaker=breaker, interval=5.0)
    loop._interval = 0.01
    loop.start()
    await asyncio.sleep(0.05)
    await loop.stop()

    # Failures counted, no Normal/downgrade emitted
    assert loop.consecutive_failures > 0
    from olive.gateway.mode import OperatingMode
    assert all(m != OperatingMode.NORMAL for m in mode_changes)


@pytest.mark.asyncio
async def test_heartbeat_three_failure_escalation():
    """Three consecutive failures → force_mode_fleet(SUSPICIOUS) escalation."""
    from olive.gateway.mode import OperatingMode
    from olive.fleet.client import FleetClient
    from olive.fleet.heartbeat import HeartbeatLoop, _FAILURE_ESCALATION_COUNT

    commander, breaker = _make_commander()
    client = MagicMock(spec=FleetClient)
    client.gateway_id = "gw-1"
    client.heartbeat = AsyncMock(side_effect=ConnectionError("refused"))

    escalations = []
    async def mock_force(mode, *, gateway_id):
        escalations.append(mode)
    commander.force_mode_fleet = mock_force

    loop = HeartbeatLoop(client=client, commander=commander, breaker=breaker, interval=5.0)
    loop._interval = 0.02
    loop.start()
    # Wait for (_FAILURE_ESCALATION_COUNT + 1) full ticks with a safety margin
    await asyncio.sleep(loop._interval * (_FAILURE_ESCALATION_COUNT + 2))
    await loop.stop()

    assert OperatingMode.SUSPICIOUS in escalations
    assert loop.consecutive_failures >= _FAILURE_ESCALATION_COUNT


@pytest.mark.asyncio
async def test_heartbeat_ignores_unknown_mode():
    """An unknown mode string from the control plane is logged and ignored."""
    from olive.fleet.client import FleetClient
    from olive.fleet.heartbeat import HeartbeatLoop

    commander, breaker = _make_commander()
    client = MagicMock(spec=FleetClient)
    client.gateway_id = "gw-1"
    client.heartbeat = AsyncMock(return_value="turbo-mode-9000")

    mode_changes = []
    async def mock_force(mode, *, gateway_id):
        mode_changes.append(mode)
    commander.force_mode_fleet = mock_force

    loop = HeartbeatLoop(client=client, commander=commander, breaker=breaker, interval=5.0)
    loop._interval = 0.01
    loop.start()
    await asyncio.sleep(0.05)
    await loop.stop()

    assert mode_changes == []  # no mode change applied


# ── GatewayRegistry ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_registry_heartbeat_registers_gateway(tmp_path):
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        mode = await reg.record_heartbeat("gw-1", "org-a", "normal")
        assert mode == "normal"  # default commanded_mode
        gateways = await reg.list_gateways()
        assert len(gateways) == 1
        assert gateways[0]["gateway_id"] == "gw-1"
    finally:
        await reg.close()


@pytest.mark.asyncio
async def test_registry_set_fleet_mode_propagates(tmp_path):
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        await reg.record_heartbeat("gw-1", "org-a", "normal")
        await reg.record_heartbeat("gw-2", "org-a", "normal")
        await reg.set_fleet_mode("siege", issued_by="operator-1")
        # Next heartbeat for each gateway should return "siege"
        mode1 = await reg.record_heartbeat("gw-1", "org-a", "normal")
        mode2 = await reg.record_heartbeat("gw-2", "org-a", "suspicious")
        assert mode1 == "siege"
        assert mode2 == "siege"
    finally:
        await reg.close()


@pytest.mark.asyncio
async def test_registry_records_events_and_incidents(tmp_path):
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        await reg.record_events("gw-1", [
            {"event_id": "e1", "agent_id": "agent-a", "tool": "read_file",
             "decision": "allow", "timestamp": "2026-06-18T00:00:00Z"},
        ])
        await reg.record_incidents("gw-1", [
            {"incident_id": "i1", "agent_id": "agent-a", "attack_type": "injection",
             "confidence": 0.9, "decision": "block", "status": "open",
             "timestamp": "2026-06-18T00:00:00Z"},
        ])
        events = await reg.recent_events()
        incidents = await reg.recent_incidents()
        assert any(e["event_id"] == "e1" for e in events)
        assert any(i["incident_id"] == "i1" for i in incidents)
    finally:
        await reg.close()


# ── Control plane app ──────────────────────────────────────────────────────


async def _cp_client(tmp_path: Path, policies_dir: Path | None = None):
    """Async factory: open registry, return (AsyncClient, token, registry)."""
    from olive.fleet.registry import GatewayRegistry
    from olive.fleet.control_plane import build_control_plane_app
    from olive.identity.tokens import MockCA

    ca = MockCA()
    token = ca.issue(
        agent_id="fleet-operator",
        organization="org",
        role="operator",
        session_id="sess-cp",
        capabilities=["olive:fleet"],
    )
    reg = GatewayRegistry(":memory:")
    await reg.open()
    pd = policies_dir or (tmp_path / "policies")
    pd.mkdir(exist_ok=True)
    app = build_control_plane_app(reg, ca.public_key_pem(), pd)
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    return client, token, reg


@pytest.mark.asyncio
async def test_cp_heartbeat_requires_auth(tmp_path):
    client, _, reg = await _cp_client(tmp_path)
    async with client:
        resp = await client.post(
            "/fleet/heartbeat", json={"gateway_id": "gw-1", "current_mode": "normal"}
        )
        assert resp.status_code == 401
    await reg.close()


@pytest.mark.asyncio
async def test_cp_heartbeat_registers_and_returns_mode(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        resp = await client.post(
            "/fleet/heartbeat",
            json={"gateway_id": "gw-1", "org_id": "org-a", "current_mode": "normal"},
            headers={"Authorization": f"Bearer {token}"},
        )
    await reg.close()
    assert resp.status_code == 200
    data = resp.json()
    assert data["gateway_id"] == "gw-1"
    assert data["commanded_mode"] == "normal"


@pytest.mark.asyncio
async def test_cp_list_gateways_read_only(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        await client.post(
            "/fleet/heartbeat",
            json={"gateway_id": "gw-1", "org_id": "org", "current_mode": "normal"},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = await client.get(
            "/fleet/gateways", headers={"Authorization": f"Bearer {token}"}
        )
    await reg.close()
    assert resp.status_code == 200
    assert any(g["gateway_id"] == "gw-1" for g in resp.json())


@pytest.mark.asyncio
async def test_cp_set_fleet_mode(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        await client.post(
            "/fleet/heartbeat",
            json={"gateway_id": "gw-1", "org_id": "org", "current_mode": "normal"},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = await client.post(
            "/fleet/mode",
            json={"mode": "siege"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        resp2 = await client.post(
            "/fleet/heartbeat",
            json={"gateway_id": "gw-1", "org_id": "org", "current_mode": "normal"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp2.json()["commanded_mode"] == "siege"
    await reg.close()


@pytest.mark.asyncio
async def test_cp_set_fleet_mode_invalid(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        resp = await client.post(
            "/fleet/mode",
            json={"mode": "turbo"},
            headers={"Authorization": f"Bearer {token}"},
        )
    await reg.close()
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cp_policy_served(tmp_path):
    pd = tmp_path / "policies"
    pd.mkdir()
    (pd / "analyst.yaml").write_text("roles:\n  analyst:\n    allowed_tools: []\n")
    client, token, reg = await _cp_client(tmp_path, policies_dir=pd)
    async with client:
        resp = await client.get(
            "/fleet/policy/analyst", headers={"Authorization": f"Bearer {token}"}
        )
    await reg.close()
    assert resp.status_code == 200
    assert "analyst" in resp.text


@pytest.mark.asyncio
async def test_cp_policy_path_traversal_blocked(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        resp = await client.get(
            "/fleet/policy/..%2F..%2Fetc%2Fpasswd",
            headers={"Authorization": f"Bearer {token}"},
        )
    await reg.close()
    assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_cp_policy_not_found(tmp_path):
    client, token, reg = await _cp_client(tmp_path)
    async with client:
        resp = await client.get(
            "/fleet/policy/nonexistent", headers={"Authorization": f"Bearer {token}"}
        )
    await reg.close()
    assert resp.status_code == 404


# ── FleetSink rule-3 ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fleet_sink_never_sends_raw_content():
    """FleetSink must never include content or arguments in the pushed summary."""
    from olive.fleet.client import FleetClient
    from olive.fleet.sink import FleetSink
    from olive.gateway.context import SecurityContext
    from olive.gateway.pipeline import Decision, Verdict

    client = MagicMock(spec=FleetClient)
    enqueued: list[dict] = []
    client.enqueue_event = lambda summary: enqueued.append(summary)

    sink = FleetSink(client)

    from olive.gateway.telemetry import TelemetryEvent
    ctx = MagicMock(spec=SecurityContext)
    ctx.agent_id = "agent-x"
    ctx.session_id = "sess-1"
    ctx.tool = "read_file"
    ctx.direction = MagicMock()
    ctx.direction.value = "inbound"
    ctx.arguments_hash = "sha256-abc"
    ctx.organization_id = "org-1"

    verdict = Verdict(decision=Decision.ALLOW, rule="policy.allow", evidence="")
    event = TelemetryEvent(ctx=ctx, verdict=verdict, content="SECRET DATA", arguments={"key": "val"})

    await sink.publish(event)

    assert len(enqueued) == 1
    summary = enqueued[0]
    assert "content" not in summary
    assert "arguments" not in summary
    assert "SECRET" not in str(summary)
    assert summary["arguments_hash"] == "sha256-abc"


# ── Import-set: gateway/ must not import fleet/ ────────────────────────────


def test_gateway_core_does_not_import_fleet():
    """ADR-0024: the fleet layer is intelligence-side; gateway core must never
    import it. Check every module in gateway/, store/, identity/, inspectors/."""
    import sys
    fleet_prefix = "olive.fleet"
    core_prefixes = (
        "olive.gateway",
        "olive.store",
        "olive.identity",
        "olive.inspectors",
    )
    for mod_name, mod in list(sys.modules.items()):
        if not any(mod_name.startswith(p) for p in core_prefixes):
            continue
        if mod is None or not hasattr(mod, "__file__"):
            continue
        src = Path(mod.__file__).read_text(encoding="utf-8", errors="replace")
        assert fleet_prefix not in src, (
            f"{mod_name} imports from {fleet_prefix!r} — violates ADR-0024 layering rule"
        )


# ── SecurityCommander.force_mode_fleet ────────────────────────────────────


@pytest.mark.asyncio
async def test_force_mode_fleet_does_not_require_olive_command():
    """fleet path bypasses the olive:command gate — auth already happened at fleet boundary."""
    from olive.gateway.mode import OperatingMode
    from olive.intelligence.bus import IncidentBus

    commander, breaker = _make_commander()
    bus = IncidentBus(":memory:", b"k" * 32)
    await bus.open()
    commander._bus = bus

    changed = await commander.force_mode_fleet(
        OperatingMode.SUSPICIOUS, gateway_id="gw-test"
    )
    assert changed is True
    assert await breaker.mode() == OperatingMode.SUSPICIOUS
    await bus.close()
