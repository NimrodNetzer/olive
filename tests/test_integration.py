"""Integration hardening tests (ADR-0028, Plan C).

Three test groups:
  1. CapabilityInspector — missing cap blocks, present cap allows, no-req passes
  2. Per-gateway fleet mode — targeted set, broadcast unaffected, 404 on unknown
  3. LangChain adapter — get_tools wraps correctly, run calls gateway, missing dep error
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── helpers ────────────────────────────────────────────────────────────────


def _ctx(
    tool: str,
    role: str = "finance",
    capabilities: tuple[str, ...] = (),
    direction: str = "outbound",
):
    from olive.gateway.context import SecurityContext, hash_arguments

    return SecurityContext(
        agent_id="test-agent",
        session_id="sess-test",
        organization_id="test-org",
        role=role,
        declared_goal="test",
        tool=tool,
        arguments_hash=hash_arguments(None),
        direction=direction,
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
        capabilities=capabilities,
    )


# ── CapabilityInspector ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_capability_inspector_blocks_missing_cap():
    from olive.inspectors.capability import CapabilityInspector
    from olive.gateway.pipeline import Decision

    inspector = CapabilityInspector({"transfer_funds": frozenset({"finance:transfer"})})
    ctx = _ctx("transfer_funds", capabilities=())
    verdict = await inspector.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK
    assert verdict.rule == "policy.capability_missing"
    assert "finance:transfer" in (verdict.evidence or "")


@pytest.mark.asyncio
async def test_capability_inspector_allows_with_correct_cap():
    from olive.inspectors.capability import CapabilityInspector
    from olive.gateway.pipeline import Decision

    inspector = CapabilityInspector({"transfer_funds": frozenset({"finance:transfer"})})
    ctx = _ctx("transfer_funds", capabilities=("finance:transfer",))
    verdict = await inspector.inspect(ctx, None)
    assert verdict.decision is Decision.ALLOW


@pytest.mark.asyncio
async def test_capability_inspector_allows_tool_without_requirement():
    from olive.inspectors.capability import CapabilityInspector
    from olive.gateway.pipeline import Decision

    inspector = CapabilityInspector({"transfer_funds": frozenset({"finance:transfer"})})
    ctx = _ctx("read_balance", capabilities=())
    verdict = await inspector.inspect(ctx, None)
    assert verdict.decision is Decision.ALLOW


@pytest.mark.asyncio
async def test_capability_inspector_blocks_partial_caps():
    """AND semantics: all required capabilities must be present."""
    from olive.inspectors.capability import CapabilityInspector
    from olive.gateway.pipeline import Decision

    inspector = CapabilityInspector(
        {"transfer_funds": frozenset({"finance:transfer", "finance:approve"})}
    )
    ctx = _ctx("transfer_funds", capabilities=("finance:transfer",))  # missing finance:approve
    verdict = await inspector.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK


@pytest.mark.asyncio
async def test_capability_inspector_empty_registry_allows_everything():
    from olive.inspectors.capability import CapabilityInspector
    from olive.gateway.pipeline import Decision

    inspector = CapabilityInspector({})
    ctx = _ctx("transfer_funds", capabilities=())
    verdict = await inspector.inspect(ctx, None)
    assert verdict.decision is Decision.ALLOW


@pytest.mark.asyncio
async def test_capability_inspector_inbound_skipped():
    """Inspector is outbound-only; inbound calls must not be filtered."""
    from olive.inspectors.capability import CapabilityInspector

    inspector = CapabilityInspector({"transfer_funds": frozenset({"finance:transfer"})})
    assert "inbound" not in inspector.directions


def test_capability_inspector_name():
    from olive.inspectors.capability import CapabilityInspector

    assert CapabilityInspector({}).name == "capability"


# ── config: capability_requirements parsing ────────────────────────────────


def test_load_config_parses_capability_requirements(tmp_path):
    from olive.config import load_config

    policy = tmp_path / "cap.yaml"
    policy.write_text(
        """
gateway:
  agent_id: test-agent
  role: finance
  declared_goal: test
  db_path: test.db

roles:
  finance:
    allowed_tools: [transfer_funds, read_balance]

upstream:
  trust: untrusted

capability_requirements:
  transfer_funds:
    required_capabilities: ["finance:transfer"]
""",
        encoding="utf-8",
    )
    config = load_config(policy)
    assert config.tool_capabilities == {"transfer_funds": frozenset({"finance:transfer"})}


def test_load_config_no_capability_requirements(tmp_path):
    from olive.config import load_config

    policy = tmp_path / "nocap.yaml"
    policy.write_text(
        """
gateway:
  agent_id: test-agent
  role: support
  declared_goal: test
  db_path: test.db

roles:
  support:
    allowed_tools: [read_faq]

upstream:
  trust: untrusted
""",
        encoding="utf-8",
    )
    config = load_config(policy)
    assert config.tool_capabilities == {}


# ── capability in SecurityContext carries through proxy ────────────────────


def test_security_context_has_capabilities_field():
    from olive.gateway.context import SecurityContext, hash_arguments

    ctx = SecurityContext(
        agent_id="a",
        session_id="s",
        organization_id="o",
        role="r",
        declared_goal="g",
        tool="t",
        arguments_hash=hash_arguments(None),
        direction="outbound",
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
        capabilities=("finance:transfer", "secrets:read"),
    )
    assert ctx.capabilities == ("finance:transfer", "secrets:read")


def test_security_context_capabilities_default_empty():
    from olive.gateway.context import SecurityContext, hash_arguments

    ctx = SecurityContext(
        agent_id="a",
        session_id="s",
        organization_id="o",
        role="r",
        declared_goal="g",
        tool="t",
        arguments_hash=hash_arguments(None),
        direction="outbound",
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
    )
    assert ctx.capabilities == ()


# ── Per-gateway fleet mode ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_registry_set_gateway_mode_targets_single(tmp_path):
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        await reg.record_heartbeat("gw-A", "org", "normal")
        await reg.record_heartbeat("gw-B", "org", "normal")

        found = await reg.set_gateway_mode("gw-A", "siege", issued_by="admin")
        assert found is True

        gateways = {g["gateway_id"]: g for g in await reg.list_gateways()}
        assert gateways["gw-A"]["commanded_mode"] == "siege"
        assert gateways["gw-B"]["commanded_mode"] == "normal"  # unaffected
    finally:
        await reg.close()


@pytest.mark.asyncio
async def test_registry_set_gateway_mode_unknown_returns_false(tmp_path):
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        found = await reg.set_gateway_mode("nonexistent", "siege", issued_by="admin")
        assert found is False
    finally:
        await reg.close()


@pytest.mark.asyncio
async def test_registry_set_fleet_mode_broadcast_unaffected_by_gateway_mode(tmp_path):
    """Broadcast POST /fleet/mode still updates all gateways."""
    from olive.fleet.registry import GatewayRegistry

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    try:
        await reg.record_heartbeat("gw-A", "org", "normal")
        await reg.record_heartbeat("gw-B", "org", "normal")
        await reg.set_fleet_mode("suspicious", issued_by="admin")

        gateways = {g["gateway_id"]: g for g in await reg.list_gateways()}
        assert gateways["gw-A"]["commanded_mode"] == "suspicious"
        assert gateways["gw-B"]["commanded_mode"] == "suspicious"
    finally:
        await reg.close()


@pytest.mark.asyncio
async def test_control_plane_per_gateway_mode_endpoint(tmp_path):
    """POST /fleet/mode/{gateway_id} commands a single gateway via the HTTP layer."""
    import httpx
    from olive.fleet.registry import GatewayRegistry
    from olive.fleet.control_plane import build_control_plane_app
    from olive.identity.tokens import MockCA

    ca = MockCA()
    token = ca.issue(
        agent_id="admin",
        organization="org",
        role="admin",
        session_id="sess-admin",
        capabilities=["olive:fleet"],
    )

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    await reg.record_heartbeat("gw-A", "org", "normal")
    await reg.record_heartbeat("gw-B", "org", "normal")

    app = build_control_plane_app(reg, ca.public_key_pem(), tmp_path)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/fleet/mode/gw-A",
            json={"mode": "siege"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["gateway_id"] == "gw-A"
    assert data["mode"] == "siege"

    # gw-B must be unaffected
    gateways = {g["gateway_id"]: g for g in await reg.list_gateways()}
    assert gateways["gw-A"]["commanded_mode"] == "siege"
    assert gateways["gw-B"]["commanded_mode"] == "normal"

    await reg.close()


@pytest.mark.asyncio
async def test_control_plane_per_gateway_mode_404_on_unknown(tmp_path):
    import httpx
    from olive.fleet.registry import GatewayRegistry
    from olive.fleet.control_plane import build_control_plane_app
    from olive.identity.tokens import MockCA

    ca = MockCA()
    token = ca.issue(
        agent_id="admin",
        organization="org",
        role="admin",
        session_id="sess-admin",
        capabilities=["olive:fleet"],
    )

    reg = GatewayRegistry(tmp_path / "fleet.db")
    await reg.open()
    app = build_control_plane_app(reg, ca.public_key_pem(), tmp_path)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/fleet/mode/does-not-exist",
            json={"mode": "siege"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 404
    await reg.close()


# ── LangChain adapter ──────────────────────────────────────────────────────


def test_olive_toolkit_raises_importerror_without_langchain():
    """OliveToolkit raises ImportError (with instructions) when langchain-core absent."""
    import sys

    with patch.dict(sys.modules, {"langchain_core": None, "langchain_core.tools": None}):
        from olive.adapters.langchain import OliveToolkit

        toolkit = OliveToolkit(gateway_url="http://localhost:7800/mcp")
        with pytest.raises(ImportError, match="langchain-core"):
            toolkit.get_tools()


def test_olive_toolkit_get_tools_returns_base_tools():
    """get_tools() wraps each tool the gateway lists as a BaseTool."""
    try:
        import langchain_core.tools  # noqa: F401
    except ImportError:
        pytest.skip("langchain-core not installed")

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(
        return_value={
            "result": {
                "tools": [
                    {
                        "name": "transfer_funds",
                        "description": "Transfer money between accounts",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "read_balance",
                        "description": "Read account balance",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]
            }
        }
    )

    with patch("httpx.post", return_value=mock_response):
        from olive.adapters.langchain import OliveToolkit

        toolkit = OliveToolkit(gateway_url="http://localhost:7800/mcp", token="test-token")
        tools = toolkit.get_tools()

    assert len(tools) == 2
    tool_names = {t.name for t in tools}
    assert tool_names == {"transfer_funds", "read_balance"}


def test_olive_toolkit_tool_run_calls_gateway():
    """BaseTool.run() sends a tools/call request to the gateway."""
    try:
        import langchain_core.tools  # noqa: F401
    except ImportError:
        pytest.skip("langchain-core not installed")

    list_response = MagicMock()
    list_response.raise_for_status = MagicMock()
    list_response.json = MagicMock(
        return_value={
            "result": {
                "tools": [
                    {"name": "read_balance", "description": "Read balance", "inputSchema": {}}
                ]
            }
        }
    )

    call_response = MagicMock()
    call_response.raise_for_status = MagicMock()
    call_response.json = MagicMock(
        return_value={
            "result": {
                "content": [{"type": "text", "text": "Balance: $1000"}]
            }
        }
    )

    posted = []

    def fake_post(url, content, headers, timeout):
        body = json.loads(content)
        posted.append(body)
        if body.get("method") == "tools/list":
            return list_response
        return call_response

    with patch("httpx.post", side_effect=fake_post):
        from olive.adapters.langchain import OliveToolkit

        toolkit = OliveToolkit(gateway_url="http://localhost:7800/mcp")
        tools = toolkit.get_tools()
        result = tools[0]._run(account_id="acct-1")

    assert result == "Balance: $1000"
    call_bodies = [p for p in posted if p.get("method") == "tools/call"]
    assert len(call_bodies) == 1
    assert call_bodies[0]["params"]["name"] == "read_balance"
