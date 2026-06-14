"""End-to-end contextual authorization (ADR-0010) through the real proxy path:
resource extraction -> SecurityContext -> ContextPolicyInspector -> decision.
Proves refine-only: the coarse allowlist still gates first, and a task-scoped
resource rule blocks an out-of-task id while allowing the bound one."""

from __future__ import annotations

import mcp.types as types
import pytest

from olive.config import GatewayConfig
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.pipeline import Decision, InspectorPipeline
from olive.gateway.proxy import OliveGateway
from olive.gateway.ratelimit import RateLimiter
from olive.gateway.resources import ResourceExtractor
from olive.identity.claims import IdentityClaims
from olive.inspectors.context_policy import ContextPolicyInspector, ContextRule
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.policy import PolicyInspector, RolePolicy
from olive.store.events import EventStore

pytestmark = pytest.mark.asyncio


class StubUpstream:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call_tool(self, name, arguments=None):
        self.calls.append(name)
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


def _config() -> GatewayConfig:
    binding = ContextRule(
        id="order-must-match-task",
        tool="read_order",
        when={"resource.type": "order"},
        require={"resource.id_in": "task.resources"},
        effect=Decision.BLOCK,
    )
    return GatewayConfig(
        agent_id="a",
        organization_id="o",
        role="support",
        declared_goal="resolve ticket",
        db_path=":memory:",
        upstream_trust="untrusted",
        roles={"support": RolePolicy(allowed_tools=frozenset({"read_order"}))},
        injection_patterns=[],
        resource_extractors={
            "read_order": ResourceExtractor(
                type="order", id_arg="order_id", classification="customer-pii"
            )
        },
        context_rules={"support": (binding,)},
    )


def _gateway(store: EventStore) -> OliveGateway:
    config = _config()
    pipeline = InspectorPipeline(
        [
            PolicyInspector(config.roles),
            ContextPolicyInspector(config.context_rules),
            PatternInspector(config.injection_patterns),
        ]
    )
    return OliveGateway(
        config, store, pipeline, breaker=CircuitBreaker(), rate_limiter=RateLimiter()
    )


def _identity(task_resources: tuple[str, ...]) -> IdentityClaims:
    return IdentityClaims(
        agent_id="a",
        organization="o",
        role="support",
        session_id="s1",
        task_resources=task_resources,
        verified=True,
    )


@pytest.fixture
async def fixture(tmp_path):
    store = EventStore(tmp_path / "e.db")
    await store.open()
    gw = _gateway(store)
    up = StubUpstream()
    yield gw, up, store
    await store.close()


async def test_in_task_resource_is_forwarded(fixture):
    gw, up, _ = fixture
    result = await gw.handle_call_tool(
        up, "read_order", {"order_id": "4471"}, identity=_identity(("4471",))
    )
    assert not result.isError
    assert up.calls == ["read_order"]  # reached the upstream


async def test_out_of_task_resource_is_blocked(fixture):
    gw, up, _ = fixture
    result = await gw.handle_call_tool(
        up, "read_order", {"order_id": "9999"}, identity=_identity(("4471",))
    )
    assert result.isError
    assert up.calls == []  # never reached the upstream


async def test_block_is_recorded_as_incident_and_audited(fixture):
    gw, up, store = fixture
    await gw.handle_call_tool(up, "read_order", {"order_id": "9999"}, identity=_identity(("4471",)))
    summary = await store.summary()
    assert summary.incidents == 1  # the contextual block minted an incident
    assert summary.blocked >= 1  # and was audited as a non-allow event


async def test_coarse_allowlist_still_gates_first(fixture):
    # A tool not in allowed_tools is blocked by PolicyInspector before any
    # contextual rule runs - contextual rules can only refine, never grant.
    gw, up, _ = fixture
    result = await gw.handle_call_tool(
        up, "read_secret", {"order_id": "4471"}, identity=_identity(("4471",))
    )
    assert result.isError
    assert up.calls == []


# --- HOLD path (ADR-0010): governance pause, not an attack -------------------


def _hold_gateway(store: EventStore) -> OliveGateway:
    rule = ContextRule(
        id="payroll-needs-approval",
        tool="read_payroll",
        require={"approval": "operator"},
        effect=Decision.HOLD,
    )
    config = GatewayConfig(
        agent_id="a",
        organization_id="o",
        role="support",
        declared_goal="g",
        db_path=":memory:",
        upstream_trust="untrusted",
        roles={"support": RolePolicy(allowed_tools=frozenset({"read_payroll"}))},
        injection_patterns=[],
        context_rules={"support": (rule,)},
    )
    pipeline = InspectorPipeline(
        [
            PolicyInspector(config.roles),
            ContextPolicyInspector(config.context_rules),
            PatternInspector(config.injection_patterns),
        ]
    )
    return OliveGateway(
        config, store, pipeline, breaker=CircuitBreaker(max_blocks=2), rate_limiter=RateLimiter()
    )


async def test_hold_withholds_call_without_executing(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    up = StubUpstream()
    result = await gw.handle_call_tool(
        up, "read_payroll", {}, identity=_identity(())
    )
    assert result.isError
    assert "held for approval" in result.content[0].text
    assert up.calls == []  # not executed
    await store.close()


async def test_hold_mints_no_incident_and_never_quarantines(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    up = StubUpstream()
    ident = _identity(())
    # Repeated holds, well past the breaker threshold (max_blocks=2).
    for _ in range(5):
        await gw.handle_call_tool(up, "read_payroll", {}, identity=ident)
    summary = await store.summary()
    assert summary.incidents == 0  # a hold is not an attack
    # The session is NOT quarantined: a 6th call still holds, not quarantines.
    result = await gw.handle_call_tool(up, "read_payroll", {}, identity=ident)
    assert "held for approval" in result.content[0].text
    await store.close()


async def test_hold_is_audited_not_silent(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    up = StubUpstream()
    await gw.handle_call_tool(up, "read_payroll", {}, identity=_identity(()))
    summary = await store.summary()
    assert summary.total >= 1  # the hold was written as an event (rule 5)
    await store.close()


async def test_operator_approval_releases_one_held_call(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    up = StubUpstream()
    ident = _identity(())

    # 1) First attempt holds and registers a pending approval.
    held = await gw.handle_call_tool(up, "read_payroll", {}, identity=ident)
    assert held.isError and up.calls == []
    pending = gw.approvals.pending()
    assert len(pending) == 1
    approval_id = pending[0].approval_id

    # 2) Operator approves that specific id.
    assert await gw.approve_hold(approval_id) is True

    # 3) Retrying the same call now proceeds to the upstream (one-shot).
    result = await gw.handle_call_tool(up, "read_payroll", {}, identity=ident)
    assert not result.isError
    assert up.calls == ["read_payroll"]

    # 4) The approval was consumed: a further call holds again.
    again = await gw.handle_call_tool(up, "read_payroll", {}, identity=ident)
    assert again.isError
    assert up.calls == ["read_payroll"]  # not called a second time
    await store.close()


async def test_approval_is_specific_to_exact_arguments(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    up = StubUpstream()
    ident = _identity(())

    await gw.handle_call_tool(up, "read_payroll", {"period": "may"}, identity=ident)
    approval_id = gw.approvals.pending()[0].approval_id
    await gw.approve_hold(approval_id)

    # A different argument set is a different call: it must still hold.
    other = await gw.handle_call_tool(up, "read_payroll", {"period": "june"}, identity=ident)
    assert other.isError
    assert up.calls == []
    await store.close()


async def test_approve_unknown_id_returns_false(tmp_path):
    store = EventStore(tmp_path / "h.db")
    await store.open()
    gw = _hold_gateway(store)
    assert await gw.approve_hold("APR-doesnotexist") is False
    await store.close()
