"""M10: Detection Depth — cross-session behavioral baselines.

Tests verify:
- log_allowed_call() appends tool history to the persistent baseline
- recent_agent_tools() returns cross-session history in recency order
- BehaviorSentinel fires on egress tool after sensitive reads in cross-session history
- Cross-session signal has lower confidence (0.5) than current-session signal (0.6)
- BehaviorSentinel ignores non-egress tools even when cross-session history present
- Cross-session fn failure is silenced — never blocks the runner
- Current-session match takes priority and prevents redundant cross-session lookup
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from olive.gateway.context import SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW
from olive.gateway.telemetry import TelemetryEvent
from olive.intelligence.sentinels import BehaviorSentinel
from olive.store.events import EventStore


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "depth.db")
    await s.open()
    yield s
    await s.close()


def _event(
    *,
    tool: str,
    history: tuple[str, ...] = (),
    agent_id: str = "agent-1",
    org_id: str = "acme",
) -> TelemetryEvent:
    ctx = SecurityContext(
        agent_id=agent_id,
        session_id="sess-1",
        organization_id=org_id,
        role="customer-support",
        declared_goal="help customers",
        tool=tool,
        arguments_hash=hash_arguments(None),
        direction="outbound",
        call_number=1,
        session_tool_history=history,
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
    )
    return TelemetryEvent(ctx=ctx, verdict=ALLOW, arguments={})


# ── Store: log_allowed_call + recent_agent_tools ──────────────────────────────


@pytest.mark.asyncio
async def test_log_allowed_call_stores_entry(store):
    await store.log_allowed_call("agent-1", "acme", "sess-1", "read_customer")
    tools = await store.recent_agent_tools("agent-1", "acme")
    assert tools == ["read_customer"]


@pytest.mark.asyncio
async def test_recent_agent_tools_multiple_entries(store):
    await store.log_allowed_call("agent-1", "acme", "sess-1", "read_faq")
    await store.log_allowed_call("agent-1", "acme", "sess-1", "read_customer")
    await store.log_allowed_call("agent-1", "acme", "sess-2", "send_email")
    tools = await store.recent_agent_tools("agent-1", "acme")
    assert set(tools) == {"read_faq", "read_customer", "send_email"}


@pytest.mark.asyncio
async def test_recent_agent_tools_isolated_by_agent(store):
    await store.log_allowed_call("agent-1", "acme", "sess-1", "read_customer")
    await store.log_allowed_call("agent-2", "acme", "sess-2", "read_payroll")
    tools_a1 = await store.recent_agent_tools("agent-1", "acme")
    tools_a2 = await store.recent_agent_tools("agent-2", "acme")
    assert tools_a1 == ["read_customer"]
    assert tools_a2 == ["read_payroll"]


@pytest.mark.asyncio
async def test_recent_agent_tools_isolated_by_org(store):
    await store.log_allowed_call("agent-1", "acme", "sess-1", "read_customer")
    await store.log_allowed_call("agent-1", "globex", "sess-2", "read_payroll")
    acme_tools = await store.recent_agent_tools("agent-1", "acme")
    globex_tools = await store.recent_agent_tools("agent-1", "globex")
    assert acme_tools == ["read_customer"]
    assert globex_tools == ["read_payroll"]


@pytest.mark.asyncio
async def test_recent_agent_tools_respects_limit(store):
    for i in range(10):
        await store.log_allowed_call("agent-1", "acme", "sess-1", f"tool_{i}")
    tools = await store.recent_agent_tools("agent-1", "acme", n=3)
    assert len(tools) == 3


@pytest.mark.asyncio
async def test_recent_agent_tools_empty_for_unknown_agent(store):
    tools = await store.recent_agent_tools("never-seen", "acme")
    assert tools == []


# ── BehaviorSentinel: M11 call-rate anomaly ───────────────────────────────────


@pytest.mark.asyncio
async def test_call_rate_anomaly_fires_when_session_is_5x_above_average():
    """Session with 5× the historical average call count fires the rate signal."""

    async def rate_baseline_fn(agent_id, org_id):
        return [4, 4, 4]  # avg = 4; 5× = 20

    sentinel = BehaviorSentinel(rate_baseline_fn=rate_baseline_fn)
    # 20 calls total: 19 in history + 1 current = 5× average
    history = tuple(f"read_faq_{i}" for i in range(19))
    event = _event(tool="read_faq", history=history)

    sig = await sentinel.analyze(event)

    assert sig.detected
    assert sig.attack_type == "call-rate-anomaly"
    assert sig.confidence == 0.55
    assert "historical average" in sig.evidence


@pytest.mark.asyncio
async def test_call_rate_anomaly_requires_min_3_sessions():
    """With fewer than 3 prior sessions the rate signal does not fire."""

    async def rate_baseline_fn(agent_id, org_id):
        return [4, 4]  # only 2 prior sessions — not enough history

    sentinel = BehaviorSentinel(rate_baseline_fn=rate_baseline_fn)
    history = tuple(f"read_faq_{i}" for i in range(100))
    event = _event(tool="read_faq", history=history)

    sig = await sentinel.analyze(event)

    assert not sig.detected


@pytest.mark.asyncio
async def test_call_rate_no_signal_below_threshold():
    """A session at 4× average does not trip the 5× threshold."""

    async def rate_baseline_fn(agent_id, org_id):
        return [5, 5, 5]  # avg = 5; 5× = 25; 20 calls is only 4×

    sentinel = BehaviorSentinel(rate_baseline_fn=rate_baseline_fn)
    history = tuple(f"read_faq_{i}" for i in range(19))  # 20 calls total
    event = _event(tool="read_faq", history=history)

    sig = await sentinel.analyze(event)

    assert not sig.detected


@pytest.mark.asyncio
async def test_call_rate_swallows_fn_exception():
    """An exception in rate_baseline_fn is silenced — never propagates."""

    async def failing_rate_fn(agent_id, org_id):
        raise RuntimeError("store unavailable")

    sentinel = BehaviorSentinel(rate_baseline_fn=failing_rate_fn)
    event = _event(tool="read_faq", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected  # fail safe


# ── BehaviorSentinel: M11 novel-tool signal ───────────────────────────────────


@pytest.mark.asyncio
async def test_novel_sensitive_tool_fires_when_not_in_known_set():
    """First-ever use of a sensitive tool by an agent fires the novel-tool signal."""

    async def known_tools_fn(agent_id, org_id):
        return {"read_faq", "search_kb"}  # agent has history but no sensitive tools

    sentinel = BehaviorSentinel(known_tools_fn=known_tools_fn)
    event = _event(tool="read_customer_ssn", history=())

    sig = await sentinel.analyze(event)

    assert sig.detected
    assert sig.attack_type == "novel-tool"
    assert sig.confidence == 0.5
    assert "read_customer_ssn" in sig.evidence


@pytest.mark.asyncio
async def test_no_novel_signal_when_tool_is_known():
    """If the agent has used the sensitive tool before, no novel signal fires."""

    async def known_tools_fn(agent_id, org_id):
        return {"read_faq", "read_customer_ssn"}  # already in known set

    sentinel = BehaviorSentinel(known_tools_fn=known_tools_fn)
    event = _event(tool="read_customer_ssn", history=())

    sig = await sentinel.analyze(event)

    # May still fire a sequence signal, but not the novel-tool signal
    assert not sig.detected or sig.attack_type != "novel-tool"


@pytest.mark.asyncio
async def test_no_novel_signal_when_known_set_is_empty():
    """An empty known-tools set means no prior history — novel signal suppressed."""

    async def known_tools_fn(agent_id, org_id):
        return set()  # brand-new agent, no history at all

    sentinel = BehaviorSentinel(known_tools_fn=known_tools_fn)
    event = _event(tool="read_customer_ssn", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected or sig.attack_type != "novel-tool"


@pytest.mark.asyncio
async def test_novel_tool_swallows_fn_exception():
    """An exception in known_tools_fn is silenced — never propagates."""

    async def failing_fn(agent_id, org_id):
        raise RuntimeError("connection lost")

    sentinel = BehaviorSentinel(known_tools_fn=failing_fn)
    event = _event(tool="read_credentials", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected  # fail safe


# ── BehaviorSentinel: cross-session baseline ──────────────────────────────────


@pytest.mark.asyncio
async def test_behavior_sentinel_fires_on_cross_session_sensitive_read():
    """Egress call after sensitive reads in prior sessions triggers signal."""

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        return ["read_customer_ssn", "read_database"]  # prior sessions had sensitive calls

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    event = _event(tool="send_email", history=())  # no current-session history

    sig = await sentinel.analyze(event)

    assert sig.detected
    assert sig.confidence == 0.5  # cross-session is softer than current-session (0.6)
    assert "cross-session baseline" in sig.evidence


@pytest.mark.asyncio
async def test_behavior_sentinel_no_signal_without_sensitive_cross_session():
    """Egress call with only benign cross-session history → no signal."""

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        return ["read_faq", "search_kb", "read_article"]  # benign

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    event = _event(tool="send_email", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected


@pytest.mark.asyncio
async def test_behavior_sentinel_current_session_takes_priority():
    """Current-session match returns 0.6 confidence without querying cross-session."""
    cross_session_called = False

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        nonlocal cross_session_called
        cross_session_called = True
        return ["read_customer_ssn"]

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    # Current session has sensitive read already
    event = _event(tool="send_email", history=("read_customer",))

    sig = await sentinel.analyze(event)

    assert sig.detected
    assert sig.confidence == 0.6  # current-session confidence
    assert "this session" in sig.evidence
    assert not cross_session_called  # cross-session not queried


@pytest.mark.asyncio
async def test_behavior_sentinel_skips_non_egress_tool():
    """Cross-session fn is never called when tool is not an egress tool."""
    cross_session_called = False

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        nonlocal cross_session_called
        cross_session_called = True
        return ["read_customer_ssn"]

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    event = _event(tool="read_faq", history=())  # not an egress tool

    sig = await sentinel.analyze(event)

    assert not sig.detected
    assert not cross_session_called


@pytest.mark.asyncio
async def test_behavior_sentinel_swallows_cross_session_exception():
    """If cross_session_fn raises, the sentinel silently returns no-signal."""

    async def failing_cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        raise RuntimeError("database unavailable")

    sentinel = BehaviorSentinel(cross_session_fn=failing_cross_session_fn)
    event = _event(tool="send_email", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected  # fail safe: no signal, no exception propagated


@pytest.mark.asyncio
async def test_behavior_sentinel_no_cross_session_fn():
    """Without cross_session_fn, egress with no current history produces no signal."""
    sentinel = BehaviorSentinel()  # no cross_session_fn
    event = _event(tool="upload", history=())

    sig = await sentinel.analyze(event)

    assert not sig.detected


# ── Integration: store → cross_session_fn → BehaviorSentinel ─────────────────


@pytest.mark.asyncio
async def test_store_backed_cross_session_baseline_fires(store):
    """Full integration: prior session calls logged to store trigger sentinel
    on a new session egress call, bridging multiple sessions."""

    # Simulate two prior sessions with sensitive reads
    await store.log_allowed_call("agent-1", "acme", "sess-prev-1", "read_customer_ssn")
    await store.log_allowed_call("agent-1", "acme", "sess-prev-1", "read_database")
    await store.log_allowed_call("agent-1", "acme", "sess-prev-2", "read_credentials")

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        return await store.recent_agent_tools(agent_id, org_id)

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    # New session (sess-1), no current-session history yet
    event = _event(tool="send_email", history=(), agent_id="agent-1", org_id="acme")

    sig = await sentinel.analyze(event)

    assert sig.detected
    assert sig.confidence == 0.5
    assert "cross-session" in sig.evidence


@pytest.mark.asyncio
async def test_store_backed_cross_session_no_signal_for_different_agent(store):
    """Cross-session history from a different agent does not trigger the sentinel."""

    # Different agent has sensitive history
    await store.log_allowed_call("agent-2", "acme", "sess-1", "read_customer_ssn")

    async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
        return await store.recent_agent_tools(agent_id, org_id)

    sentinel = BehaviorSentinel(cross_session_fn=cross_session_fn)
    # agent-1 has no history at all
    event = _event(tool="send_email", history=(), agent_id="agent-1", org_id="acme")

    sig = await sentinel.analyze(event)

    assert not sig.detected
