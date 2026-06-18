from __future__ import annotations

import sqlite3

import pytest

from olive.gateway.context import hash_arguments
from olive.gateway.pipeline import ALLOW, Decision, Verdict
from olive.store.events import EventStore


@pytest.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "events.db")
    await s.open()
    yield s
    await s.close()


async def test_event_roundtrip(store, make_context, tmp_path):
    ctx = make_context(tool="read_faq")
    event_id = await store.log_event(ctx, ALLOW, latency_ms=3)
    assert event_id.startswith("evt-")

    db = sqlite3.connect(tmp_path / "events.db")
    row = db.execute(
        "SELECT tool, decision, arguments_hash, incident_id FROM events WHERE event_id=?",
        (event_id,),
    ).fetchone()
    db.close()
    assert row == ("read_faq", "allow", ctx.arguments_hash, None)


async def test_incident_ids_are_sequential(store, make_context):
    verdict = Verdict(Decision.BLOCK, rule="policy.forbidden_tool", evidence="e")
    ctx = make_context(tool="access_payroll")
    first = await store.create_incident(ctx, verdict, "privilege-escalation", "deterministic")
    second = await store.create_incident(ctx, verdict, "privilege-escalation", "deterministic")
    assert (first, second) == ("INC-0001", "INC-0002")


async def test_concurrent_incidents_get_unique_ids(store, make_context):
    """Security review finding: id generation must not race under concurrency."""
    import asyncio

    verdict = Verdict(Decision.BLOCK, rule="r", evidence="e")
    ctx = make_context()
    ids = await asyncio.gather(
        *(store.create_incident(ctx, verdict, "prompt-injection", "pattern") for _ in range(20))
    )
    assert len(set(ids)) == 20, f"duplicate incident ids: {sorted(ids)}"


async def test_summary_counts(store, make_context):
    ctx = make_context()
    await store.log_event(ctx, ALLOW)
    blocked = Verdict(Decision.BLOCK, rule="r", evidence="e")
    incident = await store.create_incident(ctx, blocked, "prompt-injection", "pattern")
    await store.log_event(ctx, blocked, incident_id=incident)

    summary = await store.summary()
    assert (summary.total, summary.allowed, summary.blocked, summary.incidents) == (2, 1, 1, 1)


async def test_tool_baseline_tofu_lifecycle(store):
    from olive.store.events import BaselineStatus

    assert await store.observe_tool("files.read", "h1") is BaselineStatus.NEW
    assert await store.observe_tool("files.read", "h1") is BaselineStatus.UNCHANGED
    # a changed declaration is flagged...
    assert await store.observe_tool("files.read", "h2") is BaselineStatus.CHANGED
    # ...and the baseline is NOT overwritten by the swap
    assert await store.observe_tool("files.read", "h2") is BaselineStatus.CHANGED
    # the original baseline still matches
    assert await store.observe_tool("files.read", "h1") is BaselineStatus.UNCHANGED


async def test_reset_baseline_reaccepts_first_use(store):
    from olive.store.events import BaselineStatus

    await store.observe_tool("a", "h1")
    assert await store.reset_baseline("a") == 1
    assert await store.observe_tool("a", "h2") is BaselineStatus.NEW


async def test_no_raw_arguments_ever_persisted(store, make_context, tmp_path):
    """CLAUDE.md rule 3: the secret value must not appear anywhere in the DB file."""
    secret = "super-secret-api-key-12345"
    ctx = make_context(tool="send_email", arguments={"body": secret})
    await store.log_event(ctx, ALLOW)
    await store.close()

    raw = (tmp_path / "events.db").read_bytes()
    assert secret.encode() not in raw
    assert hash_arguments({"body": secret}).encode() in raw


# ── M11: cross-session behavioral baseline queries ──────────────────────────


async def test_agent_calls_per_session_returns_counts_in_recency_order(store):
    """agent_calls_per_session groups by session and returns most-recent first."""
    await store.log_allowed_call("agent-a", "org-1", "sess-old", "read_faq")
    await store.log_allowed_call("agent-a", "org-1", "sess-old", "search")
    await store.log_allowed_call("agent-a", "org-1", "sess-new", "read_faq")
    counts = await store.agent_calls_per_session("agent-a", "org-1")
    assert sorted(counts, reverse=True) == [2, 1]  # both sessions present


async def test_agent_calls_per_session_empty_for_unknown_agent(store):
    assert await store.agent_calls_per_session("nobody", "org-1") == []


async def test_agent_calls_per_session_respects_n_sessions_limit(store):
    for i in range(5):
        await store.log_allowed_call("agent-b", "org-1", f"sess-{i}", "read_faq")
    counts = await store.agent_calls_per_session("agent-b", "org-1", n_sessions=3)
    assert len(counts) == 3


async def test_agent_known_tools_returns_distinct_set(store):
    await store.log_allowed_call("agent-a", "org-1", "s1", "read_faq")
    await store.log_allowed_call("agent-a", "org-1", "s1", "read_faq")  # duplicate
    await store.log_allowed_call("agent-a", "org-1", "s2", "search")
    known = await store.agent_known_tools("agent-a", "org-1")
    assert known == {"read_faq", "search"}


async def test_agent_known_tools_scoped_to_org(store):
    await store.log_allowed_call("agent-a", "org-1", "s1", "privileged_tool")
    known_org2 = await store.agent_known_tools("agent-a", "org-2")
    assert "privileged_tool" not in known_org2
