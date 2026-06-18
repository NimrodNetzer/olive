"""Circuit breaker unit tests (ADR-0006)."""

from __future__ import annotations

import asyncio
from time import monotonic

import pytest

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.session import SessionStatus

SID = "sess-1"


def breaker(max_blocks: int = 3) -> CircuitBreaker:
    return CircuitBreaker(max_blocks=max_blocks)


async def test_begin_call_sequences_and_snapshots_history():
    b = breaker()
    t1 = await b.begin_call(SID)
    assert (t1.call_number, t1.history, t1.quarantined) == (1, (), False)
    await b.record_allowed_call(SID, "read_faq")
    t2 = await b.begin_call(SID)
    assert t2.call_number == 2
    assert t2.history == ("read_faq",)


async def test_block_trips_at_threshold():
    b = breaker(max_blocks=3)
    assert await b.record_block(SID, "INC-0001") is False
    assert await b.record_block(SID, "INC-0002") is False
    # third block crosses the threshold -> trips exactly once
    assert await b.record_block(SID, "INC-0003") is True
    assert await b.status(SID) is SessionStatus.QUARANTINED


async def test_quarantine_records_the_tripping_incident():
    b = breaker(max_blocks=1)
    await b.record_block(SID, "INC-0042")
    state = b.snapshot(SID)
    assert state is not None
    assert state.quarantine_incident_id == "INC-0042"
    assert state.quarantine_reason is not None


async def test_quarantined_session_is_not_advanced():
    b = breaker(max_blocks=1)
    await b.begin_call(SID)  # call 1
    await b.record_block(SID, "INC-0001")  # trips
    before = b.snapshot(SID).call_number
    ticket = await b.begin_call(SID)
    assert ticket.quarantined is True
    assert ticket.incident_id == "INC-0001"
    assert b.snapshot(SID).call_number == before  # no increment while quarantined


async def test_record_block_is_noop_once_quarantined():
    b = breaker(max_blocks=1)
    assert await b.record_block(SID, "INC-0001") is True
    # already quarantined: further blocks neither re-trip nor raise count
    assert await b.record_block(SID, "INC-0002") is False
    assert b.snapshot(SID).block_count == 1


async def test_release_is_reversible_and_resets_count():
    b = breaker(max_blocks=2)
    await b.record_block(SID, "INC-0001")
    await b.record_block(SID, "INC-0002")  # trips
    assert await b.release(SID) is True
    assert await b.status(SID) is SessionStatus.ACTIVE
    state = b.snapshot(SID)
    assert state.block_count == 0
    assert state.quarantine_incident_id is None
    # releasing an active session is a no-op
    assert await b.release(SID) is False


async def test_trip_is_the_sentinel_entry_point():
    b = breaker()
    assert await b.trip(SID, "behavior-sentinel: goal drift", "INC-0009") is True
    assert await b.status(SID) is SessionStatus.QUARANTINED
    assert await b.trip(SID, "again", "INC-0010") is False  # already tripped


async def test_concurrent_begin_calls_get_unique_numbers():
    b = breaker(max_blocks=100)
    tickets = await asyncio.gather(*(b.begin_call(SID) for _ in range(50)))
    numbers = sorted(t.call_number for t in tickets)
    assert numbers == list(range(1, 51))


def test_max_blocks_must_be_positive():
    with pytest.raises(ValueError):
        CircuitBreaker(max_blocks=0)


async def test_idle_active_sessions_are_evicted():
    b = CircuitBreaker(idle_ttl_seconds=100)
    await b.begin_call("s1")
    await b.begin_call("s2")
    assert b.session_count() == 2
    # far-future sweep: both are idle past the TTL
    evicted = await b.evict_idle(now=monotonic() + 10_000)
    assert evicted == 2
    assert b.session_count() == 0


async def test_quarantined_sessions_are_never_evicted():
    """Critical: going idle must not clear a quarantine."""
    b = CircuitBreaker(max_blocks=1, idle_ttl_seconds=100)
    await b.record_block("attacker", "INC-0001")  # trips -> quarantined
    await b.begin_call("idle-active")  # an ordinary active session
    evicted = await b.evict_idle(now=monotonic() + 10_000)
    assert evicted == 1  # only the active one
    assert await b.status("attacker") is SessionStatus.QUARANTINED
    assert b.snapshot("idle-active") is None


# ── M11 Slice B: JTI tracking ───────────────────────────────────────────────


async def test_record_jti_updates_current_jti():
    b = breaker()
    await b.record_jti(SID, "tok-abc123")
    state = b.snapshot(SID)
    assert state is not None and state.current_jti == "tok-abc123"


async def test_record_jti_empty_string_is_noop():
    """Empty jti (stdio/unverified sessions) must not overwrite a real one."""
    b = breaker()
    await b.record_jti(SID, "tok-real")
    await b.record_jti(SID, "")
    state = b.snapshot(SID)
    assert state is not None and state.current_jti == "tok-real"


async def test_record_jti_most_recent_wins():
    b = breaker()
    await b.record_jti(SID, "tok-v1")
    await b.record_jti(SID, "tok-v2")
    state = b.snapshot(SID)
    assert state is not None and state.current_jti == "tok-v2"


async def test_quarantined_jtis_returns_only_quarantined_with_jti():
    b = CircuitBreaker(max_blocks=1)
    # Session with JTI, trips into quarantine
    await b.record_jti("attacker", "tok-evil")
    await b.record_block("attacker", "INC-0001")
    # Active session with JTI
    await b.record_jti("normal", "tok-ok")
    # Quarantined session with no JTI (stdio)
    await b.record_block("nojti", "INC-0002")

    result = b.quarantined_jtis()
    assert result == {"attacker": "tok-evil"}
    assert "normal" not in result
    assert "nojti" not in result


async def test_quarantined_jtis_empty_when_no_quarantines():
    b = breaker()
    await b.record_jti(SID, "tok-abc")
    assert b.quarantined_jtis() == {}


async def test_recent_sessions_survive_eviction():
    b = CircuitBreaker(idle_ttl_seconds=10_000)
    await b.begin_call("fresh")
    assert await b.evict_idle() == 0
    assert b.snapshot("fresh") is not None
