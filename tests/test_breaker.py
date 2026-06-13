"""Circuit breaker unit tests (ADR-0006)."""

from __future__ import annotations

import asyncio

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
