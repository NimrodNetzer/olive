"""Operating-mode seam (ADR-0014): mode lives in core, the breaker owns it, and
the inline containment threshold reads it. Mode is a deterministic value the
Commander delivers through the same narrow inward call as `trip` - tested here
purely at the breaker, with no intelligence-layer imports."""

from __future__ import annotations

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode


async def test_default_mode_is_normal():
    b = CircuitBreaker()
    assert await b.mode() is OperatingMode.NORMAL


async def test_set_mode_reports_change_once():
    b = CircuitBreaker()
    assert await b.set_mode(OperatingMode.SUSPICIOUS, "reason") is True
    # idempotent: setting the same mode again is not a change (caller audits once)
    assert await b.set_mode(OperatingMode.SUSPICIOUS, "reason") is False
    assert await b.mode() is OperatingMode.SUSPICIOUS


async def test_siege_quarantines_on_first_block():
    b = CircuitBreaker(max_blocks=3)
    await b.set_mode(OperatingMode.SIEGE, "under attack")
    # one block trips immediately under siege (threshold collapses to 1)
    assert await b.record_block("s1", incident_id=None) is True


async def test_suspicious_halves_the_threshold():
    b = CircuitBreaker(max_blocks=3)
    await b.set_mode(OperatingMode.SUSPICIOUS, "watchful")
    # threshold = (3+1)//2 = 2: first block does not trip, second does
    assert await b.record_block("s1", incident_id=None) is False
    assert await b.record_block("s1", incident_id=None) is True


async def test_normal_uses_full_threshold():
    b = CircuitBreaker(max_blocks=3)
    assert await b.record_block("s1", None) is False
    assert await b.record_block("s1", None) is False
    assert await b.record_block("s1", None) is True


async def test_mode_change_is_reversible():
    b = CircuitBreaker()
    await b.set_mode(OperatingMode.SIEGE, "attack")
    assert await b.set_mode(OperatingMode.NORMAL, "all clear") is True
    assert await b.mode() is OperatingMode.NORMAL
