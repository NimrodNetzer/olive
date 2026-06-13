"""RateLimiter unit tests - deterministic sliding window."""

from __future__ import annotations

import asyncio

import pytest

from olive.gateway.ratelimit import RateLimiter

KEY = "sess-1"


async def test_none_means_unlimited():
    rl = RateLimiter(None)
    assert rl.enabled is False
    for i in range(1000):
        assert await rl.check_and_record(KEY, now=float(i)) is True


async def test_allows_up_to_limit_then_denies():
    rl = RateLimiter(3, window_seconds=60)
    assert await rl.check_and_record(KEY, now=0.0) is True
    assert await rl.check_and_record(KEY, now=0.1) is True
    assert await rl.check_and_record(KEY, now=0.2) is True
    assert await rl.check_and_record(KEY, now=0.3) is False  # 4th in window


async def test_window_slides_and_frees_capacity():
    rl = RateLimiter(2, window_seconds=60)
    assert await rl.check_and_record(KEY, now=0.0) is True
    assert await rl.check_and_record(KEY, now=1.0) is True
    assert await rl.check_and_record(KEY, now=2.0) is False  # full
    # advance past the window: the first two timestamps expire
    assert await rl.check_and_record(KEY, now=61.0) is True


async def test_denied_calls_are_not_recorded():
    rl = RateLimiter(1, window_seconds=60)
    assert await rl.check_and_record(KEY, now=0.0) is True
    assert await rl.check_and_record(KEY, now=1.0) is False
    assert await rl.check_and_record(KEY, now=2.0) is False
    # the single recorded call expires at 60s, so a call at 61 is allowed -
    # the denials in between did not extend the window
    assert await rl.check_and_record(KEY, now=61.0) is True


async def test_keys_are_isolated():
    rl = RateLimiter(1, window_seconds=60)
    assert await rl.check_and_record("a", now=0.0) is True
    assert await rl.check_and_record("a", now=0.1) is False
    assert await rl.check_and_record("b", now=0.1) is True  # different session


async def test_concurrent_calls_respect_the_limit():
    rl = RateLimiter(10, window_seconds=60)
    results = await asyncio.gather(
        *(rl.check_and_record(KEY, now=0.0) for _ in range(25))
    )
    assert sum(results) == 10, "exactly the limit may pass under concurrency"


def test_invalid_limit_rejected():
    with pytest.raises(ValueError):
        RateLimiter(0)
