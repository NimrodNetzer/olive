"""RateLimiter unit tests - deterministic keyed sliding window.

The limit is passed per call so one limiter serves many roles, each keyed
independently (multi-tenant safe).
"""

from __future__ import annotations

import asyncio

import pytest

from olive.gateway.ratelimit import RateLimiter

KEY = "sess-1"


async def test_none_limit_means_unlimited():
    rl = RateLimiter()
    for i in range(1000):
        assert await rl.check_and_record(KEY, None, now=float(i)) is True


async def test_allows_up_to_limit_then_denies():
    rl = RateLimiter(window_seconds=60)
    assert await rl.check_and_record(KEY, 3, now=0.0) is True
    assert await rl.check_and_record(KEY, 3, now=0.1) is True
    assert await rl.check_and_record(KEY, 3, now=0.2) is True
    assert await rl.check_and_record(KEY, 3, now=0.3) is False  # 4th in window


async def test_window_slides_and_frees_capacity():
    rl = RateLimiter(window_seconds=60)
    assert await rl.check_and_record(KEY, 2, now=0.0) is True
    assert await rl.check_and_record(KEY, 2, now=1.0) is True
    assert await rl.check_and_record(KEY, 2, now=2.0) is False  # full
    assert await rl.check_and_record(KEY, 2, now=61.0) is True  # first two expired


async def test_denied_calls_are_not_recorded():
    rl = RateLimiter(window_seconds=60)
    assert await rl.check_and_record(KEY, 1, now=0.0) is True
    assert await rl.check_and_record(KEY, 1, now=1.0) is False
    assert await rl.check_and_record(KEY, 1, now=2.0) is False
    # the single recorded call expires at 60s; denials did not extend the window
    assert await rl.check_and_record(KEY, 1, now=61.0) is True


async def test_keys_are_isolated():
    rl = RateLimiter(window_seconds=60)
    assert await rl.check_and_record("a", 1, now=0.0) is True
    assert await rl.check_and_record("a", 1, now=0.1) is False
    assert await rl.check_and_record("b", 1, now=0.1) is True  # different session


async def test_same_key_can_carry_different_role_limits():
    # the limit is per call; two keys with different limits are independent
    rl = RateLimiter(window_seconds=60)
    assert await rl.check_and_record("strict", 1, now=0.0) is True
    assert await rl.check_and_record("strict", 1, now=0.1) is False
    assert await rl.check_and_record("loose", 5, now=0.1) is True


async def test_concurrent_calls_respect_the_limit():
    rl = RateLimiter(window_seconds=60)
    results = await asyncio.gather(
        *(rl.check_and_record(KEY, 10, now=0.0) for _ in range(25))
    )
    assert sum(results) == 10, "exactly the limit may pass under concurrency"


async def test_invalid_limit_rejected():
    rl = RateLimiter()
    with pytest.raises(ValueError):
        await rl.check_and_record(KEY, 0)
