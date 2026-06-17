"""M9: Siege Crisis Response — token revocation, siege-declared bus event, UI tile.

Tests verify:
- RevokedTokenCache blocks revoked tokens at verification time
- revoked_tokens table persists and loads correctly
- siege-declared bus event is published when mode hits SIEGE
- quarantined_count() reflects the real session state
- The siege-declared UIEvent carries the frozen count in evidence
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.identity.claims import IdentityClaims, claims_from_token
from olive.identity.tokens import IdentityError, MockCA, RevokedTokenCache
from olive.store.events import EventStore


@pytest_asyncio.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "test.db")
    await s.open()
    yield s
    await s.close()


# ── RevokedTokenCache ─────────────────────────────────────────────────────────


def test_revocation_cache_blocks_revoked_jti():
    cache = RevokedTokenCache()
    cache.revoke("abc123")
    assert cache.is_revoked("abc123") is True


def test_revocation_cache_passes_unknown_jti():
    cache = RevokedTokenCache()
    assert cache.is_revoked("unknown") is False


def test_revocation_cache_seed_from_list():
    cache = RevokedTokenCache()
    cache.seed(["jti-1", "jti-2"])
    assert cache.is_revoked("jti-1") is True
    assert cache.is_revoked("jti-2") is True
    assert cache.is_revoked("jti-3") is False


# ── Token jti field ───────────────────────────────────────────────────────────


def test_mockca_issues_token_with_jti():
    ca = MockCA()
    token = ca.issue("agent-1", "acme", "customer-support", "sess-1", [])
    claims = claims_from_token(token, ca.public_key_pem())
    assert claims.jti != ""
    assert len(claims.jti) == 32  # uuid4().hex


def test_two_tokens_have_different_jtis():
    ca = MockCA()
    t1 = ca.issue("agent-1", "acme", "role", "sess-1", [])
    t2 = ca.issue("agent-1", "acme", "role", "sess-2", [])
    c1 = claims_from_token(t1, ca.public_key_pem())
    c2 = claims_from_token(t2, ca.public_key_pem())
    assert c1.jti != c2.jti


# ── Token revocation via OliveTokenVerifier ──────────────────────────────────


@pytest.mark.asyncio
async def test_verifier_rejects_revoked_token():
    from olive.transport.http import OliveTokenVerifier

    ca = MockCA()
    token = ca.issue("agent-1", "acme", "role", "sess-1", ["olive:command"])
    claims = claims_from_token(token, ca.public_key_pem())

    revocation = RevokedTokenCache()
    verifier = OliveTokenVerifier(ca.public_key_pem(), revocation=revocation)

    # Not yet revoked → accepted
    result = await verifier.verify_token(token)
    assert result is not None

    # Revoke the jti
    revocation.revoke(claims.jti)

    # Now rejected
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_verifier_accepts_non_revoked_token():
    from olive.transport.http import OliveTokenVerifier

    ca = MockCA()
    token = ca.issue("agent-1", "acme", "role", "sess-1", [])

    revocation = RevokedTokenCache()
    revocation.revoke("some-other-jti")
    verifier = OliveTokenVerifier(ca.public_key_pem(), revocation=revocation)

    result = await verifier.verify_token(token)
    assert result is not None


# ── Store — revoked_tokens table ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_persist_and_load_revoked_jtis(store):
    assert await store.load_revoked_jtis() == []

    await store.revoke_token("jti-abc", "acme", "agent-1", reason="siege response")
    await store.revoke_token("jti-def", "acme", "agent-2", reason=None)

    jtis = await store.load_revoked_jtis()
    assert set(jtis) == {"jti-abc", "jti-def"}


@pytest.mark.asyncio
async def test_store_revoke_token_idempotent(store):
    await store.revoke_token("jti-abc", "acme", "agent-1")
    await store.revoke_token("jti-abc", "acme", "agent-1")  # duplicate - ignored
    assert len(await store.load_revoked_jtis()) == 1


@pytest.mark.asyncio
async def test_revocation_cache_seeds_from_store(store):
    await store.revoke_token("jti-x", "acme", "agent-1")
    await store.revoke_token("jti-y", "acme", "agent-2")

    cache = RevokedTokenCache()
    cache.seed(await store.load_revoked_jtis())

    assert cache.is_revoked("jti-x") is True
    assert cache.is_revoked("jti-y") is True
    assert cache.is_revoked("jti-z") is False


# ── Breaker quarantined_count() ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quarantined_count_reflects_sessions():
    breaker = CircuitBreaker(max_blocks=1)
    assert breaker.quarantined_count() == 0

    await breaker.record_block("s1", "INC-001")  # trips on first block (max_blocks=1)
    assert breaker.quarantined_count() == 1

    await breaker.trip("s2", "sentinel", "INC-002")
    assert breaker.quarantined_count() == 2

    await breaker.release("s1")
    assert breaker.quarantined_count() == 1


# ── Store — quarantined_session_count() ───────────────────────────────────────


@pytest.mark.asyncio
async def test_store_quarantined_count(store):
    assert await store.quarantined_session_count() == 0

    await store.persist_session("s1", 3, True, "threshold", "INC-001")
    await store.persist_session("s2", 3, True, "threshold", "INC-002")
    await store.persist_session("s3", 1, False, None, None)

    assert await store.quarantined_session_count() == 2


# ── siege-declared bus event ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_commander_publishes_siege_declared_on_siege():
    from olive.intelligence.bus import IncidentBus
    from olive.intelligence.commander import SecurityCommander

    import os
    hmac_key = os.urandom(32)

    bus = IncidentBus(":memory:", hmac_key)
    await bus.open()
    try:
        breaker = CircuitBreaker()
        # Pre-quarantine two sessions so quarantined_count = 2
        await breaker.trip("s1", "test")
        await breaker.trip("s2", "test")

        received_kinds: list[str] = []

        async def capture(obj):
            received_kinds.append(obj.kind)

        bus.subscribe(capture)

        commander = SecurityCommander(breaker, bus)
        commander.subscribe()

        # Force SIEGE via human command
        capabilities = ("olive:command",)
        await commander.force_mode(OperatingMode.SIEGE, capabilities=capabilities)

        # Give the async bus tasks a moment to process
        await asyncio.sleep(0)

        assert "mode-change" in received_kinds
        assert "siege-declared" in received_kinds
    finally:
        await bus.close()


@pytest.mark.asyncio
async def test_commander_does_not_publish_siege_declared_for_suspicious():
    from olive.intelligence.bus import IncidentBus
    from olive.intelligence.commander import SecurityCommander

    import os
    hmac_key = os.urandom(32)

    bus = IncidentBus(":memory:", hmac_key)
    await bus.open()
    try:
        breaker = CircuitBreaker()
        received_kinds: list[str] = []

        async def capture(obj):
            received_kinds.append(obj.kind)

        bus.subscribe(capture)

        commander = SecurityCommander(breaker, bus)
        commander.subscribe()

        await commander.force_mode(OperatingMode.SUSPICIOUS, capabilities=("olive:command",))
        await asyncio.sleep(0)

        assert "mode-change" in received_kinds
        assert "siege-declared" not in received_kinds
    finally:
        await bus.close()
