"""Tests for policy file integrity and audit chain (ADR-0026 layers 1 & 2)."""

from __future__ import annotations

import sqlite3

import pytest

from olive.gateway.pipeline import ALLOW, Decision, Verdict
from olive.security.integrity import PolicyIntegrityStatus, compute_file_hash
from olive.store.events import AuditChainStatus, EventStore


@pytest.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "events.db")
    await s.open()
    yield s
    await s.close()


# ── compute_file_hash ─────────────────────────────────────────────────────────

def test_file_hash_is_sha256_hex(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_bytes(b"hello world")
    h = compute_file_hash(f)
    import hashlib
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert h == expected


def test_file_hash_changes_with_content(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_bytes(b"content v1")
    h1 = compute_file_hash(f)
    f.write_bytes(b"content v2")
    h2 = compute_file_hash(f)
    assert h1 != h2


# ── policy checksum store ─────────────────────────────────────────────────────

async def test_first_run_is_new(store):
    status, stored = await store.check_policy_hash("/etc/policy.yaml", "abc123")
    assert status == "new"
    assert stored is None


async def test_record_then_check_unchanged(store):
    await store.record_policy_hash("/etc/policy.yaml", "abc123")
    status, stored = await store.check_policy_hash("/etc/policy.yaml", "abc123")
    assert status == "unchanged"
    assert stored == "abc123"


async def test_changed_hash_is_detected(store):
    await store.record_policy_hash("/etc/policy.yaml", "abc123")
    status, stored = await store.check_policy_hash("/etc/policy.yaml", "def456")
    assert status == "changed"
    assert stored == "abc123"


async def test_record_policy_hash_upserts(store):
    await store.record_policy_hash("/etc/policy.yaml", "v1")
    await store.record_policy_hash("/etc/policy.yaml", "v2")
    status, stored = await store.check_policy_hash("/etc/policy.yaml", "v2")
    assert status == "unchanged"


# ── audit chain ───────────────────────────────────────────────────────────────

async def test_empty_chain_is_ok(store):
    result = await store.verify_audit_chain()
    assert isinstance(result, AuditChainStatus)
    assert result.ok
    assert result.chained_events == 0


async def test_single_event_chain_ok(store, make_context):
    ctx = make_context(direction="inbound")
    await store.log_event(ctx, ALLOW, latency_ms=1)
    result = await store.verify_audit_chain()
    assert result.ok
    assert result.chained_events == 1
    assert result.broken_at_event_id is None


async def test_multiple_events_chain_ok(store, make_context):
    ctx = make_context(direction="inbound")
    blocked = Verdict(Decision.BLOCK, rule="patterns.injection", evidence="e")
    for _ in range(10):
        await store.log_event(ctx, ALLOW)
    inc = await store.create_incident(ctx, blocked, "prompt-injection", "pattern")
    await store.log_event(ctx, blocked, incident_id=inc)
    result = await store.verify_audit_chain()
    assert result.ok
    assert result.chained_events == 11


async def test_chain_detects_row_deletion(store, make_context, tmp_path):
    ctx = make_context(direction="inbound")
    for _ in range(5):
        await store.log_event(ctx, ALLOW)

    # Simulate tamper: delete a row from the middle of the chain.
    await store.close()
    conn = sqlite3.connect(tmp_path / "events.db")
    rows = conn.execute("SELECT rowid FROM audit_chain ORDER BY rowid").fetchall()
    mid = rows[2][0]
    conn.execute("DELETE FROM audit_chain WHERE rowid = ?", (mid,))
    conn.commit()
    conn.close()

    s2 = EventStore(tmp_path / "events.db")
    await s2.open()
    try:
        result = await s2.verify_audit_chain()
        assert not result.ok
        assert result.broken_at_event_id is not None
    finally:
        await s2.close()


async def test_chain_detects_row_modification(store, make_context, tmp_path):
    ctx = make_context(direction="inbound")
    for _ in range(3):
        await store.log_event(ctx, ALLOW)

    await store.close()
    conn = sqlite3.connect(tmp_path / "events.db")
    # Corrupt the row_hash of the first chain record.
    conn.execute(
        "UPDATE audit_chain SET row_hash = 'deadbeef' || substr(row_hash, 9) WHERE rowid = 1"
    )
    conn.commit()
    conn.close()

    s2 = EventStore(tmp_path / "events.db")
    await s2.open()
    try:
        result = await s2.verify_audit_chain()
        assert not result.ok
    finally:
        await s2.close()


async def test_chain_row_written_per_event(store, make_context, tmp_path):
    ctx = make_context(direction="inbound")
    await store.log_event(ctx, ALLOW)
    await store.log_event(ctx, ALLOW)
    await store.close()

    conn = sqlite3.connect(tmp_path / "events.db")
    count = conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]
    conn.close()

    assert count == 2

    s2 = EventStore(tmp_path / "events.db")
    await s2.open()
    result = await s2.verify_audit_chain()
    await s2.close()
    assert result.ok
