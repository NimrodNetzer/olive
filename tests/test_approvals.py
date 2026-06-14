"""ApprovalRegistry (ADR-0010): pending registration, idempotency, one-shot
consume, and key specificity to the exact call."""

from __future__ import annotations

import pytest

from olive.gateway.approvals import ApprovalRegistry, ApprovalStatus, approval_key

pytestmark = pytest.mark.asyncio


def _key(args_hash="h1"):
    return approval_key("org\x1fagent\x1fsess", "read_payroll", args_hash)


async def test_register_returns_id_and_marks_pending():
    reg = ApprovalRegistry()
    aid = await reg.register(_key(), "sk", "read_payroll", "h1", "context.r")
    assert aid.startswith("APR-")
    [entry] = reg.pending()
    assert entry.status is ApprovalStatus.PENDING
    assert entry.tool == "read_payroll"


async def test_register_is_idempotent_per_key():
    reg = ApprovalRegistry()
    a1 = await reg.register(_key(), "sk", "read_payroll", "h1", None)
    a2 = await reg.register(_key(), "sk", "read_payroll", "h1", None)
    assert a1 == a2
    assert len(reg.pending()) == 1


async def test_consume_requires_prior_approval():
    reg = ApprovalRegistry()
    await reg.register(_key(), "sk", "read_payroll", "h1", None)
    # pending, not yet approved -> cannot consume
    assert await reg.consume(_key()) is False


async def test_approve_then_consume_is_one_shot():
    reg = ApprovalRegistry()
    aid = await reg.register(_key(), "sk", "read_payroll", "h1", None)
    assert await reg.approve(aid) is True
    assert await reg.consume(_key()) is True  # first consume succeeds
    assert await reg.consume(_key()) is False  # second does not (one-shot)
    assert reg.pending() == []


async def test_approve_unknown_id_is_false():
    reg = ApprovalRegistry()
    assert await reg.approve("APR-nope") is False


async def test_key_is_specific_to_arguments():
    assert _key("h1") != _key("h2")
    reg = ApprovalRegistry()
    aid = await reg.register(_key("h1"), "sk", "read_payroll", "h1", None)
    await reg.approve(aid)
    # an approval for h1 must not release a call with arguments h2
    assert await reg.consume(_key("h2")) is False
