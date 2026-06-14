"""The remediation cycle ledger (ADR-0013) is enforcement-adjacent: it gates the
two transitions an attacker would target (verify, approve->learn), so it is
tested like enforcement code. Focus: the state machine fails closed on every
illegal move, the human gate cannot be skipped, and rule 3 holds (hashes +
bounded text only).
"""

from __future__ import annotations

import argparse

import pytest

from olive.intelligence.remediation import (
    RemediationError,
    RemediationLedger,
    RemediationState,
    hash_patch,
)


@pytest.fixture
async def ledger(tmp_path):
    led = RemediationLedger(tmp_path / "audit.db")
    await led.open()
    try:
        yield led
    finally:
        await led.close()


async def _to_verified(ledger, patch_path, *, gate_passed=True):
    cycle = await ledger.open_cycle("INC-0001", "inj-9001")
    await ledger.propose_fix(cycle.cycle_id, patch_hash=hash_patch(patch_path), patch_summary="fix")
    await ledger.record_verification(
        cycle.cycle_id, gate_passed=gate_passed, detected=28, false_positives=0
    )
    return cycle.cycle_id


@pytest.fixture
def patch_file(tmp_path):
    p = tmp_path / "fix.patch"
    p.write_text("--- a\n+++ b\n@@ +pattern @@\n", encoding="utf-8")
    return p


# ---- happy path --------------------------------------------------------------


async def test_full_loop(ledger, patch_file):
    cid = await _to_verified(ledger, patch_file)
    approved = await ledger.approve(cid, approved_by="ops-human")
    assert approved.state is RemediationState.APPROVED
    assert approved.approved_by == "ops-human"
    assert approved.approved_at is not None
    learned = await ledger.learn(cid)
    assert learned.state is RemediationState.LEARNED


async def test_open_records_incident_and_case(ledger):
    cycle = await ledger.open_cycle("INC-0007", "inj-0021")
    assert cycle.state is RemediationState.REPRODUCED
    assert cycle.incident_id == "INC-0007"
    assert cycle.corpus_case_id == "inj-0021"


async def test_cycle_ids_are_sequential(ledger):
    a = await ledger.open_cycle("INC-1", "c-1")
    b = await ledger.open_cycle("INC-2", "c-2")
    assert a.cycle_id == "CYC-0001"
    assert b.cycle_id == "CYC-0002"


# ---- fail-closed: the verify gate cannot be skipped --------------------------


async def test_cannot_approve_unverified(ledger, patch_file):
    cycle = await ledger.open_cycle("INC-0001", "inj-9001")
    await ledger.propose_fix(cycle.cycle_id, patch_hash=hash_patch(patch_file), patch_summary="fix")
    # still FIX_PROPOSED, never verified
    with pytest.raises(RemediationError, match="requires verified"):
        await ledger.approve(cycle.cycle_id, approved_by="ops-human")


async def test_gate_failure_rejects(ledger, patch_file):
    cid = await _to_verified(ledger, patch_file, gate_passed=False)
    cycle = await ledger.get(cid)
    assert cycle.state is RemediationState.REJECTED
    assert cycle.gate_passed == 0
    # a rejected cycle cannot be approved
    with pytest.raises(RemediationError):
        await ledger.approve(cid, approved_by="ops-human")


# ---- fail-closed: the human gate cannot be skipped ---------------------------


async def test_cannot_learn_without_approval(ledger, patch_file):
    cid = await _to_verified(ledger, patch_file)
    # verified but not approved
    with pytest.raises(RemediationError, match="requires approved"):
        await ledger.learn(cid)


async def test_approve_requires_identity(ledger, patch_file):
    cid = await _to_verified(ledger, patch_file)
    with pytest.raises(RemediationError, match="approver"):
        await ledger.approve(cid, approved_by="")


# ---- fail-closed: ordering + unknown ids -------------------------------------


async def test_propose_requires_reproduced(ledger, patch_file):
    cid = await _to_verified(ledger, patch_file)  # now VERIFIED
    with pytest.raises(RemediationError, match="requires reproduced"):
        await ledger.propose_fix(cid, patch_hash="x", patch_summary="again")


async def test_unknown_cycle(ledger):
    with pytest.raises(RemediationError, match="unknown cycle"):
        await ledger.get("CYC-9999")


async def test_open_requires_both_ids(ledger):
    with pytest.raises(RemediationError):
        await ledger.open_cycle("", "case")
    with pytest.raises(RemediationError):
        await ledger.open_cycle("INC-1", "")


async def test_reject_then_no_further_moves(ledger, patch_file):
    cycle = await ledger.open_cycle("INC-1", "c-1")
    await ledger.propose_fix(cycle.cycle_id, patch_hash=hash_patch(patch_file), patch_summary="fix")
    rejected = await ledger.reject(cycle.cycle_id)
    assert rejected.state is RemediationState.REJECTED
    with pytest.raises(RemediationError, match="already"):
        await ledger.reject(cycle.cycle_id)


async def test_reject_requires_open_state(ledger):
    cycle = await ledger.open_cycle("INC-1", "c-1")  # REPRODUCED, nothing to reject yet
    with pytest.raises(RemediationError, match="only a proposed or verified"):
        await ledger.reject(cycle.cycle_id)


# ---- rule 3: hashes + bounded text only --------------------------------------


async def test_summary_is_bounded(ledger, patch_file):
    cycle = await ledger.open_cycle("INC-1", "c-1")
    long = "A" * 500
    proposed = await ledger.propose_fix(
        cycle.cycle_id, patch_hash=hash_patch(patch_file), patch_summary=long
    )
    assert len(proposed.patch_summary) == 200


async def test_patch_hash_is_sha256_of_file(tmp_path):
    p = tmp_path / "fix.patch"
    p.write_text("diff body", encoding="utf-8")
    import hashlib

    assert hash_patch(p) == hashlib.sha256(b"diff body").hexdigest()


async def test_list_cycles(ledger):
    await ledger.open_cycle("INC-1", "c-1")
    await ledger.open_cycle("INC-2", "c-2")
    cycles = await ledger.list_cycles()
    assert [c.cycle_id for c in cycles] == ["CYC-0001", "CYC-0002"]


# ---- CLI: the olive:remediate capability gate on approve ---------------------


def _cycle_args(config, db, **kw):
    return argparse.Namespace(command="cycle", config=str(config), db=str(db), **kw)


async def _seed_verified(db_path, patch_file):
    led = RemediationLedger(db_path)
    await led.open()
    try:
        cid = await _to_verified(led, patch_file)
    finally:
        await led.close()
    return cid


@pytest.fixture
def default_config():
    from pathlib import Path

    return Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


async def test_cli_approve_rejects_token_without_capability(tmp_path, patch_file, default_config):
    from olive.cli import run_cycle
    from olive.identity.tokens import MockCA

    db = tmp_path / "audit.db"
    cid = await _seed_verified(db, patch_file)
    ca = MockCA()
    pub = tmp_path / "ca.pem"
    pub.write_bytes(ca.public_key_pem())
    token = ca.issue(
        agent_id="ops-human",
        organization="demo",
        role="operator",
        session_id="s1",
        capabilities=["read_faq"],  # missing olive:remediate
    )
    args = _cycle_args(
        default_config, db, cycle_command="approve", cycle=cid, ca_pubkey=str(pub), token=token
    )
    rc = await run_cycle(args)
    assert rc == 1
    # state unchanged - the gate held
    led = RemediationLedger(db)
    await led.open()
    try:
        assert (await led.get(cid)).state is RemediationState.VERIFIED
    finally:
        await led.close()


async def test_cli_approve_accepts_remediate_token(tmp_path, patch_file, default_config):
    from olive.cli import REMEDIATE_SCOPE, run_cycle
    from olive.identity.tokens import MockCA

    db = tmp_path / "audit.db"
    cid = await _seed_verified(db, patch_file)
    ca = MockCA()
    pub = tmp_path / "ca.pem"
    pub.write_bytes(ca.public_key_pem())
    token = ca.issue(
        agent_id="ops-human",
        organization="demo",
        role="operator",
        session_id="s1",
        capabilities=[REMEDIATE_SCOPE],
    )
    args = _cycle_args(
        default_config, db, cycle_command="approve", cycle=cid, ca_pubkey=str(pub), token=token
    )
    rc = await run_cycle(args)
    assert rc == 0
    led = RemediationLedger(db)
    await led.open()
    try:
        cycle = await led.get(cid)
        assert cycle.state is RemediationState.APPROVED
        assert cycle.approved_by == "ops-human"
    finally:
        await led.close()


async def test_cli_approve_rejects_token_from_wrong_ca(tmp_path, patch_file, default_config):
    """A token signed by a different CA (or otherwise malformed) is rejected by
    the CLI's own fail-closed branch, leaving the cycle unchanged."""
    from olive.cli import REMEDIATE_SCOPE, run_cycle
    from olive.identity.tokens import MockCA

    db = tmp_path / "audit.db"
    cid = await _seed_verified(db, patch_file)
    signer, other = MockCA(), MockCA()
    pub = tmp_path / "ca.pem"
    pub.write_bytes(other.public_key_pem())  # verify against the WRONG key
    token = signer.issue(
        agent_id="ops-human",
        organization="demo",
        role="operator",
        session_id="s1",
        capabilities=[REMEDIATE_SCOPE],
    )
    args = _cycle_args(
        default_config, db, cycle_command="approve", cycle=cid, ca_pubkey=str(pub), token=token
    )
    assert await run_cycle(args) == 1
    led = RemediationLedger(db)
    await led.open()
    try:
        assert (await led.get(cid)).state is RemediationState.VERIFIED
    finally:
        await led.close()


async def test_cli_learn_returns_nonzero_when_baseline_update_fails(
    tmp_path, patch_file, default_config, monkeypatch
):
    """The cycle reaches LEARNED (approval passed), but if the baseline re-pin
    subprocess fails, the CLI exits non-zero so automation re-runs it."""
    import olive.cli as cli

    db = tmp_path / "audit.db"
    led = RemediationLedger(db)
    await led.open()
    try:
        cid = await _to_verified(led, patch_file)
        await led.approve(cid, approved_by="ops-human")
    finally:
        await led.close()

    monkeypatch.setattr(cli, "_run_eval_gate", lambda *a, **k: (1, None))
    args = _cycle_args(default_config, db, cycle_command="learn", cycle=cid)
    assert await cli.run_cycle(args) == 1

    led = RemediationLedger(db)
    await led.open()
    try:
        assert (await led.get(cid)).state is RemediationState.LEARNED
    finally:
        await led.close()
