"""IdentityClaims tests - identity is verified, not asserted (ADR-0007)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from olive.identity.claims import (
    IdentityClaims,
    claims_from_token,
    unverified_from_config,
)
from olive.identity.tokens import IdentityError, MockCA


@pytest.fixture(scope="module")
def ca() -> MockCA:
    return MockCA()


def issue(ca: MockCA, **overrides) -> str:
    defaults = dict(
        agent_id="support-agent",
        organization="demo-company",
        role="customer-support",
        session_id="sess-abc",
        capabilities=["read_faq", "search_kb"],
    )
    defaults.update(overrides)
    return ca.issue(**defaults)


def test_verified_token_maps_to_claims(ca):
    claims = claims_from_token(issue(ca), ca.public_key_pem())
    assert claims.agent_id == "support-agent"
    assert claims.organization == "demo-company"
    assert claims.role == "customer-support"
    assert claims.session_id == "sess-abc"
    assert claims.capabilities == ("read_faq", "search_kb")
    assert claims.verified is True


def test_forged_token_is_rejected(ca):
    other = MockCA()
    with pytest.raises(IdentityError):
        claims_from_token(issue(ca), other.public_key_pem())


def test_expired_token_is_rejected(ca):
    token = issue(ca, ttl=timedelta(seconds=-5))
    with pytest.raises(IdentityError):
        claims_from_token(token, ca.public_key_pem())


def test_token_without_role_is_rejected(ca):
    # role is required: it selects the policy, so it must be attested
    token = issue(ca, role="")
    with pytest.raises(IdentityError):
        claims_from_token(token, ca.public_key_pem())


def test_missing_session_id_gets_generated(ca):
    token = issue(ca, session_id="")
    claims = claims_from_token(token, ca.public_key_pem())
    assert claims.session_id.startswith("sess-")


def test_config_fallback_is_marked_unverified():
    claims = unverified_from_config("agent-x", "org-y", "customer-support")
    assert claims.verified is False
    assert claims.agent_id == "agent-x"
    assert isinstance(claims, IdentityClaims)
    assert claims.session_id.startswith("sess-")


def test_session_key_namespaces_by_org_and_agent():
    # same session_id, different agent/org => different containment keys
    a = IdentityClaims(agent_id="a", organization="o1", role="r", session_id="sess-1")
    b = IdentityClaims(agent_id="b", organization="o1", role="r", session_id="sess-1")
    c = IdentityClaims(agent_id="a", organization="o2", role="r", session_id="sess-1")
    assert a.session_key != b.session_key
    assert a.session_key != c.session_key
    # identical triples => identical key (stable)
    again = IdentityClaims(agent_id="a", organization="o1", role="x", session_id="sess-1")
    assert a.session_key == again.session_key
