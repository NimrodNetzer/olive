from __future__ import annotations

from datetime import timedelta

import jwt as pyjwt
import pytest

from shieldwall.identity.tokens import IdentityError, MockCA, verify_token


@pytest.fixture(scope="module")
def ca() -> MockCA:
    return MockCA()


def issue(ca: MockCA, **overrides) -> str:
    defaults = dict(
        agent_id="support-agent",
        organization="demo-company",
        role="customer-support",
        session_id="sess-1",
        capabilities=["read_faq"],
    )
    defaults.update(overrides)
    return ca.issue(**defaults)


def test_roundtrip(ca):
    claims = verify_token(issue(ca), ca.public_key_pem())
    assert claims["sub"] == "support-agent"
    assert claims["role"] == "customer-support"
    assert claims["capabilities"] == ["read_faq"]


def test_expired_token_rejected(ca):
    token = issue(ca, ttl=timedelta(seconds=-10))
    with pytest.raises(IdentityError):
        verify_token(token, ca.public_key_pem())


def test_wrong_key_rejected(ca):
    other = MockCA()
    with pytest.raises(IdentityError):
        verify_token(issue(ca), other.public_key_pem())


def test_unsigned_token_rejected(ca):
    forged = pyjwt.encode(
        {"sub": "support-agent", "aud": "shieldwall-gateway"}, key="", algorithm="none"
    )
    with pytest.raises(IdentityError):
        verify_token(forged, ca.public_key_pem())


def test_tampered_payload_rejected(ca):
    header, payload, sig = issue(ca).split(".")
    import base64
    import json

    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["role"] = "admin"
    tampered_payload = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    with pytest.raises(IdentityError):
        verify_token(f"{header}.{tampered_payload}.{sig}", ca.public_key_pem())
