"""Agent identity tokens - mock CA, real cryptography.

A local RSA keypair stands in for a real certificate authority, but the
JWTs are real RS256: signature, expiry, and audience are actually verified,
and the algorithm is pinned (no 'alg' confusion). Identity is therefore
cryptographically bound from day one; what is mocked is only the trust
root, not the crypto.

Wire enforcement lands with the HTTP transport (M2, see ROADMAP.md). In
stdio mode the gateway is configured per-agent via the policy file.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_ALGORITHM = "RS256"
_AUDIENCE = "olive-gateway"


class IdentityError(Exception):
    """Token could not be verified. Callers must treat this as block."""


class MockCA:
    """Local issuing authority for demo/test agent identities."""

    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def issue(
        self,
        agent_id: str,
        organization: str,
        role: str,
        session_id: str,
        capabilities: list[str],
        task_resources: list[str] | None = None,
        ttl: timedelta = timedelta(hours=1),
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": agent_id,
            "org": organization,
            "role": role,
            "session_id": session_id,
            "capabilities": capabilities,
            "task_resources": task_resources or [],
            "aud": _AUDIENCE,
            "iat": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,  # unique token ID for revocation (M9)
        }
        return jwt.encode(payload, self._private_key, algorithm=_ALGORITHM)


def verify_token(token: str, public_key_pem: bytes) -> dict[str, Any]:
    """Verify signature, expiry, and audience. Algorithm is pinned to RS256."""
    try:
        return jwt.decode(
            token,
            public_key_pem,
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
            options={"require": ["exp", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise IdentityError(f"token verification failed: {type(exc).__name__}") from exc


class RevokedTokenCache:
    """In-memory token revocation list (M9 — Siege Crisis Response).

    Kept in memory for fast synchronous lookup during token verification.
    Backed by the event store's `revoked_tokens` table for persistence across
    restarts. The store write is done by the caller (admin endpoint or commander);
    this cache provides the sync lookup the verifier needs without async I/O.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def seed(self, jtis: list[str]) -> None:
        """Populate from the DB on startup."""
        self._revoked.update(jtis)

    def revoke(self, jti: str) -> None:
        """Add a jti to the in-memory revocation set."""
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked
