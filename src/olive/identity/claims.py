"""IdentityClaims - the verified identity the gateway is built around (ADR-0007).

Transport-independent on purpose: HTTP supplies the token from a Bearer header,
stdio falls back to a config-derived unverified identity, but the rest of the
gateway only ever sees an `IdentityClaims`. No SDK/transport imports here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from olive.identity.tokens import IdentityError, verify_token


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    agent_id: str
    organization: str
    role: str
    session_id: str
    capabilities: tuple[str, ...] = ()
    # True only when these claims came from a cryptographically verified token.
    verified: bool = False


def _new_session_id() -> str:
    return f"sess-{uuid.uuid4().hex[:8]}"


def claims_from_token(token: str, public_key_pem: bytes) -> IdentityClaims:
    """Verify a signed token and map it to identity. Raises IdentityError on any
    verification failure - callers must treat that as fail-closed (refuse)."""
    payload = verify_token(token, public_key_pem)  # raises IdentityError
    role = payload.get("role")
    if not role:
        raise IdentityError("token is missing the required 'role' claim")
    return IdentityClaims(
        agent_id=payload["sub"],
        organization=payload.get("org", ""),
        role=role,
        session_id=payload.get("session_id") or _new_session_id(),
        capabilities=tuple(payload.get("capabilities", ())),
        verified=True,
    )


def unverified_from_config(
    agent_id: str, organization: str, role: str, session_id: str | None = None
) -> IdentityClaims:
    """Local-dev fallback when no token is presented (stdio). Marked unverified
    so it is never mistaken for an attested identity (ADR-0007)."""
    return IdentityClaims(
        agent_id=agent_id,
        organization=organization,
        role=role,
        session_id=session_id or _new_session_id(),
        capabilities=(),
        verified=False,
    )
