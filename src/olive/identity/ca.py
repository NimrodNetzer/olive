"""Persistent certificate authority for Olive agent identity (real RS256).

The cryptography was always real (RS256 JWTs, pinned algorithm, audience
check). What this module adds is durable key management: generate a keypair
once, save it to disk, reuse it to issue tokens. The trust root is a local
RSA private key rather than a PKI hierarchy — identical security model to a
self-signed CA, which is appropriate for a local gateway or a single-org
deployment. A real enterprise PKI integration is a future ADR.

Directory layout (default: ~/.olive/ca/):
    ca.key    — RSA-2048 private key, PEM, readable only by owner (0600)
    ca.pub    — RSA public key, PEM, distributable (passed to --ca-pubkey)
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import jwt

_ALGORITHM = "RS256"
_AUDIENCE = "olive-gateway"
_DEFAULT_CA_DIR = Path.home() / ".olive" / "ca"


def default_ca_dir() -> Path:
    return _DEFAULT_CA_DIR


class CertificateAuthority:
    """A persistent RS256 CA backed by a keypair on disk.

    Use `CertificateAuthority.init(dir)` to generate a new keypair.
    Use `CertificateAuthority.load(dir)` to load an existing one.
    Use `.issue(...)` to mint agent identity tokens.
    Use `.public_key_path` to get the path to pass to `--ca-pubkey`."""

    def __init__(self, private_key, ca_dir: Path) -> None:
        self._private_key = private_key
        self._ca_dir = ca_dir

    @classmethod
    def init(cls, ca_dir: Path | None = None) -> "CertificateAuthority":
        """Generate a new RSA-2048 keypair and save to ca_dir.
        Raises FileExistsError if a keypair already exists there."""
        d = Path(ca_dir or _DEFAULT_CA_DIR)
        key_path = d / "ca.key"
        if key_path.exists():
            raise FileExistsError(
                f"CA keypair already exists at {d}. "
                "Delete it manually or use a different --dir if you want a new one."
            )
        d.mkdir(parents=True, exist_ok=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)
        (d / "ca.pub").write_bytes(pub_pem)
        return cls(private_key, d)

    @classmethod
    def load(cls, ca_dir: Path | None = None) -> "CertificateAuthority":
        """Load an existing keypair from ca_dir.
        Raises FileNotFoundError if not initialised yet."""
        d = Path(ca_dir or _DEFAULT_CA_DIR)
        key_path = d / "ca.key"
        if not key_path.exists():
            raise FileNotFoundError(
                f"No CA keypair found at {d}. Run `olive ca init` first."
            )
        key_pem = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        return cls(private_key, d)

    @property
    def public_key_path(self) -> Path:
        return self._ca_dir / "ca.pub"

    def public_key_pem(self) -> bytes:
        return self.public_key_path.read_bytes()

    def issue(
        self,
        agent_id: str,
        organization: str,
        role: str,
        session_id: str | None = None,
        capabilities: list[str] | None = None,
        task_resources: list[str] | None = None,
        ttl_hours: float = 24.0,
    ) -> str:
        """Mint a signed RS256 JWT for an agent. Returns the token string."""
        now = datetime.now(UTC)
        payload = {
            "sub": agent_id,
            "org": organization,
            "role": role,
            "session_id": session_id or uuid.uuid4().hex,
            "capabilities": capabilities or [],
            "task_resources": task_resources or [],
            "aud": _AUDIENCE,
            "iat": now,
            "exp": now + timedelta(hours=ttl_hours),
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(payload, self._private_key, algorithm=_ALGORITHM)
