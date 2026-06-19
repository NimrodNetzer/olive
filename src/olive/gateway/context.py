"""SecurityContext - the object every enforcement decision reasons about.

One frozen context is built per inspected message (outbound tool call or
inbound tool response). Raw arguments never enter the context: only their
SHA-256 hash (CLAUDE.md rule 3).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

Direction = Literal["outbound", "inbound"]
TrustLevel = Literal["trusted", "untrusted"]


def hash_arguments(arguments: dict[str, Any] | None) -> str:
    """Canonical SHA-256 of tool arguments. The raw values are never stored."""
    canonical = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """The structured target of a tool call, for contextual authorization
    (ADR-0010). Only the *scoping identifier* of a resource enters the
    context - never the payload (CLAUDE.md rule 3).

    `type`/`classification` are non-secret labels (e.g. "order", "customer-pii").
    `id` is a non-secret scoping key (an order number, a file-path label). When
    the scoping id is itself sensitive, the extractor pre-hashes it and sets
    `id_hashed`; predicates may then only test equality, never substring.
    """

    type: str
    id: str
    classification: str | None = None
    id_hashed: bool = False


@dataclass(frozen=True, slots=True)
class SecurityContext:
    agent_id: str
    session_id: str
    organization_id: str
    role: str
    declared_goal: str
    tool: str
    arguments_hash: str
    direction: Direction
    call_number: int
    session_tool_history: tuple[str, ...]
    source_trust: TrustLevel
    timestamp: str
    # The structured target of the call, when the policy declares a resource
    # extractor for this tool (ADR-0010). None when no extractor applies - then
    # contextual resource predicates simply do not match, and authorization
    # falls back to the coarse allowlist. Never carries raw argument payloads.
    requested_resource: ResourceRef | None = None
    # Capabilities carried in the agent's identity token (ADR-0007, ADR-0028).
    # CapabilityInspector enforces per-tool required_capabilities against this set.
    capabilities: tuple[str, ...] = ()
    # Resource ids the current task is scoped to (from the attested identity,
    # ADR-0010). Explicit task binding: a resource rule checks the requested
    # resource id against this set.
    task_resources: tuple[str, ...] = ()

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat()
