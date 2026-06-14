"""Resource extraction - the structured target of a tool call (ADR-0010).

A tool whose policy declares a resource extractor has the *scoping identifier*
of its target pulled from a named argument into a `ResourceRef`. Only that one
declared identifier is read - never the rest of the payload, and never any
value beyond the scoping key (CLAUDE.md rule 3). When the id is itself
sensitive, the extractor hashes it (`hash_id`) so predicates can only test
equality, never substring.

This module is pure: it sees raw arguments at the proxy boundary for the single
purpose of lifting the declared scoping id, and returns a `ResourceRef` that
carries non-secret labels plus that one id (optionally hashed). The raw
arguments themselves never leave the boundary.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from olive.gateway.context import ResourceRef


@dataclass(frozen=True, slots=True)
class ResourceExtractor:
    """Declares how to lift a resource reference from one tool's arguments.

    `type`/`classification` are non-secret labels attached to the ref.
    `id_arg` names the single argument that carries the scoping id. `hash_id`
    pre-hashes that id when it is itself sensitive.
    """

    type: str
    id_arg: str
    classification: str | None = None
    hash_id: bool = False

    def extract(self, arguments: dict[str, Any] | None) -> ResourceRef:
        raw = (arguments or {}).get(self.id_arg)
        # A declared scoping arg that is absent yields an empty id: predicates
        # that require a matching id will then fail closed, which is correct -
        # a call to a scoped tool with no scope is not authorized by default.
        scope = "" if raw is None else str(raw)
        if self.hash_id and scope:
            scope = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        return ResourceRef(
            type=self.type,
            id=scope,
            classification=self.classification,
            id_hashed=self.hash_id,
        )


def extract_resource(
    tool: str,
    extractors: dict[str, ResourceExtractor],
    arguments: dict[str, Any] | None,
) -> ResourceRef | None:
    """Return the structured resource for `tool`, or None when no extractor is
    declared for it (then contextual resource predicates simply do not match
    and authorization falls back to the coarse allowlist)."""
    extractor = extractors.get(tool)
    if extractor is None:
        return None
    return extractor.extract(arguments)
