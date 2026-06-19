"""Tool-level capability enforcement inspector (ADR-0028).

Runs AFTER PolicyInspector (which grants by role) and BEFORE ContextPolicyInspector.
Refine-only: it can block a call the allowlist already permits, never grant one.

For each tool that declares `required_capabilities` in the policy, every listed
capability must appear in the calling agent's token capabilities. Missing any one
capability blocks the call (AND semantics). Tools with no declared requirements
are unaffected — the inspector is a no-op for them.
"""

from __future__ import annotations

from olive.gateway.context import Direction, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict


class CapabilityInspector:
    name = "capability"
    directions: frozenset[Direction] = frozenset({"outbound"})

    def __init__(self, tool_capabilities: dict[str, frozenset[str]]) -> None:
        self._requirements = dict(tool_capabilities)

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        required = self._requirements.get(ctx.tool)
        if not required:
            return ALLOW
        missing = required - set(ctx.capabilities)
        if missing:
            missing_str = ", ".join(sorted(missing))
            return Verdict(
                Decision.BLOCK,
                rule="policy.capability_missing",
                evidence=(
                    f"tool '{ctx.tool}' requires capabilities [{missing_str}]"
                    f" not present in token for role '{ctx.role}'"
                ),
            )
        return ALLOW
