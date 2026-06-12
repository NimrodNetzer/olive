"""Policy inspector - outbound tool-call authorization, default deny.

A tool is allowed only if it appears in the role's allowed_tools. Forbidden
listings exist for explicitness and clearer audit rules, but an unknown tool
is blocked regardless (default deny).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from olive.gateway.context import Direction, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict


@dataclass(frozen=True, slots=True)
class RolePolicy:
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    forbidden_tools: frozenset[str] = field(default_factory=frozenset)


class PolicyInspector:
    name = "policy"
    directions: frozenset[Direction] = frozenset({"outbound"})

    def __init__(self, roles: dict[str, RolePolicy]) -> None:
        self._roles = dict(roles)

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        role = self._roles.get(ctx.role)
        if role is None:
            return Verdict(
                Decision.BLOCK,
                rule="policy.unknown_role",
                evidence=f"no policy defined for role '{ctx.role}'",
            )
        if ctx.tool in role.forbidden_tools:
            return Verdict(
                Decision.BLOCK,
                rule="policy.forbidden_tool",
                evidence=f"tool '{ctx.tool}' is explicitly forbidden for role '{ctx.role}'",
            )
        if ctx.tool not in role.allowed_tools:
            return Verdict(
                Decision.BLOCK,
                rule="policy.not_allowed",
                evidence=f"tool '{ctx.tool}' is not in allowed_tools for role '{ctx.role}'",
            )
        return ALLOW
