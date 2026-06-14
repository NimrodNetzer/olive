"""Contextual authorization inspector (ADR-0010).

Refines the coarse allowlist: it runs AFTER `PolicyInspector`, so it can only
further restrict (block) or pause (hold) a call the allowlist already permits -
never grant one it denied. Default-deny is unchanged.

Every predicate is a deterministic structured comparison over `SecurityContext`
fields (set membership, ordinal classification) - never a regex over arguments,
never an LLM signal (ADR-0005). A rule that references a resource for which no
extractor ran simply does not match, and the call passes to the next inspector.

A rule declares, per (role): the `tool` it governs, optional `when` conditions
that must all hold for it to apply, the `require` predicates that must all be
satisfied, and the `effect` (block or hold) applied when any requirement is not
met. `hold` is a governance pause (human approval), not an attack signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from olive.gateway.context import Direction, ResourceRef, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict

# Ordinal sensitivity, least -> most. An unknown label ranks above all known
# ones so a misconfigured/novel classification fails closed (treated as the
# most sensitive), never silently slips under a ceiling.
DEFAULT_CLASSIFICATIONS: tuple[str, ...] = (
    "public",
    "internal",
    "confidential",
    "customer-pii",
    "secret",
)


def _rank(classification: str | None, order: tuple[str, ...]) -> int:
    if classification is None:
        return -1
    try:
        return order.index(classification)
    except ValueError:
        return len(order)  # unknown -> most sensitive (fail closed)


@dataclass(frozen=True, slots=True)
class ContextRule:
    id: str
    tool: str | None = None  # None = any tool
    when: dict[str, str] = field(default_factory=dict)
    require: dict[str, str] = field(default_factory=dict)
    effect: Decision = Decision.BLOCK  # BLOCK or HOLD

    def applies_to(self, ctx: SecurityContext, res: ResourceRef | None) -> bool:
        if self.tool is not None and self.tool != ctx.tool:
            return False
        for key, expected in self.when.items():
            if key == "resource.type":
                if res is None or res.type != expected:
                    return False
            else:  # an unknown `when` key can never be satisfied -> rule inert
                return False
        return True


class ContextPolicyInspector:
    name = "context_policy"
    directions: frozenset[Direction] = frozenset({"outbound"})

    def __init__(
        self,
        rules_by_role: dict[str, tuple[ContextRule, ...]],
        classifications: tuple[str, ...] = DEFAULT_CLASSIFICATIONS,
    ) -> None:
        self._rules = {role: tuple(rules) for role, rules in rules_by_role.items()}
        self._order = classifications

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        res = ctx.requested_resource
        for rule in self._rules.get(ctx.role, ()):  # ordered; first failure wins
            if not rule.applies_to(ctx, res):
                continue
            unmet = self._first_unmet(rule, ctx, res)
            if unmet is not None:
                predicate, evidence = unmet
                return Verdict(
                    rule.effect,
                    rule=f"context.{rule.id}.{predicate}",
                    evidence=evidence,
                )
        return ALLOW

    def _first_unmet(
        self, rule: ContextRule, ctx: SecurityContext, res: ResourceRef | None
    ) -> tuple[str, str] | None:
        """Return (predicate_name, evidence) for the first requirement not met,
        or None when every requirement holds."""
        for predicate, expected in rule.require.items():
            evidence = self._check(predicate, expected, ctx, res)
            if evidence is not None:
                return predicate, evidence
        return None

    def _check(
        self, predicate: str, expected: str, ctx: SecurityContext, res: ResourceRef | None
    ) -> str | None:
        """None if the predicate is satisfied; otherwise a bounded evidence
        string describing the violation (never the raw payload)."""
        if predicate == "resource.id_in":
            if expected != "task.resources":
                return f"unsupported binding source '{expected}' (fail closed)"
            if res is None:
                return "rule requires a resource but none was extracted"
            # Compare as strings on both sides: the extractor string-normalizes
            # the resource id, but task_resources arrive from token/identity and
            # may be ints (unquoted YAML/JSON). Without this an integer task id
            # would never match its own string-normalized resource id and would
            # false-block the agent's own bound resource.
            allowed = {str(t) for t in ctx.task_resources}
            if res.id not in allowed:
                kind = "hashed id" if res.id_hashed else f"id '{res.id}'"
                return f"resource {res.type} {kind} is not in the task's allowed resources"
            return None

        if predicate == "resource.classification_max":
            # Fail closed when the rule requires a classification ceiling but no
            # resource was extracted: an unknown classification must never slip
            # under a ceiling (CLAUDE.md rule 4). Mirrors resource.id_in above.
            if res is None:
                return f"rule requires classification <= '{expected}' but no resource was extracted"
            ceiling = _rank(expected, self._order)
            actual = _rank(res.classification, self._order)
            if actual > ceiling:
                label = res.classification if res.classification else "unknown"
                return f"resource classification '{label}' exceeds ceiling '{expected}'"
            return None

        if predicate == "approval":
            # No inline approval state exists on the fast path: an approval
            # requirement is therefore never satisfied here and always yields
            # the rule's effect (hold). Release happens out-of-band, operator-
            # gated (ADR-0010) - never by this inspector, never by an LLM.
            return f"action requires {expected} approval"

        # Unknown predicate -> fail closed (treated as unmet).
        return f"unknown predicate '{predicate}' (fail closed)"
