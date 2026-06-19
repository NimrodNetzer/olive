"""Self-protection inspector — hardcoded gateway-manipulation detection (ADR-0026).

Catches inbound content that attempts to manipulate Olive's OWN operation:
modifying the allowlist, disabling inspection, overriding policies, etc.
These patterns are hardcoded — not config-driven — so they cannot be neutered
by an attacker who also tampers with the policy YAML.

Runs BEFORE PatternInspector in the pipeline so that a tampered policy file
with all injection_patterns removed still catches gateway-directed content.
Rule prefix: self_protect.
"""

from __future__ import annotations

from olive.gateway.context import Direction, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict, bound_evidence
from olive.inspectors.patterns import find_trigger, normalize

# Phrases that specifically target Olive's own enforcement layer.
# These are deliberately minimal and high-precision — not a catch-all list.
# The existing injection_patterns in policy YAML handle general agent manipulation.
_GATEWAY_MANIPULATION_PHRASES: list[str] = [
    # Explicit policy bypass attempts
    "ignore your security policy",
    "bypass your security policy",
    "disable your security policy",
    "override your security policy",
    "ignore security policy",
    # Tool allowlist manipulation
    "add to allowed_tools",
    "add to your allowed tools",
    "modify your allowed tools",
    "remove from forbidden_tools",
    "remove from your forbidden tools",
    # Inspection bypass
    "disable inspection",
    "bypass inspection",
    "disable olive",
    "bypass olive",
    "ignore olive",
    "override olive",
    # Gateway override
    "bypass gateway",
    "override gateway",
    "disable gateway",
    # Policy override
    "override your policy",
    "bypass your policy",
    "disable your policy",
    "ignore your policy",
]

# Pre-normalize patterns once at import time.
_NORMALIZED_PHRASES: list[str] = [normalize(p) for p in _GATEWAY_MANIPULATION_PHRASES]


class SelfProtectInspector:
    """Inbound inspector: blocks tool responses that attempt to manipulate
    Olive's own enforcement layer. Patterns are hardcoded (not config-driven)."""

    name = "self_protect"
    directions: frozenset[Direction] = frozenset({"inbound"})

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        if not content:
            return ALLOW
        match = find_trigger(normalize(content), _NORMALIZED_PHRASES)
        if match is None:
            return ALLOW
        pattern, excerpt = match
        return Verdict(
            Decision.BLOCK,
            rule="self_protect.gateway_manipulation",
            evidence=bound_evidence(f"matched '{pattern}' in: ...{excerpt}..."),
        )
