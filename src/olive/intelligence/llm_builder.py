"""LLM Builder Agent (ADR-0029).

Given a confirmed incident + reproduced corpus case, prompts an LLM to
propose a minimal YAML policy addition or new detection pattern.
Output is advisory data appended to the fix-proposed bus object.
Never auto-applied: the olive cycle approve gate is unchanged.
"""

from __future__ import annotations

import json

from olive.intelligence.agent_client import AgentLLMClient

_SYSTEM = """You are a security policy engineer. You are given:
1. A confirmed attack incident (evidence excerpt ≤200 chars, attack type).
2. The reproduced corpus case that triggered it.

Propose the MINIMAL policy change to block this attack class without
over-blocking legitimate traffic. Be specific: if a YAML pattern, write
the exact YAML block. If a rule, write the exact role rule.

Respond ONLY with JSON:
{
  "patch_type": "pattern" or "role_rule" or "context_rule",
  "yaml_snippet": string,
  "rationale": string,
  "false_positive_risk": "low" or "medium" or "high"
}

yaml_snippet must be ≤300 chars. rationale must be ≤200 chars.
"""

_VALID_PATCH_TYPES = frozenset({"pattern", "role_rule", "context_rule"})
_VALID_FP_RISKS = frozenset({"low", "medium", "high"})


class LLMBuilderAgent:
    """Patch-proposal agent for the builder department (ADR-0029)."""

    def __init__(self, client: AgentLLMClient) -> None:
        self._client = client

    async def propose(
        self,
        evidence_excerpt: str,  # ≤200 chars, CLAUDE.md rule 3
        attack_type: str,
        corpus_case_id: str,
    ) -> dict | None:
        """Return a patch proposal dict, or None on any failure."""
        if not self._client.available:
            return None
        try:
            prompt = (
                f"Incident evidence (excerpt): {evidence_excerpt[:200]}\n"
                f"Attack type: {attack_type}\n"
                f"Reproduced corpus case: {corpus_case_id}"
            )
            raw = await self._client.complete(_SYSTEM, prompt, max_tokens=400)
            return _parse_proposal(raw)
        except Exception:  # noqa: BLE001 — fail-safe: any error → no proposal
            return None


def _parse_proposal(raw: str | None) -> dict | None:
    """Defensive parse of LLM JSON proposal. Any deviation → None."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        patch_type = data.get("patch_type", "")
        yaml_snippet = data.get("yaml_snippet", "")
        rationale = data.get("rationale", "")
        fp_risk = data.get("false_positive_risk", "")
        if patch_type not in _VALID_PATCH_TYPES:
            return None
        if not isinstance(yaml_snippet, str) or not isinstance(rationale, str):
            return None
        if fp_risk not in _VALID_FP_RISKS:
            return None
        return {
            "patch_type": patch_type,
            "yaml_snippet": str(yaml_snippet)[:300],
            "rationale": str(rationale)[:200],
            "false_positive_risk": fp_risk,
        }
    except (ValueError, TypeError):
        return None
