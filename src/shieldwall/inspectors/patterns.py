"""Pattern inspector - deterministic injection-phrase matching. LAYER ZERO.

This catches only verbatim known trigger phrases (case- and whitespace-
insensitive). It is trivially bypassed by encoding, paraphrase, or language
switching - that is documented in THREAT_MODEL.md and measured honestly by
the eval corpus. Its job is to be fast, free, and the floor that smarter
layers (M3 sentinels) are measured against. It must never be presented as
the detection story.
"""

from __future__ import annotations

import re
import unicodedata

from shieldwall.gateway.context import Direction, SecurityContext
from shieldwall.gateway.pipeline import ALLOW, Decision, Verdict, bound_evidence


def _normalize(text: str) -> str:
    """NFKC folds fullwidth/compatibility forms; format characters (Cf:
    zero-width spaces, joiners, BiDi controls) are stripped so they cannot
    split a trigger phrase. Homoglyph substitution (e.g. Cyrillic lookalikes)
    is NOT covered - that is a documented layer-zero limitation.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", folded.lower())


class PatternInspector:
    name = "patterns"
    directions: frozenset[Direction] = frozenset({"inbound"})

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = [_normalize(p) for p in patterns if p.strip()]

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        if not content:
            return ALLOW
        haystack = _normalize(content)
        for pattern in self._patterns:
            index = haystack.find(pattern)
            if index != -1:
                # Evidence: only the matched region, bounded - never the payload.
                excerpt = haystack[max(0, index - 40) : index + len(pattern) + 40]
                return Verdict(
                    Decision.BLOCK,
                    rule="patterns.injection",
                    evidence=bound_evidence(f"matched '{pattern}' in: ...{excerpt}..."),
                )
        return ALLOW
