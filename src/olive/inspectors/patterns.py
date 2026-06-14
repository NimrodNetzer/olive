"""Pattern inspector - deterministic injection-phrase matching. LAYER ZERO.

This catches only verbatim known trigger phrases (case- and whitespace-
insensitive). It is trivially bypassed by encoding, paraphrase, or language
switching - that is documented in THREAT_MODEL.md and measured honestly by
the eval corpus. Its job is to be fast, free, and the floor that smarter
layers (the M6 DecodeInspector and the semantic sentinels) are measured
against. It must never be presented as the detection story.

`normalize` and `find_trigger` are shared with `decode.py` (layer 0.5), which
re-runs the same matcher over decoded/normalized views of the same content.
"""

from __future__ import annotations

import re
import unicodedata

from olive.gateway.context import Direction, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict, bound_evidence

_EVIDENCE_WINDOW = 40


def normalize(text: str) -> str:
    """NFKC folds fullwidth/compatibility forms; format characters (Cf:
    zero-width spaces, joiners, BiDi controls) are stripped so they cannot
    split a trigger phrase. Homoglyph substitution (e.g. Cyrillic lookalikes)
    is NOT covered here - that is the DecodeInspector's job (layer 0.5).
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", folded.lower())


def find_trigger(haystack: str, patterns: list[str]) -> tuple[str, str] | None:
    """Search an already-normalized haystack for any already-normalized pattern.
    Returns (matched_pattern, bounded_excerpt) on the first hit, else None. The
    excerpt is only the matched region (rule 3) - never the whole payload."""
    for pattern in patterns:
        index = haystack.find(pattern)
        if index != -1:
            start = max(0, index - _EVIDENCE_WINDOW)
            end = index + len(pattern) + _EVIDENCE_WINDOW
            return pattern, haystack[start:end]
    return None


class PatternInspector:
    name = "patterns"
    directions: frozenset[Direction] = frozenset({"inbound"})

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = [normalize(p) for p in patterns if p.strip()]

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        if not content:
            return ALLOW
        match = find_trigger(normalize(content), self._patterns)
        if match is None:
            return ALLOW
        pattern, excerpt = match
        return Verdict(
            Decision.BLOCK,
            rule="patterns.injection",
            evidence=bound_evidence(f"matched '{pattern}' in: ...{excerpt}..."),
        )
