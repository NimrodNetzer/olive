"""Decode inspector - deterministic obfuscation defeat. LAYER 0.5.

Layer zero (`patterns.py`) only sees verbatim trigger phrases. This inspector
runs right after it and defeats the *deterministic* obfuscations a layer-zero
matcher misses: homoglyph substitution, base64 / hex / rot13 / percent-encoding.
It derives a bounded set of decoded "views" of the same inbound content and
re-runs the exact same trigger matcher over each view. A hit is a deterministic
BLOCK (it enforces inline - ADR-0012), with evidence naming the transform and
only the matched region (rule 3).

It is NOT semantic: a paraphrase with no trigger phrase still slips past, and
that is the (advisory, parallel-path) PromptInjectionSentinel's job. Decoders are
deliberately conservative - a view is only scanned if it decodes to plausible
text - so the benign hard-negatives keep passing (the eval gate enforces this).
"""

from __future__ import annotations

import binascii
import codecs
import re
from base64 import b64decode
from collections.abc import Iterator
from urllib.parse import unquote

from olive.gateway.context import Direction, SecurityContext
from olive.gateway.pipeline import ALLOW, Decision, Verdict, bound_evidence
from olive.inspectors.patterns import find_trigger, normalize

# Common Cyrillic/Greek lookalikes -> ASCII. NFKC does not fold these (they are
# distinct letters, not compatibility forms), so a homoglyph attack survives
# layer zero. This table is intentionally small and targeted; it is a layer-0.5
# heuristic, not a complete Unicode confusables database.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "г": "r",
    # Greek
    "ο": "o", "ε": "e", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "υ": "u",
    "ι": "i", "κ": "k", "μ": "m", "χ": "x",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# A base64 run worth trying: >= 16 symbols so we don't decode short words like
# "test". Hex: >= 16 hex digits, even length. Both bounds keep noise down.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{16,}\b")

_MIN_PRINTABLE_RATIO = 0.8

# Cap the content fed to the (allocation-heavy) decode views so a giant hostile
# tool body cannot amplify CPU/memory on the inline fast path. Anything past the
# cap is still covered by the advisory PromptInjectionSentinel - the same
# truncation trade-off the semantic analyzer already makes (ADR-0012).
_MAX_DECODE_CHARS = 65536


def _is_plausible_text(text: str) -> bool:
    """A decoded blob is only worth scanning if it looks like text: non-empty and
    mostly printable. Garbage from a false-positive decode then never reaches the
    matcher (and would not match a trigger phrase anyway)."""
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return printable / len(text) >= _MIN_PRINTABLE_RATIO


def _decoded_views(content: str) -> Iterator[tuple[str, str]]:
    """Yield (transform_name, decoded_text) for every deterministic view of the
    content worth re-scanning. Each is best-effort and failure-silent: a decode
    that errors or yields implausible text simply yields nothing."""
    # Homoglyph fold: substitute lookalikes, then the normal matcher handles it.
    folded = content.translate(_CONFUSABLE_TABLE)
    if folded != content and _is_plausible_text(folded):
        yield "homoglyph", folded

    # rot13 over the whole body (only ASCII letters move). rot13 of benign prose
    # is gibberish; rot13 of a rot13'd payload reveals the trigger.
    rotated = codecs.encode(content, "rot_13")
    if rotated != content and _is_plausible_text(rotated):
        yield "rot13", rotated

    # percent / url decoding.
    unquoted = unquote(content)
    if unquoted != content and _is_plausible_text(unquoted):
        yield "url", unquoted

    # base64 runs - per run, plus a whitespace-stripped whole-body attempt for
    # payloads split across lines.
    seen: set[str] = set()
    candidates = list(_B64_RUN.findall(content))
    stripped = re.sub(r"\s+", "", content)
    if stripped not in candidates and _B64_RUN.fullmatch(stripped):
        candidates.append(stripped)
    for run in candidates:
        if run in seen:
            continue
        seen.add(run)
        try:
            raw = b64decode(run + "=" * (-len(run) % 4), validate=True)
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _is_plausible_text(text):
            yield "base64", text

    # hex runs.
    for run in _HEX_RUN.findall(content):
        if len(run) % 2:
            continue
        try:
            text = bytes.fromhex(run).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_plausible_text(text):
            yield "hex", text


def deterministic_trigger(
    content: str, normalized_patterns: list[str]
) -> tuple[str, str, str] | None:
    """Plain + every decoded view, in one call. Returns (transform, pattern,
    excerpt) on the first hit, else None. This is the deterministic-first stage
    the PromptInjectionSentinel runs before spending a Claude API call (ADR-0012):
    if a known trigger is already present (plain or obfuscated), no LLM is needed.
    """
    plain = find_trigger(normalize(content), normalized_patterns)
    if plain is not None:
        return ("plain", *plain)
    for transform, view in _decoded_views(content[:_MAX_DECODE_CHARS]):
        match = find_trigger(normalize(view), normalized_patterns)
        if match is not None:
            return (transform, *match)
    return None


class DecodeInspector:
    name = "decode"
    directions: frozenset[Direction] = frozenset({"inbound"})

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = [normalize(p) for p in patterns if p.strip()]

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict:
        if not content or not self._patterns:
            return ALLOW
        for transform, view in _decoded_views(content[:_MAX_DECODE_CHARS]):
            match = find_trigger(normalize(view), self._patterns)
            if match is not None:
                pattern, excerpt = match
                return Verdict(
                    Decision.BLOCK,
                    rule="decode.injection",
                    evidence=bound_evidence(
                        f"matched '{pattern}' after {transform} decode in: ...{excerpt}..."
                    ),
                )
        return ALLOW
