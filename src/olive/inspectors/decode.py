"""Decode inspector - deterministic obfuscation defeat. LAYER 0.5.

Layer zero (`patterns.py`) only sees verbatim trigger phrases. This inspector
runs right after it and defeats the *deterministic* obfuscations a layer-zero
matcher misses: homoglyph substitution, base64 / hex / rot13 / percent-encoding,
base32, base85, chunked/double-encoded base64, spaced hex, and HTML comments.
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
from base64 import b32decode, b64decode, b85decode
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
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "г": "r",
    # Cyrillic uppercase (NFKC leaves these as-is; .lower() maps Ѕ→ѕ, not s)
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X",
    "Ѕ": "S", "І": "I", "Ј": "J", "В": "B", "М": "M", "Т": "T",
    "Н": "H", "К": "K",
    # Greek lowercase
    "ο": "o", "ε": "e", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "υ": "u",
    "ι": "i", "κ": "k", "μ": "m", "χ": "x",
    # Greek uppercase
    "Α": "A", "Ε": "E", "Ο": "O", "Ρ": "P", "Ν": "N", "Τ": "T",
    "Υ": "Y", "Ι": "I", "Κ": "K", "Μ": "M", "Χ": "X",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# A base64 run worth trying: >= 16 symbols so we don't decode short words like
# "test". Hex: >= 16 hex digits, even length. Both bounds keep noise down.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Isolated base64 token: >= 8 chars, bounded by whitespace/start/end on both
# sides. The 8-char floor excludes common English words (which are mostly < 8
# chars and happen to use only base64-alphabet letters), preventing them from
# polluting the concatenated candidate when prose is mixed with chunked b64.
_B64_ISOLATED = re.compile(r"(?<!\S)[A-Za-z0-9+/]{8,}={0,2}(?!\S)")

# Base32: uppercase A-Z and digits 2-7 only.
_B32_RUN = re.compile(r"[A-Z2-7]{16,}={0,6}")

# Space-separated 2-digit hex bytes (xxd / wire-dump format).
_HEX_PAIR = re.compile(r"\b[0-9a-fA-F]{2}\b")

# Printable-ASCII run for base85: RFC 1924 alphabet is almost all of !–~.
# Length must be a multiple of 5 (b85 encodes 4 bytes → 5 chars).
_B85_RUN = re.compile(r"[!-~]{25,}")

# HTML/XML comment body extractor: captures the text INSIDE <!-- ... -->.
# The injection is inside the comment, so we scan the inner content as a view.
_HTML_COMMENT_INNER = re.compile(r"<!--(.*?)-->", re.DOTALL)

_MIN_PRINTABLE_RATIO = 0.8


def _caesar_shift(text: str, shift: int) -> str:
    """Rotate ASCII letters only by `shift` positions; non-letters unchanged."""
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)

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
    # Covers both lowercase AND uppercase Cyrillic/Greek confusables so that
    # capital-letter substitutions (e.g. Ѕ for S) are also caught.
    folded = content.translate(_CONFUSABLE_TABLE)
    if folded != content and _is_plausible_text(folded):
        yield "homoglyph", folded

    # rot13 over the whole body (only ASCII letters move). rot13 of benign prose
    # is gibberish; rot13 of a rot13'd payload reveals the trigger.
    rotated = codecs.encode(content, "rot_13")
    if rotated != content and _is_plausible_text(rotated):
        yield "rot13", rotated

    # rot47: rotates all printable ASCII (codepoints 33-126) by 47 positions mod
    # 94. Covers digits, punctuation, and symbols that rot13 leaves untouched.
    rot47 = "".join(
        chr((ord(c) - 33 + 47) % 94 + 33) if 33 <= ord(c) <= 126 else c
        for c in content
    )
    if rot47 != content and _is_plausible_text(rot47):
        yield "rot47", rot47

    # Caesar brute-force: try all 25 letter-only shifts. Shift 13 = rot13
    # (already yielded above); skip it to avoid a duplicate scan.
    for _shift in range(1, 26):
        if _shift == 13:
            continue
        shifted = _caesar_shift(content, _shift)
        if shifted != content:
            yield f"caesar{_shift}", shifted

    # percent / url decoding.
    unquoted = unquote(content)
    if unquoted != content and _is_plausible_text(unquoted):
        yield "url", unquoted

    # HTML comment inner content: injection hidden inside <!-- ... --> is
    # revealed by extracting and scanning each comment body as a separate view.
    for m in _HTML_COMMENT_INNER.finditer(content):
        inner = m.group(1).strip()
        if len(inner) >= 10 and _is_plausible_text(inner):
            yield "html-comment", inner

    # base64 — three paths:
    #   1. Contiguous run >= 16 chars (original behavior, catches most cases).
    #   2. Whitespace-stripped whole-body when the entire body is one run.
    #   3. Token-concat: concatenate isolated base64 tokens (>= 4 chars each,
    #      bounded by whitespace) to catch chunked/mixed payloads like
    #      "Data: SWdub3Jl IHByZXZp ..." where each chunk is < 16 chars.
    seen_b64: set[str] = set()
    candidates: list[str] = list(_B64_RUN.findall(content))
    stripped = re.sub(r"\s+", "", content)
    if stripped not in candidates and _B64_RUN.fullmatch(stripped):
        candidates.append(stripped)

    # Token-concat: pick up chunked base64 split by whitespace or mixed prose.
    isolated_tokens = _B64_ISOLATED.findall(content)
    if len(isolated_tokens) >= 3:
        concat = "".join(t.rstrip("=") for t in isolated_tokens)
        if len(concat) >= 16 and concat not in candidates:
            candidates.append(concat)

    for run in candidates:
        if run in seen_b64:
            continue
        seen_b64.add(run)
        try:
            raw = b64decode(run + "=" * (-len(run) % 4), validate=True)
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not _is_plausible_text(text):
            continue
        yield "base64", text
        # Second-pass: if the decoded text itself contains a base64 run, decode
        # one more layer to catch double-encoded payloads (e.g. base64(base64(x))).
        for inner_run in _B64_RUN.findall(text):
            if inner_run in seen_b64:
                continue
            seen_b64.add(inner_run)
            try:
                raw2 = b64decode(inner_run + "=" * (-len(inner_run) % 4), validate=True)
                text2 = raw2.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _is_plausible_text(text2):
                yield "double-base64", text2

    # hex runs (contiguous).
    for run in _HEX_RUN.findall(content):
        if len(run) % 2:
            continue
        try:
            text = bytes.fromhex(run).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_plausible_text(text):
            yield "hex", text

    # Spaced hex: space-separated 2-digit byte pairs (xxd / wire-dump format).
    # Requires at least 8 pairs (16 bytes) to avoid noise from short hex IDs.
    hex_pairs = _HEX_PAIR.findall(content)
    if len(hex_pairs) >= 8:
        concat_hex = "".join(hex_pairs)
        try:
            text = bytes.fromhex(concat_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            text = ""
        if _is_plausible_text(text):
            yield "hex-spaced", text

    # base32: uppercase A-Z and digits 2-7, padded to multiple of 8.
    for run in _B32_RUN.findall(content):
        padded = run + "=" * (-len(run) % 8)
        try:
            raw = b32decode(padded)
            text = raw.decode("utf-8")
        except Exception:
            continue
        if _is_plausible_text(text):
            yield "base32", text

    # base85 (RFC 1924 / git format): printable-ASCII run. Let b85decode raise
    # on invalid inputs rather than pre-filtering by length — the length-mod-5
    # rule does not always hold for all encoder implementations.
    for run in _B85_RUN.findall(content):
        try:
            raw = b85decode(run)
            text = raw.decode("utf-8")
        except Exception:
            continue
        if _is_plausible_text(text):
            yield "base85", text


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
