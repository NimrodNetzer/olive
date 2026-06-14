"""The advisory sentinels (M6, ADR-0012). Each consumes a TelemetryEvent and
returns a Signal - evidence only, never an enforcement decision (ADR-0005).

- PromptInjectionSentinel (inbound): deterministic-first, then Claude semantic.
- DataLeakSentinel (outbound): exfiltration indicators in call arguments.
- BehaviorSentinel (outbound): read -> egress chain across the session sequence.

All three are fail-safe: any error or missing input yields Signal.none. None of
them ever raises into the runner.
"""

from __future__ import annotations

import json
import re
from typing import Protocol, runtime_checkable

from olive.gateway.context import Direction
from olive.gateway.telemetry import TelemetryEvent
from olive.inspectors.decode import deterministic_trigger
from olive.inspectors.patterns import normalize
from olive.intelligence.client import SemanticAnalyzer
from olive.intelligence.signals import Signal


@runtime_checkable
class Sentinel(Protocol):
    name: str
    directions: frozenset[Direction]

    async def analyze(self, event: TelemetryEvent) -> Signal: ...


class PromptInjectionSentinel:
    """Deterministic-first prompt-injection detection. A known trigger (plain or
    obfuscated) yields a high-confidence signal with no LLM call; only otherwise
    is the Claude semantic analyzer consulted, and its verdict is still advisory."""

    name = "prompt-injection"
    directions: frozenset[Direction] = frozenset({"inbound"})

    def __init__(
        self,
        patterns: list[str],
        analyzer: SemanticAnalyzer | None = None,
        min_confidence: float = 0.7,
    ) -> None:
        self._patterns = [normalize(p) for p in patterns if p.strip()]
        self._analyzer = analyzer or SemanticAnalyzer()
        self._min_confidence = min_confidence

    async def analyze(self, event: TelemetryEvent) -> Signal:
        content = event.content
        if not content:
            return Signal.none(self.name)
        det = deterministic_trigger(content, self._patterns)
        if det is not None:
            transform, pattern, excerpt = det
            return Signal.fire(
                self.name,
                confidence=1.0,
                evidence=f"deterministic trigger '{pattern}' ({transform}): ...{excerpt}...",
                attack_type="prompt-injection",
            )
        detected, confidence, rationale = await self._analyzer.classify(
            content, event.ctx.role, event.ctx.declared_goal
        )
        if detected and confidence >= self._min_confidence:
            return Signal.fire(
                self.name,
                confidence=confidence,
                evidence=f"semantic: {rationale}",
                attack_type="prompt-injection",
            )
        return Signal.none(self.name)


# Known secret shapes + a generic high-entropy assignment. Deterministic, bounded.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("openai-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("credential-field", re.compile(r"(?i)(password|api[_-]?key|secret|token)\s*[=:]\s*\S{6,}")),
]
# Exfiltration = an egress verb aimed at a destination outside the conversation.
_EGRESS_VERB = re.compile(r"(?i)\b(send|post|upload|exfiltrate|forward|email|leak|transmit)\b")
_EXTERNAL_DEST = re.compile(r"(?i)(https?://|@[\w.-]+\.\w+|webhook|pastebin|\b\d+\.\d+\.\d+\.\d+\b)")


class DataLeakSentinel:
    """Scans outbound call arguments (in memory only - rule 3) for secrets being
    moved and for egress-to-external-destination patterns."""

    name = "data-leak"
    directions: frozenset[Direction] = frozenset({"outbound"})

    async def analyze(self, event: TelemetryEvent) -> Signal:
        if not event.arguments:
            return Signal.none(self.name)
        try:
            blob = json.dumps(event.arguments, default=str)
        except (TypeError, ValueError):
            return Signal.none(self.name)
        for label, pattern in _SECRET_PATTERNS:
            m = pattern.search(blob)
            if m:
                return Signal.fire(
                    self.name,
                    confidence=0.9,
                    evidence=f"{label} present in outbound arguments",
                    attack_type="data-exfiltration",
                )
        if _EGRESS_VERB.search(blob) and _EXTERNAL_DEST.search(blob):
            return Signal.fire(
                self.name,
                confidence=0.6,
                evidence="egress verb + external destination in outbound arguments",
                attack_type="data-exfiltration",
            )
        return Signal.none(self.name)


_SENSITIVE_TOOLS = ("secret", "credential", "password", "database", "customer", "payroll", "ssn")
_EGRESS_TOOLS = ("send", "email", "upload", "post", "webhook", "exfil", "external", "http")


class BehaviorSentinel:
    """Session-sequence drift: a sensitive read earlier in the session followed by
    an egress tool now is the classic read -> exfiltrate chain that no single
    message reveals. Substring sets are configurable; confidence is modest because
    behavioral inference is soft (advisory by design)."""

    name = "behavior"
    directions: frozenset[Direction] = frozenset({"outbound"})

    def __init__(
        self,
        sensitive_tools: tuple[str, ...] = _SENSITIVE_TOOLS,
        egress_tools: tuple[str, ...] = _EGRESS_TOOLS,
    ) -> None:
        self._sensitive = sensitive_tools
        self._egress = egress_tools

    def _is(self, tool: str, needles: tuple[str, ...]) -> bool:
        low = tool.lower()
        return any(n in low for n in needles)

    async def analyze(self, event: TelemetryEvent) -> Signal:
        tool = event.ctx.tool
        if not self._is(tool, self._egress):
            return Signal.none(self.name)
        history = event.ctx.session_tool_history
        prior_sensitive = [t for t in history if self._is(t, self._sensitive)]
        if not prior_sensitive:
            return Signal.none(self.name)
        return Signal.fire(
            self.name,
            confidence=0.6,
            evidence=(
                f"egress tool '{tool}' after sensitive read(s) "
                f"{prior_sensitive[:3]} in this session"
            ),
            attack_type="suspicious-sequence",
        )
