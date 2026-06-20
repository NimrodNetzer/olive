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
    is the Claude semantic analyzer consulted, and its verdict is still advisory.
    When an LLMContextSentinel is wired (ADR-0029), it runs after SemanticAnalyzer
    and reasons about the full session window rather than a single call."""

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
        self._llm_sentinel = None  # LLMContextSentinel | None; wired by departments.py

    @property
    def llm_enabled(self) -> bool:
        return self._analyzer.enabled

    @llm_enabled.setter
    def llm_enabled(self, value: bool) -> None:
        self._analyzer.enabled = value

    @property
    def llm_available(self) -> bool:
        return self._analyzer.available

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
        # Session-window LLM reasoning (ADR-0029): only when no deterministic or
        # per-call semantic signal fired. Advisory only — fail-safe on any error.
        if self._llm_sentinel is not None:
            excerpt = (content[:200] if content else "")
            ctx_det, ctx_conf, ctx_type, ctx_rat = await self._llm_sentinel.score(
                event.ctx.session_id,
                event.ctx.role,
                event.ctx.tool,
                excerpt,
            )
            if ctx_det and ctx_conf >= self._min_confidence:
                return Signal.fire(
                    self.name,
                    confidence=ctx_conf,
                    evidence=f"llm-context ({ctx_type}): {ctx_rat}",
                    attack_type=ctx_type or "prompt-injection",
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
    """Behavioral drift detection across sessions (M10/M11).

    Three complementary signals, all advisory (ADR-0005):

    1. Sequence (existing): sensitive read → egress in the same session.
    2. Call-rate anomaly (M11): current session call count is anomalously high
       compared to the agent's historical per-session average. A compromised agent
       being used to enumerate/exfiltrate at scale will hit this even if every
       individual call looks innocent.
    3. Novel-tool (M11): the agent calls a sensitive tool it has never used in any
       prior session. Normal agents have stable tool repertoires; a sudden first-
       ever call to a privileged tool is a meaningful deviation signal.

    Confidence is modest throughout because behavioral inference is soft — the
    sentinel advises, the deterministic breaker decides (ADR-0005).
    """

    name = "behavior"
    directions: frozenset[Direction] = frozenset({"outbound"})

    # Call-rate anomaly: trip signal when current session is this many times
    # above the agent's historical average (requires >= _MIN_SESSIONS_FOR_RATE).
    _RATE_MULTIPLIER = 5.0
    _MIN_SESSIONS_FOR_RATE = 3

    def __init__(
        self,
        sensitive_tools: tuple[str, ...] = _SENSITIVE_TOOLS,
        egress_tools: tuple[str, ...] = _EGRESS_TOOLS,
        cross_session_fn=None,       # Callable[[str, str], Awaitable[list[str]]] | None
        rate_baseline_fn=None,       # Callable[[str, str], Awaitable[list[int]]] | None
        known_tools_fn=None,         # Callable[[str, str], Awaitable[set[str]]] | None
    ) -> None:
        self._sensitive = sensitive_tools
        self._egress = egress_tools
        self._cross_session_fn = cross_session_fn
        self._rate_baseline_fn = rate_baseline_fn
        self._known_tools_fn = known_tools_fn

    def _is(self, tool: str, needles: tuple[str, ...]) -> bool:
        low = tool.lower()
        return any(n in low for n in needles)

    async def analyze(self, event: TelemetryEvent) -> Signal:
        tool = event.ctx.tool
        call_count = len(event.ctx.session_tool_history) + 1  # +1 for current call

        # ── Signal 1: call-rate anomaly ───────────────────────────────────────
        # Check BEFORE the egress gate so high-volume attacks on any tool fire it.
        if self._rate_baseline_fn is not None:
            try:
                counts = await self._rate_baseline_fn(
                    event.ctx.agent_id, event.ctx.organization_id
                )
                if len(counts) >= self._MIN_SESSIONS_FOR_RATE:
                    avg = sum(counts) / len(counts)
                    if avg > 0 and call_count >= self._RATE_MULTIPLIER * avg:
                        return Signal.fire(
                            self.name,
                            confidence=0.55,
                            evidence=(
                                f"call #{call_count} in session; agent historical "
                                f"average is {avg:.1f} calls/session "
                                f"({len(counts)} prior sessions)"
                            ),
                            attack_type="call-rate-anomaly",
                        )
            except Exception:  # noqa: BLE001
                pass

        # ── Signals 2 & 3 only fire on egress or sensitive tool calls ─────────
        if not (self._is(tool, self._egress) or self._is(tool, self._sensitive)):
            return Signal.none(self.name)

        # ── Signal 2: novel sensitive/egress tool ─────────────────────────────
        if self._known_tools_fn is not None:
            try:
                known = await self._known_tools_fn(
                    event.ctx.agent_id, event.ctx.organization_id
                )
                if known and tool not in known:
                    return Signal.fire(
                        self.name,
                        confidence=0.5,
                        evidence=(
                            f"'{tool}' is a sensitive/egress tool this agent "
                            f"has never used across {len(known)} known tools"
                        ),
                        attack_type="novel-tool",
                    )
            except Exception:  # noqa: BLE001
                pass

        # ── Signal 3a: sequence — within this session ─────────────────────────
        if self._is(tool, self._egress):
            history = event.ctx.session_tool_history
            prior_sensitive = [t for t in history if self._is(t, self._sensitive)]
            if prior_sensitive:
                return Signal.fire(
                    self.name,
                    confidence=0.6,
                    evidence=(
                        f"egress tool '{tool}' after sensitive read(s) "
                        f"{prior_sensitive[:3]} in this session"
                    ),
                    attack_type="suspicious-sequence",
                )

            # ── Signal 3b: sequence — across prior sessions ───────────────────
            if self._cross_session_fn is not None:
                try:
                    cross = await self._cross_session_fn(
                        event.ctx.agent_id, event.ctx.organization_id
                    )
                    prior_cross = [t for t in cross if self._is(t, self._sensitive)]
                    if prior_cross:
                        return Signal.fire(
                            self.name,
                            confidence=0.5,
                            evidence=(
                                f"egress tool '{tool}' after sensitive reads "
                                f"{prior_cross[:3]} in cross-session baseline history"
                            ),
                            attack_type="suspicious-sequence",
                        )
                except Exception:  # noqa: BLE001
                    pass

        return Signal.none(self.name)
