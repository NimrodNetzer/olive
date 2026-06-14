"""Olive intelligence layer - the advisory parallel path (M6, ADR-0012).

This package is the open-core boundary's far side (ADR-0003): it imports from the
gateway core (telemetry events, the breaker, verdict/context types) but the
gateway core NEVER imports it. Sentinels here only ever produce signals; the
deterministic circuit breaker makes every enforcement decision (ADR-0005).
"""

from olive.intelligence.runner import SentinelRunner
from olive.intelligence.signals import Signal

__all__ = ["SentinelRunner", "Signal"]
