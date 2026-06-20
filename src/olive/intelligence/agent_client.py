"""Shared LLM client for runtime agents (ADR-0029).

All three agents (LLMContextSentinel, LLMRedTeamAgent, LLMBuilderAgent) go
through this client. It provides:
  - Provider auto-detection: Anthropic → Groq (same priority as SemanticAnalyzer)
  - Per-minute + per-day token budget (advisory: over-budget → no-op)
  - Defensive response extraction
  - Fail-safe: any error → returns None
"""

from __future__ import annotations

import os
import time
from pathlib import Path

_GROQ_MODEL = "llama-3.3-70b-versatile"
_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


def _dotenv_keys() -> dict[str, str]:
    """Read key=value pairs from the nearest .env file without a library dep.
    Only keys absent from os.environ are returned — explicit env vars win."""
    for candidate in (Path.cwd() / ".env", Path(__file__).parents[4] / ".env"):
        try:
            result: dict[str, str] = {}
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip("\"'")
                if k and k not in os.environ:
                    result[k] = v
            return result
        except FileNotFoundError:
            continue
    return {}


class AgentLLMClient:
    """Rate-limited, fail-safe LLM client shared by the three runtime agents.

    `complete()` returns a raw string or None. Agents parse it themselves with
    defensive JSON parsing. None always means "no signal, continue."
    """

    def __init__(
        self,
        *,
        max_tokens_per_min: int = 5000,
        max_tokens_per_day: int = 50000,
        model: str | None = None,
    ) -> None:
        self._min_limit = max_tokens_per_min
        self._day_limit = max_tokens_per_day
        self._minute_window: list[tuple[float, int]] = []  # (monotonic_ts, tokens)
        self._day_used: int = 0
        self._client: object | None = None
        self._provider: str | None = None
        self._model: str = model or ""

        _extra = _dotenv_keys()

        # Anthropic first (same priority order as SemanticAnalyzer)
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or _extra.get("ANTHROPIC_API_KEY")
        if anthropic_key:
            try:
                import anthropic  # lazy: gateway core never needs the SDK
                self._client = anthropic.AsyncAnthropic(api_key=anthropic_key)
                self._provider = "anthropic"
                self._model = model or _ANTHROPIC_MODEL
                return
            except Exception:  # noqa: BLE001
                self._client = None

        # Fall back to Groq (free tier, OpenAI-compatible)
        groq_key = os.environ.get("GROQ_API_KEY") or _extra.get("GROQ_API_KEY")
        if groq_key:
            try:
                import openai  # lazy: optional dependency
                self._client = openai.AsyncOpenAI(
                    base_url="https://api.groq.com/openai/v1",
                    api_key=groq_key,
                )
                self._provider = "groq"
                self._model = model or _GROQ_MODEL
            except Exception:  # noqa: BLE001
                self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def provider(self) -> str | None:
        return self._provider

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 512,
    ) -> str | None:
        """Single completion. Returns None on any error or budget exceeded.
        Never raises. Caller must handle None as 'no signal'."""
        if not self.available:
            return None
        if self._over_budget(max_tokens):
            return None
        try:
            if self._provider == "groq":
                return await self._call_openai(system, user, max_tokens)
            return await self._call_anthropic(system, user, max_tokens)
        except Exception:  # noqa: BLE001
            return None

    def _over_budget(self, requested: int) -> bool:
        """Sliding window per-minute + cumulative per-day check.
        Reserves the budget on success (optimistic reservation)."""
        now = time.monotonic()
        # Evict entries older than 60 seconds
        self._minute_window = [
            (t, tok) for t, tok in self._minute_window if now - t < 60.0
        ]
        min_used = sum(tok for _, tok in self._minute_window)
        if min_used + requested > self._min_limit:
            return True
        if self._day_used + requested > self._day_limit:
            return True
        # Reserve
        self._minute_window.append((now, requested))
        self._day_used += requested
        return False

    async def _call_openai(self, system: str, user: str, max_tokens: int) -> str | None:
        resp = await self._client.chat.completions.create(  # type: ignore[union-attr]
            model=self._model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        try:
            return resp.choices[0].message.content  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return None

    async def _call_anthropic(self, system: str, user: str, max_tokens: int) -> str | None:
        resp = await self._client.messages.create(  # type: ignore[union-attr]
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        try:
            return next(
                b.text  # type: ignore[attr-defined]
                for b in resp.content  # type: ignore[attr-defined]
                if getattr(b, "type", None) == "text"
            )
        except (StopIteration, AttributeError):
            return None
