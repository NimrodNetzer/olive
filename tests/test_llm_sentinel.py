"""Tests for LLMContextSentinel (ADR-0029). All LLM calls are mocked — no real API."""

import pytest
import pytest_asyncio

from olive.intelligence.agent_client import AgentLLMClient
from olive.intelligence.llm_sentinel import LLMContextSentinel, _parse


# ── _parse unit tests ─────────────────────────────────────────────────────────

def test_parse_valid_attack():
    det, conf, atype, rat = _parse(
        '{"is_attack": true, "confidence": 0.92, "attack_type": "role-override", "rationale": "test"}'
    )
    assert det is True
    assert conf == pytest.approx(0.92)
    assert atype == "role-override"
    assert rat == "test"


def test_parse_no_attack():
    det, conf, atype, rat = _parse(
        '{"is_attack": false, "confidence": 0.1, "attack_type": "", "rationale": "benign"}'
    )
    assert det is False
    assert conf == pytest.approx(0.1)


def test_parse_none_input():
    assert _parse(None) == (False, 0.0, "", "")


def test_parse_empty_string():
    assert _parse("") == (False, 0.0, "", "")


def test_parse_malformed_json():
    assert _parse("not json") == (False, 0.0, "", "")


def test_parse_missing_required_key():
    # Missing is_attack
    assert _parse('{"confidence": 0.9, "attack_type": "x", "rationale": "y"}') == (False, 0.0, "", "")


def test_parse_wrong_types():
    # confidence is a string
    assert _parse('{"is_attack": true, "confidence": "high", "attack_type": "x", "rationale": "y"}') == (
        False, 0.0, "", ""
    )


def test_parse_confidence_out_of_range():
    # confidence > 1.0
    assert _parse('{"is_attack": true, "confidence": 1.5, "attack_type": "x", "rationale": "y"}') == (
        False, 0.0, "", ""
    )


def test_parse_optional_fields_missing():
    # attack_type and rationale are optional
    det, conf, atype, rat = _parse('{"is_attack": true, "confidence": 0.8}')
    assert det is True
    assert atype == ""
    assert rat == ""


# ── LLMContextSentinel behavioural tests ────────────────────────────────────

@pytest.mark.asyncio
async def test_no_signal_when_client_unavailable():
    class UnavailableClient:
        available = False
        provider = None

    sentinel = LLMContextSentinel(UnavailableClient())  # type: ignore[arg-type]
    det, conf, _, _ = await sentinel.score("sess-1", "support", "read_file", "test")
    assert not det
    assert conf == 0.0


@pytest.mark.asyncio
async def test_no_signal_on_llm_error():
    class BoomClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            raise RuntimeError("api down")

    sentinel = LLMContextSentinel(BoomClient())  # type: ignore[arg-type]
    det, conf, _, _ = await sentinel.score("sess-1", "support", "read_file", "test")
    assert not det  # fail-safe
    assert conf == 0.0


@pytest.mark.asyncio
async def test_injection_detected_from_llm_signal():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            return '{"is_attack": true, "confidence": 0.92, "attack_type": "role-override", "rationale": "test"}'

    sentinel = LLMContextSentinel(FakeClient())  # type: ignore[arg-type]
    det, conf, atype, rat = await sentinel.score("s", "support", "read_file", "excerpt")
    assert det
    assert conf == pytest.approx(0.92)
    assert atype == "role-override"
    assert rat == "test"


@pytest.mark.asyncio
async def test_no_signal_on_malformed_json():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            return "not json at all"

    sentinel = LLMContextSentinel(FakeClient())  # type: ignore[arg-type]
    det, conf, _, _ = await sentinel.score("s", "support", "read_file", "excerpt")
    assert not det
    assert conf == 0.0


@pytest.mark.asyncio
async def test_context_bounded_to_200_chars():
    """Excerpt passed to the LLM must be bounded to 200 chars."""
    received_prompts: list[str] = []

    class CapturingClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            received_prompts.append(user)
            return '{"is_attack": false, "confidence": 0.0, "attack_type": "", "rationale": ""}'

    sentinel = LLMContextSentinel(CapturingClient())  # type: ignore[arg-type]
    long_excerpt = "X" * 500
    await sentinel.score("s", "support", "read_file", long_excerpt)
    assert received_prompts
    # The excerpt in the prompt should not exceed 200 chars
    prompt = received_prompts[0]
    # The excerpt is bounded before being embedded: ...{excerpt[:200]}...
    assert "X" * 201 not in prompt


@pytest.mark.asyncio
async def test_store_history_used_in_context():
    """When a store is provided, its events are included in the context."""

    class FakeStore:
        async def recent_events(self, limit):
            return [
                {"session_id": "sess-1", "tool": "read_file", "decision": "allow"},
                {"session_id": "other-sess", "tool": "send_email", "decision": "block"},
            ]

    received_prompts: list[str] = []

    class CapturingClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            received_prompts.append(user)
            return '{"is_attack": false, "confidence": 0.0, "attack_type": "", "rationale": ""}'

    sentinel = LLMContextSentinel(CapturingClient(), store=FakeStore())  # type: ignore[arg-type]
    await sentinel.score("sess-1", "analyst", "read_file", "test excerpt")
    assert received_prompts
    prompt = received_prompts[0]
    # Only the matching session event should appear
    assert "read_file" in prompt
    # The other session's event should not appear
    assert "send_email" not in prompt


# ── Import sandbox test (ADR-0027) ───────────────────────────────────────────

def test_llm_sentinel_does_not_import_gateway():
    import sys
    import olive.intelligence.llm_sentinel as m
    # The module must not have pulled in the gateway enforcement layer
    mod_vars = {k: getattr(v, "__module__", "") for k, v in vars(m).items()}
    forbidden = ("olive.gateway.proxy", "olive.gateway.breaker")
    for attr, origin in mod_vars.items():
        for f in forbidden:
            assert not (origin == f or origin.startswith(f + ".")), (
                f"llm_sentinel attribute {attr!r} originates from forbidden {f!r}"
            )
