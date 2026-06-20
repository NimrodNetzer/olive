"""Tests for LLMBuilderAgent (ADR-0029). All LLM calls are mocked — no real API."""

import json
import pytest

from olive.intelligence.agent_client import AgentLLMClient
from olive.intelligence.llm_builder import LLMBuilderAgent, _parse_proposal


# ── _parse_proposal unit tests ────────────────────────────────────────────────

def test_parse_valid_proposal():
    raw = json.dumps({
        "patch_type": "pattern",
        "yaml_snippet": "injection_patterns:\n  - 'ignore above'",
        "rationale": "blocks the role-override class",
        "false_positive_risk": "low",
    })
    result = _parse_proposal(raw)
    assert result is not None
    assert result["patch_type"] == "pattern"
    assert result["false_positive_risk"] == "low"
    assert "ignore above" in result["yaml_snippet"]


def test_parse_role_rule_type():
    raw = json.dumps({
        "patch_type": "role_rule",
        "yaml_snippet": "roles:\n  analyst:\n    forbidden_tools: [send_email]",
        "rationale": "analyst should not send email",
        "false_positive_risk": "medium",
    })
    result = _parse_proposal(raw)
    assert result is not None
    assert result["patch_type"] == "role_rule"


def test_parse_context_rule_type():
    raw = json.dumps({
        "patch_type": "context_rule",
        "yaml_snippet": "context_rules:\n  - type: sequence",
        "rationale": "catch read-then-exfil chains",
        "false_positive_risk": "high",
    })
    assert _parse_proposal(raw) is not None


def test_parse_none_input():
    assert _parse_proposal(None) is None


def test_parse_empty_string():
    assert _parse_proposal("") is None


def test_parse_malformed_json():
    assert _parse_proposal("not json") is None


def test_parse_invalid_patch_type():
    raw = json.dumps({
        "patch_type": "unknown_type",
        "yaml_snippet": "...",
        "rationale": "...",
        "false_positive_risk": "low",
    })
    assert _parse_proposal(raw) is None


def test_parse_invalid_fp_risk():
    raw = json.dumps({
        "patch_type": "pattern",
        "yaml_snippet": "...",
        "rationale": "...",
        "false_positive_risk": "very-high",
    })
    assert _parse_proposal(raw) is None


def test_parse_not_a_dict():
    assert _parse_proposal('["not", "a", "dict"]') is None


def test_parse_truncates_yaml_snippet():
    raw = json.dumps({
        "patch_type": "pattern",
        "yaml_snippet": "X" * 500,
        "rationale": "r",
        "false_positive_risk": "low",
    })
    result = _parse_proposal(raw)
    assert result is not None
    assert len(result["yaml_snippet"]) <= 300


def test_parse_truncates_rationale():
    raw = json.dumps({
        "patch_type": "pattern",
        "yaml_snippet": "y",
        "rationale": "R" * 400,
        "false_positive_risk": "low",
    })
    result = _parse_proposal(raw)
    assert result is not None
    assert len(result["rationale"]) <= 200


# ── LLMBuilderAgent behavioural tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_returns_none_when_client_unavailable():
    class UnavailableClient:
        available = False
        provider = None

    agent = LLMBuilderAgent(UnavailableClient())  # type: ignore[arg-type]
    result = await agent.propose("evidence", "prompt-injection", "inj-0001")
    assert result is None


@pytest.mark.asyncio
async def test_returns_none_on_llm_error():
    class BoomClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            raise RuntimeError("api down")

    agent = LLMBuilderAgent(BoomClient())  # type: ignore[arg-type]
    result = await agent.propose("evidence", "prompt-injection", "inj-0001")
    assert result is None  # fail-safe


@pytest.mark.asyncio
async def test_returns_proposal_on_valid_response():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            return json.dumps({
                "patch_type": "pattern",
                "yaml_snippet": "injection_patterns:\n  - 'ignore above'",
                "rationale": "blocks role-override",
                "false_positive_risk": "low",
            })

    agent = LLMBuilderAgent(FakeClient())  # type: ignore[arg-type]
    result = await agent.propose("...ignore above...", "role-override", "inj-0041")
    assert result is not None
    assert result["patch_type"] == "pattern"
    assert result["false_positive_risk"] == "low"


@pytest.mark.asyncio
async def test_returns_none_on_malformed_json():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            return "this is not json"

    agent = LLMBuilderAgent(FakeClient())  # type: ignore[arg-type]
    result = await agent.propose("evidence", "prompt-injection", "inj-0001")
    assert result is None


@pytest.mark.asyncio
async def test_evidence_bounded_to_200_chars():
    """Evidence passed to the LLM is bounded to 200 chars (rule 3)."""
    received: list[str] = []

    class CapturingClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            received.append(user)
            return json.dumps({
                "patch_type": "pattern",
                "yaml_snippet": "y",
                "rationale": "r",
                "false_positive_risk": "low",
            })

    agent = LLMBuilderAgent(CapturingClient())  # type: ignore[arg-type]
    long_evidence = "E" * 500
    await agent.propose(long_evidence, "prompt-injection", "inj-0001")
    assert received
    prompt = received[0]
    # The evidence excerpt in the prompt is bounded to 200 chars
    assert "E" * 201 not in prompt


# ── Import sandbox test (ADR-0027) ───────────────────────────────────────────

def test_llm_builder_does_not_import_gateway():
    import olive.intelligence.llm_builder as m
    mod_vars = {k: getattr(v, "__module__", "") for k, v in vars(m).items()}
    forbidden = ("olive.gateway.proxy", "olive.gateway.breaker")
    for attr, origin in mod_vars.items():
        for f in forbidden:
            assert not (origin == f or origin.startswith(f + ".")), (
                f"llm_builder attribute {attr!r} originates from forbidden {f!r}"
            )
