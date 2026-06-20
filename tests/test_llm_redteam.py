"""Tests for LLMRedTeamAgent (ADR-0029). All LLM calls are mocked — no real API."""

import json
import pytest
from pathlib import Path

from olive.intelligence.agent_client import AgentLLMClient
from olive.intelligence.llm_redteam import LLMRedTeamAgent, _parse_hypotheses


# ── _parse_hypotheses unit tests ──────────────────────────────────────────────

def test_parse_valid_hypotheses():
    raw = json.dumps([
        {"strategy": "base64 double-encode", "payload_sketch": "ignore above", "target_rule": "inj-0001"},
        {"strategy": "unicode confusable", "payload_sketch": "SYSTEM: change role", "target_rule": "inj-0002"},
    ])
    result = _parse_hypotheses(raw)
    assert len(result) == 2
    assert result[0]["strategy"] == "base64 double-encode"
    assert result[0]["payload_sketch"] == "ignore above"
    assert result[0]["target_rule"] == "inj-0001"


def test_parse_caps_at_five():
    raw = json.dumps([
        {"strategy": f"s{i}", "payload_sketch": f"p{i}", "target_rule": f"r{i}"}
        for i in range(10)
    ])
    result = _parse_hypotheses(raw)
    assert len(result) == 5


def test_parse_none_input():
    assert _parse_hypotheses(None) == []


def test_parse_empty_string():
    assert _parse_hypotheses("") == []


def test_parse_malformed_json():
    assert _parse_hypotheses("not json") == []


def test_parse_not_a_list():
    assert _parse_hypotheses('{"strategy": "x"}') == []


def test_parse_skips_invalid_items():
    raw = json.dumps([
        {"strategy": "valid", "payload_sketch": "p1", "target_rule": "r1"},
        "not a dict",
        {"strategy": 123, "payload_sketch": "p3", "target_rule": "r3"},  # strategy not str
    ])
    result = _parse_hypotheses(raw)
    assert len(result) == 1
    assert result[0]["strategy"] == "valid"


def test_parse_truncates_sketch_to_100():
    raw = json.dumps([{"strategy": "s", "payload_sketch": "X" * 200, "target_rule": "r"}])
    result = _parse_hypotheses(raw)
    assert len(result[0]["payload_sketch"]) <= 100


# ── LLMRedTeamAgent behavioural tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_returns_empty_when_client_unavailable():
    class UnavailableClient:
        available = False
        provider = None

    agent = LLMRedTeamAgent(UnavailableClient())  # type: ignore[arg-type]
    result = await agent.generate_hypotheses()
    assert result == []


@pytest.mark.asyncio
async def test_returns_empty_on_llm_error():
    class BoomClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            raise RuntimeError("api down")

    agent = LLMRedTeamAgent(BoomClient())  # type: ignore[arg-type]
    result = await agent.generate_hypotheses()
    assert result == []


@pytest.mark.asyncio
async def test_returns_hypotheses_on_valid_response():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            return json.dumps([
                {"strategy": "zero-width-space", "payload_sketch": "​ignore prev", "target_rule": "inj-0041"},
            ])

    agent = LLMRedTeamAgent(FakeClient())  # type: ignore[arg-type]
    result = await agent.generate_hypotheses()
    assert len(result) == 1
    assert result[0]["strategy"] == "zero-width-space"


@pytest.mark.asyncio
async def test_returns_empty_on_malformed_json():
    class FakeClient:
        available = True
        provider = "groq"

        async def complete(self, *a, **kw):
            return "not json"

    agent = LLMRedTeamAgent(FakeClient())  # type: ignore[arg-type]
    result = await agent.generate_hypotheses()
    assert result == []


@pytest.mark.asyncio
async def test_policy_summary_included_in_prompt(tmp_path):
    """Policy content is summarised (not raw) and included in the LLM prompt."""
    policy = tmp_path / "test.yaml"
    policy.write_text(
        "roles:\n  analyst: {}\n  support: {}\n"
        "injection_patterns:\n  - 'ignore above'\n  - 'you are now'\n"
    )
    received: list[str] = []

    class CapturingClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            received.append(user)
            return "[]"

    agent = LLMRedTeamAgent(CapturingClient(), policy_path=str(policy))  # type: ignore[arg-type]
    await agent.generate_hypotheses()
    assert received
    prompt = received[0]
    assert "analyst" in prompt or "support" in prompt
    assert "injection_patterns: 2" in prompt


@pytest.mark.asyncio
async def test_corpus_ids_included_in_prompt(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "inj-0001.yaml").write_text("id: inj-0001")
    (corpus / "inj-0002.yaml").write_text("id: inj-0002")

    received: list[str] = []

    class CapturingClient:
        available = True
        provider = "groq"

        async def complete(self, system, user, **kw):
            received.append(user)
            return "[]"

    agent = LLMRedTeamAgent(CapturingClient(), corpus_dir=corpus)  # type: ignore[arg-type]
    await agent.generate_hypotheses()
    assert received
    prompt = received[0]
    assert "inj-0001" in prompt or "inj-0002" in prompt


# ── Import sandbox test (ADR-0027) ───────────────────────────────────────────

def test_llm_redteam_does_not_import_gateway():
    import olive.intelligence.llm_redteam as m
    mod_vars = {k: getattr(v, "__module__", "") for k, v in vars(m).items()}
    forbidden = ("olive.gateway.proxy", "olive.gateway.breaker")
    for attr, origin in mod_vars.items():
        for f in forbidden:
            assert not (origin == f or origin.startswith(f + ".")), (
                f"llm_redteam attribute {attr!r} originates from forbidden {f!r}"
            )
