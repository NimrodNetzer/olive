"""Pipeline contract tests - fail-closed is the most important one."""

from __future__ import annotations

from shieldwall.gateway.pipeline import ALLOW, Decision, InspectorPipeline, Verdict, bound_evidence


class AllowAll:
    name = "allow-all"
    directions = frozenset({"outbound", "inbound"})

    async def inspect(self, ctx, content):
        return ALLOW


class BlockAll:
    name = "block-all"
    directions = frozenset({"outbound", "inbound"})

    async def inspect(self, ctx, content):
        return Verdict(Decision.BLOCK, rule="block-all.test")


class Exploder:
    name = "exploder"
    directions = frozenset({"outbound", "inbound"})

    async def inspect(self, ctx, content):
        raise RuntimeError("secret-internal-state-" + "x" * 500)


class InboundOnlyBlock:
    name = "inbound-only"
    directions = frozenset({"inbound"})

    async def inspect(self, ctx, content):
        return Verdict(Decision.BLOCK, rule="inbound-only.test")


async def test_all_allow(make_context):
    verdict = await InspectorPipeline([AllowAll(), AllowAll()]).run(make_context())
    assert verdict.allowed


async def test_first_block_short_circuits(make_context):
    calls = []

    class Recorder(AllowAll):
        name = "recorder"

        async def inspect(self, ctx, content):
            calls.append(1)
            return ALLOW

    verdict = await InspectorPipeline([BlockAll(), Recorder()]).run(make_context())
    assert verdict.decision is Decision.BLOCK
    assert calls == [], "inspectors after a block must not run"


async def test_inspector_exception_fails_closed(make_context):
    verdict = await InspectorPipeline([Exploder()]).run(make_context())
    assert verdict.decision is Decision.BLOCK
    assert verdict.rule == "exploder.error"


async def test_exception_evidence_is_bounded(make_context):
    verdict = await InspectorPipeline([Exploder()]).run(make_context())
    assert verdict.evidence is not None
    assert len(verdict.evidence) <= 203  # EVIDENCE_LIMIT + ellipsis


async def test_direction_filtering(make_context):
    pipeline = InspectorPipeline([InboundOnlyBlock()])
    assert (await pipeline.run(make_context(direction="outbound"))).allowed
    assert not (await pipeline.run(make_context(direction="inbound"))).allowed


def test_bound_evidence_clamps():
    assert bound_evidence("a" * 1000) == "a" * 200 + "..."
    assert bound_evidence("short") == "short"
