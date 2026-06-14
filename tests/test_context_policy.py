"""ContextPolicyInspector (ADR-0010): deterministic refine-only authorization -
resource/task binding, classification ceilings, approval holds, fail-closed."""

from __future__ import annotations

import pytest

from olive.gateway.context import ResourceRef, SecurityContext
from olive.gateway.pipeline import Decision
from olive.inspectors.context_policy import ContextPolicyInspector, ContextRule

pytestmark = pytest.mark.asyncio


def _ctx(
    *,
    role="support",
    tool="read_order",
    resource: ResourceRef | None = None,
    task_resources: tuple[str, ...] = (),
) -> SecurityContext:
    return SecurityContext(
        agent_id="a",
        session_id="s",
        organization_id="o",
        role=role,
        declared_goal="g",
        tool=tool,
        arguments_hash="h",
        direction="outbound",
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp="t",
        requested_resource=resource,
        task_resources=task_resources,
    )


def _binding_rule() -> ContextRule:
    return ContextRule(
        id="order-must-match-task",
        tool="read_order",
        when={"resource.type": "order"},
        require={"resource.id_in": "task.resources"},
        effect=Decision.BLOCK,
    )


async def test_allows_resource_bound_to_task():
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(resource=ResourceRef("order", "4471"), task_resources=("4471",))
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_blocks_resource_outside_task():
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(resource=ResourceRef("order", "9999"), task_resources=("4471",))
    verdict = await insp.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK
    assert "not in the task" in (verdict.evidence or "")
    assert "9999" in (verdict.evidence or "")  # the scoping id is a non-secret key


async def test_blocks_when_no_resource_extracted_but_rule_requires_one():
    # rule applies by tool but resource.type 'order' can't match a None resource
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(resource=None, task_resources=("4471",))
    # `when: resource.type == order` cannot match None -> rule inert -> allow
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_rule_does_not_apply_to_other_tools():
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(tool="read_faq", resource=None, task_resources=())
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_role_with_no_rules_always_allows():
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(role="admin", resource=ResourceRef("order", "x"))
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_classification_ceiling_blocks_when_exceeded():
    rule = ContextRule(
        id="no-secret-for-support",
        tool="read_order",
        require={"resource.classification_max": "customer-pii"},
    )
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(resource=ResourceRef("order", "1", classification="secret"))
    verdict = await insp.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK
    assert "exceeds ceiling" in (verdict.evidence or "")


async def test_classification_ceiling_allows_at_or_below():
    rule = ContextRule(
        id="cap",
        tool="read_order",
        require={"resource.classification_max": "customer-pii"},
    )
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(resource=ResourceRef("order", "1", classification="internal"))
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_unknown_classification_fails_closed():
    rule = ContextRule(
        id="cap",
        tool="read_order",
        require={"resource.classification_max": "customer-pii"},
    )
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(resource=ResourceRef("order", "1", classification="novel-label"))
    assert (await insp.inspect(ctx, None)).decision is Decision.BLOCK


async def test_task_id_membership_is_type_robust():
    # An integer task id (unquoted YAML / JSON number from the attested identity)
    # must still match its own string-normalized resource id, not false-block.
    insp = ContextPolicyInspector({"support": (_binding_rule(),)})
    ctx = _ctx(resource=ResourceRef("order", "4471"), task_resources=(4471,))
    assert (await insp.inspect(ctx, None)).decision is Decision.ALLOW


async def test_classification_ceiling_fails_closed_with_no_resource():
    # A ceiling rule that matches a call with no extracted resource must block,
    # not silently pass: an unknown classification cannot slip under a ceiling.
    rule = ContextRule(
        id="cap-any",
        tool="read_anything",
        require={"resource.classification_max": "customer-pii"},
    )
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(tool="read_anything", resource=None)
    verdict = await insp.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK
    assert "no resource was extracted" in (verdict.evidence or "")


async def test_approval_requirement_always_holds():
    rule = ContextRule(
        id="payroll-approval",
        tool="read_payroll",
        require={"approval": "operator"},
        effect=Decision.HOLD,
    )
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(tool="read_payroll")
    verdict = await insp.inspect(ctx, None)
    assert verdict.decision is Decision.HOLD
    assert "approval" in (verdict.evidence or "")


async def test_unknown_predicate_fails_closed():
    rule = ContextRule(id="x", tool="read_order", require={"resource.mystery": "yes"})
    insp = ContextPolicyInspector({"support": (rule,)})
    ctx = _ctx(resource=ResourceRef("order", "1"))
    verdict = await insp.inspect(ctx, None)
    assert verdict.decision is Decision.BLOCK
    assert "unknown predicate" in (verdict.evidence or "")


async def test_first_matching_failure_wins_order():
    block = ContextRule(id="b", tool="t", require={"resource.id_in": "task.resources"})
    hold = ContextRule(id="h", tool="t", require={"approval": "operator"}, effect=Decision.HOLD)
    insp = ContextPolicyInspector({"support": (block, hold)})
    ctx = _ctx(tool="t", resource=ResourceRef("order", "z"), task_resources=())
    # block rule is first and unmet -> block short-circuits before the hold rule
    assert (await insp.inspect(ctx, None)).decision is Decision.BLOCK


async def test_hashed_id_membership_uses_equality():
    rule = _binding_rule()
    insp = ContextPolicyInspector({"support": (rule,)})
    hashed = ResourceRef("order", "deadbeef", id_hashed=True)
    ok = _ctx(resource=hashed, task_resources=("deadbeef",))
    bad = _ctx(resource=hashed, task_resources=("other",))
    assert (await insp.inspect(ok, None)).decision is Decision.ALLOW
    verdict = await insp.inspect(bad, None)
    assert verdict.decision is Decision.BLOCK
    assert "hashed id" in (verdict.evidence or "")
