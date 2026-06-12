from __future__ import annotations

from shieldwall.gateway.pipeline import Decision
from shieldwall.inspectors.policy import PolicyInspector, RolePolicy

ROLES = {
    "customer-support": RolePolicy(
        allowed_tools=frozenset({"read_faq", "search_kb"}),
        forbidden_tools=frozenset({"access_payroll"}),
    )
}


async def test_allowed_tool(make_context):
    verdict = await PolicyInspector(ROLES).inspect(make_context(tool="read_faq"), None)
    assert verdict.allowed


async def test_forbidden_tool(make_context):
    verdict = await PolicyInspector(ROLES).inspect(make_context(tool="access_payroll"), None)
    assert verdict.decision is Decision.BLOCK
    assert verdict.rule == "policy.forbidden_tool"


async def test_unknown_tool_default_deny(make_context):
    verdict = await PolicyInspector(ROLES).inspect(make_context(tool="delete_everything"), None)
    assert verdict.decision is Decision.BLOCK
    assert verdict.rule == "policy.not_allowed"


async def test_unknown_role_blocked(make_context):
    verdict = await PolicyInspector(ROLES).inspect(
        make_context(tool="read_faq", role="never-configured"), None
    )
    assert verdict.decision is Decision.BLOCK
    assert verdict.rule == "policy.unknown_role"
