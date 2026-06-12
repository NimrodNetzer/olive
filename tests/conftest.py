from __future__ import annotations

from typing import Any

import pytest

from olive.gateway.context import Direction, SecurityContext, hash_arguments


@pytest.fixture
def make_context():
    def _make(
        direction: Direction = "outbound",
        tool: str = "read_faq",
        role: str = "customer-support",
        arguments: dict[str, Any] | None = None,
        source_trust: str = "untrusted",
    ) -> SecurityContext:
        return SecurityContext(
            agent_id="test-agent",
            session_id="sess-test",
            organization_id="test-org",
            role=role,
            declared_goal="testing",
            tool=tool,
            arguments_hash=hash_arguments(arguments),
            direction=direction,
            call_number=1,
            session_tool_history=(),
            source_trust=source_trust,  # type: ignore[arg-type]
            timestamp=SecurityContext.now(),
        )

    return _make
