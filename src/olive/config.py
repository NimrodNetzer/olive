"""Policy-as-code configuration loading.

One YAML file configures a gateway instance: the agent it fronts, role
policies, upstream trust label, and layer-zero injection patterns.
yaml.safe_load only - policy files are trusted at load time (threat model),
but we still never execute content from them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from olive.gateway.context import TrustLevel
from olive.inspectors.policy import RolePolicy


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    agent_id: str
    organization_id: str
    role: str
    declared_goal: str
    db_path: str
    upstream_trust: TrustLevel
    roles: dict[str, RolePolicy] = field(default_factory=dict)
    injection_patterns: list[str] = field(default_factory=list)


def load_config(path: str | Path) -> GatewayConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError(f"policy file {path} is not a mapping")

    try:
        gateway = raw["gateway"]
        roles_raw = raw["roles"]
    except KeyError as exc:
        raise ConfigError(f"policy file missing required section: {exc}") from exc

    roles = {
        name: RolePolicy(
            allowed_tools=frozenset(spec.get("allowed_tools", [])),
            forbidden_tools=frozenset(spec.get("forbidden_tools", [])),
        )
        for name, spec in roles_raw.items()
    }

    trust = raw.get("upstream", {}).get("trust", "untrusted")
    if trust not in ("trusted", "untrusted"):
        raise ConfigError(f"invalid upstream trust label: {trust!r}")

    role = gateway["role"]
    if role not in roles:
        raise ConfigError(f"gateway role '{role}' has no policy in roles section")

    return GatewayConfig(
        agent_id=gateway["agent_id"],
        organization_id=gateway.get("organization_id", "default-org"),
        role=role,
        declared_goal=gateway.get("declared_goal", ""),
        db_path=gateway.get("db_path", "olive_events.db"),
        upstream_trust=trust,
        roles=roles,
        injection_patterns=list(raw.get("injection_patterns", [])),
    )
