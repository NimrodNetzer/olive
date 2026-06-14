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
class UpstreamSpec:
    name: str  # tool-namespace prefix; "" only for a lone single upstream
    command: tuple[str, ...]


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
    max_blocks_before_quarantine: int = 3
    upstreams: tuple[UpstreamSpec, ...] = ()


def load_config(path: str | Path) -> GatewayConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError(f"policy file {path} is not a mapping")

    try:
        gateway = raw["gateway"]
        roles_raw = raw["roles"]
    except KeyError as exc:
        raise ConfigError(f"policy file missing required section: {exc}") from exc

    def _rate_limit(name: str, spec: dict) -> int | None:
        rate = spec.get("max_calls_per_minute")
        if rate is None:
            return None
        if not isinstance(rate, int) or isinstance(rate, bool) or rate < 1:
            raise ConfigError(
                f"role '{name}' max_calls_per_minute must be an integer >= 1, got {rate!r}"
            )
        return rate

    roles = {
        name: RolePolicy(
            allowed_tools=frozenset(spec.get("allowed_tools", [])),
            forbidden_tools=frozenset(spec.get("forbidden_tools", [])),
            max_calls_per_minute=_rate_limit(name, spec),
        )
        for name, spec in roles_raw.items()
    }

    trust = raw.get("upstream", {}).get("trust", "untrusted")
    if trust not in ("trusted", "untrusted"):
        raise ConfigError(f"invalid upstream trust label: {trust!r}")

    role = gateway["role"]
    if role not in roles:
        raise ConfigError(f"gateway role '{role}' has no policy in roles section")

    max_blocks = raw.get("containment", {}).get("max_blocks_before_quarantine", 3)
    if not isinstance(max_blocks, int) or isinstance(max_blocks, bool) or max_blocks < 1:
        raise ConfigError(
            f"max_blocks_before_quarantine must be an integer >= 1, got {max_blocks!r}"
        )

    upstreams = _parse_upstreams(raw.get("upstreams", []))

    return GatewayConfig(
        agent_id=gateway["agent_id"],
        organization_id=gateway.get("organization_id", "default-org"),
        role=role,
        declared_goal=gateway.get("declared_goal", ""),
        db_path=gateway.get("db_path", "olive_events.db"),
        upstream_trust=trust,
        roles=roles,
        injection_patterns=list(raw.get("injection_patterns", [])),
        max_blocks_before_quarantine=max_blocks,
        upstreams=upstreams,
    )


def _parse_upstreams(raw: object) -> tuple[UpstreamSpec, ...]:
    if not raw:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("'upstreams' must be a list of {name, command}")
    specs: list[UpstreamSpec] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or "name" not in entry or "command" not in entry:
            raise ConfigError("each upstream needs a 'name' and a 'command'")
        name = entry["name"]
        command = entry["command"]
        if not isinstance(name, str) or not name or "." in name:
            raise ConfigError(f"upstream name must be a non-empty string without '.', got {name!r}")
        if not isinstance(command, list) or not command or not all(
            isinstance(part, str) for part in command
        ):
            raise ConfigError(f"upstream '{name}' command must be a non-empty list of strings")
        if name in seen:
            raise ConfigError(f"duplicate upstream name: {name!r}")
        seen.add(name)
        specs.append(UpstreamSpec(name=name, command=tuple(command)))
    return tuple(specs)
