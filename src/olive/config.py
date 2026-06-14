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
from olive.gateway.pipeline import Decision
from olive.gateway.resources import ResourceExtractor
from olive.inspectors.context_policy import ContextRule
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
    # Per-tool resource extractors (ADR-0010), keyed by tool name. Optional and
    # additive: a tool with no extractor simply has no structured resource.
    resource_extractors: dict[str, ResourceExtractor] = field(default_factory=dict)
    # Contextual authorization rules (ADR-0010), keyed by role. A role with no
    # rules behaves exactly as before - coarse allowlist only.
    context_rules: dict[str, tuple[ContextRule, ...]] = field(default_factory=dict)


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
    context_rules = {
        name: _parse_rules(name, spec.get("rules", []))
        for name, spec in roles_raw.items()
        if spec.get("rules")
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
    resource_extractors = _parse_resources(raw.get("resources", {}))

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
        resource_extractors=resource_extractors,
        context_rules=context_rules,
    )


def _parse_rules(role: str, raw: object) -> tuple[ContextRule, ...]:
    if not isinstance(raw, list):
        raise ConfigError(f"role '{role}' rules must be a list")
    rules: list[ContextRule] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigError(f"role '{role}' each rule must be a mapping")
        rid = entry.get("id")
        if not isinstance(rid, str) or not rid:
            raise ConfigError(f"role '{role}' rule missing a non-empty string 'id'")
        if rid in seen:
            raise ConfigError(f"role '{role}' duplicate rule id: {rid!r}")
        seen.add(rid)
        effect_raw = entry.get("effect", "block")
        if effect_raw not in ("block", "hold"):
            raise ConfigError(
                f"role '{role}' rule '{rid}' effect must be 'block' or 'hold', got {effect_raw!r}"
            )
        when = entry.get("when", {})
        require = entry.get("require", {})
        if not isinstance(when, dict) or not isinstance(require, dict):
            raise ConfigError(f"role '{role}' rule '{rid}' when/require must be mappings")
        if not require:
            raise ConfigError(f"role '{role}' rule '{rid}' must declare at least one requirement")
        tool = entry.get("tool")
        if tool is not None and not isinstance(tool, str):
            raise ConfigError(f"role '{role}' rule '{rid}' tool must be a string")
        rules.append(
            ContextRule(
                id=rid,
                tool=tool,
                when={str(k): str(v) for k, v in when.items()},
                require={str(k): str(v) for k, v in require.items()},
                effect=Decision.HOLD if effect_raw == "hold" else Decision.BLOCK,
            )
        )
    return tuple(rules)


def _parse_resources(raw: object) -> dict[str, ResourceExtractor]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("'resources' must be a mapping of tool -> extractor")
    extractors: dict[str, ResourceExtractor] = {}
    for tool, spec in raw.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"resource extractor for '{tool}' must be a mapping")
        try:
            rtype = spec["type"]
            id_arg = spec["id_arg"]
        except KeyError as exc:
            raise ConfigError(
                f"resource extractor for '{tool}' missing required key: {exc}"
            ) from exc
        if not isinstance(rtype, str) or not rtype:
            raise ConfigError(f"resource extractor for '{tool}' needs a non-empty string 'type'")
        if not isinstance(id_arg, str) or not id_arg:
            raise ConfigError(f"resource extractor for '{tool}' needs a non-empty string 'id_arg'")
        classification = spec.get("classification")
        if classification is not None and not isinstance(classification, str):
            raise ConfigError(f"resource extractor for '{tool}' classification must be a string")
        hash_id = spec.get("hash_id", False)
        if not isinstance(hash_id, bool):
            raise ConfigError(f"resource extractor for '{tool}' hash_id must be a boolean")
        extractors[tool] = ResourceExtractor(
            type=rtype, id_arg=id_arg, classification=classification, hash_id=hash_id
        )
    return extractors


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
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(part, str) for part in command)
        ):
            raise ConfigError(f"upstream '{name}' command must be a non-empty list of strings")
        if name in seen:
            raise ConfigError(f"duplicate upstream name: {name!r}")
        seen.add(name)
        specs.append(UpstreamSpec(name=name, command=tuple(command)))
    return tuple(specs)
