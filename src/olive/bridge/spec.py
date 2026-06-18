"""Bridge config — load and validate the YAML tool mapping (ADR-0025 §2).

Imports: stdlib + pyyaml only. Must not import from olive.gateway, olive.store,
olive.intelligence, olive.fleet, or olive.identity (ADR-0025 §6).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_ENV_RE = re.compile(r"\$\{([^}]+)\}")
_VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class BridgeToolSpec:
    method: str
    url: str
    path_params: tuple[str, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)
    body_from_arguments: bool = False
    description: str = ""
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.method not in _VALID_METHODS:
            raise ValueError(f"invalid HTTP method: {self.method!r}")


@dataclass(frozen=True)
class BridgeConfig:
    tools: dict[str, BridgeToolSpec]


def _resolve_env(value: str) -> str:
    """Expand ${VAR} references; raise ValueError if a var is unset."""
    def _sub(m: re.Match) -> str:
        var = m.group(1)
        val = os.environ.get(var)
        if val is None:
            raise ValueError(f"bridge config: env var ${{{var}}} is not set")
        return val
    return _ENV_RE.sub(_sub, value)


def load_bridge_config(path: str | Path) -> BridgeConfig:
    """Load and validate a bridge YAML config file.

    Raises ValueError on any validation error (caller should treat as fatal /
    fail-closed — do not start the server with a bad config)."""
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError("bridge config must be a YAML mapping")
    tools_raw = raw.get("tools") or {}
    if not isinstance(tools_raw, dict):
        raise ValueError("bridge config: 'tools' must be a mapping")

    tools: dict[str, BridgeToolSpec] = {}
    for name, td in tools_raw.items():
        if not isinstance(td, dict):
            raise ValueError(f"bridge config tool {name!r}: must be a mapping")
        method = str(td.get("method", "GET")).upper()
        if method not in _VALID_METHODS:
            raise ValueError(f"bridge config tool {name!r}: invalid method {method!r}")
        if "url" not in td:
            raise ValueError(f"bridge config tool {name!r}: 'url' is required")
        url = str(td["url"])
        path_params = tuple(str(p) for p in (td.get("path_params") or []))
        headers_raw = dict(td.get("headers") or {})
        headers = {k: _resolve_env(str(v)) for k, v in headers_raw.items()}
        body_from_arguments = bool(td.get("body_from_arguments", False))
        description = str(td.get("description") or f"HTTP {method} {url}")
        timeout_seconds = float(td.get("timeout_seconds", 30.0))
        tools[name] = BridgeToolSpec(
            method=method,
            url=url,
            path_params=path_params,
            headers=headers,
            body_from_arguments=body_from_arguments,
            description=description,
            timeout_seconds=timeout_seconds,
        )
    return BridgeConfig(tools=tools)
