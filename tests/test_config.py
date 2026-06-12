from __future__ import annotations

from pathlib import Path

import pytest

from shieldwall.config import ConfigError, load_config

ROOT = Path(__file__).parent.parent


def test_default_policy_loads():
    config = load_config(ROOT / "policies" / "default.yaml")
    assert config.role == "customer-support"
    assert config.role in config.roles
    assert "read_faq" in config.roles[config.role].allowed_tools
    assert "access_payroll" in config.roles[config.role].forbidden_tools
    assert config.upstream_trust == "untrusted"
    assert config.injection_patterns, "layer-zero patterns must not be empty"


def test_invalid_trust_label_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "upstream: {trust: probably-fine}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="trust"):
        load_config(bad)


def test_gateway_role_must_have_policy(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: ghost}\nroles: {other: {allowed_tools: []}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="ghost"):
        load_config(bad)


def test_missing_sections_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("gateway: {agent_id: a, role: r}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="roles"):
        load_config(bad)
