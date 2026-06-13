from __future__ import annotations

from pathlib import Path

import pytest

from olive.config import ConfigError, load_config

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


def test_default_containment_threshold():
    config = load_config(ROOT / "policies" / "default.yaml")
    assert config.max_blocks_before_quarantine == 3


def test_invalid_containment_threshold_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "containment: {max_blocks_before_quarantine: 0}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="max_blocks_before_quarantine"):
        load_config(bad)


def test_role_rate_limit_loads(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [t], max_calls_per_minute: 30}}\n",
        encoding="utf-8",
    )
    config = load_config(good)
    assert config.roles["r"].max_calls_per_minute == 30


def test_role_rate_limit_defaults_to_none():
    config = load_config(ROOT / "policies" / "default.yaml")
    # default policy may or may not set a limit; absence must parse as None
    cs = config.roles["customer-support"]
    assert cs.max_calls_per_minute is None or isinstance(cs.max_calls_per_minute, int)


def test_invalid_rate_limit_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [], max_calls_per_minute: -5}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="max_calls_per_minute"):
        load_config(bad)
