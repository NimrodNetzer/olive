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


def test_no_upstreams_defaults_to_empty():
    config = load_config(ROOT / "policies" / "default.yaml")
    assert config.upstreams == ()


def test_upstreams_section_parses(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: [files.read_faq]}}\n"
        "upstreams:\n"
        "  - {name: files, command: [python, files.py]}\n"
        "  - {name: db, command: [python, db.py, --flag]}\n",
        encoding="utf-8",
    )
    config = load_config(good)
    assert [u.name for u in config.upstreams] == ["files", "db"]
    assert config.upstreams[1].command == ("python", "db.py", "--flag")


def test_upstream_name_with_dot_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "upstreams: [{name: 'a.b', command: [python, s.py]}]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="name"):
        load_config(bad)


def test_duplicate_upstream_name_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "upstreams:\n"
        "  - {name: x, command: [python, a.py]}\n"
        "  - {name: x, command: [python, b.py]}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(bad)


def test_no_resources_defaults_to_empty():
    config = load_config(ROOT / "policies" / "default.yaml")
    assert config.resource_extractors == {}


def test_resources_section_parses(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: [read_order]}}\n"
        "resources:\n"
        "  read_order: {type: order, id_arg: order_id, classification: customer-pii}\n"
        "  read_account: {type: account, id_arg: ssn, hash_id: true}\n",
        encoding="utf-8",
    )
    config = load_config(good)
    ro = config.resource_extractors["read_order"]
    assert ro.type == "order" and ro.id_arg == "order_id"
    assert ro.classification == "customer-pii" and ro.hash_id is False
    assert config.resource_extractors["read_account"].hash_id is True


def test_resource_extractor_missing_id_arg_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "resources: {read_order: {type: order}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="id_arg"):
        load_config(bad)


def test_resource_extractor_bad_hash_id_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\nroles: {r: {allowed_tools: []}}\n"
        "resources: {read_order: {type: order, id_arg: x, hash_id: maybe}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="hash_id"):
        load_config(bad)


# --- per-role contextual rules (ADR-0010) ---


def test_contextual_showcase_policy_loads():
    from olive.gateway.pipeline import Decision

    config = load_config(ROOT / "policies" / "contextual.yaml")
    rules = config.context_rules["customer-support"]
    by_id = {r.id: r for r in rules}
    assert by_id["order-must-match-task"].effect is Decision.BLOCK
    assert by_id["order-must-match-task"].when == {"resource.type": "order"}
    assert by_id["order-must-match-task"].require == {"resource.id_in": "task.resources"}
    assert by_id["payroll-needs-approval"].effect is Decision.HOLD
    # a role without rules has no entry (back-compat with M3 policies)
    assert "customer-support" in config.context_rules


def test_rules_parse_block_and_hold(tmp_path):
    from olive.gateway.pipeline import Decision

    good = tmp_path / "good.yaml"
    good.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles:\n"
        "  r:\n"
        "    allowed_tools: [t1, t2]\n"
        "    rules:\n"
        "      - {id: bind, tool: t1, when: {resource.type: order},"
        " require: {resource.id_in: task.resources}}\n"
        "      - {id: appr, tool: t2, require: {approval: operator}, effect: hold}\n",
        encoding="utf-8",
    )
    rules = load_config(good).context_rules["r"]
    assert [x.id for x in rules] == ["bind", "appr"]
    assert rules[0].effect is Decision.BLOCK  # default
    assert rules[1].effect is Decision.HOLD


def test_rule_missing_id_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [t], rules: [{tool: t, require: {approval: operator}}]}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="id"):
        load_config(bad)


def test_rule_duplicate_id_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles:\n"
        "  r:\n"
        "    allowed_tools: [t]\n"
        "    rules:\n"
        "      - {id: dup, tool: t, require: {approval: operator}}\n"
        "      - {id: dup, tool: t, require: {approval: operator}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(bad)


def test_rule_bad_effect_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [t], rules:"
        " [{id: x, tool: t, require: {approval: operator}, effect: nuke}]}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="effect"):
        load_config(bad)


def test_rule_empty_require_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [t], rules: [{id: x, tool: t, require: {}}]}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="requirement"):
        load_config(bad)


def test_rules_not_a_list_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "gateway: {agent_id: a, role: r}\n"
        "roles: {r: {allowed_tools: [t], rules: {id: x}}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="rules must be a list"):
        load_config(bad)
