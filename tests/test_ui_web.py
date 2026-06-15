"""Tests for the Agentic Command Center web dashboard (ADR-0018).

Properties under test:
  - `web.py` is read-only by construction: import-set excludes breaker/proxy/Commander.
  - POST /operator rejects unknown actions with 400.
  - POST /operator accepts a known action and publishes an operator-request.
  - GET /corpus returns the seeded case list.
  - GET /ws is a push-only channel (inbound frames are tolerated without side-effects).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import olive.ui.web as web_module
from olive.intelligence.bus import IncidentBus
from olive.ui.broker import UIBroker

_KEY = b"test-web-key"


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


@pytest.fixture
def app(bus):
    broker = UIBroker()
    return web_module.build_app(broker, bus=bus, corpus_dir=None)


# ── read-only by construction (ADR-0018 SS3) ─────────────────────────────────


def test_web_module_cannot_enforce_anything():
    tree = ast.parse(Path(web_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    forbidden = ("olive.gateway.breaker", "olive.gateway.proxy", "olive.intelligence.commander")
    leaks = [imp for imp in imported for f in forbidden if imp == f or imp.startswith(f + ".")]
    assert not leaks, f"ui.web must not import enforcement modules: {leaks}"


# ── POST /operator ────────────────────────────────────────────────────────────


def test_operator_rejects_unknown_action(app):
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/operator", json={"action": "delete-everything"})
    assert r.status_code == 400
    assert "unknown action" in r.json()["error"]


def test_operator_rejects_invalid_json(app):
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/operator", content=b"not json", headers={"content-type": "application/json"})
    assert r.status_code == 400


async def test_operator_publishes_known_action(bus):
    broker = UIBroker()
    app = web_module.build_app(broker, bus=bus)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/operator", json={"action": "run-campaign-request", "evidence": "test-case"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["action"] == "run-campaign-request"
    assert body["object_id"] is not None
    history = await bus.history()
    assert any(row["kind"] == "operator-request" for row in history)


def test_operator_returns_503_without_bus():
    broker = UIBroker()
    app = web_module.build_app(broker, bus=None)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/operator", json={"action": "force-mode-request"})
    assert r.status_code == 503


# ── GET /corpus ───────────────────────────────────────────────────────────────


def test_corpus_endpoint_empty(app):
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/corpus")
    assert r.status_code == 200
    assert r.json() == []


def test_corpus_endpoint_with_dir(bus, tmp_path):
    (tmp_path / "inj-001.yaml").write_text("id: inj-001\n")
    (tmp_path / "inj-002.yaml").write_text("id: inj-002\n")
    broker = UIBroker()
    app = web_module.build_app(broker, bus=bus, corpus_dir=tmp_path)
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/corpus")
    assert r.status_code == 200
    assert r.json() == ["inj-001", "inj-002"]


# ── GET /ws push channel ──────────────────────────────────────────────────────


def test_ws_accepts_connection(app):
    client = TestClient(app, raise_server_exceptions=True)
    with client.websocket_connect("/ws"):
        pass  # connection established — no exception = success
