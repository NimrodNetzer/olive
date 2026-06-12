# Shield Wall

**Zero-trust runtime security gateway for AI agents.**

Shield Wall is a transparent [MCP](https://modelcontextprotocol.io) proxy that
sits between an AI agent and its tools. It inspects every tool call **and
every tool response**, blocks unauthorized actions before they execute, stops
prompt injections hidden in tool output before they ever reach the agent, and
writes an auditable event for every decision.

> Repo codename: `olive` · Product name: Shield Wall

```
agent (any MCP client) ──► SHIELD WALL ──► real MCP tool server
                            │  outbound: policy (default deny)
                            │  inbound:  content inspection
                            └─► SQLite audit trail (events + incidents)
```

Point any MCP client at the gateway instead of the tool server — zero changes
to the agent or the tools.

## Quickstart

```bash
pip install -e ".[dev]"

# the full walking-skeleton demo: allow / block escalation / block injection
python demo/run_demo.py

# measured detection against the attack corpus (honest numbers, see docs/EVALS.md)
python evals/run_evals.py

# run the gateway yourself in front of any stdio MCP server
shieldwall run --config policies/default.yaml -- python demo/tools_server.py
```

## What the demo shows

1. **Legitimate work flows freely** — allowed tools pass through, responses
   inspected and released.
2. **Privilege escalation blocked outbound** — a forbidden tool call is
   stopped *before the tool server is ever contacted*; incident logged.
3. **Prompt injection blocked inbound** — a poisoned document returned by a
   tool is caught and never reaches the agent; the session's audit trail
   shows exactly which rule fired.

## Status

Walking skeleton (Milestone 1). Real MCP protocol, real bidirectional
enforcement, real audit trail — deliberately small. Current detection is
deterministic layer zero only; the eval report says so honestly.
See [docs/ROADMAP.md](docs/ROADMAP.md) for what's next (sessions + circuit
breaker, LLM sentinels, measured-detection CI gate).

## Documentation

| Doc | What it covers |
|---|---|
| [docs/VISION.md](docs/VISION.md) | Product thesis, market, differentiation |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, surfaces, guarantees and non-guarantees |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The proxy, inspector pipeline, audit store |
| [docs/EVALS.md](docs/EVALS.md) | How detection is measured |
| [docs/decisions/](docs/decisions/) | ADRs |
| [CLAUDE.md](CLAUDE.md) | Engineering constitution + the agent company process |

## Development

```bash
pytest            # unit + end-to-end (real MCP over stdio)
ruff check .      # lint
```

Non-negotiable rules live in [CLAUDE.md](CLAUDE.md): all tool output is
untrusted, LLM verdicts never enforce, raw payloads are never logged,
inspectors fail closed, every decision is auditable.
