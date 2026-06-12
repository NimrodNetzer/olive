# ADR-0002: Python core

**Status:** accepted (2026-06-12)

## Context
The MCP reference SDK and most servers are TypeScript, but an official Python
SDK exists and is maintained. The founder is fastest in Python, and the
intelligence layer (LLM sentinels, evals) is Python-native territory.

## Decision
The gateway core, inspectors, evals, and demo are Python ≥ 3.11, async
throughout, on the official `mcp` Python SDK.

## Consequences
- Fastest path to a working product and eval harness for this team.
- Gateway latency is acceptable at this stage; if it ever matters, the
  inspector pipeline boundary is where a faster fast-path could be rewritten.
- Revisit if Python SDK gaps (transport features, spec lag) start hurting.
