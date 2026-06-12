# ADR-0001: Speak real MCP from day one

**Status:** accepted (2026-06-12)

## Context
The original v2 plan defined a custom FastAPI `POST /tool-call` protocol with
simulated agents. That is faster to demo but protects nothing real, and real
MCP support would later be a rewrite. Meanwhile, MCP is becoming the de-facto
agent↔tool protocol, and a gateway is only credible if a real client (Claude
Code, Cursor, any MCP host) can be pointed at it unchanged.

## Decision
Olive is a transparent MCP proxy built on the official `mcp` Python SDK.
It presents an MCP server to the client and acts as an MCP client to the
upstream. No custom tool-call protocol, ever. stdio transport first;
streamable HTTP in M2.

## Consequences
- Week one is harder (proxying a real protocol vs. a toy API).
- Everything built protects real agents immediately; demos run on real software.
- MCP-specific attack surfaces (tool-description poisoning, rug pulls) are in
  scope from day one — these don't exist in a custom protocol.
- We track the MCP spec; breaking spec changes are our problem to absorb.
