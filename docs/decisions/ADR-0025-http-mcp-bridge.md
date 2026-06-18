# ADR-0025: HTTP-to-MCP Bridge

**Number:** ADR-0025
**Title:** HTTP-to-MCP Bridge — expose external HTTP APIs as inspectable MCP tools
**Date:** 2026-06-18
**Status:** accepted

---

## Context

Olive currently proxies upstream MCP servers. Real-world deployments increasingly need to expose plain HTTP REST APIs (internal microservices, third-party SaaS endpoints, OpenAPI-documented services) as MCP tools that agents can call — and that Olive can inspect and enforce on.

Today there is no path for this. An operator wanting to gate an HTTP endpoint must wrap it in a full MCP server themselves. That friction is a deployment barrier; removing it is a product-level priority.

Two implementation approaches exist:

**A. In-process adapter.** A `BridgeUpstream` class that implements the `UpstreamSession` protocol (ADR-0008 / `gateway/upstreams.py`) directly, translating `call_tool` to an outbound HTTP request internally. The gateway wires it alongside any other upstream in `MultiplexUpstream`. No subprocess.

**B. Standalone subprocess MCP server.** A `BridgeServer` process that reads a config file and speaks MCP over stdio. Olive spawns it as any other upstream, using the existing `UpstreamSpec.command` mechanism. The bridge is just another MCP server from Olive's perspective.

**Option A** is architecturally simpler in code but introduces a new import dependency in `cli.py` (or `config.py`) on an `httpx` HTTP client. More seriously, it moves network I/O into the gateway composition root, whose job is wiring, not protocol translation. It also ties the bridge lifecycle to the gateway process.

**Option B** keeps the gateway completely unaware of HTTP bridging: it spawns a subprocess, the subprocess speaks MCP, enforcement runs exactly as it does for any upstream. The bridge can crash, restart, or be replaced without touching the gateway. The subprocess boundary is a clean isolation layer that also limits the blast radius of a buggy or malicious HTTP API: a hung or misbehaving bridge connection surfaces as an upstream error, which the gateway handles fail-closed.

**Config format.** Full OpenAPI spec support (path parameter extraction, auth scheme negotiation, response schema validation) is substantial scope with no immediate security benefit. The threat model already requires Olive to inspect every tool response regardless of what the tool nominally returns; Olive does not trust OpenAPI's stated response schema. A simple YAML mapping (`tool_name → {method, url, headers?, params?}`) is the smallest format that enables the feature. OpenAPI import can be layered as a pre-processing step later (a CLI command that reads an OpenAPI spec and emits bridge YAML) without touching the bridge server itself.

**Identity.** When Olive runs with `olive serve` (HTTP transport, ADR-0007), every upstream MCP connection is a subprocess over stdio. The bridge subprocess is also stdio — no bearer token is needed for the bridge's MCP connection to Olive, because that connection is a local subprocess pipe, the same trust model as any other upstream (the gateway spawned it, it is not a network peer). The bridge's outbound HTTP calls to external APIs are a separate surface, handled by per-endpoint `headers` in the config (bearer tokens, API keys). Those headers are loaded from the config file at startup and are never logged (rule 3).

**Rule 3 enforcement.** HTTP responses from external APIs are untrusted input under rule 1, regardless of whether the external API is considered "trusted" by the operator. The bridge must not log raw response bodies. It returns them as MCP tool-result content; Olive's inbound inspector pipeline then applies the same content inspection and bounded-evidence logging it applies to every other upstream response.

---

## Decision

### 1. Architecture: standalone subprocess MCP server

`src/olive/bridge/` is a new package that implements a standalone MCP server (`bridge/server.py`). It is invoked as a subprocess by Olive's existing upstream-spawn mechanism — it appears in the policy file under `upstreams:` with a `command:` that invokes `python -m olive.bridge.server --config <path>`. Olive's gateway and proxy code are unchanged.

The bridge lives inside `src/olive/` but on the same side of the ADR-0003 seam as `fleet/` and `ui/`: it is a separate process that Olive spawns, not code the gateway core imports. `gateway/`, `store/`, `identity/`, and `inspectors/` must not import from `bridge/`. A test asserts this in both directions.

### 2. Config format: simple YAML mapping, OpenAPI deferred

Bridge config is a standalone YAML file (separate from the gateway policy file) with the following MVP schema:

```yaml
tools:
  get_user:
    method: GET
    url: "https://api.example.com/users/{user_id}"
    path_params: [user_id]        # lifted from MCP call arguments
    headers:
      Authorization: "Bearer ${API_TOKEN}"   # env-var interpolation only
  create_order:
    method: POST
    url: "https://api.example.com/orders"
    headers:
      Authorization: "Bearer ${API_TOKEN}"
      Content-Type: application/json
    body_from_arguments: true     # serialize remaining arguments as JSON body
```

Constraints:
- URL templates support `{name}` path parameters lifted from MCP call arguments.
- Header values support `${ENV_VAR}` interpolation resolved at startup. A missing env var is a startup error (fail closed).
- `method` must be one of `GET | POST | PUT | PATCH | DELETE`. Any other value is a config validation error (fail closed).
- No inline credential values. Credentials must be `${ENV_VAR}` references.

OpenAPI spec import is explicitly out of scope. A future `olive bridge generate-config --openapi <spec.yaml>` CLI command may emit this format from an OpenAPI spec.

### 3. Trust model

HTTP responses are untrusted input under rule 1, regardless of the external API's operator-assigned trust label. The bridge upstream's trust label in the gateway policy (`trusted | untrusted`) tunes inspection depth, never disables inspection. The recommended label for any bridge upstream is `untrusted`. Tool descriptions emitted by the bridge come from config, not from HTTP responses — this structurally prevents tool-description poisoning via HTTP responses (ADR-0009).

### 4. Payload logging — Rule 3 compliance

The bridge subprocess must not log raw HTTP response bodies. When a bridge tool call fails (HTTP 4xx/5xx, timeout, connection error), the bridge returns an MCP error result with the HTTP status code and a bounded error message (≤ 200 chars, first 200 chars of the response body's UTF-8 encoding, non-printable chars stripped). Successful HTTP response bodies are returned verbatim as MCP `TextContent` to Olive. Olive's inbound inspector pipeline owns hashing/excerpting. The bridge has no event store and writes no audit rows.

### 5. HTTP client

The bridge subprocess uses `httpx` as its async HTTP client. TLS certificate verification is enabled by default; `verify=False` is not supported without a new ADR. Default timeout: 30 s total per request, configurable per-tool via `timeout_seconds:`. A timed-out request returns an MCP error result (fail closed).

### 6. Layering rule (ADR-0003)

`gateway/`, `store/`, `identity/`, `inspectors/` must not import from `olive.bridge`. The bridge imports `mcp` (the SDK) and `httpx` only — it must not import from `olive.gateway`, `olive.intelligence`, `olive.fleet`, or `olive.store`. A test asserts the import set in both directions.

### 7. MCP tool schema generation

For each configured tool the bridge generates an MCP `Tool` with:
- `name`: the key from config.
- `description`: optional `description:` field in config, defaulting to `"HTTP {method} {url_template}"`.
- `inputSchema`: a JSON Schema object with properties derived from `path_params` + (if `body_from_arguments: true`) an additional `body` object property. Static, generated at startup from config — never reflects a live HTTP response.

### 8. What this ADR does not decide

- OpenAPI spec parsing or automatic schema extraction.
- Response schema validation against an expected shape.
- mTLS or client-certificate authentication for outbound HTTP calls.
- Streaming HTTP responses (SSE / chunked transfer encoding). The bridge reads the full response body before returning it as MCP content. Streaming is deferred.
- Any mechanism by which the bridge can modify Olive's policy, trip the circuit breaker, or alter operating mode. The bridge has no such path by construction.

---

## Consequences

**Positive:**
- HTTP REST APIs become MCP tools with zero changes to the gateway core or inspector pipeline. Enforcement, auditing, containment, and operating-mode behavior are fully inherited.
- The subprocess isolation boundary limits blast radius: a misbehaving bridge does not crash the gateway process.
- Tool-description poisoning from HTTP responses is structurally prevented (descriptions come from config).
- ADR-0003 layering is preserved. Rule 3 enforced at the subprocess boundary.

**Negative / residual risk:**
- HTTP credentials (`${ENV_VAR}` header values) are a new secret class in the operator's environment — same insider-class residual risk as the fleet token (ADR-0024) and mock-CA key.
- External HTTP endpoints introduce network latency and availability dependence. The 30 s timeout bounds this.
- The bridge config file is a trusted component at load time, like policy YAML files (THREAT_MODEL.md). A malicious bridge config pointing at attacker-controlled URLs is an insider-class threat.
- The bridge does not authenticate to Olive's gateway with a CA-signed bearer token — acceptable because the connection is a local subprocess stdio pipe. A future network-deployed bridge would require a new ADR slice.

**Required doc updates:**
- `docs/ARCHITECTURE.md` — add `bridge/` to the component list; note subprocess-upstream pattern; note layering rule extends to `bridge/`.
- `docs/THREAT_MODEL.md` — add bridge config as trusted component; add HTTP credentials as a new secret class; note the stdio-subprocess exemption from bearer-token auth and its network-deployment constraint.
