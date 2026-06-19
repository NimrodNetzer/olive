# ADR-0028 — Tool-level capability enforcement: CapabilityInspector

**Status:** accepted  
**Date:** 2026-06-19

## Context

Olive's identity tokens carry a `capabilities` tuple (ADR-0007). These capabilities
are verified at token parse time and stored on `IdentityClaims`, but until now
they have never been checked at the tool-call boundary: any agent with a valid
token and the correct role can call any allowed tool, regardless of whether its
token carries the specific capability required for that tool.

This is a privilege-escalation gap. A token issued for general read access
should not be able to invoke high-privilege tools such as `transfer_funds` or
`read_secret` without carrying an explicit `finance:transfer` or `secrets:read`
capability claim. The gap is especially relevant in multi-tenant fleet deployments
where tokens are issued with narrow scopes that differ across sessions.

## Decision

### 1. `capabilities` added to `SecurityContext`

`SecurityContext` gains a `capabilities: tuple[str, ...]` field (default empty).
The proxy maps `identity.capabilities` → `SecurityContext.capabilities` when
building the context for each tool call.

### 2. `CapabilityInspector` (new inspector)

A new outbound inspector: `src/olive/inspectors/capability.py`.

It runs **after** `PolicyInspector` and **before** `ContextPolicyInspector` —
same refine-only contract: it can block a call the allowlist permits, never grant
one the allowlist denied.

Policy YAML gains an optional `capability_requirements` top-level section:

```yaml
capability_requirements:
  transfer_funds:
    required_capabilities: ["finance:transfer"]   # AND semantics
  read_secret:
    required_capabilities: ["secrets:read"]
```

Inspector logic: for a tool that declares `required_capabilities`, every listed
capability must be present in `SecurityContext.capabilities`. If any is absent,
the call is blocked with rule `policy.capability_missing`.

Omitting `required_capabilities` for a tool means no capability check — the
change is fully backward-compatible: existing policies and tests are unaffected.

### 3. `GatewayConfig.tool_capabilities`

`GatewayConfig` gains `tool_capabilities: dict[str, frozenset[str]]` (default
empty dict). `load_config()` parses the `capability_requirements` section.
`build_pipeline()` passes `config.tool_capabilities` to `CapabilityInspector`.

### 4. Per-gateway fleet mode command

`POST /fleet/mode/{gateway_id}` — commands a single gateway to change mode
without affecting others. `GatewayRegistry.set_gateway_mode(gateway_id, mode,
issued_by)` does a targeted `UPDATE` and returns `False` when the `gateway_id`
is unknown (404 on the HTTP layer). Complements the existing broadcast
`POST /fleet/mode` which remains unchanged.

### 5. LangChain adapter (`src/olive/adapters/langchain.py`)

`OliveToolkit` bridges Olive-protected tools as `langchain_core.tools.BaseTool`
instances. It connects to Olive's HTTP gateway, lists available tools, and wraps
each one. `langchain-core` is an optional dependency; the adapter raises a clear
`ImportError` if it is absent. No changes to the gateway are required.

## Consequences

- Agents without the required capability are blocked deterministically at the
  policy layer (rule `policy.capability_missing`), not silently permitted.
- The change is purely additive: policies that omit `capability_requirements`
  behave identically to before (no capability check runs).
- `SecurityContext` grows one new field; all existing construction sites that
  omit `capabilities` get the default empty tuple — no breakage.
- The eval corpus gains two `esc-*` cases: one blocking (missing cap) and one
  allowing (correct cap) to lock in the behavior as a regression gate.
