# ADR-0008: Multi-upstream via a multiplexing adapter

**Status:** accepted (2026-06-14)

## Context
M2 calls for one gateway fronting several upstream MCP servers. Two servers may
export the same tool name (`read_file`), so the gateway must namespace tools and
route each `tools/call` to the owning server — without weakening the per-call
enforcement that already exists.

## Decision
Introduce a **`MultiplexUpstream`** (`gateway/upstreams.py`) that presents many
upstreams to the gateway as a single one:

- Each upstream has a **name** used as a namespace **prefix**; aggregated tools
  are exposed as `"<name>.<tool>"`. `tools/call` splits on the first separator,
  resolves the owning upstream, strips the prefix, and forwards the bare name.
- It implements the same `list_tools()` / `call_tool()` surface the gateway
  already uses, so **the gateway and its tests are unchanged** — the proxy still
  sees "one upstream". Enforcement (policy, breaker, rate limit, inbound
  inspection) runs exactly as before, now over namespaced tool names.
- **Single-upstream mode is preserved**: one upstream with an empty name yields
  bare tool names — identical to talking to that server directly. The demo and
  existing policies keep working untouched.
- Upstreams are **defined in the policy file** (`upstreams:` — name + command);
  a gateway deployment is described by its policy. When absent, the CLI's
  single upstream command is used (back-compat).
- **Default-deny still routes safely**: an unknown/namespaced tool not in the
  role's `allowed_tools` is blocked by policy before routing; an allowed-but-
  unroutable name fails closed via the existing upstream-error path.

## Deferred
- **Per-upstream trust labels.** Trust currently only "tunes inspection depth",
  but the sole inspector is layer-zero and runs regardless of trust, so a
  per-upstream label would be behaviourally inert today. Multi-upstream uses the
  gateway-wide `upstream.trust` (kept conservative) for now; per-upstream trust
  lands with M6 when inspection depth actually varies by trust.

## Consequences
- One gateway can front many tool servers with collision-free tool names and
  correct routing, closing the last M2 feature.
- Policy `allowed_tools`/`forbidden_tools` reference namespaced names in
  multi-upstream mode (bare names in single mode) — precise per-server authz.
- The proxy stayed agnostic: multiplexing is isolated in one adapter, keeping
  the core simple and the layering rule (ADR-0003) intact.
