# ADR-0027 — Company of Agents Quality: runtime authority enforcement

**Status:** accepted  
**Date:** 2026-06-19

## Context

The company-of-agents hierarchy (ADR-0014) is currently enforced by convention and
build-time AST tests. Three structural gaps remain:

1. **Shared HMAC key** — every department signs with the same process-wide key; a
   compromised department could forge objects for any other department's kinds.
2. **No publisher validation** — the bus accepts any `(source_dept, kind)` pair as
   long as the HMAC verifies; a bug or malicious dept could publish unauthorized kinds.
3. **No supervisor tier** — the vision describes Commander → department supervisors →
   specialists; supervisors are absent; department health is unmonitored at runtime.
4. **Runtime import guard absent** — the AST tests protect at test time; nothing
   stops a patched or monkey-patched module from smuggling a forbidden import into
   a wired department.

## Decision

### 1. Bus publisher validation (`bus.py`)

Add a `PERMITTED_KINDS` registry mapping `source_dept → frozenset[kind]`.
`IncidentBus.publish()` checks this registry **before** HMAC verification:
- Unknown `source_dept` → `BusError` (fail-closed).
- Kind not in the department's allowed set → `BusError` (fail-closed).
- `register_dept()` allows tests and future departments to extend the registry
  without modifying core.

### 2. Per-department derived HMAC keys (`bus.py`)

Replace the single shared signing key with per-department keys derived from the
process key using HKDF (RFC 5869, one block):

```
PRK = HMAC-SHA256(salt=0x00×32, IKM=process_key)
dept_key = HMAC-SHA256(PRK, info=b"olive-bus-<dept>" + 0x01)
```

`IncidentBus.publish()` uses the publishing department's derived key for both
signing (auto-sign path) and verification. A department that obtained another
department's key material cannot forge objects — the bus verifies using the
*correct* department's derived key, which differs per department.

Interface is unchanged: callers still pass one `signing_key` (the process key).
Per-department keys are derived lazily and cached.

### 3. Supervisor tier skeleton (`supervisor.py`)

A minimal `DepartmentSupervisor` abstract base and one concrete implementation,
`DefenseSupervisor`:

- Polls `DefenseDepartment` health (publish failures, last-report timestamp) on a
  configurable interval (default 30 s).
- Publishes `supervisor-health` bus objects (advisory only, never moves mode).
- Sets `status="degraded"` and logs an alert when the Defense department has been
  silent for longer than a configurable threshold (default 120 s).
- Runs as an optional background task in `build_runtime_org()`; off by default
  (`include_supervisor=False`).

Import constraints: `supervisor.py` must not import `gateway.proxy`,
`gateway.upstreams`, `gateway.breaker`, or `mcp.client.session`. A test asserts
the import set. A `register_dept()` call in `bus.py` adds the `supervisor` entry
to `PERMITTED_KINDS` when the supervisor is wired.

### 4. Runtime import guard (`departments.py`)

`_assert_sandbox(module_name, forbidden)` scans the live module namespace
(via `sys.modules`) for attributes whose `__module__` origin matches a forbidden
namespace. Called from `build_runtime_org()` for each department module before
it is wired. Raises `RuntimeError` (fail-closed) on a violation; wiring is
aborted.

Complements (not replaces) the existing AST tests: the AST test catches static
imports at test time; the runtime guard catches monkey-patched or dynamically
injected references at process startup.

## Consequences

- A compromised department publishing an unauthorized kind is caught deterministically
  at the bus boundary (publisher validation) and cannot leverage another department's
  signing key (HKDF key isolation).
- Department health is visible at runtime via the bus audit trail; silent departments
  are flagged before an operator is surprised by a missing detection.
- The runtime import guard adds a second enforcement layer to the structural sandbox
  guarantees (ADR-0015, ADR-0016, ADR-0018).
- No change to the `IncidentBus` public API; `signing_key` parameter is unchanged
  (it becomes the HKDF input key material).
- `PERMITTED_KINDS` is module-level and mutable via `register_dept()` — tests that
  use custom `source_dept` values must call `register_dept()` first.
