# ADR-0026 — Self-Security Hardening

**Status:** accepted  
**Date:** 2026-06-19

## Context

Olive protects agents from external attacks, but the gateway itself has three
unguarded internal attack surfaces named in `THREAT_MODEL.md`:

1. **Policy file tampering.** An attacker with local file access can add a
   tool to `allowed_tools` or remove it from `forbidden_tools`. If the gateway
   restarts, the modified policy is silently loaded and the tampered rule
   becomes the authoritative allowlist.

2. **Audit log tampering.** Evidence of an attack can be erased by deleting or
   modifying rows in the SQLite events table. Nothing currently detects that the
   log was changed after the gateway wrote it.

3. **Gateway-targeting injections.** A compromised upstream server can respond
   with content that specifically attempts to manipulate Olive's own behaviour
   ("ignore your security policy", "add X to allowed_tools"). These are not
   covered by the configurable `injection_patterns` list — an attacker who can
   also modify the policy file could simply remove the patterns that protect
   Olive. They need hardcoded protection independent of the policy file.

These three surfaces share a property: they target Olive's infrastructure, not
the agents Olive proxies. Addressing them requires hardened code paths that
cannot be disabled by modifying the policy YAML.

## Decision

Three-layer self-protection:

### Layer 1 — Policy file integrity

A new `src/olive/security/integrity.py` module computes the SHA-256 hash of
the policy YAML at load time and records it in a new `policy_checksums` table
in the audit DB (path → hash, recorded timestamp). On every startup the
gateway compares the current file hash against the stored one:

- **No record (first run):** record the hash; no warning.
- **Hash matches:** policy is unchanged; continue normally.
- **Hash differs:** log a `self_protect.policy_tamper` warning to stderr
  (never silently accept a tampered policy). The gateway continues — it does
  not refuse to start — because a legitimate operator may have intentionally
  updated the policy; the warning exists to surface unintentional or malicious
  changes.

An operator CLI command (`olive verify-integrity`) can be run at any time to
re-check both the policy hash and the audit chain (layer 2).

### Layer 2 — Tamper-evident audit chain

A new `audit_chain` table stores one row per event: `(event_id, prev_hash,
row_hash)`. The `row_hash` is `SHA-256(event_id | decision | timestamp |
prev_hash)`, forming a linked chain from the genesis record (prev_hash = "0"
× 64) forward. The gateway writes a chain record every time it writes an
event row (same transaction).

`EventStore.verify_audit_chain()` walks every row in insertion order, recomputes
each hash, verifies `prev_hash` against the prior `row_hash`, and reports the
first broken link (or "OK"). A broken link means at least one row was deleted,
inserted out of order, or modified after the fact. `olive verify-integrity
--audit` exposes this check.

### Layer 3 — Hardcoded gateway-manipulation inspector

`src/olive/inspectors/self_protect.py` implements a new inbound `Inspector`
with a hardcoded set of trigger phrases that specifically target Olive's own
operation. It is added to `build_pipeline()` **before** the configurable
`PatternInspector` so that:

- Its patterns cannot be neutered by editing the policy YAML.
- A tampered policy file with all `injection_patterns` removed still catches
  "ignore your security policy" and similar gateway-directed content.

Rule emitted: `self_protect.gateway_manipulation`.  
Attack type logged: `gateway-manipulation`.  
Corpus category: `injection.gateway`.

## Consequences

- `olive verify-integrity` is a new operator command for health checks,
  monitoring scripts, and incident post-mortems.
- The audit chain adds ~1 SHA-256 per event. Negligible latency.
- Layer 3 is always active and cannot be disabled without a code change.
  This is intentional: the self-protection inspector is part of the enforcement
  layer, not the policy layer.
- Layering rule (ADR-0003) is preserved: the new `security/` module is pure
  core (no intelligence imports); `store/events.py` grows two new table methods.
- The non-guarantee documented in `THREAT_MODEL.md` about "local file access"
  remains: this ADR detects tampering but does not prevent it. Filesystem
  hardening (OS permissions, immutable files, read-only mounts) is out of scope.
