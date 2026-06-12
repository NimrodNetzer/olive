# ADR-0004: SQLite event store behind an interface

**Status:** accepted (2026-06-12)

## Context
Every decision must be auditable (CLAUDE.md rule 5). MVP needs a queryable,
zero-ops, single-file store; production fleets will eventually need
Postgres/ClickHouse and streaming.

## Decision
`aiosqlite` with `events` + `incidents` tables (schema in ARCHITECTURE.md),
accessed only through `store/events.py`'s interface. No raw SQL outside that
module. Raw payloads are never stored — SHA-256 hashes and bounded evidence
excerpts (≤200 chars) only.

## Consequences
- Zero-dependency audit trail, queryable with stock `sqlite3`.
- Store swap later is one module, not a refactor.
- WAL mode for concurrent demo reads; fine at MVP scale.
