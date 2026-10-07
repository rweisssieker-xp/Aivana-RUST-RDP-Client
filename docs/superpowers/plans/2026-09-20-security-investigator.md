# Security Investigator Implementation Plan

**Goal:** Integrate the supplied autonomous investigator PRD as a runnable, bounded read-only investigation service in Relayne.

**Architecture:** Independent Rust service, SQLite domain store, fixed read-only connectors, shared authenticated HTTP/MCP commands, embedded web UI and native launcher.

**Tech Stack:** Existing Rust dependencies; no additional model service or browser build chain.

**Spec:** `docs/superpowers/specs/2026-09-20-security-investigator-design.md` and `docs/PRD_Autonomous_Security_Investigator_2026-09-20.md`.

## Global constraints

- Preserve existing uncommitted work and all existing remote-access features.
- A0 is default; A1 requires configured readiness; A2/A3 source mutations are denied.
- Tenant and actor come exclusively from server-side authenticated mappings.
- Unknown operations fail closed. Network calls are fixed, bounded, charged before execution and cannot expand scope.
- No live tenant credentials or existing RDP environment files are read during development.

## Review focus

- Forged tenant/role/object IDs must not cross authenticated scope.
- Retries, expired leases and duplicate ingestion must not reset budgets or duplicate evidence.
- Missing source/retention coverage and successful logins must never imply excluded exfiltration.
- Hostile log text must render as data and never become a tool command.
- Claimed completion and expired risk approvals must remain distinguishable from technical verification and valid decisions.

## Tasks

- [x] Core subagent: `src/investigator/core.rs` and `core_tests.rs`; public `Core::open` and authenticated `Core::execute`; tenant-scoped SQLite, queue, audit, evidence, deterministic analysis, budgets, human governance and exports. Test transaction/restart/security/reference behavior.
- [x] UI subagent: `src/investigator/web.html`, `src/app/investigator_panel.rs`, narrow existing app navigation edits. Consume POST `/api/command` with `{action,payload}`, bearer kept only in memory, safe text rendering. Include operational status and all governance views.
- [x] Primary agent: configuration validation, fixed Microsoft Graph contracts, authenticated API/MCP, persistent worker, standalone CLI and synthetic replay. Add bounded HTTP and credential/connector failure tests.
- [x] Integrate contracts, run focused binary tests, compile Relayne native UI, execute synthetic end-to-end HTTP/MCP checks, and repair failures.
- [x] Document setup, operating boundaries, source-readiness gates, replay evidence, backup/recovery and honest PRD coverage. Review final diffs without committing unrelated work.

## Shared interface

`Core::execute(&mut self, &Principal, action: &str, payload: Value, now: DateTime<Utc>) -> anyhow::Result<Value>` is the only business-command entry point. `Principal {tenant, actor, role}` is constructed by the server. UI, HTTP, MCP and worker reuse the same persisted domain state. Worker-only commands are excluded from external dispatch.
