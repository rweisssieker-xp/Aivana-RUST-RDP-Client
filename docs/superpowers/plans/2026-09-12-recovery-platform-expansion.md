# Recovery Platform Expansion Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for isolated modules and review each deliverable.

**Goal:** Implement the six user-approved missing features: background monitoring, scheduled clone drills, expert procedure compiler, broader repairs, compatibility catalog, and ticket integration.

**Architecture:** Extend the existing typed recovery, teaching, workflow, proof and trust systems. Background work runs through an explicitly enabled per-user Windows scheduled task; external tickets use reviewed adapters and outbound actions need a separate user action. No production mutation from a schedule or imported ticket.

**Tech Stack:** Rust/egui, existing reqwest/serde/DPAPI, bounded PowerShell, Windows Task Scheduler.

**Spec:** The user's “bau das alles ein” approves the six features listed immediately before it. Implementation is local; live infrastructure/account activation remains an operator configuration step.

## Global constraints
- Preserve all existing dirty work. No commits, reset, stash, deployment or live customer calls.
- Reuse typed validation, target binding, fresh rehearsal receipts, audit journals and explicit production review.
- Credentials never appear in task arguments, logs or ticket exports. Persist any operator-approved unattended secrets with user DPAPI only.
- No arbitrary commands synthesized by AI or ticket text. Failed/ambiguous evidence never grants execution authority.
- Tests use local fixtures; report infrastructure/provider gaps honestly.

## Deliverables
- [x] Background module and panel: persisted opt-in, one-pass headless worker, task install/remove, notifications, schedule/consent expiration, no duplicate runs, local tests.
- [x] Scheduled drills: exact authorized plan and clones, bounded credentials, fresh equivalence and real receipts, clear invalidated evidence only through existing renewal, failures notified.
- [x] Expert procedure compiler: visible demonstration input, typed parameterization/assertions, AI proposals, ambiguity rejection, reviewed adoption into existing teaching/workflow pipeline.
- [x] Broader repairs: at least one substantive additional supported recovery operation, real before/after verification and rollback, preserve legacy stored cases and current guards.
- [x] Compatibility catalog: evidence-bound signed package matching against actual environment fingerprints; unknown and mismatch states; reviewed package handoff.
- [x] Ticket integration: bounded import, deduplication, case linking, previewed result export/outbound adapter, no ticket-triggered execution.
- [x] Integrate navigation/CLI, document scope and activation, focused/full tests, both binaries and native capture, independent final review.

## Ownership

Background/drills agent owns new recovery_daemon module and panel only. Compiler agent owns new procedure_compiler and teaching-panel changes. Repairs agent owns recovery domain/tests/panel and required execution/promotion changes. Parent owns catalog/tickets modules, global state/CLI/navigation wiring and final integration. Announce interface conflicts before editing another owner's file.

## Completion evidence — 2026-09-12

All six deliverables are integrated. Independent reviews covered compiler, background/drills, restart semantics and catalog/ticket persistence. Findings were resolved: bounded reads, fail-closed catalog loading, staged catalog writes, stable ticket case identity, explicit uncertain-delivery resolution and compiler index bounds.

Full offline suite: 416 application tests and 16 team tests passed; five existing tests ignored. Final catalog hardening: four focused tests passed. Both binaries passed offline check and build. Native background and ticket/catalog captures were inspected. Live Task Scheduler installation, WinRM/Hyper-V infrastructure, model output quality and Jira delivery require operator configuration and were not exercised against external systems.
