# Relayne Product Waves Implementation Plan

> For agentic workers: execute with superpowers:subagent-driven-development, task by task, with independent review.

**Goal:** Connect Relayne's existing investigation, verification, setup, dependency and team controls into a usable and tested operational flow.

**Architecture:** Extend the existing incident/diagnostic engines and egui panels. Keep read-only diagnosis distinct from functional verification and production change authorization. Add typed, server-controlled team approval lifecycle around the existing execution gates.

**Tech Stack:** Rust 1.95.0, egui/eframe, serde, existing encrypted stores and SQLite team service.

**Spec:** `docs/superpowers/specs/2026-10-08-product-waves.md`

## Global Constraints

All specification constraints apply. No remote customer changes, no fabricated proof, no weakening approvals, no secrets in shared records, no automatic connection on navigation/save. Preserve existing transports and storage compatibility. Each task receives a separate implementation report and scoped review.

## Wave 1

### Task 1: Guided incident and plain findings

- [x] Extend existing `src/incident.rs`, `src/diagnostic_lab.rs`, `src/app/incident_panel.rs`, `src/app/diagnostic_panel.rs` and minimal app routing as needed.
- [x] Add an inert context handoff from an incident to the exact selected Windows profile diagnostic case; retain source evidence references.
- [x] Show scope/checks/interpretation/functional-verification progression with supported, contradicted, missing and stale evidence in plain language.
- [x] Provide a distinct approved functional retest or a truthful link to existing functional verification; never mark a diagnostic model match as repair success.
- [x] Test handoff identity, changed profile, simulation separation, stale/missing data, and no verified state without functional evidence. Document behavior, test, commit, independent review.

### Task 2: Setup and first useful check

- [x] Extend existing profile/preflight UX using a focused module/panel, with minimal routing in `src/app.rs` and `src/app/desktop.rs`.
- [x] Show saved target/profile, protocol, local transport prerequisite and current authentication mode, required incident/service/application/dependency configuration, approval and live verification status.
- [x] Missing items expose direct navigation/preparation actions without connecting or modifying OS settings. Offline checks report remote reachability unknown.
- [x] Test checklist state and inert transitions, invalid/example URLs, missing tools and unsupported profiles. Document behavior, test, commit, independent review.

## Wave 2

### Task 3: Dependency evidence

- [x] Extend `src/telemetry.rs` and `src/app/insights_panel.rs` to show source → destination:port, known service, observation time/freshness and current targeted path probe outcome.
- [x] Explain historical observed relationship versus tested reachability versus unknown application function. Preserve exact endpoint binding.
- [x] Test stale edges, profile mismatch, unknown probe and shared dependency representation. No automatic probes. Document, test, commit, independent review.

### Task 4: Failed repair and restoration guidance

- [x] Inspect and extend uncovered failure transitions in `src/execution.rs`, `src/workflow.rs`, `src/test_lab` and their panels, choosing concrete gaps rather than duplicate tests.
- [x] Explain failed functional checks, restoration success/failure, cancellation and uncertain outcomes with safe next steps; never imply transaction rollback guarantees.
- [x] Add meaningful tests showing failed/unknown outcomes block later targets/actions, changed proof/review cannot execute, and persistence failure prevents mutation. Use fake/loopback adapters only.
- [x] Document, test, commit, independent review.

## Wave 3

### Task 5: Actor-bound team repair approval

- [x] Add typed request/decision/consume and metadata-only outcome lifecycle to the existing team service/client, with bounded safe storage and transaction rules.
- [x] Bind approval to exact reviewed run/plan/target/before-state/health/proof. Requester/approver must differ, viewer cannot request/decide/consume, decisions require authorized approver, and token revocation/expiry/replay invalidate authorization.
- [x] Integrate optional team-controlled mode into existing repair execution UI; revalidate/consume just before Apply while keeping all local gates and journal requirements. Outage must fail closed without remote enqueue.
- [x] Test role/self/expiry/replay/revocation/binding/persistence/outage failures and no-secret payloads. Document actual authority model, test, commit, independent review.

### Task 6: Team readiness and acceptance

- [x] Present role, pending/approved/consumed/expired repair approvals and decision/outcome audit status in existing Team UI, with clear standalone/team-controlled distinction.
- [x] Explain local credential storage and current Windows identity; mask tokens and avoid secret-bearing support exports.
- [x] Add missing boundary/integration tests and operator acceptance instructions for the new end-to-end flow.
- [x] Run whole-branch review, build, all appropriate tests, format and static checks. Fix material findings, preserve customer acceptance limitations.

## Review focus

Changed profile or edited plan after approval; stale or simulated evidence; server/token outage before apply; interrupted changes with uncertain outcomes; corrupt/persistence-failed stores. Every one must remain blocked or explicitly unknown rather than silently successful.
