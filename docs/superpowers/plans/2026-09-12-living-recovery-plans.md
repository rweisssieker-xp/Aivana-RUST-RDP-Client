# Living Recovery Plans Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the independent core and observer modules, then review the integrated result.

**Goal:** Keep proved Windows-service recovery plans current through scheduled read-only comparisons, persistent evidence invalidation and a native readiness overview.

**Architecture:** Import an exact plan, fresh clone receipts and their real production fingerprints from the promotion workflow. A protected contract book stores two independent intervals, the immutable baseline, latest comparison, sticky invalidation and revoked receipt references. An opt-in session scheduler reads production fingerprints; existing mutation gates consult the book before using tracked evidence.

**Tech Stack:** Existing Rust, egui, serde, DPAPI, bounded PowerShell/WinRM; no new dependencies.

**Spec:** User-approved next USP following docs/forgemind/innovation-opportunities-2026-09-12.md: intervals, relevant change detection, stale evidence invalidation and recovery readiness.

## Global constraints

- Keep existing uncommitted prerequisites in the current codex/mission-control workspace; do not reset, stash, commit or publish unrelated work.
- Read-only monitoring uses the current Windows identity and starts only after explicit session consent. No persisted consent or guest credentials, no unattended service changes.
- New comparisons never renew the rehearsal interval. Detected changes remain invalid until a new independently successful rehearsal is imported; reverting a change cannot revive old proofs.
- Production's existing one-hour evidence limit remains unchanged. Readiness is a planning status, not production authorization or a prediction of recovery success.
- Preserve revoked references through renewal and reject stale concurrent saves. Persistence failure blocks affected approvals.

## Tasks

- [x] Core: src/recovery_contracts.rs, tests. Contract, Check, Readiness, bounded Book, scheduling and renewal rules, fail-closed receipt guard and concurrent-save protection.
- [x] Observer: src/equivalence.rs. Extract actual rehearsal baseline in mapping order; shared fingerprint collector adds bounded, cancellable read-only production observation. Tests execute scripts with guarded system fixtures, not live infrastructure.
- [x] UI: src/app/contracts_panel.rs, navigation/state/capture. Readiness cards, interval settings, explicit manual/session monitoring, failure reporting, protected import/renew and return to rehearsal.
- [x] Gates: promotion.check_receipts consults persisted contracts; execution UI checks in-memory failures and in-flight comparison before Apply. Poll monitoring before execution. Late replies cannot update another revision; profile edits invalidate evidence before any new observation.
- [x] Validation: focused failing/passing domain and integration tests, full offline suite, both binaries, native screenshot and user documentation.

## Interface / review ledger

Observer owns RehearsalBaseline { observed_at, rehearsed_at, fingerprints } and observe_production(plan,cancel). Core consumes those exact fields; UI schedules Check { started,finished,fingerprints,error } against an ID/revision snapshot. Core Book::ensure_allowed and disk ensure_execution_allowed share the same gate. No task writes another task's owned module.

Ruling: a changed endpoint/plan requires a new contract, while a same-plan fresh rehearsal renews an existing contract. Revoked receipts are retained even after renewal. This avoids silently transferring authorization to different targets.

## Completion evidence

Full offline suite: 374 application tests + 16 team tests passed; five existing manual tests ignored. Latest persistence hardening: 17 focused contract tests passed. Both binaries built offline; explicit changed-file rustfmt check and git diff whitespace check passed. Native recovery-plans capture visually reviewed. No live WinRM/Hyper-V or paid model calls.

Independent review findings resolved: matching plan hashes block in-flight comparisons even with new receipt references; restrictive evidence is journaled before CAS/lock, reload preserves it, main/journal reads share the writer lock, and conflicting renewal reports failure after preserving revocations. Failed journal writes attempt a durable blocked marker. See docs/relayne-living-recovery-plans.md for operator behavior and storage limitations.
