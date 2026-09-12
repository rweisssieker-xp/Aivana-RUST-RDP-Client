# Recovery Agent Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement and review the bounded core while integrating the native UI.

**Goal:** Implement one incident-to-recovery workspace using existing clone, approval and execution components.

**Architecture:** A bounded DPAPI case book holds incident provenance. Typed AI suggestions are reviewed before preparing a clone draft. The draft carries a case ID into a production Run; the recovery overview derives completion from that exact run's deterministic evidence.

**Tech Stack:** Rust, egui, serde, existing reqwest and DPAPI helpers; no new dependencies.

**Spec:** docs/forgemind/innovation-opportunities-2026-09-12.md, highest-ranked Recovery Agent card.

## Global Constraints

- Windows service recovery with explicit HTTP health criteria; preserve clone and production approval gates.
- No automatic remote connections, credential upload, customer outreach, billing change or tenant deployment.
- Current workspace is on codex/mission-control with substantial uncommitted prerequisite functionality. Ruling: integrate here without stashing, resetting or committing those changes; a clean worktree would omit the required product foundations.
- This implements the first product slice, not measured savings or a hosted SaaS launch.

## Tasks and interfaces

- [x] Core domain and tests: `src/recovery.rs`; `Suggestion { service, rationale }`, `Case::new`, `Book::{load,save}`, `outcome(&Case, &[Run])`. Reject incomplete model output and invalid evidence; round-trip protected storage. Domain agent owns only this new module.
- [x] Run provenance: `Run.recovery_case: Option<Uuid>` defaults to None for existing journals. Promotion draft persists the same optional ID. Never infer association from the latest global run.
- [x] Native integration: `src/app/recovery_panel.rs`, app state/view/navigation/capture. Review incident and typed service suggestion, then prepare existing promotion UI; retain a selected case and allow return to the matching execution. Navigation itself starts no execution.
- [x] Integration tests: opening a case produces no job; blocked or busy promotion is not overwritten; draft adoption clears old proof/review/credentials; unrelated run cannot be selected as case evidence; narrow/wide renderer supports Recovery.
- [x] Verify focused tests, full offline tests and both binaries; inspect native recovery screenshot and update README plus feature documentation.

## Review ledger

Core/UI share `Case`, `Book`, and `Run.recovery_case`; ownership is disjoint except the parent wires module registration and Run field. Promotion/execution both consume the same optional provenance ID. The ID is carried only after deliberate draft adoption. AI is advisory; no added executable model action or automatic success claim.

The twenty-case timing experiment remains a subsequent empirical validation activity; no fabricated baselines are shipped.

Verified: 354 application + 16 team tests passed, five existing manual tests ignored; both binaries built. After widening the intake fields, the narrow/wide renderer test passed again and both binaries were rebuilt. Independent review reports no residual findings. Native screenshot inspected. Branch and existing uncommitted work retained in place.
