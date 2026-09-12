# Mission Control Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for bounded implementation and independent review.

**Goal:** Turn the existing native RDP workspace into an operational multi-host administration workspace with persistent missions, inspectable automation, evidence history and real remote management integrations.

**Architecture:** Preserve Rust/egui/IronRDP and existing edits. Dedicated modules own mission state, remote jobs and integrations. The app supplies profiles and session evidence. Remote operations run off the UI thread; process exit alone never proves a business outcome.

**Tech Stack:** Existing Rust dependencies, Windows PowerShell and OpenSSH where installed.

**Spec:** User-approved conversation of 11 September: implement the outstanding Mission Control and administration features. Existing compatibility limits remain tracked in docs/rdp-workbench.md.

## Global Constraints
- Never invent server data or success. Show transport and local tool prerequisites.
- No live authentication retries against the previously failing test credentials.
- No external changes during implementation; execution is exposed through deliberate app controls.
- Preserve credentials; never put passwords in command arguments, plans or exports.
- Retain current uncommitted work. No automatic commits or publishing.
- Modules use bounded output, explicit cancellation, source identity and timestamps.

## Task 1: Remote operations
Files: src/operations.rs, src/app/operations_panel.rs. Root integrates module and state hooks.
- [x] Implement async job runner with cancellation, timeout, bounded output and hidden Windows processes.
- [x] Provide SSH command execution, WinRM typed inventory/services/processes/events queries, explicit reviewed service actions and SFTP list/upload/download jobs using local OpenSSH.
- [x] Validate endpoints, separate args from shell data, require strict SSH host-key checks, avoid credentials on process command lines.
- [x] Native German panel shows command preview, actual output, progress/error, cancellation and file queue. Use `OperationsState::default()` and `AivanaApp::operations_view(&mut self, ui: &mut Ui)`; root field `operations`.
- [x] Test command construction, invalid host/path input, queue lifecycle, timeout/cancel, and output bounds.

## Task 2: Missions, knowledge and history
Files: src/mission.rs, src/app/mission_panel.rs; root integration in app.rs, desktop.rs, main.rs.
- [x] Persistent mission targets, steps, evidence, per-host status, manual verification, pilot gating and abort/resume semantics.
- [x] Target selection + objective + editable steps, preview, first-host pilot and explicit rollout; no uncontrolled generated commands.
- [x] Fleet search over captured local evidence; timestamped snapshots and structured key/value changes across time or targets.
- [x] Reusable procedure from completed mission, expectation and rollback notes, import/export handoff with collision-safe IDs.
- [x] Test restart interruption, cannot pass without evidence, pilot gate, stale targets, import validation and diff/search.

## Task 3: Inventory and credential integration
Files: src/integrations.rs, src/app/integrations_panel.rs; root hooks.
- [x] AD inventory via installed PowerShell AD module, explicit JSON inventory import with review/dedup and dynamic rule groups.
- [x] Vault integration through installed KeePassXC CLI or Bitwarden CLI, secret handling only through stdin/output memory and DPAPI store; prerequisites visible.
- [x] Test identity validation, imports without secret restoration, target matching and inventory collision handling.

## Task 4: Recording, session layout and interoperability
- [x] Add explicit local recording controls with bounded retained frames and searchable event index, playback/export; do not equate keyframe archive with video.
- [x] Add detachable viewports and persist named session layouts without automatic connections.
- [x] Inspect available RDP stack for RemoteApp/gateway MFA support and implement only where real protocol behavior is available; report remaining upstream limitations.

## Task 5: Integration and review
- [x] Format, build, full tests, focused native rendering tests and renderer screenshot.
- [x] Independent review of new modules and integration, fix actionable findings.
- [x] Update exact implementation/capability ledger; explicitly distinguish local tests from live acceptance.

## Execution ledger

Final verification: 224 tests passed, 4 live tests ignored, build successful. Native renderer screenshot saved to docs/gui-concepts/mission-control-implemented.png and inspected. Scoped final independent review has no important findings. Full scope is NOT claimed complete: remote protocol extensions, central team backend and autonomous semantic planning remain explicitly open in docs/mission-control.md; live acceptance remains blocked by unavailable verified authentication.
2026-09-11: Started on codex/mission-control preserving existing working tree. Read existing modules and prior verification; broad feature families have independent modules. Task 1/2 share app hooks only, owned by root. Task 3 uses same profile/credential stores through child module. Task 4 hooks session rendering and frame ingestion. No worker edits shared hooks.

2026-09-11: Tasks 1–4 implemented in their bounded native forms; see docs/mission-control.md for capabilities and open protocol/team/autonomous-planning scope. Operations and inventory agents completed; independent reviewer findings were fixed and scoped re-reviewed. Teaching added with source-timestamp input capture and eight tests. Full suite: 224 passed, 0 failed, 4 live tests ignored. Build and native renderer capture in progress. Existing unrelated orchestrator files and concurrent repository checkpoint commits preserved.
