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
- [ ] Implement async job runner with cancellation, timeout, bounded output and hidden Windows processes.
- [ ] Provide SSH command execution, WinRM typed inventory/services/processes/events queries, explicit reviewed service actions and SFTP list/upload/download jobs using local OpenSSH.
- [ ] Validate endpoints, separate args from shell data, require strict SSH host-key checks, avoid credentials on process command lines.
- [ ] Native German panel shows command preview, actual output, progress/error, cancellation and file queue. Use `OperationsState::default()` and `AivanaApp::operations_view(&mut self, ui: &mut Ui)`; root field `operations`.
- [ ] Test command construction, invalid host/path input, queue lifecycle, timeout/cancel, and output bounds.

## Task 2: Missions, knowledge and history
Files: src/mission.rs, src/app/mission_panel.rs; root integration in app.rs, desktop.rs, main.rs.
- [ ] Persistent mission targets, steps, evidence, per-host status, manual verification, pilot gating and abort/resume semantics.
- [ ] Target selection + objective + editable steps, preview, first-host pilot and explicit rollout; no uncontrolled generated commands.
- [ ] Fleet search over captured local evidence; timestamped snapshots and structured key/value changes across time or targets.
- [ ] Reusable procedure from completed mission, expectation and rollback notes, import/export handoff with collision-safe IDs.
- [ ] Test restart interruption, cannot pass without evidence, pilot gate, stale targets, import validation and diff/search.

## Task 3: Inventory and credential integration
Files: src/integrations.rs, src/app/integrations_panel.rs; root hooks.
- [ ] AD inventory via installed PowerShell AD module, explicit JSON inventory import with review/dedup and dynamic rule groups.
- [ ] Vault integration through installed KeePassXC CLI or Bitwarden CLI, secret handling only through stdin/output memory and DPAPI store; prerequisites visible.
- [ ] Test identity validation, imports without secret restoration, target matching and inventory collision handling.

## Task 4: Recording, session layout and interoperability
- [ ] Add explicit local recording controls with bounded retained frames and searchable event index, playback/export; do not equate keyframe archive with video.
- [ ] Add detachable viewports and persist named session layouts without automatic connections.
- [ ] Inspect available RDP stack for RemoteApp/gateway MFA support and implement only where real protocol behavior is available; report remaining upstream limitations.

## Task 5: Integration and review
- [ ] Format, build, full tests, focused native rendering tests and renderer screenshot.
- [ ] Independent review of new modules and integration, fix actionable findings.
- [ ] Update exact implementation/capability ledger; explicitly distinguish local tests from live acceptance.

## Execution ledger
2026-09-11: Started on codex/mission-control preserving existing working tree. Read existing modules and prior verification; broad feature families have independent modules. Task 1/2 share app hooks only, owned by root. Task 3 uses same profile/credential stores through child module. Task 4 hooks session rendering and frame ingestion. No worker edits shared hooks.
