# Diagnostic Foresight Implementation Plan

**Goal:** Explain the possible effects of an available diagnostic probe before it runs.

**Architecture:** `Case::preview` borrows a case immutably, validates an available request and evaluates Pass, Fail and Unknown on separate ephemeral copies. Only typed hypothetical summaries leave the module. The existing panel renders them for the selected probe without persistence, jobs or network access.

**Tech Stack:** Rust, chrono, egui; no new dependencies.

**Design:** Show surviving hypotheses, known-check count, next check and the existing bounded-model conclusion for each assumed outcome. Use current freshness and attempt limits. All four checks remain necessary for a complete model match. Warnings distinguish assumptions from measurements and probabilities. Preview output cannot be applied as evidence or promoted to a repair.

- [x] Add `src/diagnostic_lab/foresight.rs` and expose it from the diagnostic module.
- [x] Render the three branches beside the selected probe in `src/app/diagnostic_panel.rs`.
- [x] Test real-case immutability, ambiguity, contradiction, repetition limits, expired evidence, four-check completion and rendering at 640/1440 pixels.
- [x] Run diagnostic regressions, offline build, native visual inspection and formatting checks.

Development only. Preserve existing changes; no real host connection, external model call, commit or deployment.

Validation: 28 focused diagnostic tests passed, 0 failures. Offline build, rustfmt check and git diff check passed. Native entry to preview visually inspected; no live connections or model calls.
