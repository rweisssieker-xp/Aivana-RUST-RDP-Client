# Diagnostic Scenario Comparison Implementation Plan

**Goal:** Run the seven existing diagnostic simulation scenarios together and expose expected versus actual model outcomes and probe sequences.

**Architecture:** A bounded in-memory runner uses the existing Case simulation and assessment methods. The diagnostic panel holds an optional report; JSON export contains fixture results only. No case persistence, external access, model calls or new dependencies.

**Tech Stack:** Rust, serde, chrono, egui.

**Design:** Four single-fault cases require all four checks. Multiple faults and healthy checks must expose model gaps; unavailable observations must exhaust exactly three attempts per probe and remain inconclusive. One fixed clock per run keeps evidence fresh; at most twelve probes per scenario. Report metadata explicitly identifies simulation and the model version. Matching a fixture is neither causal proof nor a repair result.

- [x] Add `src/diagnostic_lab/comparison.rs`: typed results, fixed fixtures, expected outcomes, bounded runner and strict terminal classification.
- [x] Integrate an explicit run button, expandable probe sequences and deliberate JSON copying in `src/app/diagnostic_panel.rs`.
- [x] Add tests for all outcomes, attempt limits, reproducibility, incomplete evidence and rendering without case/queue mutation.
- [x] Run offline diagnostic regressions, build and formatting checks; document actual results.

Existing working-tree changes remain intact. No commit, deployment or live acceptance is part of this development step.

Validation: 24 focused diagnostic tests passed; offline relayne build, rustfmt check and git diff check passed. Native simulation screenshot inspected. No full-suite rerun for this bounded addition.
