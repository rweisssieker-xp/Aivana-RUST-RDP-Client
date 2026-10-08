# Task 1 — guided incident to Diagnostic Lab

## Behavior

- A documented failure can be handed off only after selecting its exact saved Windows profile and matching endpoint. The handoff carries the event ID, timestamp, title, and source evidence IDs; navigation itself creates no case, saves nothing, and starts no job.
- The Diagnostic Lab prepares a real read-only case with that context. The source is part of the case binding. Existing cases without a source keep their original binding and remain readable through the `serde` default.
- The case view separates scope, approved read-only checks, model interpretation, and functional verification. It identifies absent, inconclusive, and stale observations and shows supported/contradicted/missing evidence for each model hypothesis. Even a four-check model match does not indicate repair success.
- Functional verification is explicitly pending. An action opens the existing reviewed execution workflow with case ID, diagnostic binding, original profile/endpoint, incident, and source evidence IDs. A changed profile blocks this handoff; the execution workflow retains its own reviews and observed functional checks. No diagnostic state is promoted to functional success.

## Changed files

- `src/incident.rs`: source snapshot and exact failure/endpoint validation.
- `src/diagnostic_lab.rs`, `src/diagnostic_lab/handoff_tests.rs`: source-bound case compatibility, verification context, focused tests.
- `src/app/incident_panel.rs`, `src/app/diagnostic_panel.rs`, `src/app/intelligence_panel.rs`, `src/app/execution_panel.rs`, `src/app.rs`: inert handoff, guidance and navigation.

## Verification

- `cargo test --locked --bin relayne handoff_tests -- --test-threads=1`: 4 passed, 0 failed.
- `cargo test --locked --bin relayne accepting_incident_context_is_inert -- --test-threads=1`: 1 passed, 0 failed, after the final UI change.
- `cargo test --locked --bin relayne -- --test-threads=1`: 546 passed, 0 failed, 4 ignored, before the final nonfunctional nested-if cleanup; the focused test was rerun afterward.
- `cargo build --locked --bin relayne`: succeeded; 100 compiler warnings in the normal binary build, primarily existing dead-code warnings. The test binary reported 28 warnings; these warning totals are not directly comparable to the coordinator's baseline no-run count of 31 because the commands/build targets differ.
- `cargo clippy --locked --bin relayne --tests`: succeeded; 175 warnings (133 duplicates). The one warning introduced by the new incident button was fixed and the final lint count dropped from 176 to 175.
- `rustfmt --edition 2024 --config skip_children=true --check` passed on the scoped new core, test, and incident/diagnostic panels. Whole-repository and `app.rs` format checks still report unrelated pre-existing formatting differences; no broad formatting churn was applied. `git diff --check` passed.

## Limits

Historical incident proximity is evidence to investigate, not proof of cause. The execution handoff is navigation with exact context and pending status; it does not itself create a run or record functional proof. No customer infrastructure or live repair was exercised. The four ignored tests were already marked ignored by the suite.

Implementation commit: `7f5f3da` (`Guide incident evidence into Diagnostic Lab`).
