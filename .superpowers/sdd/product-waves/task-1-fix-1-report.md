# Task 1 review fix 1 — case-linked functional verification

Base: `3633542`. Review: `.superpowers/sdd/product-waves/task-1-review.md` (P1, P2).

## Changes

- Each new incident-linked Execution run persists an optional `DiagnosticLink` with case ID, case binding, and exact production target. Old journal records deserialize with no link. A linked run requires exactly one mapping to that production target and the unchanged plan/hash; malformed links block journal load/save. Existing rehearsal, approval, proof, journal, and restoration gates still apply.
- While a handoff is active, mismatched preparation and approval controls are disabled, and execution dispatch rejects an unrelated selected run. Dismissing the handoff restores standalone execution. An already linked run may continue its pending verification or restoration when the UI profile selection changes: dispatch checks the immutable run link, while new preparation and approval require the selected original profile.
- Diagnostic Lab and Execution show the newest matching production run ID and its pending/succeeded/failed/unknown check outcome, actual check scope, observation time and evidence detail. A successful TCP check is labeled **TCP reachability only**. Success requires the existing `evidenced_success` conditions; a model match or rehearsal cannot supply this result. An unavailable journal is shown as unknown.
- Selecting another diagnostic case, changing its binding/reloading it, or accepting a new incident clears the application-level handoff. Prior journal runs remain tied to their original case and may be viewed again by selecting that case.

## Files

`src/execution.rs`, `src/execution/diagnostic_link_tests.rs`, `src/diagnostic_lab.rs`, `src/app/diagnostic_panel.rs`, `src/app/execution_panel.rs`, `src/app/intelligence_panel.rs`, `src/app/incident_panel.rs`.

## Verification

- `cargo test --locked --bin relayne diagnostic_link_tests -- --test-threads=1`: **5 passed**, 0 failed. Tests cover wrong target/changed case/plan, linked success/failure/unknown with observed time and evidence, rehearsal and old JSON, journal rejection of tampered links, and selection of only the case-linked production run. Final log: `.superpowers/sdd/product-waves/task1-fix1-tests-final.log`.
- `cargo test --locked --bin relayne changing_case_binding_or_incident_clears_active_verification_context -- --test-threads=1`: **1 passed**, 0 failed. Log: `.superpowers/sdd/product-waves/task1-fix1-context.log`.
- `cargo build --locked --bin relayne`: passed after final guard adjustment, 100 existing binary warnings. Log: `.superpowers/sdd/product-waves/task1-fix1-build-final.log`.
- `cargo clippy --locked --bin relayne --tests`: passed after final guard adjustment; 175 test-binary warnings (133 duplicates) and 220 normal-binary warnings, with no increase in the test-binary count from Task 1. Log: `.superpowers/sdd/product-waves/task1-fix1-clippy-final.log`.
- Scoped `rustfmt --edition 2024 --config skip_children=true --check` passed for the new test file, diagnostic core and diagnostic panel; `git diff --check` passed. Whole-file formatting of the existing execution/app files would introduce unrelated changes, so their changed blocks were kept locally formatted.

The full binary suite was run for Task 1 before this fix (546 passed, 4 ignored); this review fix used the focused regressions above. No customer system was contacted, and a linked check is not a claim of end-to-end application recovery beyond its configured scope.

Implementation commit: `1d71f72` (`Bind incident verification to exact execution run`).
