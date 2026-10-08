# Task 2 review fix 1

## Changes

- The checklist now identifies the selected saved case and derives its incident, service, application URL, dependency URL, mode, and source from that case. With no selected case, it identifies and uses the unsaved new-case draft. Actions for a saved case lead to review or creation of a corrected case.
- The real service-name gate applies to both the displayed active configuration and saved-case readiness. `ExampleService` cannot show ready merely because the unsaved draft contains a real service.
- An active unsaved incident handoff that differs from the selected saved case's source blocks handoff and case readiness. Comparison binds record ID, profile ID, endpoint, and observation timestamp; a common profile alone is insufficient.
- Local-only routing, persisted-store error handling, and remote/evidence uncertainty remain unchanged.

## Verification

- `. .superpowers/sdd/product-waves/rust-env.ps1; cargo test --bin relayne setup_panel --offline`: 8 passed, 0 failed. Three new regressions cover selected case versus draft in both directions and two incidents on the same profile.
- `. .superpowers/sdd/product-waves/rust-env.ps1; cargo build --bins --offline`: passed.
- `. .superpowers/sdd/product-waves/rust-env.ps1; cargo clippy --bin relayne --offline`: passed; no diagnostic in the changed setup panel. Existing repository warnings remain.
- `rustfmt --edition 2024 --check src/app/setup_panel.rs` and `git diff --check`: passed.

Native narrow/wide rendering and actual remote approved checks remain for integrated operator acceptance.
