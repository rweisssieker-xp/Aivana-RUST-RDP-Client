# Task 4 report — failed repair and restoration

## Delivered

- Service execution now gives distinct next steps for failed functional checks, pending restoration, verified return to the original service state, and unknown remote/restoration outcomes. It explicitly says service-state restoration is not transaction rollback and requires separate application/dependency checks.
- Switching the selected diagnostic case does not strand verification or restoration already in progress. A newly dispatched capture or Apply still requires the matching diagnostic context. Existing review, profile, rehearsal-proof, fresh-capture and journal-before-mutation gates remain in place.
- Service failures and operator cancellation share `Run::fail_current`, which marks the current target `Unknown`, finishes the run and leaves later targets untouched.
- Workflow cancellation while awaiting evidence now records an uncertain `Cancelled` state. The UI explains failed, canceled, interrupted and persistence-only outcomes and directs the operator to inspect the journal and actual target before separately reviewed recovery.
- Test-lab trial guidance distinguishes a verified guest return with a retained checkpoint from a failed return; neither is production proof.
- Updated `docs/relayne-execution.md` and `docs/relayne-workflows.md`.

## Focused verification

Commands sourced `.superpowers/sdd/product-waves/rust-env.ps1` before Cargo. Results:

- `cargo test --bin relayne failed_restoration_is_unknown_and_never_advances_to_next_target` — passed. Covers failed or mismatched restoration evidence in a two-target rehearsal, with no second target or production proof.
- `cargo test --bin relayne failed_initial_journal_save_prevents_action_dispatch` — passed. Injected save failure before worker creation; loopback endpoint was untouched.
- `cargo test --bin relayne cancelled_manual_checkpoint_never_dispatches_later_action` — passed after cancellation-state refinement. The waiting checkpoint ends as uncertain `Cancelled` and later loopback HTTP action remains untouched.
- `cargo test --bin relayne changed_diagnostic_blocks_new_dispatch_but_not_in_flight_verification_or_restore` — passed. New dispatch remains blocked on context mismatch; in-flight verification/restoration can finish.
- `cargo test --bin relayne runner_persists_failure_and_never_launches_following_step` — passed. Existing loopback regression remains intact.
- `cargo build --bins` — passed; main binary emitted 100 warnings.
- `cargo clippy --bin relayne --no-deps -- -D clippy::correctness` — passed; 219 non-correctness warnings remain in the repository.
- `git diff --check` — passed.
- `rustfmt --check --edition 2024 --config skip_children=true src/workflow.rs src/app/workflow_panel.rs src/app/change_trial_panel.rs` — passed after formatting those touched files.
- Scoped rustfmt check of `src/execution.rs` and `src/app/execution_panel.rs` still fails on formatting debt already present at `HEAD^` (verified against both previous file versions). `cargo fmt --all -- --check` also fails on broad pre-existing differences across unrelated files, including `src/bin/relayne_team.rs` and `src/ticket_intake.rs`. No broad formatting rewrite was applied.

All new tests use fake journal storage, state transitions or a local loopback listener. They do not prove behavior on customer WinRM, Hyper-V or application infrastructure. The final whole-branch suite remains Task 6's integration gate.
