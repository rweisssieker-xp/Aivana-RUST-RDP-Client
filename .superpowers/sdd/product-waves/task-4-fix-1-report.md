# Task 4 fix 1 — restored-state wording

The review found that `Restored` can follow an Apply response with verified rollback before a functional check runs. The execution panel now says the functional check failed only when saved health evidence records a failed check. Otherwise it says no functional check result was recorded. Both messages retain the verified original service state, separate application/dependency inspection, and the warning that this is not transaction rollback. No execution states or gates changed.

Verification (with `rust-env.ps1` loaded):

- `cargo build --bin relayne` — passed; 100 existing compiler warnings.
- `cargo test --bin relayne failed_restoration_is_unknown_and_never_advances_to_next_target` — passed.
- `cargo clippy --bin relayne --no-deps -- -D clippy::correctness` — passed; repository warnings outside correctness remain.
- `git diff --check` — passed.

This is a local wording correction. It does not establish behavior on customer infrastructure.
