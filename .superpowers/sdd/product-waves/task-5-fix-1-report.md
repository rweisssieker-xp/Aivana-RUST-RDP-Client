# Task 5 fix 1 — review withdrawal and outcome durability

## Changes

- A returned consume receipt advances Apply only while the operator's local review remains checked. The final Apply dispatch checks the same flag again. Successful enqueue clears the flag, so another Apply cannot reuse that review; failed persistence or enqueue does not claim a committed dispatch. A withdrawn review discards the receipt and stays in Review.
- Outcome delivery now saves the exact pending event, including its UUID and timestamp, before starting the network worker. A journal error blocks the Send action. If the server acknowledges an outcome but saving `delivered=true` fails, the in-memory flag returns to pending; the durable event retains its original ID and payload for the same-payload retry after restart. Outcome handling remains after terminal execution phases and does not gate an already launched Restore.

## Focused verification

Cargo commands sourced `.superpowers/sdd/product-waves/rust-env.ps1` first.

- `cargo build --locked --bins` — passed; 113 existing compiler warnings in `relayne`.
- `cargo test --locked --bin relayne repair_execution_tests -- --test-threads=1 --quiet` — 7 passed. New fake-enqueue coverage withdraws review while a valid consume response is in flight and again at final dispatch; it checks pre-send journal failure, acknowledgement-save failure, exact event equality after reload, and successful retry persistence. Existing checks cover single dispatch and Restore through team outage.
- `cargo test --locked --bin relayne_team repair_denial_expiry_unknown_fields_and_outcome_idempotence -- --test-threads=1 --quiet` — 1 passed. The server accepts an identical event twice, rejects the same ID with changed content, and stores one row.
- `cargo clippy --locked --bin relayne -- -A warnings -W clippy::collapsible_if` — passed without targeted warnings. `git diff --check` passed.
- `cargo fmt --all -- --check` still fails on repository-wide existing formatting. The new/edited regions were aligned with rustfmt's suggestions without changing unrelated formatting.

The earlier Task 5 serial full-suite pass was not repeated for this scoped fix; these tests exercise the changed state paths. The client fault tests use injected journal paths and fake enqueue, while the server idempotence test uses its loopback harness. No real customer service or live OIDC provider was involved.
