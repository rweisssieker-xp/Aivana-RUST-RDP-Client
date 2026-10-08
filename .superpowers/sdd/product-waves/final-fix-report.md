# Final product-waves audit fix — expiry on list refresh

The authorized repair-approval list now uses an immediate SQLite transaction to load at most the requested page and materialize any elapsed pending or approved rows through the existing expiry helper. Each transition and its metadata-only `repair_expired` audit entry commit together before the response is returned. A failed audit insert rolls the state change back and prevents a successful list response. Repeated or concurrent refreshes see the stored terminal state and do not append duplicate expiry events. The viewer role is rejected before the transaction.

The Team panel distinguishes an expiry already returned by the server from a cached pending or approved row whose deadline has since passed on the local clock. Its copy and `docs/relayne-team.md` explain that reloading confirms the centrally stored transition and audit entry. No new authority, shared secret, or subsystem was added.

Verification used `.superpowers/sdd/product-waves/rust-env.ps1`:

- Focused `relayne_team` repair tests and the injected list-audit-failure test passed. The new list test covers elapsed pending and approved requests without a decision or consume after the deadline, viewer denial before writes, repeated and concurrent refreshes with one audit event per expiry, and unchanged denied and consumed records. The failure test rejects a falsely successful response and confirms rollback of both state and audit.
- Focused `relayne` Team status tests passed, including cached clock expiry versus recorded expiry labels.
- `cargo build --locked --bins` passed. Existing compiler warnings remain.
- `cargo clippy --locked --bin relayne --bin relayne_team -- -D clippy::correctness` passed. Existing non-correctness warnings remain.
- `rustfmt --check --edition 2024 --config skip_children=true` passed for `src/app/team_panel.rs`, `src/team_server.rs`, and `src/team_server/repair.rs`; `git diff --check` passed. Repository-wide `cargo fmt --all -- --check` still fails on previously documented formatting debt outside the fix.
- Final `cargo test --locked --bins -- --test-threads=1` passed after the last server and test changes.

This verification uses local loopback Team requests and temporary SQLite stores. It does not establish customer WinRM/RDP behavior, organizational identity-provider or TLS-proxy behavior, or that actor labels represent separate people. No live customer connection, deployment, push, or merge was performed.
