# Relayne implementation and acceptance ledger

User authorization: complete the outstanding USP and functionality list, including a new product name. Working name: Relayne. Native Rust desktop retained. Existing persisted Aivana paths stay readable; visible branding and start artifact change without deleting user data.

## Parallel ownership
- team_backend_complete: team_server.rs, team_client.rs, app/team_panel.rs, src/bin/relayne_team.rs; authenticated SQLite backend, server-enforced roles, revision conflicts and audit.
- protocol_expansion: terminal.rs, app/terminal_panel.rs, rd_gateway.rs, gateway vendor changes, RemoteApp channel work. Root owns shared transport hooks.
- semantic_vision: vision.rs, app/vision_panel.rs, teaching and recordings integration. Native OCR, semantic target resolution and redaction before storage.
- root: shared app/main/dependencies, intelligence/planning/remediation/evidence modules, monitor mapping, rebranding, integration and tests.

## Acceptance
- [x] Real local OCR and explicit semantic word matching; ambiguous/stale matches blocked. Heuristic redaction before persisted image/OCR, not a completeness guarantee.
- [x] Natural-language planning into validated editable actions; no unreviewed arbitrary generated execution. Cloud API live invocation remains unverified.
- [x] Supported service-state repair captures pre-state, verifies post-state and attempts/restores the original service state with outcome evidence. No general rollback claim.
- [x] Cross-host cause candidates reference observed evidence and explicit dependencies; no correlation asserted as proven cause.
- [x] Experience store retains prerequisites, failed attempts and verified outcomes for retrieval.
- [x] Central team service with auth, roles, revisions, revocation and audit; native client tested against local service.
- [x] Interactive embedded SSH PTY terminal with input/output/resize and bounded lifetime.
- [ ] Gateway/RemoteApp complete: NTLM and external MFA waiting implemented/tested locally, RemoteApp via native Windows handoff. Embedded RAIL, gateway interactive consent and additional MFA transports remain open.
- [x] Remote monitor panes with saved local positions and correct coordinates/input ownership. Physical-display acceptance remains open.
- [x] Relayne branding/start binary with compatible existing user storage.
- [x] Full local tests, native renderer capture and explicit live-acceptance ledger in docs/relayne-acceptance.md.
- [ ] Authenticated external/live acceptance, team deployment and cloud planner live acceptance.

No repeat of failed live credentials, no external deployment, no secret uploads or commits by implementers. Authentication required for live acceptance remains external input; local implementation proceeds. Agents use isolated file ownership under dispatching-parallel-agents skill.
