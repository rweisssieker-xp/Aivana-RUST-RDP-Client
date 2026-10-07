# Remaining Investigator software expansion — 2026-10-06

Final PRD review also identified the FR-24 interactive site matrix as a software gap. A Sol subagent implements the authenticated, scoped, finding-specific read model and tests; a Luna subagent implements the browser table and existing assessment/supplier controls. Unchecked sites remain explicit and generic site assessments cannot clear unrelated findings. Final verification is recorded in `docs/investigator-validation-2026-10-06.md`.

The fetched remote main matches local HEAD f7d5bb8. The Investigator implementation is still local/untracked; this task does not publish unrelated dirty work.

Implement three bounded changes using parallel Sol/Sol/Luna workstreams: genuinely separated executor startup and API, native multi-instance scoped collection including CA policy reads, and reproducible offline acceptance/deployment/CI. Parent owns the independent signing utility and browser integration. Existing approved PRD governs scope; A3 remains optional and must not introduce irreversible autonomous actions.

Review shared credential boundaries across every collector instance, signed approval scope, budget persistence, stop/restore/restart effects, provider schemas and exact CA binding. Validate fresh builds, relevant tests/static analysis, offline acceptance harness and separate browser consoles with only synthetic credentials. Real tenant compatibility, rights, infrastructure and operating measurements remain explicitly unmeasured until an operator performs the live acceptance protocol.
