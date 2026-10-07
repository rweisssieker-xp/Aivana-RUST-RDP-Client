# Investigator implementation validation — 2026-10-05

Historical snapshot. The separate executor process and native CA policy reads were added afterward; see [the October 6 validation](investigator-validation-2026-10-06.md) for the current implementation and remaining acceptance limits.

The approved continuation is implemented using three concurrent subagents: GPT-6 Sol for native collection and signed A2 execution, GPT-6 Luna for pilot records/documentation and routine static-analysis fixes. No Astra was used.

## Delivered

- Native fixed-query collectors: Entra token/session context (Graph beta), Defender device process events, Azure Monitor StorageBlobLogs and CommonSecurityLog, and read-only Windows AD CS LDAP inventory.
- Explicit reviewed site bindings and bounded user/device allowlists; workspace/CA site scope must be confirmed. One configured source instance per source type is supported. Missing, partial, failed and inapplicable coverage stays visible.
- Leased A1 worker runs enabled scoped collectors and evidence playbooks, checking readiness before each provider request. It does not execute A2 actions autonomously.
- A2 revokeSignInSessions executor uses a separate Entra client identity, exact Ed25519 approvals, tenant/site/target/action/policy/version/expiry binding, additional independent signers for critical/Tier0 targets, shared persistent budgets and at-most-once dispatch fencing. Unknown outcomes require independent reconciliation.
- Attributable immutable pilot observations, measured-metric reports and explicit missing operating evidence. Observations and matching audit events commit atomically.
- Configuration, authenticated HTTP/MCP command routing, browser controls, native launcher description, restore health invalidation and release-component revisions.

## Fresh local evidence

- `cargo test --bin relayne_investigator`: **82 passed, 0 failed**, no ignored tests.
- `cargo clippy --bin relayne_investigator -- -D warnings`: passed.
- `cargo build --bin relayne --bin relayne_investigator`: passed. Native Relayne retains 100 existing compiler warnings; Investigator build has no compiler warnings.
- JavaScript syntax, bundled AD CS PowerShell syntax and changed-file whitespace checks: passed.
- Browser: synthetic local sign-in, Collector/A2/Pilot statuses, scoped-case creation and collector payload verified; no console errors/warnings. Collector payload contains exactly case_id and source. The test tab was signed out and closed; its server was stopped.
- CLI synthetic backup/verify/restore: SQLite integrity `ok`, audit chain `verified`, 44 audit events and one synthetic DEMO case; restore status `restored_paused`, reconciliation required.
- Cross-component tests cover immutable pilot audit compatibility with backup/restore, scope rejection, signature/expiry/stop/restore gates, persistent response fencing, worker readiness and normalized provider evidence through existing playbooks.

Logs: `target/investigator-continuation-tests.log`, `target/investigator-continuation-clippy.log`, `target/investigator-continuation-build.log`. Synthetic backup artifacts: `target/investigator-continuation-validation-20261005-084655/`.

## Live acceptance and intentional boundaries

No production credential was read and no production collector request, session revocation or external notification was executed. Actual tenant permissions, licenses, provider compatibility, encrypted storage, retention, notification receivers, named operators, release review, shadow/canary and measured RTO/RPO/availability/analyst effort/cost remain operator acceptance steps.

AD CS LDAP does not expose the CA-wide issuance policy: that prerequisite remains an explicit gap until separately sourced. Graph beta token/session fields can be absent or change; partial coverage does not prove token misuse. The executor's same-provider signInSessionsValidFromDateTime observation does not prove session/token invalidation; independent effectiveness evidence is required. Response credentials have a separate Entra identity, but the executor runs in the same process; this is not process isolation. A3 is optional in the PRD and remains disabled.

Operating instructions: investigator-live-collectors.md, investigator-response.md, investigator-pilot.md, security-investigator-acceptance.md.
