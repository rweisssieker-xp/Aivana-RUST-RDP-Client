# Relayne product completion waves

The user authorizes implementation of all six previously proposed improvement areas in waves with subagents. This specification bounds that work to strengthening existing modules, rather than claiming a complete enterprise platform or production certification.

## Required behavior

1. Carry a selected incident and its exact profile/evidence context into the existing Diagnostic Lab. Show a clear progression from scope, through approved read-only checks and interpretation, to functional verification. Explain findings in plain language. A diagnostic model match is provisional and never itself a repair proof.
2. Offer an onboarding/preflight checklist with actionable missing prerequisites. Navigation, profile selection, and saving remain inert. Missing local tools, target configuration, or live evidence are reported as missing/unknown, never guessed ready.
3. Present existing observed application dependency edges and their targeted probe evidence with source, destination, port, freshness, and limitations. Historical TCP relationships do not prove function or causation.
4. Make failed repair, failed restoration, cancellation, interruption, and unknown outcomes understandable. Strengthen meaningful state-machine and application-verification tests; unknown outcomes prevent later changes. Preserve durable journals and existing rollback gates.
5. Add optional server-backed team repair approvals bound to an exact run/plan/target/state. Separate requester and approver identity; enforce roles, expiry, revocation, and atomic one-use consumption. When team control is enabled, missing/unavailable/invalid approval blocks remote application. Existing local reviews and proof checks remain required. Standalone local mode remains explicitly identified.
6. Make team approval status, role boundaries, credential locality, and audit coverage understandable, with metadata-only decision/outcome records and focused acceptance tests. Detailed commands, output bodies, secret slots, tokens, passwords, and credential IDs never become shared approval/audit payloads.

## Constraints

- Work on `codex/relayne-product-waves` in the isolated managed worktree. Preserve original checkout and promotional media.
- Use existing Rust/egui architecture and current transports; avoid new dependencies unless essential and justified.
- No real remote mutations, customer connections, credential changes, deployment, push, or merge are part of development verification.
- Simulated evidence remains separate and explicitly labelled. Functional verification needs a distinct successful observed check with time and evidence; 4/4 diagnostic matches do not prove cause.
- Stores, digest/profile binding, review invalidation, current Windows identity for WinRM, and fail-closed behavior remain intact.
- Preserve old stored records through serde defaults or explicit safe migration; corrupt stores never silently become ready.
- Run build, meaningful tests, formatting and relevant static analysis. Document actual compiler/static-analysis limitations and customer acceptance remaining.

## Acceptance

Each wave delivers usable UI behavior with state-machine/validation tests, passes a separate scoped review, and updates the execution ledger. Final verification covers all binaries and the existing suite, plus offline/loopback tests for new approval lifecycle and failure gates. No local test result is described as proof of customer infrastructure compatibility.
