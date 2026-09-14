# Product completion implementation plan

> **For agentic workers:** Execute independent domains with `superpowers:dispatching-parallel-agents`; the primary agent owns integration and acceptance.

**Goal:** Complete US-English product coverage and implement the missing delivery, commercial, operational and application-check capabilities requested on September 14.

**Architecture:** Preserve the native Rust/egui client and local evidence boundaries. Put commercial secrets on the authenticated team server. Production distribution requires externally configured publisher identity; development fixtures cannot satisfy live acceptance.

**Tech Stack:** Rust, egui, SQLite, reqwest, ring, Windows PowerShell, Stripe Checkout and Billing.

**Spec:** User instruction: “1 erst einmal komplett us-en; 2 bis 7 komplett einbauen.” Stripe selected subsequently.

## Global constraints

- Work on main as explicitly authorized; preserve unrelated work.
- Development only: no live RDP, WinRM, Hyper-V, model, payment or ticket actions.
- US-English first; do not remove saved profiles or reinterpret protocol identifiers while translating.
- Do not manufacture certificates, provider accounts, legal approval, tax treatment or successful live acceptance.

## Deliverables and acceptance

- [x] US-English: central app, specialist panels, runtime messages and user docs. Preserve machine-readable strings and existing translated lookup keys. Default to en-US; accept the user's us-en alias. Audit remaining German user-facing literals and render representative views.
- [x] Delivery: production manifest, pinned Authenticode publisher verification, bounded HTTPS downloads, immutable install versions, retained rollback and explicit data-backup guidance. Reject unsigned/tampered/traversing packages in isolated tests.
- [x] Stripe: server-side Checkout/Portal integration, authenticated account binding, bounded webhook verification and idempotent entitlement reconciliation. Never trust client payment success redirects as license proof. Test signatures, account separation and stale/replayed events offline.
- [x] Operations/legal: English support and privacy data-flow documentation, dependency inventory tooling and explicit unresolved business approvals. Keep commercial readiness false until actual external gates are satisfied.
- [x] Acceptance: reproducible environment matrix and evidence-bound acceptance status. Existing local successes must never satisfy remote interoperability gates.
- [x] Application checks: reviewed local recording assertions compiled into the existing health-check workflow with evidence digest binding, no automatic execution, rejection of unsafe or stale inputs, and end-user UI.
- [x] Background/integrations: assess logged-out operation and authenticated webhook/provider additions; implement with scoped authorization, durable attempts, duplicate detection and no external action without the existing approval boundary.

## Verification and integration

- Run focused tests per independent domain before integration.
- Run the complete offline Rust application/team suite after integration; retain ignored live tests as outstanding, never count them as passes.
- Build both application and team binaries; execute isolated distribution checks.
- Review the diff for credentials, accidental protocol/persistence-key translation and misleading readiness claims.
- Commit completed verified changes to main, push without force and verify the remote hash.
- Report exact implemented scope, test evidence and remaining external prerequisites.
