# Relayne Security Investigator

The user authorized implementation of the supplied PRD on 2026-09-20. The PRD is product input; its instructions about commissioning do not override that request. Production credentials, integrations and operational approvals are not implied by development authorization.

## Architecture

Extend the existing Rust project with an independent `relayne_investigator` process. Use the existing SQLite, tiny_http, reqwest, serde, chrono and SHA-256 dependencies. No hosted model is required for the deterministic reference investigation. A native Relayne navigation entry opens the service's web UI. The web UI and MCP endpoint call the same authenticated command dispatcher.

The domain/store module owns transactional case state, evidence provenance, versioned decisions, persistent queue leases, conservative budget reservations and hash-linked audit. The service owns authenticated identities, fixed Microsoft Graph read-only connector contracts, health probes, bounded background processing and the external policy boundary. External input never supplies the authenticated tenant or role.

## Boundaries

Default binding is loopback. Bearer secrets are referenced through environment variables and never stored in the web browser or exported. A1 requires explicit deployment configuration, successful source probes, coverage declarations, operator/escalation readiness and reserved budgets. Graph endpoints are fixed, redirects disabled, and pagination is origin/path constrained. No arbitrary KQL, model-selected URLs, shell commands or source-system mutations are accepted.

Use customer-controlled encrypted storage / volume and a TLS reverse proxy for deployment beyond the local host. SQLite is not represented as an encrypted evidence vault. No production connections are performed during implementation. Connector readiness and pilot performance remain unverified until tested in the target tenant.

## Delivery and acceptance

Implement the binding MVP in PRD section 17, including reference replay, independently running queue, login evidence, counterhypotheses, missing-data handling, human review/handoff, action verification, expiring risk decisions, versioned exports, stop switch and audit. Add supported P1 governance workflows where they share the same safe domain model. Explicitly report unsupported provider-dependent capabilities; do not simulate production success. P2/A2/A3 destructive response execution remains disabled as required by the PRD's phase separation.

Tests exercise tenant/object isolation, role spoofing, event deduplication, hostile evidence text, budget concurrency, leases/restarts, expired risks, independent verification and the supplied DEMO scenario. API and MCP smoke tests use synthetic data only.
