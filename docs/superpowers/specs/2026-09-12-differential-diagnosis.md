# Differential diagnosis, first supported model

Build the approved next innovation in development mode: compare hypotheses using distinguishing observations. No live hosts, credentials, model APIs or VM mutations are used during development.

The first model concerns an unavailable Windows application with four alternatives: stopped application service, application DNS failure, TLS handshake/trust failure, or an unhealthy upstream HTTP dependency. Its explicit assumption is one dominant fault across the configured checks. It is a diagnostic model, not a causal proof; conflicting checks must expose model gaps and possible multiple faults.

A typed engine chooses the next unobserved check by the number of surviving hypothesis pairs it distinguishes. If only one hypothesis remains, the other checks still need confirmation. Unknown, stale, future-dated, interrupted and mismatched results cannot become positive evidence. Observations are scoped to an immutable case and exact configuration. Simulation and real read-only evidence are separate case modes.

The UI integrates with Planen & Lernen. Development scenarios exercise the complete workflow without connections. A separately reviewed read-only mode can later use the existing selected Windows profile and job queue; this turn will not execute it. Fixed adapters read service state, DNS, TLS and dependency HTTP status. No generated shell or repair action is accepted. AI planning uses a locally generated prompt and strict reviewed JSON suggestions; no automatic model request, no AI-authored evidence, no target changes.

Cases and bounded observations are persisted with DPAPI and concurrent-write protection. A simulation report is visibly labeled and never fed into recovery/promotion receipts. The UI exposes supporting and contradictory observations, missing checks, a concrete next check and saved history. Tests exercise algorithms, binding, freshness, persistence, adapter behavior with doubles and the native UI.
