# Relayne Generic IT Helper — architectural specification

Date: 2026-10-08

Status: proposed architecture for user review; no implementation authorized by this document alone.

Base: `671080c`, following the completed six product improvements. Working branch: `codex/relayne-generic-helper` in the existing attached isolated worktree. Previous branch and original checkout remain intact.

## 1. Outcome and scope

The operator describes an IT problem in plain language. Relayne asks for missing facts, binds the problem to reviewed targets, collects domain-specific evidence, proposes distinguishing checks, presents an evidence-linked repair, applies a supported change only through the existing authorization discipline, and verifies the original symptom and declared performance limits. A reviewed lesson can subsequently be reused only after context matching and fresh validation.

All ten previously discussed areas are included: intake, system context, specialist diagnostics, extensible connectors, investigation planning, provenance, versioned action catalog, SQL change approval, end-to-end verification, and operating knowledge. These form one shared helper workflow, not ten independent assistants.

“Generic” means extensible, versioned capabilities with implemented initial adapters and explicit unsupported states. It does not mean arbitrary generated command execution or universal coverage of every vendor/product/version. Initial supported families are Windows/WinRM, Linux/OpenSSH, public HTTP/network checks, PostgreSQL, SQL Server, Docker, Kubernetes, Azure, and AWS. Each family has named bounded read capabilities described below. New adapters must satisfy the same execution and evidence contracts.

A complete delivery requires executable adapters and a usable desktop workflow, not only structs, mocked results, documentation, registry entries, or scripts run outside Relayne. Unit/fixture verification and live interoperability must be reported separately. Unavailable environments cannot be represented as tested.

## 2. Grounded existing capability

Twelve parallel read-only audits examined the current source, documentation, and recorded SQL sandbox evidence. Reuse these established boundaries:

| Concern | Existing implementation | Extension direction |
|---|---|---|
| Targets and context | `models::ConnectionProfile`, `mission::Target`, exact endpoint comparison | Keep profile UUID and endpoint identity; add typed service/database/resource scopes |
| Incident reconstruction | `incident.rs`, `app/incident_panel.rs` | Preserve historical records; add provenance and an immutable helper-case envelope |
| Topology | `telemetry.rs`, `app/insights_panel.rs` | Derive inventory from saved profiles/observations; retain both capture refs and freshness |
| Diagnosis | `diagnostic_lab.rs`, `diagnostic_lab/foresight.rs`, fixed `adapter.rs`/`probes.ps1` | Generalize hypothesis/probe capabilities without weakening the existing four-probe semantics |
| Processes and remote checks | `operations.rs`, bounded cancellable `JobQueue` | Typed adapter dispatch; no model-generated shell/SQL path |
| Planning | `intelligence.rs`, `mission.rs`, `procedure_compiler.rs` | Local-first intake and advisory structured plans; reuse normal mission handoff |
| Workflow catalogs | `workflow.rs`, `repair_catalog.rs`, `recovery_contracts.rs` | Versioned typed proposals, exact reviewed digest, protected persistence |
| Change authorization | `repair_approval.rs`, `team_server/repair.rs`, `app/execution_panel.rs` | Versioned generic action binding alongside backward-compatible service approval |
| Success proof | `execution.rs`, `test_lab.rs`, `promotion.rs`, `equivalence.rs` | Separate functional and performance receipts; production success remains bound to production run |
| Knowledge | `execution/learning.rs`, `memory.rs`, recovery contracts | Reviewed lessons from verified journal evidence; invalidation and fresh revalidation |
| Desktop workflow | `app.rs`, `app/desktop.rs`, existing panel pollers | One IT Helper entry with a shared case context, existing navigation and asynchronous workers |

The existing “OptionalCloudAiProvider” delegating to local heuristics is not a general LLM assistant. The real structured OpenAI planner already exists separately. The frame-pipeline benchmark measures local CPU work, not application/SQL/network performance.

## 3. Architecture and contracts

### 3.1 Shared case and intake

A versioned helper case references existing incident and mission IDs where applicable, saved profile IDs, immutable endpoint/scope fingerprints, and journal runs. It owns the reviewed problem statement, impact, onset/frequency, recent changes, attempted remedies, operational constraints, unknown facts, and measurable success criteria. Information supplied by a ticket/model remains untrusted data.

Local deterministic clarification rules ask only relevant missing questions. The user can correct or explicitly mark facts unknown. Missing required scope, production/sandbox classification, permission, or success criteria prevents action preparation. Changing a target, scope, criterion, or proposal invalidates applicable evidence and approvals; historical evidence remains visibly historical.

An optional structured LLM request sends only an explicit preview of reviewed fields after provider consent. It may propose questions, hypotheses, explanations, and capability IDs. It cannot invent observations, confirm causes, select credentials, or supply executable text. Reject unknown fields/capabilities and oversized or incomplete responses. Consent to a model request is not consent to a probe or repair.

Accept intake when a sparse “application is slow” report asks for affected scope and a measurable success criterion, correction changes only the intended fact, and an explicitly unknown fact stays unknown after reload. A complete reviewed report asks no redundant required questions. Missing mutation constraints blocks repair preparation. Accept diagnosis when every candidate has resolvable support/counterevidence/gap references, a mixed-symptom case remains uncertain or multifault, wrong-target or stale observations cannot influence current ranking, and selecting a suggested check causes zero adapter dispatches until the collection control is deliberately used.

### 3.2 Asset and scope resolver

Build an inventory read model from current profiles and telemetry, rather than a duplicate independent host store. Distinguish configured assets, observed relationships, manually declared dependencies, and inferred candidates. Ambiguous IPs or common database ports do not establish identity or causality.

Database scope includes explicit engine, server identity, database, schema/object identifiers, connector version, and credential reference. Container/cloud scope includes declared platform, resource IDs, namespace/account/subscription/region, and credential scope. Verify product/platform identity with a bounded adapter probe before interpreting engine-specific results.

### 3.3 Versioned connector and probe registry

Each connector declares its stable ID/version, platform, supported probe and action IDs, parameter schema, authentication modes, minimum privileges, readiness prerequisites, limits, and parser version. Readiness distinguishes local tool availability, configured credentials, unknown remote access, verified remote permission, unsupported operation, and last attempt failure.

Registry entries point to actual implementations. A registry entry cannot claim a capability based solely on a missing driver or executable. Fixed typed input becomes an adapter request; general SSH and other free-command facilities remain separate from helper-generated plans.

The planner-to-dispatch contract is an immutable `HelperPlanStep` containing capability ID/version, discriminated typed parameters, exact scope fingerprint, required evidence references, declared prerequisites, and check/verification role. Canonical validated step data is hashed into the plan. Neither local nor cloud helper planning can populate `mission::Step::command`, produce `StepKind::SshCommand`, or translate a proposal into a legacy arbitrary SSH/WinRM/SQL command. Mission handoff creates display/operator checkpoints and references the helper plan; actual probe dispatch resolves a supported typed capability through the registry after the deliberate collection control. A helper action uses the generic authorization path, not an executable legacy mission text field. Test both direct proposal acceptance and mission handoff for zero arbitrary-command dispatches.

Persist schema/version explicitly. Existing profile, incident, diagnostic, service-approval v1, catalog and execution fixtures must load unchanged; migration of new helper records is additive and tested. Unknown future schemas are refused with a recoverable unsupported-version result, never downgraded into executable state. Adapter upgrades invalidate incompatible evidence/recipe applicability without rewriting historical source records.

Resolve secrets just in time through the existing protected credential store or explicit environment/provider references. Never persist secrets in case JSON, process arguments, command previews, receipts, exports, or approval metadata. Credential failures are redacted. Default to validated TLS; a disposable loopback sandbox exception must be explicit, visible, and excluded from production readiness.

Workers are nonblocking, cancellable, and bounded. Default probe deadline is 15 seconds with a hard maximum of 30 seconds; result envelope limit 128 KiB, 100 records, 64 metrics, and 16 evidence references per observation. SQL plan artifacts may use a separate explicit 1 MiB limit and depth/node caps. Partial, malformed, permission-denied, truncated, canceled, or missing output yields coverage gaps, never a passing finding.

### 3.4 Evidence envelope and diagnosis

Every observation includes schema/probe/parser version, case/revision/request identity, exact target/scope digest, credential-scope fingerprint without secrets, source identity, source-observed time, retrieved time, time-quality/clock uncertainty, content digest, status, coverage, and bounded typed findings/metrics. Validate binding and time at ingestion and again at use. Future or out-of-window observations cannot support current decisions.

Retain the existing 120-second mutation precondition rule and existing stricter per-domain deadlines. Helper diagnostic observations are current for at most five minutes unless their existing domain rule is stricter. Approval wait does not extend evidence freshness. Preserve stale evidence with its label.

Hypotheses cite supporting, contradicting, and missing evidence. Multiple faults and model gaps remain possible. Distinguishing-check selection comes from the registry and current coverage; it does not dispatch on selection. Connectivity, chronology, similarity, or a running service never establishes a confirmed cause. A human confirmation requires rationale, cited evidence, actor, time, and immutable case revision. Numeric confidence is omitted unless a transparent rubric is specified; preflight readiness is not causal probability.

Reuse existing diagnostic case assessment and mission execution as the authority boundaries. General domain extensions can be separate small modules, but must expose one case workflow; do not create another independent authorization or success detector.

New helper storage is limited to 128 cases, 32 targets and 1,000 evidence envelopes per case. Raw plan artifacts expire after 90 days, while redacted case/evidence metadata can remain for 365 days; active or ambiguously executed runs and unresolved restoration references are held until reconciliation. Expiry removes current eligibility immediately, but does not silently destroy referenced journal evidence. At capacity, block new capture/save with an archive/export message rather than evict referenced evidence. Deletion/archiving is an explicit operator action; retained historical records keep stale/expired labels. These policies apply to new helper stores, not retroactive rewriting of existing stores. Test limits, references, retention holds, stale eligibility and redacted bounded exports across restart and concurrent saves.

## 4. Initial implemented diagnostic coverage

### 4.1 Windows, Linux, and network

Windows fixed WinRM/CIM collectors: host/OS identity; short CPU sample; available/total memory and commit pressure when supported; volumes/free capacity; bounded top process resource usage without command lines; selected-service status/dependencies; bounded event metadata; interface errors/discards; TCP connection/retransmission counters when available. Counter resets, zero sample windows, unsupported locales/counters, and insufficient permissions yield unknown metrics.

Linux fixed OpenSSH collectors: OS identity and uptime/load, `/proc` CPU/memory snapshots, selected filesystem capacity, bounded process resource summary, interface counters, listening/socket summary, and selected systemd-service status. Validate service/namespace parameters and pass data safely to fixed collector definitions. No arbitrary command text from intake or model. Missing OpenSSH, unsupported OS, or missing collectors must be visible.

Network checks: explicit DNS, bounded TCP connect, validated TLS handshake, public HTTP GET and configured functional assertion. Distinguish transport reachability from application function. No broad subnet scan or implicit discovery; probes operate only on reviewed explicit endpoints.

### 4.2 PostgreSQL and SQL Server

Add real database adapters, preferably native Rust clients integrated with Tokio and validated TLS, rather than relying on user SQL through general shell dispatch. Exact client/dependency choice and lockfile changes belong to the implementation plan. Use dedicated least-privilege identities. PostgreSQL read probes use read-only transactions, statement/lock deadlines, and rollback. SQL Server read capability is limited by grants and fixed metadata templates; transaction isolation does not itself prohibit writes.

Implemented fixed probes: engine/version/database identity; active request/session summary with raw SQL/literal text omitted by default; wait/blocker graph; table/index usage and sizes; statistics metadata/estimates; permission/capability report. Restrict scope to the selected database and bounded records, and disclose broader views only when explicitly required and permitted.

Plan analysis supports imported bounded PostgreSQL JSON and SQL Server XML plans with source provenance and explicit “imported/unverified” status. Explain plan operators, scan/selectivity estimates, actual/estimated row differences, spill/sort evidence, index usage, and blocking. Secure XML parsing forbids DTD/external entity expansion; JSON/XML depth, nodes, and bytes are bounded. Imported measured plans remain observations from their declared collection context, never fresh live proof by themselves.

Live plan collection uses fixed app-owned SELECT templates with validated object identifiers and parameter binding. Never execute arbitrary user SQL for explanation, and never use EXPLAIN ANALYZE or actual-query execution as a default read probe. An opt-in bounded sandbox benchmark may execute only reviewed known SELECT workloads and must be classified as a workload execution, not a passive metadata query.

Recommendations cite evidence and limitations: index opportunity plus write/storage cost; statistics mismatch plus permissions/side effects; blocking session plus transaction ownership; memory spill plus per-operation/concurrency cost. An index scan or lower one-shot time alone does not prove whole-application repair.

### 4.3 Container and cloud adapters

Implement fixed read-only Docker container identity/state/resource summary, Kubernetes namespace-scoped pod/workload status and event metadata, Azure explicitly selected resource inventory/health, and AWS explicitly selected resource inventory/health. Use reviewed account/resource/namespace scopes and existing local authenticated tools or native bounded API clients. No shell-interpolated query language, no automatic account/subscription scan, and no state-changing CLI commands.

Each adapter reports its exact supported operations, selected context, privilege/access limitations, and unverified prerequisites. Normalize structured results into the shared evidence envelope. Live cloud/customer access is not required or silently authorized during implementation; local fake APIs and tool fixtures test the executable adapter path. Live interoperability remains separately reported until actual endpoints/credentials are supplied.

Initial container/cloud operation lists are deliberately concrete:

| Adapter | Implemented fixed read operations | Required reviewed scope/prerequisites |
|---|---|---|
| Docker | Selected-container inspect/state and one bounded stats snapshot | Exact container ID, installed Docker CLI and access to the chosen daemon |
| Kubernetes | Selected namespace pod/workload status and bounded related event metadata | Explicit kube context, namespace and resource name; kubectl and read RBAC |
| Azure | Selected Azure VM identity/state and Resource Health availability | Explicit subscription/VM resource ID; authenticated Azure CLI or bounded ARM client and read grants |
| AWS | Selected EC2 instance inventory and instance/system status | Explicit account/region/instance IDs; authenticated AWS CLI or bounded EC2 client and describe grants |

Other resource types are unsupported until separately registered and implemented; do not substitute a general cloud command box. Every adapter has fixture acceptance for healthy/degraded, denied permission, missing tool/auth, wrong context, malformed/truncated output, cancellation, deadline, unknown schema, and secret redaction. The real parser and dispatch implementation run against the fake endpoint/tool. The shared UI lists the same supported operations, prerequisite gaps and live/fixture verification label for each family. Windows/Linux/network adapters likewise reach this UI and preserve missing-counter/unsupported-platform states as unknown, not zero or healthy.

## 5. Repair catalog and authorization

Use a versioned catalog containing problem family, exact prerequisites, required connector/privileges, parameters, risk, expected result, independent checks, rehearsal evidence, rollback availability/limits, and provenance. Existing signed service recipes remain valid. Suggestions and catalog browsing are inert.

Initially executable repair kinds are the existing single-service start/stop/restart pathway and narrowly scoped PostgreSQL/SQL Server index creation and statistics maintenance. Use typed schema/table/index/column identities obtained from verified metadata, validate/recheck before state, display exact operation and cost/locking warnings, and require explicit review. Do not allow arbitrary DDL/DML, session termination, global database memory tuning, or cloud/container mutation through a generic free-text escape hatch. Unsupported changes remain clearly advisory/manual with no success claim.

The initial SQL action grammar is exactly: PostgreSQL nonunique B-tree `CREATE INDEX` on one verified base table with one to four verified plain columns and typed ASC/DESC directions; PostgreSQL `ANALYZE` of that one table; SQL Server nonunique nonclustered rowstore `CREATE INDEX` on one verified base table with one to four verified plain columns and typed ASC/DESC directions; SQL Server `UPDATE STATISTICS` of that one table using engine defaults. Reject expressions, predicates/partial indexes, INCLUDE/options/storage clauses, concurrent/online creation, unique constraints, arbitrary hints, cross-database names, DML, query text, custom statistics arguments and other grammar. More forms require a future registered action version.

Resolve each schema/table/column/index identifier against same-database metadata and object identity; recheck type, definition, existing index names and privileges before dispatch. Apply engine-correct identifier escaping (PostgreSQL double-quote escaping, SQL Server bracket escaping), engine identifier length limits and control-character rejection. Identifiers are never appended from model/free text without this resolution. Bind all supported data values; identifiers are handled only through the verified quoting builder. SQL reads and changes use separate credential capability scopes. PostgreSQL ownership/schema privileges and SQL Server table ALTER privileges must be checked, not silently granted. Set a 30-second action statement deadline and a five-second lock deadline where the engine supports it; apply client cancellation and reconciliation if timeout/connection loss leaves outcome uncertain. PostgreSQL index creation uses an explicit transaction with postcondition verification before commit. SQL Server uses an explicit transaction where supported. Statistics maintenance remains explicitly non-restorable to the original statistics. No retries after an ambiguous commit; re-observe exact object/action state first. Test identifier injection/length, same-database identity, rejected grammar/options, privilege denial, blocked DDL, deadline, commit ambiguity and exact-index rollback ownership.

Generic action authority must carry a versioned digest of case/revision/run, exact target and scope, connector/action ID/version, normalized parameters, credential scope, before/precondition evidence, plan, functional/performance checks, rehearsal proof, restoration recipe, and restoration limits. The team server understands supported action schemas, validates them, retains requester/approver separation, and atomically consumes an exact one-use binding. Backward-compatible service v1 requests cannot authorize generic actions. Unknown versions fail closed.

Use a discriminated wire boundary: legacy service binding v1 retains its existing schema/digest domain and behavior; generic binding v2 uses an independent `relayne-helper-action-binding-v2` digest domain and explicitly tagged action/parameter/restoration variants. Hash validated canonical serialized Rust fields with fixed field order, no arbitrary maps or omitted optional semantics; include every stated authority field. Reject unknown fields, unknown tags, unsupported versions, malformed hashes and out-of-scope values on both server and client. Stored v1 requests remain readable and consumable only by the v1 service path. Generic requests use a versioned endpoint/operation contract that old servers cannot accidentally accept.

The team server authorizes actor/role separation, configured organization scope, structural action schema, recorded decision, TTL, exact metadata digest, revocation and atomic one-use consume/audit. It does not attest remote target state, credentials, live privileges, rehearsal equivalence or fresh functional evidence from metadata alone. The managed client revalidates these facts locally, including current credential-scope identity and exact supported operation, immediately before dispatch; missing verification fails closed. Credential contents are never sent to the team server. Concurrency, replay, schema downgrade and changed-credential tests cover this trust split.

Recheck freshness, local review, target, credentials and before state after asynchronous consume and immediately before dispatch. Save durable dispatch intent before any remote side effect. Persistence failure prevents dispatch. Ambiguous consumption/dispatch after a crash is not retried blindly. Team outages block new Apply; bounded restoration after a launched change remains independent of team availability. Preserve exact durable outcome-event retry behavior.

For index creation, rollback may drop only the exact index created by this run after verifying its current definition and ownership; ambiguity blocks automatic drop. Statistics maintenance has no exact restoration of prior engine statistics and must disclose this before approval. Transactional and engine-specific execution limitations, including concurrent index creation, are explicit; do not promise reversal of all application effects. Catalog matching or prior successful execution is never permission.

Restoration is a tagged part of the approved binding: `VerifiedReversible` contains the exact validated recipe and proof; `ManualOrUnavailable` contains acknowledged limits and required operator intervention. Non-restorable statistics work requires explicit acknowledgement in both local review and team decision. After a failure with unavailable/unknown restoration, record `NeedsIntervention`, halt later targets and retain the journal for reconciliation. Do not manufacture a no-op restoration receipt. The restoration tag/limits participate in the action digest and outcome export.

## 6. Functional/performance verification and lessons

Verification uses the operator's original symptom, complete declared dependency chain, exact targets, and reviewed checks. Store results per check/target with missing coverage. A service-state/TCP check cannot satisfy an HTTP/business criterion. Rehearsal and production evidence remain separate. Failure/unknown restoration halts later targets.

Performance receipts are separate from functional success and production authorization. Record exact workload/build/host/engine/configuration/dataset definition, warmups, repeated samples, timing method, errors, sample size, median/p95, declared thresholds and tolerated noise. Compare only compatible baselines. Insufficient samples, mismatched context, invalid time, or overlapping noise bands yields inconclusive. Initial fixture comparison uses at least three warmups and fifteen measured samples, with repeatability reported; measured load stays bounded and explicitly authorized.

A case is repaired only when its actual production action and required functional checks are verified; performance criteria are additionally required if the reviewed case declares them. A completed diagnostic model, imported benchmark, successful API health on a different target, or operator narrative is insufficient.

Other legitimate terminal outcomes are `DiagnosedNoChange`, `ResolvedExternally`, `ClosedUnresolved`, and `NeedsIntervention`. They carry an operator-reviewed reason and applicable evidence/coverage. `ResolvedExternally` can include fresh independent checks of the original symptom, but identifies the change as external/unknown and never asserts a Relayne action or creates an automatically verified repair lesson. `DiagnosedNoChange` records investigation findings without implying recovery. Self-resolution can therefore finish the helper workflow without weakening the journal-backed `VerifiedRelayneRepair` state. Test each terminal state and confirm that external/no-change/unresolved outcomes cannot authorize repair or promotion.

Versioned incident lessons reference actual verified run/target/plan/evidence plus exact applicability fingerprint, reviewed explanation, creation/revalidation times, revision and invalidation history. Existing free-form memory stays unverified. Failed/restored/no-op/unbound/rehearsal-only results cannot create a verified lesson. New adverse evidence, drift, revoked trust or expired evidence retracts eligibility. Reuse requires a fresh read-only context comparison and new action approval. Concurrent stale saves must not resurrect revoked records.

## 7. Desktop delivery

One “IT Helper” workspace, with six visible stages: Describe → Scope → Investigate → Review change → Verify → Save lesson. Each stage shows knowns/unknowns, next useful step, evidence links and readiness gaps in simple language. Embed or navigate to current diagnostic, execution, team, lab and recovery controls with the exact shared case context; do not duplicate their approval state machines.

Display metrics with units, sample windows and provenance; separate observed/inferred/confirmed and simulated/live. SQL results expose plans, blockers, statistics, advisory cost and comparison. Users can inspect connector prerequisites and capability limits. Every collection/change has a distinct deliberate action. Navigation, opening/exporting a case, accepting a suggestion or saving a lesson never triggers a remote call.

Use existing asynchronous pollers and protected persistence. App frame rendering contains no blocking remote/database work. Target changes clear transient handoff and pending approvals while retaining post-launch restoration reconciliation. Exports are redacted bounded JSON/Markdown, include schema/revision/time/bindings/coverage and do not contain credentials, private keys, raw unrestricted provider output or query literals. Cap serialized export at 5 MiB and indicate truncation.

## 8. Six implementation waves

| Wave | Deliverable | Exit gate |
|---|---|---|
| 1 — Common helper foundation | Intake/clarification, shared case/scope/provenance, derived inventory and capability registry | Persistence, exact binding, stale/unknown semantics, no side effects, independent interface review |
| 2 — SQL diagnosis | Executable PostgreSQL/SQL Server read adapters, metadata/waits/statistics, bounded plan parser and evidence-based suggestions | Real PostgreSQL sandbox collection from Relayne; SQL Server fixture/loopback path and clearly reported live coverage |
| 3 — System/container/cloud diagnosis | Windows/Linux metrics/network plus Docker/Kubernetes/Azure/AWS fixed read adapters | Typed fixture paths, cancellation/bounds/permission tests, UI readiness; available live environments checked separately |
| 4 — Generic controlled change | Versioned recipe/catalog, generic team binding/consume, narrow SQL repairs and existing service actions | Replay/role/digest/persistence/race/crash tests; no advisory-to-dispatch bypass; restoration limitations tested |
| 5 — Verification and knowledge | Cross-target functional and repeated performance receipts, regression/coverage, reviewed versioned lessons | Wrong-context/stale/noisy/partial negatives, adverse evidence retraction, invalidation persistence |
| 6 — Unified desktop and acceptance | Guided workspace integration, complete SQL demo, docs and Windows CI, final branch review | Locked all-bin build/test, correctness static analysis, scoped formatting, native UI and executable end-to-end evidence |

Audit parallelism already used twelve workers. During implementation, maximize independent design/test/doc work up to twelve children, but sequence shared-core and integration edits. After interfaces are frozen, disjoint adapter work may be parallelized only with explicit file ownership and an integration gate; otherwise fresh implementer plus independent reviewer runs sequentially. Use Luna low/medium for mechanical/docs/fixtures and Sol medium/high for integration, database, concurrency and authorization. Astra requires a demonstrated unresolved Sol-level problem; none is currently established.

Vertical-slice rule: every wave includes the minimum usable shared desktop path for its own delivered capabilities. Wave 1 provides intake/scope/registry; Wave 2 adds real SQL collection and plan inspection; Wave 3 exposes each system/container/cloud adapter with its exact capabilities and readiness/error states; Wave 4 adds generic action review/approval/results; Wave 5 adds verification/lessons. Wave 6 completes the coherent guided flow, native dynamic-state acceptance, documentation and whole-branch review. Adapter implementation cannot be declared complete before its real dispatch/parser, shared UI entry and family-specific acceptance gate are integrated.

## 9. Acceptance and truthful completion

Every wave must satisfy its meaningful tests and an independent review before dependent integration. Build and serial all-bin tests use the existing provisioned Rust 1.95/MSVC environment; do not reinstall. Correctness Clippy and scoped formatting/diff checks are required. Existing compiler warnings/formatting debt are recorded separately; failed tests are never removed or weakened.

Security negatives include injected intake/model/provider content, disguised SQL mutation, credential leakage, unknown action version, unauthorized resource/tenant, altered target, stale/future/partial evidence, XML entity/depth expansion, concurrent consume/revoke, journal failure, crash boundaries, and unavailable team during restore. Connector tests exercise the real adapter dispatch and parser with fake endpoints/tools, not only enum serialization.

End-to-end PostgreSQL acceptance starts in a disposable Windows Sandbox and collects the actual slow-query, selectivity, sort-spill and blocking conditions through Relayne. It shows full case/context/proposal/approval/change/verification transitions, uses repeated comparable workload samples, and records raw bounded evidence. The previous externally executed SQL measurements are reference data only and do not count as this acceptance.

SQL Server, Linux, container and cloud live acceptance depend on actual local/disposable environments and approved credentials. Report each as measured, fixture-tested, or not live verified. Do not label customer deployment, cross-provider support, distinct-human organization identity, or production readiness as proven by loopback tests.

Named desktop/SQL acceptance scenarios:

1. Create a sparse slow-application case, answer/mark unknown the relevant questions, choose the exact sandbox database and reviewed API/portal targets, save/reload, and reach Investigate without any automatic remote call.
2. Collect PostgreSQL identity, statistics and blockers through Relayne's actual adapter. Reproduce a waiting session and resolve its blocker identity. Import the measured sort plan with imported provenance; a spill recommendation cites its disk/temp-block evidence. A live bounded SELECT benchmark, when explicitly selected, has matching schema/data/workload fingerprint and at least three warmups/fifteen samples.
3. Capture a misestimated selective status query before and after explicit statistics maintenance. Both return the same row count; the post-ANALYZE estimate is closer. Do not claim a performance win from this alone.
4. Review and approve the exact customer/date index action, execute through the actual helper journal/authorization path, then verify index definition and intended query result. A plan change to the intended index and compatible repeated timings are visible. If noise prevents a timing conclusion, report inconclusive rather than fabricate improvement.
5. Run independently configured API and both portal functional checks. Missing or failing checks prevent repaired/verified status. Passing SQL checks alone cannot close the slow-application case. No-op workload fixtures cannot stand in for database-backed application verification.
6. Change a target/criterion before dispatch and show approval invalidation; change diagnostic UI context after launch and show reconciliation/restoration remains available. Service-v1 recorded fixtures still load; unknown generic-action versions and mismatched catalog versions fail closed.
7. Save a reviewed lesson from actual verified run evidence, reproduce a context drift or later failed verification, and observe blocked/stale reuse across restart. Export redacted JSON/Markdown showing source times, coverage and exact references without credentials or query literals.

Native screenshots show these dynamic helper/approval/verification states where available, not only isolated empty panels. These named scenarios define the Wave 6 user-outcome gate. Wave 1 must pass scenarios 1 and the pure intake/diagnosis/registry/retention negatives; Wave 3 must pass every listed adapter dispatch/parser negative and shared-UI coverage; Wave 4 must pass schema migration/version/catalog and dispatch/restoration gates before later scenarios depend on it.

The branch is kept reviewable and isolated. No merge, push, publication, deployment, unsolicited notification or customer connection is part of this implementation request. Existing promotional files in the original checkout and previous committed review evidence remain intact.

## 10. Review decisions to confirm

The recommended approach is the shared typed helper workflow extending existing journals and gates. Alternatives are (a) a proposal-only assistant, which does not satisfy complete executable helper delivery, or (b) unrestricted agent shell/SQL control, which loses reviewable target/action/proof binding and is rejected.

Confirm this concrete specification before the detailed implementation plan. The user has selected wave-based subagent execution; the implementation plan must preserve that selection, enumerate file ownership/dependencies/tests, and receive its own review before code dispatch.
