# Relayne Generic IT Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task. The user has selected waves and maximum subagents; do not ask for the execution method again. Code dispatch starts after this written plan has been reviewed and confirmed.

**Goal:** Deliver a usable typed IT helper from problem intake through live diagnosis, exact change approval, actual execution, whole-application verification and reviewed knowledge reuse.

**Architecture:** Extend existing profile/incident/diagnostic/execution/recovery authority boundaries. One helper case and one desktop workspace share typed scopes, evidence, capabilities and versioned plans. Database actions use a separate v2 authority contract; existing service-v1 execution remains the service authority.

**Tech Stack:** Rust 2024, Rust 1.95.0/MSVC, eframe/egui, existing Tokio/reqwest/DPAPI/rusqlite/tiny_http; native PostgreSQL and TDS clients; fixed OpenSSH/WinRM/Docker/kubectl/Azure/AWS read collectors.

**Spec:** `docs/superpowers/specs/2026-10-08-generic-helper-design.md`, accepted by the user's “go on da fehlen noch Waves”. Base `26a89ac`; branch `codex/relayne-generic-helper`; isolated checkout `C:\Users\reinerw\.codex\worktrees\relayne-product-waves\Aivana-RUST-RDP-Client`.

## Global Constraints

- Preserve previous six product-wave improvements, old profile/incident/diagnostic/catalog/execution fixtures, service approval v1, original promotional files, and committed review evidence.
- One coherent helper workflow; every wave includes its usable desktop slice. No second service success detector/approval dispatcher. No helper/model text in `mission::Step::command` or `StepKind::SshCommand`.
- Exact case revision, target, typed resource scope, credential-scope identity, capability/version and evidence references are checked at ingestion and use. Context edits invalidate eligibility; launched work remains reconcilable.
- Default probe deadline 15 seconds; maximum 30 seconds. Envelope 128 KiB, 100 records, 64 metrics, 16 evidence refs. Plan input 1 MiB. Export 5 MiB with explicit truncation/coverage.
- Diagnostic freshness at most five minutes or the existing stricter rule. Mutation preconditions remain strictly less than 120 seconds old. Future evidence is ineligible; approval waits cannot refresh it.
- New helper storage: 128 cases, 32 targets/case, 1,000 envelopes/case; plan artifacts 90 days and redacted metadata 365 days. Active/ambiguous runs/unresolved restoration hold referenced evidence. Capacity blocks new saves; no silent reference eviction.
- Secrets are resolved just in time; none in args, previews, provider payloads, exports, logs, receipts or team metadata. Default validated TLS. A visible disposable loopback exception is excluded from production readiness.
- Partial, denied, unavailable, truncated, malformed, canceled, unknown schema and missing fields are gaps/unknown, never healthy or pass.
- Initial SQL changes are exactly the four forms in spec §5, 1–4 plain columns, no expressions/options/includes/unique/clustered/concurrent/online/cross-database forms. Explicit 30-second action and five-second lock limits; exact index ownership before drop; statistics restoration unavailable and acknowledged.
- Both functional and performance criteria declared in the reviewed case are required. Functional/performance/rehearsal/imported observations remain different evidence classes. Three warmups and at least fifteen samples for a performance comparison.
- Generic action v2 has separate wire, tables, routes and digest domain. Metadata-only server checks authority; client checks actual remote context/credentials/evidence immediately before dispatch. Durable intent before effects, one-use consumption, no blind replay.
- Builds/tests/static checks are appropriate to each product change. No weakening/deletion of failed tests. No merge/push/deploy/customer connection or unsolicited notification in this task.

## Review Focus

1. Revision changes while jobs/approvals are pending: reject stale evidence/dispatch while preserving post-launch reconciliation (Tasks 1, 3, 5, 13–15, 18).
2. Credential rotation/revocation and cross-account/resource identity: exact current scope comparison, no raw secret/error leakage (Tasks 2, 5–7, 10–11, 13).
3. Imported plans and SQL disguised as reads: bounded secure parsers, fixed templates, separate workload class, no imported authority (Tasks 6–8, 12, 14–16).
4. Legacy format/unknown schema and stale concurrent saves: fail closed without resetting state or resurrecting revoked eligibility (Tasks 1, 3, 12–13, 17).
5. Wrong/missing API or portal result and noisy/changed workload: keep case unverified or inconclusive rather than manufacture repair success (Tasks 16–18).

## Work breakdown: 18 implementation waves

The six architectural phases are grouping labels. These eighteen waves expose the previously hidden deliverables, including a separate isolated SQL trial before production promotion; none can be marked complete by a DTO, registry label or mock result alone.

| Wave/task | Working deliverable | Depends on | Architectural phase |
|---|---|---|---|
| 1 | Problem intake, clarification, protected case store and Helper entry | Existing app | Foundation |
| 2 | Exact scopes, joined inventory and topology | 1 | Foundation |
| 3 | Provenance, bounded records, manifest, retention and exports | 1–2 | Foundation |
| 4 | Adaptive hypothesis/check planning and consented LLM advice | 1–3 | Foundation |
| 5 | Executable connector registry, credential lifecycle and cancellable worker | 1–4 | Foundation |
| 6 | Native PostgreSQL diagnosis | 2–5 | SQL |
| 7 | Native SQL Server diagnosis | 2–5 | SQL |
| 8 | PostgreSQL/SQL Server plan analysis, safe plan templates and workload review | 3–7 | SQL |
| 9 | Windows/Linux resource and explicit network diagnosis | 2–5 | Systems |
| 10 | Docker/Kubernetes read adapters | 2–5 | Systems |
| 11 | Azure VM/AWS EC2 read adapters | 2–5 | Systems |
| 12 | Trusted versioned action catalog and exact proposal previews | 3–8 | Controlled change |
| 13 | Generic v2 team authority, durable dispatch intent and crash reconciliation | 5,12 | Controlled change |
| 14 | Real bounded SQL executor and isolated rehearsal receipt | 6–8,12–13 | Controlled change |
| 15 | Production SQL promotion, restoration and reconciliation | 13–14 | Controlled change |
| 16 | Complete functional chain and repeated performance verification | 3,5,8,13–15 | Verification/knowledge |
| 17 | Reviewed lessons, invalidation, revalidation and incident reports | 3,12–16 | Verification/knowledge |
| 18 | Unified desktop acceptance, real DB-backed demo and final review | All prior | Delivery |

The six architectural phase gates in spec section 8 aggregate these implementation waves: Phase 1 = Waves 1–5; Phase 2 = Waves 6–8; Phase 3 = Waves 9–11; Phase 4 = Waves 12–15; Phase 5 = Waves 16–17; Phase 6 = Wave 18. A phase is complete only after every constituent wave passes its tests and review. Wave 1 alone does not satisfy the intake/scope/registry phase gate.

## Files and ownership

- `src/helper/mod.rs`: exports only completed modules. `case.rs` owns intake/revisions/terminal states; `store.rs` owns protected persistence and concurrency.
- `src/helper/scope.rs`: tagged identities and digest; `inventory.rs`: read model over profiles/telemetry. No duplicate independent host database.
- `src/helper/evidence.rs`, `manifest.rs`, `export.rs`: provenance, typed normalized data, declarative capability contract and redacted exports. `capability.rs` in Task 5 owns actual registered implementations.
- `src/helper/planner.rs`, `advisory.rs`: deterministic assessment and consent-bound provider responses. No execution authority.
- `src/helper/worker.rs`, `credentials.rs`: dispatch/cancellation and secret resolution; `src/security.rs`/`src/models.rs`: additive scoped secret references, preserving profile references.
- `src/helper/sql/mod.rs`, `types.rs`, `postgres.rs`, `sql_server.rs`: real native readers. `plans.rs`, `templates.rs`, `benchmark.rs`: plan parsing, reviewed fixed SELECTs and sandbox workload class. `changes.rs`, `restoration.rs`: narrow SQL mutations after v2 authority.
- `src/helper/adapters/{windows,linux,network,containers,cloud}.rs` and fixed collectors: actual typed reads and parsers; no arbitrary command API.
- `src/helper_action.rs`: portable shared SQL action/object/restoration types without GUI dependencies. `src/helper_approval.rs`: portable generic v2 wire and digest. Both are included by GUI and team binary.
- `src/helper/catalog.rs`, `journal.rs`, `verification.rs`, `knowledge.rs`: catalogs, durable lifecycle, independently evidenced results and reviewed lessons.
- `src/app/helper_panel.rs` owns shared transient UI state and `poll_helper`; stage rendering lives in `src/app/helper_panel/{intake,scope,evidence,planning,connectors,sql,systems,change,verification,knowledge}_ui.rs`. Keep one `View::Helper`.
- Each implementation task modifies its own modules plus the sequential shared registration points. Only the current integration owner edits `app.rs`, `desktop.rs`, `main.rs`, `helper/mod.rs`, Cargo or shared contracts. Do not give concurrent writers these files.

## Canonical interfaces and decisions

These coordinator-selected contracts supersede differing exploratory subagent proposals. `Digest` means a validated lowercase SHA-256 string, not an unbounded/free-form identifier. Use `anyhow::Result` internally and typed sanitized status/error codes across worker/UI/wire boundaries.

1. **Case (Task 1):** `HelperCase { schema:u16, id:Uuid, revision:u64, evidence_revision:u64, intake:ProblemIntake, profile_ids:Vec<Uuid>, source:Option<incident::Source>, mission_id:Option<Uuid>, ticket_ref:Option<TicketReference>, created_at:DateTime<Utc>, updated_at:DateTime<Utc>, resolution:Option<CaseResolution> }`. Tasks 2–4 add `scopes`, `evidence_refs`, `plan` with serde defaults. Source/ticket import is reviewed inert data from existing incident/ticket surfaces. Context/criterion/plan edits increment `revision`; evidence arrival increments only `evidence_revision`, so one observation does not invalidate other observations in the same case revision. `CaseResolution` distinguishes `VerifiedRelayneRepair`, `DiagnosedNoChange`, `ResolvedExternally`, `ClosedUnresolved`, `NeedsIntervention`.
2. **Scope (Task 2):** closed `BoundScope::{Windows{target,credential},Linux{target,credential},Database{target,engine,port,database,schema,object,credential},Http{target,port,tls,path},Docker{daemon_context,container_id,credential},Kubernetes{context,cluster_fingerprint,namespace,resource_kind,resource_name,credential},AzureVm{tenant,subscription,resource_id,credential},AwsEc2{account,region,instance_id,credential}}`. `target:mission::Target`, `engine:DatabaseEngine::{Postgres,SqlServer}`. Do not add AzureAccount/AwsAccount discovery variants. DB port is separate from saved RDP/SSH port. `CredentialScope` contains only reference, purpose/generation and reviewed principal/context metadata.
3. **Evidence (Task 3):** `EvidenceBinding { case_id, case_revision, request_id, scope_sha256, credential_scope_sha256, run_id:Option<Uuid> }`; `EvidenceEnvelope { schema, binding, capability_id, capability_version, parser_version, origin, source_id, source_observed_at, retrieved_at, time_quality, status, coverage, content_sha256, records, metrics, evidence_refs }`. `Origin::{Live,ImportedUnverified,SimulationFixture}`. Manifest defines `CapabilityId`, `Prerequisite`, `CheckRole` and the closed `ProbeParams` schema before the planner uses them. Parameters cover typed network/system/SQL-read/container/cloud operations and digest-bound plan/workload references, never command/query text. Future descriptors are declared/unimplemented until an actual Task 5 registry adapter exists. Closed `RecordKind` and scalar fields; parsers whitelist fields and never retain arbitrary JSON/provider payloads, raw SQL text/literals or command lines. Metrics carry finite numeric value, unit, source counter, sample window and missing reason.
4. **Plan (Task 4):** `HelperPlanStep { capability_id:CapabilityId, version:u16, params:ProbeParams, scope_sha256:Digest, evidence_refs:Vec<Uuid>, prerequisites:Vec<Prerequisite>, role:CheckRole }`. Parameters are a closed tagged enum, extended by adapter owners; no `command`/`sql:String` variant. `HelperPlan { case_id, case_revision, evidence_revision, hypotheses, steps, rationale }` is inert. Missing prerequisites, unsupported adapters and multi-fault evidence remain visible.
5. **Worker (Task 5):** `ProbeRequest { binding:EvidenceBinding, scope:BoundScope, capability_id:CapabilityId, version:u16, params:ProbeParams, timeout:Duration, requested_at:DateTime<Utc> }`; `ProbeOutput { status, coverage, records, metrics }`. `ProbeAdapter::collect<'a>(&'a self, request:&'a ProbeRequest, secrets:&'a dyn SecretResolver, cancel:CancellationToken) -> ProbeFuture<'a>`; `ProbeFuture<'a>` is a boxed Send future returning `Result<ProbeOutput>`. Registry entries require an actual adapter. `HelperWorker::submit(request)->Result<Uuid>`, `cancel(id)`, `poll()->Vec<WorkerEvent>`. Four active reads/32 queued maximum; a case selection cannot drop a launched worker. Native SQL bypasses `CommandSpec`; fixed external tools use a helper-specific bounded process path, not the legacy 120-second shell limit.
6. **Catalog/action (Task 12):** portable `SqlAction::{PostgresCreateIndex,PostgresAnalyze,SqlServerCreateIndex,SqlServerUpdateStatistics}` contains verified object/column identity, never SQL text. Shared `RestorationSpec::{VerifiedReversible,ManualOrUnavailable}`. Generic catalog `CatalogAction::{ExistingServiceRecipe,Sql(SqlAction)}` delegates service entries to existing execution. Fixed index grammar is spec §5. Candidate→reviewed proposal is not execution permission.
7. **Authority (Task 13):** portable `ActionBindingV2` includes case/revision/run, explicit database scope metadata/digest, credential-scope digest, typed action and version, before/plan/verification/proof digests, captured/expires times and restoration/acknowledgement. Independent domain `relayne-helper-action-binding-v2`, strict fields/tags/version. `DispatchPermit` is opaque, nonserializable, not constructible from GUI/provider/imports. Journal state is `Prepared/DispatchStarted/Verified/Failed/NeedsIntervention/OutcomeUnknown`.
8. **Verification (Task 16):** `FunctionalReceipt` and `PerformanceReceipt` are separate immutable records with case/run/action/scope/check/workload/environment bindings. Task 16 also owns `ReceiptStore` protected loading/saving/reference resolution. `CheckOutcome::{Passed,Failed,Unknown,Incomplete}`; case resolution derives from actual journal and complete required results, not an operator text field. A receipt referencing the service executor retains its existing run/target checks.
9. **SQL rehearsal (Tasks 13–15):** authority binds `RunKind::{Rehearsal,Production}`. `StagingReviewProof` can start only a deliberately reviewed isolated rehearsal; it cannot authorize Production. A completed protected `SqlRehearsalReceipt` binds the production/staging mapping, normalized action semantics, actual staged run, before/after object state, reviewed equivalence/data-workload coverage, checks and expiry. Production permit requires this receipt reloaded from disk and matched to current scope/action/proof. Imported plans/benchmarks/simulated results cannot supply it.

### Additional fixed values

- Intake description 4,096 characters; other individual free-text fields 512; at most 16 constraints/attempts/changes/questions; redact before persistence/provider preview. A user-confirmed success criterion carries measure, comparator, threshold, unit and required window. An unmeasured required window is incomplete.
- SQL plan depth 64 and 4,096 nodes; input limit applies before decoding/parsing. Explicit formats `PostgresJson/PsqlAlignedExplainJson/SqlServerShowplanXml`; UTF-8 or declared BOM UTF-16 only. Do not “repair” unknown JSON/XML into an accepted plan.
- JSON/Markdown case export includes schema, source/retrieval time, origin, scope and refs; deterministic ordering. Protected case/receipt files use existing Windows exclusive-share lock + on-disk digest comparison + DPAPI + `security::atomic_write`; unknown/corrupt data never resets to empty. Bound reads before allocation. Store capacities include a 64 MiB serialized helper-metadata ceiling; block rather than silently drop at that ceiling.
- PostgreSQL: `tokio-postgres="0.7"`, `postgres-native-tls="0.5"`, `native-tls="0.2"`; TLS uses OS trust plus an explicitly reviewed public CA for the disposable fixture. SQL Server: `tiberius={version="0.12",default-features=false,features=["native-tls","tds73"]}` and `tokio-util={version="0.7",features=["compat","rt"]}`. `quick-xml="=0.39.4"` matches the existing lockfile. Each dependency change resolves Cargo.lock once, followed by locked builds; no floating unrecorded install.
- Performance policy v1: three warmups/fifteen measured samples per side; finite positive times; median, p95 and MAD. Compare same workload/data/result/host/engine/build mode. Record the exact approved schema/index/session-setting delta; that intended change is allowed, other drift is incompatible. Noise interval is median ± max(10% of median, 3×MAD). Overlapping intervals or incomplete/incompatible results are inconclusive; separate nonoverlapping intervals indicate improvement/regression, not a statistical confidence guarantee. Required absolute functional/performance thresholds are evaluated separately. Keep raw samples and policy version.

## Execution and validation convention

From the implementation checkout, source `.superpowers/sdd/product-waves/rust-env.ps1`. Use existing Rust 1.95/MSVC; no reinstall. The helper sets the shared target directory; serialize actual Cargo builds/tests to avoid contention. Commands below assume that environment.

For each task: write named failing tests, run its focused serial filter, implement the specified API, integrate its UI slice, rerun focused tests plus `cargo build --locked --bins`, inspect warnings, run relevant correctness Clippy/scoped rustfmt/diff checks, self-review, commit only owned changes, then independently review the task. Each task has a separate implementation report/review file in `.superpowers/sdd/generic-helper/`. Do not commit a half-compiled registration or declare fixture tests live coverage.

Register each test module before its red run; zero selected tests is not a pass. A new-interface compile failure is a valid initial red only when the intended assertions/test names are actually registered, then the completed filter must execute them. Product/static gates apply after implementation; this documentation preparation does not claim a new source build/test run.

When native drivers are added, test the real adapter orchestration/query templates/production parser via an injected transport plus TLS/deadline failure endpoints. An injected transport does not establish a successful native protocol login. Available disposable live DB tests additionally exercise the real client. SQL Server live success remains explicitly unverified unless an actual disposable instance is available; do not fabricate a fake-TDS login proof.

### Task 1 / Wave 1: Intake and a usable protected case workspace

**Files:** Create `src/helper/{mod,case,store}.rs`, `src/app/helper_panel.rs`, `src/app/helper_panel/intake_ui.rs`; modify `src/main.rs`, `src/app.rs`, `src/app/desktop.rs`; tests in `src/helper/case_tests.rs`, `store_tests.rs`, panel test module.

**Interfaces:** Produce `next_questions(intake:&ProblemIntake, scope_confirmed:bool)->Vec<Clarification>`, `validate_intake(...)->IntakeReadiness`, `HelperStore::load(path:&Path)->Result<Self>`, `create(intake)->Result<Uuid>`, `revise(id,expected_revision,edit:CaseEdit)->Result<u64>`, `save(&mut self,path:&Path)->Result<()>`. `CaseEdit` updates one typed field/criterion, not arbitrary JSON. Add one `View::Helper`, `AivanaApp.helper`, `helper_view` and `poll_helper`.

- [ ] Write tests `sparse_report_asks_scope_and_measurable_success`, `complete_intake_asks_no_redundant_questions`, `unknown_answer_round_trips`, `correction_changes_only_one_fact`, `stale_revision_and_corrupt_store_rejected`, `navigation_save_and_answers_dispatch_zero_jobs`, asserting the fixed intake/case caps.
- [ ] Run `cargo test --locked --bin relayne helper::case -- --test-threads=1` and store/panel filters; demonstrate the missing behavior fails.
- [ ] Implement the case/store APIs and protected concurrency pattern; create a blank/sparse case without contacting a target. Bad load is an error state, not a fresh store.
- [ ] Wire Describe UI, field corrections, unknown answers, explicit save/reload, success-criterion review and missing-scope status; required context edits increment revision. Reviewed incident/ticket adoption copies bounded sanitized intake and source IDs, never starts diagnosis or execution.
- [ ] Run focused checks plus all-bin build/static checks; independently review and commit `feat: add persistent helper intake workspace`.

### Task 2 / Wave 2: Reviewed scopes and derived system context

**Files:** Create `src/helper/{scope,inventory}.rs`, `scope_tests.rs`, `src/app/helper_panel/scope_ui.rs`; modify case serde-default scope fields and shared exports/dispatch.

**Interfaces:** Consume HelperCase/profiles/telemetry. Produce `BoundScope::validate()->Result<()>`, `digest()->Result<Digest>`, `matches_profile(&ConnectionProfile)->bool`, `derive_inventory(profiles:&[ConnectionProfile],telemetry:&telemetry::Store,now:DateTime<Utc>)->Vec<InventoryEntry>` and `review_scopes(case:&mut HelperCase,scopes:Vec<BoundScope>)->Result<()>`.

- [ ] Test every scope/credential identity field changes the digest, DB port differs from RDP port, malformed cloud IDs/protocol mismatches fail, common ports do not infer DB engine, edited profiles stale old evidence, ambiguous IP/partial capture remains unknown.
- [ ] Run `cargo test --locked --bin relayne helper::scope -- --test-threads=1` and inventory filter; record failures before implementation.
- [ ] Implement closed scopes with preserved case-sensitive identifiers, exact Target identity and metadata-only credential refs. Reuse telemetry's two-capture freshness; separate declared/observed/inferred relationships.
- [ ] Add scope selector, exact saved-profile binding, explicit database/resource fields and readiness gaps. Selection/navigation is inert; reviewed scope edits increment revision.
- [ ] Verify, review and commit `feat: bind helper cases to reviewed system scopes`.

### Task 3 / Wave 3: Evidence, provenance, compatibility and reports

**Files:** Create `src/helper/{evidence,manifest,export}.rs`, `evidence_tests.rs`, `export_tests.rs`, `src/app/helper_panel/evidence_ui.rs`; modify store/case fields with defaults.

**Interfaces:** Produce `EvidenceEnvelope::validate_ingest(binding:&EvidenceBinding)->Result<()>`, `eligibility(now:DateTime<Utc>,freshness:Duration)->Eligibility`, `attach_evidence(store:&mut HelperStore,case_id:Uuid,envelope:EvidenceEnvelope)->Result<()>`, `export_case(store:&HelperStore,id:Uuid,format:ExportFormat,now:DateTime<Utc>)->Result<CaseExport>`. Manifest is declarative, not a registered executable adapter.

- [ ] Test wrong case/revision/request/scope/credential/run, future/stale/clock-uncertain, imported/simulated, partial/denied output, all byte/record/metric/ref limits, held references at expiry/capacity, restart/concurrent saves, legacy fixtures and sentinel-secret export.
- [ ] Run `cargo test --locked --bin relayne helper::evidence -- --test-threads=1`, store/export filters; capture the failing cases.
- [ ] Implement normalized typed fields and time/origin semantics. Evidence arrival increments evidence_revision only. Keep stale history; unknown schema is recoverable failure. Apply retention holds and bounded reads/exports.
- [ ] Display evidence source/time/coverage/origin/eligibility and declarative prerequisites; implement JSON/Markdown export without remote calls or query literals.
- [ ] Verify, review and commit `feat: add provenance and bounded helper evidence`.

### Task 4 / Wave 4: Hypotheses, next checks and structured AI advice

**Files:** Create `src/helper/{planner,advisory}.rs`, `planner_tests.rs`, `advisory_tests.rs`, `src/app/helper_panel/planning_ui.rs`; modify typed case plan defaults, exports and Cargo/lock for `tokio-util` cancellation feature `rt`.

**Interfaces:** Produce `plan_local(case:&HelperCase,evidence:&[EvidenceEnvelope],manifest:&CapabilityManifest,now:DateTime<Utc>)->Result<HelperPlan>`, `request_advisory(preview:&AdvisoryPreview,consent:&AdvisoryConsent,cancel:CancellationToken)->Result<AdvisoryProposal>`, `validate_advisory(case,manifest,proposal)->Result<HelperPlan>`, `mission_checkpoint(plan:&HelperPlan)->Result<mission::Step>`. Checkpoint is Operator with empty command.

- [ ] Test mixed faults/contradiction/gaps, TCP-only cannot claim application/auth cause, stale refs excluded, all advice cites supplied IDs, missing consent sends zero requests, changed preview/case discards response, injection/unknown fields/tags rejected, legacy command path unreachable.
- [ ] Run planner/advisory serial filters; fail the unsupported behaviors first.
- [ ] Implement rule families for service/network/resources/SQL evidence; hypothesis confirmation is a separate human decision with actor/time/refs. Add schema-bounded OpenAI Responses advice using existing provider safety patterns and only the reviewed redacted preview. Introduce `AdvisoryPreview`/`AdvisoryConsent` binding preview digest, case/evidence revision, field whitelist, provider/model and grant time; `AdvisoryProposal` contains only questions/hypotheses/typed capability steps. Run requests off the UI thread with a 30-second deadline; canceled replies are discarded. Token dependency is introduced here, not deferred to Task 5.
- [ ] Render support/counterevidence/gaps and next check, distinct AI-consent and Collect controls. Neither selection nor accepting advice executes a probe/action.
- [ ] Verify, review and commit `feat: add evidence-linked helper planning`.

### Task 5 / Wave 5: Connector runtime, credentials and cancellation

**Files:** Create `src/helper/{capability,worker,credentials}.rs`, `worker_tests.rs`, `credentials_tests.rs`, `src/app/helper_panel/connectors_ui.rs`; modify `src/security.rs`, `src/models.rs`, Cargo Tokio/util features and poll integration.

**Interfaces:** Produce the canonical ProbeAdapter/Registry/Worker contracts; `CapabilityRegistry::register(descriptor,adapter:Arc<dyn ProbeAdapter>)->Result<()>`, `validate_request(case:&HelperCase,request:&ProbeRequest)->Result<()>`; `SecretResolver::resolve(scope:&CredentialScope,purpose:CredentialPurpose)->Result<ResolvedSecret>`. ResolvedSecret has no Serialize/default Debug. Add `PersistentCredentialStore::save_scoped(scope_digest:&str,purpose:CredentialPurpose,secret:SecretCredential)->Result<ScopedCredentialRef>` with separate serde-default scoped refs, not synthetic ConnectionProfiles. Rotation creates a new generation/reference; deletion/revocation is rechecked by resolver. Preserve existing `CredentialStore::get/save` and profile refs.

- [ ] Test real dispatch/parser fixture vs declared-only manifests, 4-active/32-queued bounds, 15s default/30s cap, cancellation/deadline/output streaming limits, unknown capability/version, stale response, rotated/deleted/cross-purpose secrets, sanitized native/process errors, and zero dispatch on preview.
- [ ] Run worker/credential filters, fail before implementation; record legacy credential fixture baseline.
- [ ] Implement Tokio-backed nonblocking jobs and fixed program+argv process runner with no shell interpolation; scope-specific secrets are resolved inside worker. Remove or implement redacted Debug for SecretCredential without exposing protected contents. Register a real existing bounded explicit HTTP/TCP check as the first adapter; no fake readiness entries.
- [ ] Add prerequisite/identity/permission status, explicit collect/cancel and result attachment. Case selection does not cancel or discard launched jobs; pending results revalidate original binding.
- [ ] Verify, review and commit `feat: add bounded helper connector execution`.

### Task 6 / Wave 6: Native PostgreSQL diagnosis

**Files:** Create `src/helper/sql/{mod,types,postgres}.rs`, `postgres_tests.rs`, SQL UI slice; modify Cargo/dependency lock and active registry.

**Interfaces:** Produce `PostgresAdapter:ProbeAdapter`, `PgReadProbe::{Identity,Activity,Blocking,Objects,Indexes,Statistics,Permissions}` and `SqlObservation` normalization. `collect` consumes canonical ProbeRequest and scoped read credentials. Transport seam returns typed projected rows; production transport uses tokio-postgres and native TLS.

- [ ] Test exact fixed SQL/parameter order, identity/database mismatch, read-only transaction/rollback, bounded row projection without query text, null/denied views, TLS failure/no silent fallback, cancel/timeout, credential redaction, and native adapter orchestration/parser path.
- [ ] Run `cargo test --locked --bin relayne helper::sql::postgres -- --test-threads=1`; initial driver dependency change updates lock before subsequent locked checks.
- [ ] Implement verified identity first, fixed current-database metadata/activity/blocker/index/statistics queries, read-only sessions/deadlines, dedicated role capability and bounded responses. No arbitrary SQL or plan execution.
- [ ] Mount collect/readiness/blockers/table-stat cards in the shared SQL stage. Add disposable sandbox acceptance via actual product adapter, explicitly reviewed CA/TLS or visible loopback-only sandbox mode, separate from unit fixtures. Reuse installed PG18 runtime, never the host production data directory.
- [ ] Verify, review and commit `feat: add native PostgreSQL helper diagnostics`.

### Task 7 / Wave 7: Native SQL Server diagnosis

**Files:** Create `src/helper/sql/sql_server.rs`, `sql_server_tests.rs`; modify Cargo/lock, SQL module/registry and same SQL UI slice.

**Interfaces:** Produce `SqlServerAdapter:ProbeAdapter`, `SqlServerReadProbe::{Identity,Requests,Waits,Blocking,Objects,Indexes,Statistics,Permissions}`. Initial credentials are scoped SQL login with TLS; do not advertise unimplemented integrated authentication.

- [ ] Test fixed current-database queries/TOP caps, DMV permission gaps, wrong DB/endpoint, TDS typed null/row projections, TLS hostname/trust failure, cancellation/deadline, no SQL text/secret leakage and native transport failure boundaries.
- [ ] Run `cargo test --locked --bin relayne helper::sql::sql_server -- --test-threads=1`; update dependency lock for tiberius/compat then use locked checks.
- [ ] Implement real Tiberius connect/query/stream path and the shared row-parser seam; verify identity before DMV follow-ups. VIEW SERVER STATE/PERFORMANCE STATE varies by engine/version; denied visibility cannot establish no blockers. Do not set trust_cert in production.
- [ ] Mount SQL Server capability/coverage/results in existing helper SQL controls. Clearly distinguish adapter fixtures, actual local authenticated DB test, and not-live-verified. Do not make unavailable customer credentials a prerequisite for code/testing.
- [ ] Verify, review and commit `feat: add native SQL Server helper diagnostics`.

### Task 8 / Wave 8: Plan analysis, safe templates and workload review

**Files:** Create `src/helper/sql/{plans,templates,benchmark}.rs`, `plan_tests.rs`, normalized and raw fixtures under `tests/fixtures/helper/sql`; modify SQL UI/registry/Cargo quick-xml.

**Interfaces:** Produce `parse_import(format:PlanImportFormat,bytes:&[u8],source:ImportSource)->Result<PlanReport>`, `estimated_plan(scope:&BoundScope,template:&ReviewedSelectTemplate,cancel:CancellationToken)->Result<PlanReport>`, `run_sandbox_workload(request:&ReviewedWorkload,policy:&SamplingPolicy,cancel:CancellationToken)->Result<WorkloadSamples>`. Typed fixed templates are `CustomerOrders/StatusCount/OrderSort` for the attested synthetic lab tables, not a generic SELECT text escape hatch. Reviewed metadata identifies the exact same-database objects/columns; unsupported real-app queries stay advisory/import-only until an app-owned versioned template is implemented.

- [ ] Test real aligned psql/BOM/SET+JSON exports, clean JSON and estimated/actual SQL Server XML; 1MiB/64depth/4096node limits, DTD/entities/PI rejection, wrong roots, literal/text redaction, estimate-vs-actual/spill semantics, imported proof rejection and no passive execution.
- [ ] Run plan/template/benchmark serial filters; preserve genuine reference fixtures from the original SQL sandbox without rewriting their evidence status.
- [ ] Implement strict format normalization and bounded parsers; live PG uses EXPLAIN FORMAT JSON only, SQL Server uses a dedicated SHOWPLAN connection closed afterward. Quote verified identifiers, bind values. Workload execution is a separate explicitly reviewed sandbox class with fixed SELECTs and fingerprint/sample provenance.
- [ ] Show operator tree/estimates/actuals/spills/limitations, evidence-linked suggestions and separate import/live-estimate/workload controls. One-shot timing cannot be labeled improvement.
- [ ] Verify, review and commit `feat: add bounded SQL plan analysis and workloads`.

### Task 9 / Wave 9: Windows, Linux and explicit network metrics

**Files:** Create `src/helper/adapters/{mod,windows,linux,network}.rs`, fixed `windows.ps1`/`linux.sh`, `system_tests.rs`; modify manifest/active registry and systems UI.

**Interfaces:** Produce `WindowsAdapter/LinuxAdapter/NetworkAdapter:ProbeAdapter`, `counter_delta(before:&CounterSample,after:&CounterSample)->MetricReading`, and closed typed service/interface/mount/network parameters. Reuse existing HealthCheck/http_health and WinRM/current-identity rules.

- [ ] Test real fixed collector builders/parsers, two-sample CPU/interface rates, resets/missing/zero windows, units, denied/unsupported counters, validated SSH service/mount/interface parameters and injection, scoped DNS/TCP/TLS/HTTP semantics, deadline/cancellation/bindings.
- [ ] Run `cargo test --locked --bin relayne helper::adapters -- --test-threads=1` with system filters; fail before implementation.
- [ ] Implement bounded CPU/memory/commit/disk/process/interface/service/event snapshots; omit command lines/event bodies. Fixed OpenSSH script receives validated typed data, never model/free shell. No broad scanning; rate reset is unknown, not zero.
- [ ] Mount supported-metric/prerequisite cards and real sample windows/unknown gaps in the same helper case. Local fixture success and remote measured coverage remain distinct.
- [ ] Verify, review and commit `feat: add system and network helper collectors`.

### Task 10 / Wave 10: Docker and Kubernetes

**Files:** Create `src/helper/adapters/containers.rs`, `containers_tests.rs`, subprocess fixtures; modify registry/system UI.

**Interfaces:** Produce `DockerAdapter/KubernetesAdapter:ProbeAdapter`; fixed operation IDs `docker.container.inspect.v1`, `docker.container.stats.v1`, `kubernetes.workload.status.v1`, `kubernetes.events.v1`.

- [ ] Test real argument vectors and normalized output through fixture executables: healthy/degraded, absent CLI/auth, denied, context/namespace/resource mismatch, unsafe option-like IDs, malformed/truncated output, deadline/cancel and secrets in raw inspect/env fields.
- [ ] Run container serial filter and demonstrate failure for unimplemented adapter dispatch.
- [ ] Implement selected-container inspect and single bounded stats snapshot; selected namespace pod/workload status and relevant bounded event metadata. Explicit CLI context flags, allowlisted resource kinds, no arbitrary format/query or mutation commands. Whitelist normalized fields; discard environment/secrets.
- [ ] Show exact supported operations/context/prerequisites and not-verified/fixture/live labels. No implicit current kube/Docker context fallback.
- [ ] Verify, review and commit `feat: add scoped container helper diagnostics`.

### Task 11 / Wave 11: Azure VM and AWS EC2

**Files:** Create `src/helper/adapters/cloud.rs`, `cloud_tests.rs`, fixed tool/API fixtures; modify registry/system UI.

**Interfaces:** Produce `AzureVmAdapter/AwsEc2Adapter:ProbeAdapter`; IDs `azure.vm.identity.v1`, `azure.vm.resource_health.v1`, `aws.ec2.inventory.v1`, `aws.ec2.status.v1`.

- [ ] Test real fixed dispatch/parser path with wrong account/subscription/tenant/resource/region, denied/missing CLI/auth, unknown schema, arbitrary endpoint/query injection, output limits/cancel, raw credential/token/path redaction and UI verification labels.
- [ ] Run cloud serial filter and fail expected capabilities first.
- [ ] Use fixed Azure account show/VM show and ARM Resource Health availability route with API version `2024-02-01`; validate actual subscription/tenant/resource. On Windows resolve the vendor Azure CLI Python executable and fixed `-m azure.cli` arguments; do not forward `az.cmd` into a general shell. On platforms with an actual az executable, use direct argv. Use AWS STS caller identity then exact instance inventory/status with explicit account/region/instance IDs and no pager. Missing/ambiguous status is unknown. No account-wide scan or state-changing command.
- [ ] Mount scope-bound resource state/health/coverage in the shared systems stage; tool absence and fixture-tested status cannot become live readiness.
- [ ] Verify, review and commit `feat: add scoped cloud helper diagnostics`.

### Task 12 / Wave 12: Trusted versioned recipes and proposal review

**Files:** Create portable `src/helper_action.rs`, `src/helper/catalog.rs`, `catalog_tests.rs`, `src/app/helper_panel/change_ui.rs`; modify main/module exports and compatible signed-package handling where required.

**Interfaces:** Produce `VerifiedSqlObject`, `VerifiedSqlMetadata`, `PlainIndexColumn`, `SqlAction`, `RestorationSpec`, `VerificationSpec`, `RequiredCheck` in portable shared module; `CatalogEntry::validate()->Result<()>`, `catalog.applicability(case,entry,evidence,now)->Applicability`, `propose(case,entry,params)->Result<HelperProposal>`, `proposal.review_digest()->Result<Digest>`. Checks are typed reviewed public HTTP/SQL postconditions/performance criteria, never executable text. Existing service entry references trusted existing package/contract and delegates execution.

- [ ] Test exact four SQL forms and 1–4 columns, rejected expressions/options/cross-db objects/unknown versions, trusted recipe identity/applicability drift, old catalog/service fixtures, proposal/mission handoff zero calls, non-restorable statistics acknowledgement visible.
- [ ] Run catalog/action serial filters; fail missing validation first.
- [ ] Implement versioned protected catalog with signature/provenance and current proof checks. Reuse existing trusted service packages; new SQL recipe signatures cover the portable typed action/prerequisites/check/restoration/version envelope, never rewrite a service package into SQL. Unknown recipe versions fail closed.
- [ ] Add exact-operation/locking/write/storage-cost preview, prerequisites/gaps, evidence/checks and restoration tag. Review adoption remains inert until authority and worker are implemented.
- [ ] Verify, review and commit `feat: add typed helper recipe and proposal catalog`.

### Task 13 / Wave 13: v2 authority, journal and reconciliation

**Files:** Create `src/helper_approval.rs`, `src/team_server/helper_repair.rs`, `src/helper/journal.rs`, `approval_tests.rs`, `journal_tests.rs`; modify `src/team_server.rs`, `team_client.rs`, `src/bin/relayne_team.rs`, `main.rs`, change UI/poller. Include portable helper_action/helper_approval in both binaries; team must not import GUI/helper runtime.

**Interfaces:** Produce strict `Create/Decide/ConsumeActionApprovalV2`, `ActionApprovalV2`, `ConsumeReceiptV2`, `ActionOutcomeEventV2/Ack`, `ActionBindingV2::validate(now)`/`fingerprint()`, TeamClient v2 methods; `/v2/helper-action-approvals` and `/v2/helper-action-outcomes` use separate tables. Produce `authorize_dispatch(binding,receipt,current:&DispatchContext)->Result<DispatchPermit>`, `ActionJournal::record_intent(permit)->Result<IntentId>`, `reconcile(run_id,observed)->Result<Reconciliation>`. Binding/permit includes RunKind and proof variant; only reviewed staged runs may start with StagingReviewProof, while Production requires a matched real rehearsal receipt. No SQL mutation is added in this task.

- [ ] Test actual authenticated HTTP route+SQLite transactions and client: self/viewer/revoked/expired deny, token/OIDC current-role/expiry binding, concurrent one-winner consume, exact digest/change/credential mismatch, service v1 migration, unknown version/field/tag, recorded expiry audit, list/privacy bounds.
- [ ] Test persistence-before-enqueue counter, final local withdrawal/changed scope after consume, crash after intent/ambiguous timeout no replay, outcome event durable exact retry after failed acknowledgement save; run approval/journal serial filters and team binary tests.
- [ ] Implement domain-separated canonical v2 wire/schema checks and role/TTL/revocation/one-use audit. Organization scope is the server's persisted configured instance/tenant identity, obtained by authenticated capability handshake and checked against the client's reviewed team endpoint; never accept a tenant string supplied solely by the case. Server cannot certify live evidence; final local preconditions/credential/proof/operation are required before opaque permit and durable intent. One dispatch coordination gate covers final recheck, durable intent and launched-state publication; case edits/review withdrawal use that same gate. No remote I/O under the gate. A detached old DispatchContext snapshot is insufficient for final dispatch.
- [ ] Add UI requested/approved/consumed/outcome-unknown/intervention states and exact restoration acknowledgement. A consumed receipt cannot be reused. Existing service catalog entry routes to original v1 executor; no second service dispatcher.
- [ ] Verify, review and commit `feat: add journaled generic repair authority v2`.

### Task 14 / Wave 14: Bounded SQL executor and isolated general rehearsal

**Files:** Create `src/helper/sql/{changes,rehearsal}.rs`, `change_tests.rs`, `rehearsal_tests.rs`; extend native transport execution in both engines and journal/change UI.

**Interfaces:** Produce `prepare_sql_change(action:&SqlAction,scope:&BoundScope,metadata:&VerifiedSqlMetadata)->Result<PreparedSqlChange>`, internal `execute_sql_change(permit:DispatchPermit,journal:&mut ActionJournal,cancel:CancellationToken)->Result<ActionOutcome>`, `SqlTrialMapping::validate()->Result<()>`, `run_sql_rehearsal(mapping:&SqlTrialMapping,permit:DispatchPermit,cancel:CancellationToken)->Result<SqlRehearsalReceipt>`, `load_sql_rehearsal(path:&Path)->Result<SqlRehearsalReceipt>`. Prepared SQL is private/nonserializable; only known grammar. No public execute_sql(String). No production registration/Apply button until Task 15.

- [ ] Test real builder/action path for quoting/NUL/length/hostile identifiers, 0/5 columns, wrong object/database, denied grants, name already exists, transactional postcondition failure, blocking/deadlines and ambiguous commit. Test same physical DB aliases cannot be a clone, production permits reject StagingReviewProof, unknown equivalence/partial checks cannot mint a receipt, tampered/stale/wrong-action receipt rejected.
- [ ] Run SQL-change/rehearsal serial filters and available disposable PG transaction tests; injected SQL Server transport remains clearly fixture tested until actual instance exists.
- [ ] Implement exact four-form driver execution behind opaque permits and durable intent. A rehearsal requires explicit reviewed isolated target and mapping, independently verified server/database/object identities, engine/schema/action/workload comparison and declared data-coverage limits. Existing clone/fingerprint discipline is reused, but service LabReceipt cannot authorize SQL. No automatic customer-data clone/copy or arbitrary database-drop command. Index creation also applies the fixed run-ownership marker inside the same transaction: PostgreSQL fixed COMMENT metadata or SQL Server fixed index extended property `Relayne.CreatedByRunV1`, derived from run/scope/action plus an approval-bound random nonce. This is a private implementation substep of CreateIndex, not a free metadata-write capability. Missing marker privilege or failed marker verification rolls back; never silently accept weak ownership proof.
- [ ] Run actual staged action and typed postconditions/checks; persist immutable DPAPI-bound receipt with original production/staging scope fingerprints, normalized semantics, actual staged metadata/outcomes, coverage and one-hour maximum expiry (stricter proof policy wins). Unknown required equivalence blocks trial eligibility. Synthetic/representative data is labeled and cannot claim an exact snapshot; production policy requires the reviewed coverage declared by the case. Statistics trial has acknowledged non-restorable limits; disposal/rebuild is an explicit sandbox operation, not a no-op rollback receipt.
- [ ] Add General rehearsal UI mapping/limits/check results and current receipt status. Enforce no production dispatch path yet. Verify, review and commit `feat: add bounded SQL execution and real rehearsal proof`.

### Task 15 / Wave 15: Production promotion and bounded restoration

**Files:** Create `src/helper/sql/{promotion,restoration}.rs`, `promotion_tests.rs`, `restoration_tests.rs`; modify generic permit validation, executor production registration, journal/change UI.

**Interfaces:** Produce `check_sql_promotion(case:&HelperCase,proposal:&HelperProposal,receipt:&SqlRehearsalReceipt,current:&DispatchContext,now:DateTime<Utc>)->Result<()>`, `apply_sql_production(permit:DispatchPermit,journal:&mut ActionJournal,cancel:CancellationToken)->Result<ActionOutcome>`, `restore_index(run_id:Uuid,journal:&mut ActionJournal,cancel:CancellationToken)->Result<RestorationOutcome>`. Apply delegates the same Task 14 executor; no duplicate SQL builder or separate permission system.

- [ ] Test wrong staging/production mapping, engine/schema/action/check/data-coverage drift, expired/future/tampered receipts, approval wait past 120-second before evidence, last-moment withdrawn review/rotated credential, missing statistics acknowledgement, journal fault yields zero remote calls and ambiguous commit is not retried.
- [ ] Test exact created index object/definition/ownership versus replacement index, restore after UI target change and team outage, unknown/unavailable restoration → NeedsIntervention/later-target halt, exact durable outcome retry; run promotion/restoration/journal serial filters.
- [ ] Reload protected real rehearsal receipt, re-observe production metadata/grants/credential scope, match current action/checks/proof/coverage, consume exact v2 approval, then final coordination gate/durable intent and same native executor. Before evidence remains <120 seconds old; recollect/approve if it expired. General rehearsal is not production success.
- [ ] Record created index OID or SQL Server object/index identity/definition and the verified run-ownership marker durably for that run. SQL Server may reuse index_id; name/definition/index_id alone cannot prove unchanged ownership. Compensation drops only the still-exact identity/definition/marker; absent marker or replacement refuses drop and records intervention. Statistics cannot restore prior statistics; failure records intervention. Restoration of a launched run does not require the team service to be online.
- [ ] Mount actual production Apply/reconcile/restore controls with exact target/proof/limits, preserving old service executor delegation. Verify, review and commit `feat: promote SQL repairs with verified restoration limits`.

### Task 16 / Wave 16: Functional chain and performance proof

**Files:** Create `src/helper/verification.rs`, `verification_tests.rs`, `performance_tests.rs`, `src/app/helper_panel/verification_ui.rs`; extend benchmark/journal receipt links and case derived terminal resolution.

**Interfaces:** Produce `VerificationPlan::validate(case)->Result<()>`, `run_checks(plan:&VerificationPlan,run:&RunReference,cancel:CancellationToken)->Result<FunctionalReceipt>`, `compare_performance(baseline:&PerformanceReceipt,current:&PerformanceReceipt,policy:&ComparisonPolicy)->Comparison`, `resolve_case(case,journal,functional,performance)->Result<CaseResolution>`. RunReference tags existing-service versus helper-v2 journals. Service handoff binds the helper revision, exact existing execution plan/target and eventual run; missing/mismatched linkage cannot produce helper success. Add a read-only `execution::Run::verified_target_evidence(index)->Option<VerifiedExecutionEvidence>` accessor deriving from existing internal evidenced_success/binding checks rather than duplicating that predicate in helper code.

- [ ] Test wrong case/action/run/scope/check hashes, duplicates/missing API/portal target, missing/failed/skipped/unsupported required check, stale/future/tampered receipts, required window not met, external/no-change cannot mint Relayne success, intended-vs-unexpected config delta and complete raw sample counts.
- [ ] Test deterministic clear improvement/regression, overlapping-MAD noise, zero/NaN/negative samples, missing warmups/sample count, incompatible workload/data/environment, changed resultset and incomplete window; run verification/performance serial filters.
- [ ] Reuse actual HealthCheck and existing service result derivation; fixed public HTTP functional checks cover API and both portals. Persist independent functional/performance receipts with exact approved context, raw samples and comparison-policy version; evaluate all declared criteria, not only SQL status or mean timing.
- [ ] Render per-check coverage and median/p95/noise/absolute threshold results separately. VerifiedRelayneRepair is derived only after actual action and complete required checks; other terminal reasons are reviewed and explicitly labeled.
- [ ] Verify, review and commit `feat: verify helper outcomes and workload performance`.

### Task 17 / Wave 17: Reviewed operating knowledge and incident reports

**Files:** Create `src/helper/knowledge.rs`, `knowledge_tests.rs`, `src/app/helper_panel/knowledge_ui.rs`; extend export/schema defaults and compatible catalog links.

**Interfaces:** Produce `lesson_candidates(case:&HelperCase,service:&execution::Journal,generic:&ActionJournal,receipts:&ReceiptStore,now:DateTime<Utc>)->Result<Vec<LessonCandidate>>`, `review_lesson(id,expected_revision,decision)->Result<()>`, `revalidate_lesson(id,fingerprint,evidence,now)->Result<()>`, `recommend_lessons(context,now)->Vec<LessonMatch>`, `export_report(case_id,...)->Result<CaseExport>`.

- [ ] Test service learning's qualifying-run semantics, generic verified action/full checks, no-op/failed/restored/unknown/rehearsal/imported/external exclusions, exact fingerprint only, later adverse evidence retraction, drift/expiry/revoked trust, old revisions and stale concurrent saves cannot resurrect eligibility, redacted bounded exports.
- [ ] Run knowledge/export serial filters; ensure the failure is due to missing behavior, not relaxed existing success logic.
- [ ] Reuse `execution::learning::rank` and existing journal evidence boundaries, not aggregate score as proof. Store review/revision/applicability/revalidation/invalidation history; new success cannot silently erase revocation. Existing free-form memory stays unverified. Catalog publication remains distinct from execution consent.
- [ ] Add candidate/verified/stale/invalidated cards with evidence, review/revalidate and JSON/Markdown report controls. Reuse requires fresh scope comparison and a new action approval.
- [ ] Verify, review and commit `feat: add verified helper lessons and reports`.

### Task 18 / Wave 18: Complete guided desktop and real sandbox acceptance

**Files:** Complete helper UI stage modules/poller, `src/app/capture.rs`, routing/localization; create `src/helper/lab.rs`, fixture scripts and reports under `tests/helper-sandbox/`; add explicit `--helper-lab`/`--helper-acceptance` modes in existing `src/main.rs`; update `.github/workflows/relayne-product-windows.yml`, `docs/relayne-helper.md`, `docs/relayne-helper-acceptance.md`. Reuse the existing binary/module graph, not a standalone binary that cannot import GUI-binary driver modules.

**Interfaces:** Produce `run_acceptance(config:&SandboxAcceptanceConfig)->Result<AcceptanceReport>` using actual product adapters/actions/authority/verification, not a second implementation. Fixture mode is launched explicitly with isolated data directory and generated local-only credentials; tiny_http API+two separate portal origins query the same real PG database, directly or through that shared API. Capture seeding is distinctly SimulationFixture; measured acceptance captures reference persisted real evidence. Reuse the product binary's driver modules and public helper APIs for CLI/GUI; never duplicate adapter SQL or approval gates in the fixture.

- [ ] Add complete coordinator scenarios matching spec §9: sparse intake/save/reload, actual read and blocker capture, imported spill provenance, selective estimates corrected after actual maintenance, reviewed exact index mutation, real repeated query output, API+both portal function, target/criterion edit and post-launch reconciliation, terminal no-change/external/unresolved, lesson invalidation/export.
- [ ] Add production-path integration tests and deterministic GUI-render tests before completing final UI; screenshots alone are rendering proof, never execution proof. Capture requested/approved/consumed/verified/intervention states with an explicit fixture/live label.
- [ ] Build and copy the product binary/runtime for its explicit fixture modes into the disposable Sandbox. PG18 already exists at `C:\Program Files\PostgreSQL\18`; wsb is available. Existing sandbox `962f0738-9ae2-4709-bc18-b3820ac4b273` contains reference fixture `C:\RelayneSqlLab`, but new acceptance uses a separate named DB/root/ports to avoid overwriting it. Never connect to/change the host PostgreSQL service/data. New helper driver comes from Tasks 6–7, not baseline Cargo.
- [ ] Configure trusted TLS/private key only inside guest and reviewed public CA on the helper fixture client, least-privilege read/change identities, deterministic synthetic data/slow query/selectivity/spill/blocker. API/portals execute real bounded DB SELECTs; their expected rows/content and timings are measured. Role-controlled team-v2 acceptance uses isolated loopback server/two test actors; label actor-test evidence rather than claim two real human identities. No shared/customer credentials.
- [ ] Run all seven named acceptance scenarios via the actual helper coordinator and save raw bounded evidence/receipts/approval audits plus native dynamic captures. For unavailable SQL Server/Linux/container/cloud live endpoints, retain honest fixture/not-live-verified status and do not call the local PostgreSQL demo proof of them.
- [ ] Run `cargo build --locked --bins`, `cargo test --locked --bins -- --test-threads=1`, `cargo clippy --locked --bins -- -D clippy::correctness`, touched-file rustfmt/diff and final whole-branch review. Fix material findings with one final fix wave/scoped re-review following the SDD workflow. Commit `feat: complete guided helper and sandbox acceptance`; report exact tested coverage and remaining live-validation limits.

## Parallel execution and recovery ledger

Maintain `.superpowers/sdd/generic-helper/progress.md` with this plan identity first, base/commit ranges, per-task reports/reviews, open findings and rulings. The six original product-wave tasks remain complete and are not re-dispatched.

The user explicitly requested maximum subagents. Use at most twelve children: read-only preparation, fixture/docs work and independent review can run concurrently. Shared-core tasks 1–5 and authority/dispatch tasks 12–16 are sequential integration owners. After Task 5 interfaces are reviewed, adapter Tasks 6/7/9/10/11 may be prepared independently; implementations can use disjoint owned paths only, with one designated integration owner for Cargo/root/UI registration and serialized Cargo checks. Never overlap edits to a shared interface/store/approval or let an implementer review its own changes. Respect Luna low/medium for mechanical work and Sol medium/high for native database/security/concurrency integration. No Astra is justified by current evidence.

Preflight must record a conflict table before dispatch: case/scope/evidence revisions; Task 3 manifest vs Task 5 registry; Task 4 plan vs Task 5 dispatch; both SQL readers vs shared types/dependencies; plan-template identifiers vs action grammar; Task 12 portable types vs Task 13 server inclusion; Task 13 permit/journal vs Task 14 staged executor vs Task 15 production/promotion; Task 16 comparison binding vs intentional index/config delta; Task 17 lesson eligibility vs Task 16 terminal outcomes; Task 18 fixture ownership vs original reference Sandbox. Record a ruling for any genuine conflict; do not silently improvise cross-task types.

## Plan self-review

- Every requested area maps to a named wave and real user path: intake1, context2, evidence/retention/export3, planning/LLM4, extensibility/credentials5, SQL6–8, OS/network9, containers10, cloud11, catalog12, authority13, SQL execution/rehearsal14, production promotion/restoration15, verification16, knowledge/report17, UI/end-to-end18.
- Canonical interfaces resolve the exploratory proposals' inconsistent module/type names. Evidence_revision is separate from context revision. Cloud account scans and synthetic profile credentials are excluded. Team binary includes portable wire/types only.
- All five Review Focus items have owning-task test steps. Fixture/native/actual-live claims are separated. A deliberate action delta is permitted in comparison; unplanned context drift is not.
- At plan finalization (0b4c6f4), no code changes, builds, installs, customer calls or deployment had been performed for this expansion. The user subsequently confirmed the written plan with “go”; implementation is now tracked in the plan-scoped SDD ledger.
