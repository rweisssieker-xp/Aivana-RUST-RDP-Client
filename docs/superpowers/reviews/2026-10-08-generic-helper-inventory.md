# Generic helper inventory — 2026-10-08

Reviewed source base: 671080c. The previous product waves are complete and were not restarted. Original checkout and its promotional fixtures were read only. The existing isolated worktree is reused on codex/relayne-generic-helper.

## Delegation and evidence

Twelve focused inventory subagents were dispatched under the user's maximum-subagent request. Eleven were Luna low/medium, and the architectural/security inventory was Sol high. No Astra, external system connections, test execution, package installation or product-code modification was part of these inventories. Two additional independent spec reviewers follow the inventories.

| Audit | Confirmed reuse point | Material gap |
|---|---|---|
| helper_intake_audit | intelligence structured plans, mission objectives, ticket intake, diagnostic handoff | Persistent general problem intake and clarification loop |
| helper_context_audit | profiles, exact Target identity, telemetry observations/edges/probes, Insights | Joined asset/application/database context and non-Windows collectors |
| helper_sql_audit | bounded operations jobs and request-bound fixed diagnostic adapter | No PostgreSQL or SQL Server driver/probes/plan analysis |
| helper_os_audit | inventory/services/processes/events plus DNS/TCP preflight | Typed sampled CPU/memory/disk/interface counters and Linux collectors |
| helper_connectors_audit | working SSH/SFTP/WinRM/HTTP and bounded Graph API paths | Versioned capability registry and executable DB/container/cloud adapters |
| helper_planner_audit | diagnostic_lab candidate supports/contradicts/missing and foresight | Broader hypothesis vocabulary; preflight confidence must not imply cause |
| helper_evidence_audit | incident association, strong Investigator provenance, execution case-target bindings | Common provenance envelope, clock/coverage quality, immutable helper export |
| helper_catalog_audit | versioned workflow packages, signed repair catalog and recovery contracts | Typed SQL recipe execution and action-generic exact authority |
| helper_verification_audit | real LabReceipt, exact promotion/equivalence and recovery contracts | Separate workload/performance receipt and cross-target coverage |
| helper_knowledge_audit | journal-backed execution learning, contract invalidation, memory | Reviewed versioned general lesson with applicability and revalidation |
| helper_security_arch | typed fixed checks, one-use team consume, final local recheck | Safe cross-domain action binding, credential scope, least-privilege SQL |
| helper_ui_acceptance_audit | desktop navigation, existing panel state and nonblocking pollers | One coherent helper workspace and real generic end-to-end acceptance |

An initial evidence worker reported unavailable filesystem tools without inspecting files. The coordinator supplied the functions.exec access path, and the worker then completed a grounded read-only audit. The unavailable report is not used as evidence.

## SQL reference evidence

The prior disposable PostgreSQL sandbox has actual raw measurements in C:\tmp\Aivana-RUST-RDP-Client\promo-video\sql-sandbox. Customer lookup: 42.049 ms before, 0.238 ms after the index. Sort: 196.981 ms before, 140.094 ms after session work_mem; observed disk spill versus RAM. Separate selectivity: 1,292 estimated versus 40,600 actual before ANALYZE, 40,607 estimated afterward. Actual blocking and lock timeout were observed, followed by zero blocked sessions. These were externally executed PostgreSQL tests, not Relayne feature acceptance, repeated benchmarks or proof of production performance.

## Proposed architecture

See ../specs/2026-10-08-generic-helper-design.md. It covers the ten requested capability areas in six waves and preserves existing journals, production/rehearsal separation, current approval semantics and restoration paths. Status is proposed for user review. Product implementation has not begun.

## Review and validation status

Self-review checked scope, reused authority boundaries, measurable acceptance, truthful environment coverage and no placeholder requirements. Source tests/builds have not been repeated for this documentation-only preparation; prior product-wave results are historical, not new verification claims.

Independent architectural/security review initially requested six corrections: explicit typed planner-to-dispatch boundary excluding legacy free commands, v1/v2 approval wire/digest and trust split, bounded SQL action grammar, tagged restoration availability, legitimate no-change/external terminal outcomes, and a usable vertical slice in each wave. All were added. Focused re-review verdict: PASS; all six addressed, no new Important contradiction.

Independent coverage review requested concrete intake/diagnosis scenarios, operation/prerequisite scopes, adapter/UI acceptance, retention and backward-compatibility gates. These were added. Focused re-review found all material gaps addressed and no new material contradiction. Its original malformed Wave 3 Markdown row finding was explicitly withdrawn after raw-source verification; it was transformed tool output, not a source defect. All six wave rows have three columns.

The specification and German review summary are complete for user review. Implementation planning and code execution remain pending the written-spec approval required by the selected architectural workflow. The user has already selected waves with subagents; do not ask them to choose the execution method again.
