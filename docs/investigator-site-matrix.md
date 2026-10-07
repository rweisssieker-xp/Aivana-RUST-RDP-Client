# Finding-specific site matrix

Select an authorized case, open **Sites**, then **Refresh site matrix**. The read-only `sites.matrix` command accepts `{ "case_id": "<case UUID>" }`. Tenant and approved-site scope come from the authenticated service configuration, not the request. The executor process does not expose this command.

The matrix compares the case's relevant findings with approved sites. A site without an exact linked assessment remains `not_checked`; another case at that site, a general site assessment or an accepted supplier deliverable does not establish clearance for this finding. Missing coverage stays explicit. Related cases, supplier handoffs and unlinked assessments are displayed as context, separately from the assessment result.

Use **Assess site finding** to record the exact finding ID returned by the matrix, target site, owner, scope, status, coverage description and evidence references. Supported statuses are `not_checked`, `in_progress`, `finding`, `no_evidence_in_scope`, `insufficient_data` and `not_applicable`. A scoped negative assessment requires the existing authorized human review, evidence references and reason; it is not a general claim that the site is safe. The browser prepares normal version-checked `sites.assess` commands and cannot bypass backend checks.

Supplier work orders and human acceptance retain their existing evidence and role requirements. The matrix reports supplied observations; it does not create investigations at other sites, run collectors, contact suppliers or produce measured operational KPIs. Real cross-site coverage and supplier performance still require attributed pilot evidence.

Negative and not-applicable assessments are bound to the case's evidence/scope snapshot by the backend. Missing bindings on older records or later changes invalidate their current negative interpretation: the matrix reports `insufficient_data`, hides the old coverage claim and retains the assessment for review. Finding IDs from another case cannot clear this case, even when the same playbook reuses an ID. Display limits and missing stable finding IDs are reported explicitly.
