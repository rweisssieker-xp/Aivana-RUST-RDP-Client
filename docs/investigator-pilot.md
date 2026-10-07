# Investigator pilot evidence and readiness report

The pilot API records human measured operational observations and exports a reproducible evidence report. The report surfaces configuration gaps, observations older than 90 days, and required measurements that have not been recorded. It is an evidence ledger, not a production approval: it never changes `a1_ready`, enables a connector, grants tenant rights, or asserts that deployment is production ready.

## API actions

- `pilot.status` returns the current readiness label, A1 status as computed by the existing service, missing or stale evidence, and observation count.
- `pilot.record` accepts an observation from `admin`, `reviewer`, or `incident_lead`. The server assigns tenant, operator, record time, UUID, and content hash. Rows are append-only and duplicate content is rejected. The evidence references must identify artifacts and their SHA-256 digests; artifacts are not uploaded by this endpoint.
- `pilot.report` accepts `{"format":"json"}` or `{"format":"markdown"}` and exports the same generated report payload in JSON or Markdown.

Every record includes `kind`, `case_type`, `completeness` (`complete` or `incomplete`), `observed_at` (RFC3339), `sample_count`, `metrics`, `targets` (separately stated objectives), and one or more `evidence` entries containing `artifact_ref` and `sha256`. Optional `note` is limited to 2,000 characters. Supported kinds and required measured metrics:

| Kind | Measured fields |
|---|---|
| `source_feasibility` | `result` (`passed`, `failed`, `partial`), `coverage_percent`, `p95_latency_ms` |
| `restore_drill` | `actual_rto_seconds`, `actual_rpo_seconds` |
| `shadow_comparison` | `reference_cases`, `critical_omissions`, `unauthorized_actions` |
| `availability` | `available_minutes`, `observed_minutes`; measured percentage is derived |
| `analyst_time` | `manual_minutes`, `assisted_minutes`, `rework_minutes` |
| `cost_comparison` | `manual_cost_micros`, `system_cost_micros`, `review_cost_micros` |

All numeric fields are bounded and finite. Counts must be positive and at most 100,000 (shadow counts may be zero). An observation cannot be dated more than five minutes in the future. The report gives median and nearest-rank p95 for analyst assisted minutes and system cost, split by case type and complete/incomplete cases; sample counts accompany every statistic. Empty measurements remain null/unknown. These are descriptive samples, not statistical guarantees. PRD availability 99.5%, RTO 60 minutes, RPO 15 minutes, and 30% analyst-time reduction are displayed as objectives/hypotheses only.

The observations retain evidence references and operator notes, so do not put secrets, personal data, or raw incident content in them. Keep source artifacts in the separately approved evidence store. This endpoint does not verify the referenced artifact bytes; a reviewer must validate them. A recorded measurement is not independently verified simply because it appears in the report.

## No-secret environment checklist

Run `integrations/investigator/pilot/check-env-refs.ps1 -ConfigPath <path-to-config.json>` from an authorized operator shell. It validates and lists configured environment-variable reference names for users, enabled source/collector/response credentials, and notification hooks. It does not inspect environment values, contact services, install software, start collectors, or change tenant permissions. It reports configured names only. Do not place secret values in the configuration file.

The checklist validates reference-name syntax only. It establishes neither environment-variable presence nor credential validity. Source feasibility, permissions, retention, availability, restore time, shadow quality, analyst time, and cost must be measured and recorded from approved pilot evidence. Do not use synthetic measurements as evidence of a live tenant or claim a passing gate from objectives alone.
