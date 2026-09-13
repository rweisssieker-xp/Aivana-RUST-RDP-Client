# Measured repair outcomes

Under Causes & solutions, select a production profile and expand Measured outcomes in the learning recommendations section. The report uses completed execution-journal results from the last 90 days for that endpoint. No network or AI call is made.

## What is measured
Production and rehearsal each show evidenced repairs, failures, restorations and unverified outcomes. The same strict validation as learning recommendations applies: exact plan and target binding, duplicate exclusion, failed baseline, HTTP success and actual service transition or verified restart. Excluded outcomes remain counted separately.

The median interval runs from the target's initial recorded observation to its successful health-check timestamp. It does not extend to later completion of a batch of targets. Only evidenced successes supply timing samples; the sample count and repair count are displayed together. Missing samples remain missing, not zero. Each sample exposes run/target identifiers and UTC timestamps.

## Interpretation limits
This is not total incident duration, MTTR, administrator labor, uptime, avoided loss or time saved. Successful-only timing has selection bias; failures are shown separately and are not treated as fast repairs. No manual baseline or financial costs are stored, so labor savings and ROI are explicitly unmeasured. No hypothesis of customer-environment equivalence or causal effectiveness is implied.

## Export and privacy
Copy outcome report as JSON creates a local clipboard report with selected profile ID, time window, cohort counts and timestamp evidence. It does not export credentials or host addresses and does not authorize execution. Identifiers can still be sensitive; review before sharing. Source records remain unchanged. New UI and documentation support en-US, de, fr and it.

## Verification — 2026-09-13

Four focused outcome/UI tests and 21 execution regression tests passed (three overlap). The new view was rendered in four languages at 640 and 1440 pixels. Offline application build and formatting check passed. No full-suite rerun or live connections; existing build warnings remain.

## Repair-history warning radar

The expandable radar evaluates evidenced production repairs by identical procedure key (service, action and health check). Rehearsal, duplicate run IDs, future/expired timestamps and inconsistent intervals are excluded. It generates no notifications, network requests or automatic actions; the report is recomputed when the view is opened/rendered.

Repeated repairs: at least three distinct runs on at least two UTC dates during the last seven days. This indicates recurring repair activity, not proof that the incidents share a cause.

Slower verification: the latest three successes are compared with the preceding three within a 30-day history. Each group must cover at least two UTC dates; the recent three must all be within seven days. The recent median must be at least twice the baseline and at least 5,000 milliseconds greater; a zero baseline cannot trigger this rule.

Each signal includes the exact source run identifiers and, for slowdown, both medians. JSON export now uses schema relayne-outcome-impact-v2 and includes procedure identities and signals. These are retrospective heuristics, not statistically validated forecasts. No threshold reached does not establish system health or sufficient evidence. Existing success-only timing limitations still apply.

Radar verification (2026-09-13): 24 execution tests including three new radar tests, plus the four-language UI test, passed. Offline build and formatting checks passed. No full-suite rerun or live connection.
## Local warning reviews

Radar warnings can be acknowledged with a required note and reopened manually. The warning remains visible. Acknowledgements apply to the exact profile, procedure and source evidence; changed evidence or 30 days of age reopens the review. Refreshing the view does not reset it. This never authorizes a repair or changes outcome evidence or ranking.

Reviews are stored locally in `relayne-warning-reviews.dpapi`, protected by Windows DPAPI. Notes are limited to 256 characters (1,024 bytes), with best-effort secret redaction; do not enter credentials. The store holds at most 256 reviews. Remove expired reviews to free capacity. Reload after a conflicting write or read failure; failed writes retain the previous state. Reviews are not included in outcome JSON exports.
