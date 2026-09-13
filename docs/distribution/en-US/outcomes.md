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
