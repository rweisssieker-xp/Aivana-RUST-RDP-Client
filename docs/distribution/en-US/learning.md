# Learning repair recommendations

The new section under Causes & solutions ranks existing service recovery records for the selected production endpoint. It does not train a model or call an AI provider. The ranking is deterministic and recomputed from the current execution journal without a separate learned-evidence store.

## Evidence rules
Only completed records from the last 90 days contribute. Future, expired, duplicate run/target identities, invalid plan bindings and other endpoints are excluded. Rehearsal outcomes are shown separately and never raise the production ranking. Start, restart and different health checks have separate identities.

A repair success requires the existing before/action/after evidence validation, a failed baseline, a successful HTTP health check and a real service transition or verified restart. A healthy no-op or TCP-only check does not establish repair success. Failed, restored and unverified outcomes remain visible.

## Ranking and withdrawal
Each production category is capped at five: +5 per supported repair, −8 per failed/restored result combined, −4 per unverified result. These are inspectable ranking weights, not probabilities. A recommendation requires at least one supported production repair and its latest success must be newer than every adverse or unverified production result. Ties remain blocked. Sorting is deterministic.

## Use and limits
Select a profile, inspect counts and evidence references, then prepare a new verification plan if supported. Existing running-job protection and new-target verification/approval still apply. No action starts from the ranking. Copying the report is explicit and includes service names and evidence identifiers; review it before sharing.

Same endpoint does not prove unchanged software, configuration or permissions. There is no cross-customer learning, no proof of causal effectiveness and no measured productivity claim. Excluded records are counted rather than used as positive evidence. Existing legacy solution views remain available separately. New text is available in en-US, de, fr and it.
# Evidence gaps
Historical gaps are shown explicitly: missing HTTP check, missing failed baseline, missing service transition, or incomplete/contradictory before/action/after evidence. These explain historical uncertainty, not the current host state.

## Verification — 2026-09-13

Five focused learning/localization tests and 18 execution regression tests passed (four tests overlap). Offline application build and formatting check passed. No full-suite rerun, live host access or external model calls. Existing build warnings remain.
