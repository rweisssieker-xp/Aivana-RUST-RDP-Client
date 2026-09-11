# Aivana Rust RDP Client

Native Rust desktop application for RDP operations, diagnostics, incident evidence, and guarded KI Computer Use.

The app builds as a single Rust desktop binary with `eframe`/`egui`. There is no external Windows RDP launcher, no WebView shell, and no browser runtime.

## Native workbench

The directory-first workspace combines a light computer directory with a focused dark session view, optional side-by-side comparison and contextual recovery. Native input, clipboard/files, dynamic display and multi-monitor layouts, automatic reconnection, PCM audio/microphone, scoped folder redirection, profile exchange and RD Gateway are implemented.

See [operation, supported protocols and limitations](docs/rdp-workbench.md). These are actual protocol integrations; compatibility with a specific server/device still requires live verification. Gateway currently supports WebSocket/HTTP Basic on target port 3389; clipboard folders require ZIP.

## Current Capabilities

- Native workspace with equally sized live-preview tiles in an adaptive grid, a compact list for many connections, profile-group navigation and drag-to-reorder. Choose **Groß hervorheben** in a connection menu to give that connection a large preview; **Hervorhebung aufheben** restores equal tiles. Grid/list selection and the highlighted connection persist alongside ordering in `desktop-layout.json`.
- Focus mode with session switching, fit/actual-size display, fullscreen and collapsible contextual KI/diagnostics.
- Interrupted sessions reveal diagnostics and a selectable event timeline; disconnected previews are explicitly marked as historical and accept no remote input.
- Local command palette (`Ctrl+K`) for navigation, profiles and active sessions. Opening a profile does not automatically connect.
- KI tasks stop when switching to another session. The new workspace does not display synthetic quality metrics.

The visual workspace combines the spatial overview, quiet focus and incident investigation concepts in `docs/gui-concepts/`. Session previews use real RDP framebuffers; saved profiles without a running session show an explicit empty state. The timeline is an event log, not video replay. Profile groups or tags named `production`, `produktion` or `prod` receive a `PRODUKTION` label. Layout restoration restores ordering and group selection, not network connections.

- Native desktop shell with sidebar navigation, profiles, sessions, settings, and a live RDP viewport.
- Connection profile list, search, editor, groups, tags, favorites, and JSON persistence.
- Passwords are skipped from profile JSON; the credential boundary stores only `credential_id` on profiles.
- Long-running IronRDP session thread with state events, framebuffer updates, disconnect/error handling, and native input channel.
- egui texture rendering for decoded IronRDP framebuffer frames.
- Pointer move, click, scroll, and typed text forwarding into the RDP input path.
- Local preflight diagnostics for DNS/TCP/credential readiness.
- Local KI diagnosis from deterministic findings and session evidence.
- Persistent credential store: Windows DPAPI-protected secrets on Windows, profile JSON stores only `credential_id`.
- Certificate trust gate with RDP TLS fingerprint probing, local persistence, reject/trust decisions, and KI risk explanation.
- Persistent Timeline and Blackbox evidence store with redaction, Markdown incident export, JSON evidence export, and disk export folders.
- Guarded Computer Use flow that observes native framebuffers, detects basic screen state, plans actions, queues approvals, executes approved input, and traces verification.
- Approval Center for elevated-risk KI actions with allow/deny/runbook/abort decisions.
- Runbook engine with first diagnostic/evidence runbooks, Evidence Mode, next-step execution, pause/resume/abort.
- Persistent Workspace Cockpit with host memory, workspace memory, runbook inventory, open approvals, and recommended next step.
- Proactive KI USP actions: Why did this fail, What changed, Safe next action, Evidence mode, Ticket in 30 seconds, Runbook recommendation.
- Autopilot Mission Control with persisted goal/provider/model/step/delay preferences, goal presets, local dry-run preview, batched action parsing, batch-preserving approvals with redacted action previews, safety acknowledgements, and batch-aware per-step audit output.
- Redacted LLM handoff generator that turns session timeline, diagnostics, snapshots, and Autopilot trace into a prompt-ready Markdown artifact.
- Workspace KI Operations cockpit with readiness checks, KI Action Brief, Autopilot priming, evidence goals, and one-click LLM handoff for the active session.
- KI Verification Center for OpenAI key readiness, local `rdp-live.env` auto-detection, RDP smoke-test environment checks, persisted preference status, and copyable verification briefs.
- Runbook LLM Briefs that summarize available diagnostic runbooks, actions, risks, and approval needs for model-assisted triage.
- Prompt Library Briefs for diagnosis, runbook selection, ticket drafting, and verification prompts built from the current KI action context.
- AI Brief Pack export that writes action, prompt-library, runbook, and verification briefs as redacted Markdown files with a JSON manifest.
- Latest AI Brief Pack evidence is shown in the KI Verification Center for audit-friendly reuse.
- Policy Guardrail Briefs explain active Autopilot safety behavior, allowed actions, approval-gated actions, and denied destructive text.
- OpenAI CUA Request Briefs summarize provider, model, goal, framebuffer state, step limits, delays, and guardrails before hosted Computer Use is invoked.
- KI Goal Audit in the Verification Center provides a prompt-to-artifact checklist, displayed RDP env source, blocking gate count, next-gate guidance, structured next-gate JSON copy, command-index JSON copy, visible handoff-check status, handoff-check JSON copy, handoff risk summary copy/export, verification snapshot JSON copy/export, direct RDP proof check JSON copy, no-secrets RDP proof prompt copy, RDP recovery plan copy with acceptance criteria, direct live evidence, and proxy-evidence rejection, recovery command copy, live-gate doctor JSON copy, direct live-gate next-command copy, concise operator-brief copy, full live-gate sequence copy, LLM review prompt copy with `summary.md` Early LLM Triage and `operator-handoff-risk-summary.json` cross-check, live-gate LLM plan copy, LLM action-contract JSON copy/export with `summary.md` Early LLM Triage, `direct_live_evidence_requirements`, `early_triage_artifacts`, and evidence success signals, latest handoff-pack and live-gate evidence, a live-gate runbook, copyable RDP env template, copyable Markdown, JSON/Markdown export, and one-click Operator Handoff Pack export.

## Requirements

- Rust 1.95 or newer
- Windows, Linux, or macOS supported by `eframe`
- A reachable RDP endpoint for real-session testing

## Build

```powershell
cargo build
```

## Run

```powershell
cargo run
```

OpenAI Computer Use is optional. Select `OpenAI CUA` in the app and provide `OPENAI_API_KEY` in the process environment to use the hosted Responses API provider; otherwise Aivana stays local-first.

For the built-in operator command reference, run:

```powershell
cargo run -- --ai-help
```

For a machine-readable command catalog for CI or LLM agents, run:

```powershell
cargo run -- --command-index
```

The index and next-live-gate command list include required environment variables, expected artifact folders, and a recommended live-gate sequence from env template through RDP smoke test, direct RDP proof check, proof recovery plan with direct live evidence requirements, acceptance criteria, and proxy-evidence rejection, live-gate doctor, operator brief, LLM review prompt with `summary.md` Early LLM Triage and risk-summary cross-check semantics, LLM live-gate plan, LLM action contract with `summary.md` Early LLM Triage, `direct_live_evidence_requirements`, and `early_triage_artifacts`, completion audit, goal evidence matrix, hard evidence check, handoff pack, handoff validation, risk summary, and verification snapshot.

To persist KI autopilot preferences without launching the GUI, run:

```powershell
cargo run -- --save-ki-preferences
```

The command writes or refreshes the same local `autopilot-preferences.json` used by the GUI and prints a redacted JSON save report.

To export the same redacted AI/KI action, prompt-library, runbook, and verification brief pack without launching the GUI, run:

```powershell
cargo run -- --ai-brief-pack
```

The command writes `action-brief.md`, `prompt-library.md`, `runbook-brief.md`, `verification-brief.md`, and `manifest.json` under app data in `ai-brief-packs`.

`--ki-readiness-report` and `--ki-evidence-bundle` also accept `--rdp-env-file .\rdp-live.env`, so headless readiness can validate the same ignored local file used by preflight and smoke tests.

## RDP Smoke Test

For real endpoint verification without launching the GUI, create and fill a local env file, then run:

```powershell
cargo run -- --save-rdp-env-template .\rdp-live.env
cargo run -- --rdp-env-fill-guide
cargo run -- --rdp-env-file-check --rdp-env-file .\rdp-live.env
cargo run -- --rdp-preflight --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
cargo run -- --rdp-smoke-test --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
```

Optional: `AIVANA_RDP_TEST_PORT`, `AIVANA_RDP_TEST_DOMAIN`, and `AIVANA_RDP_TEST_TIMEOUT_SECS`. You can also override the timeout per run:

```powershell
cargo run -- --rdp-smoke-test --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
```

Instead of exporting process environment variables, pass the same values in a `.env` file:

```powershell
cargo run -- --rdp-preflight --rdp-env-file .\rdp-live.env
cargo run -- --rdp-smoke-test --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
cargo run -- --live-gate --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
```

To get a single machine-readable diagnosis of the current env-file, preflight, smoke, direct proof, handoff, and completion ladder, run:

```powershell
cargo run -- --live-gate-doctor --rdp-env-file .\rdp-live.env
```

The doctor saves redacted JSON under app data in `live-gate-doctors`, reports the exact next command plus `rdp_proof_recovery_plan_command`, and exits non-zero until the live RDP proof and completion audit are satisfied. Passing `--rdp-env-file` makes the diagnosis use the current ignored local file instead of stale persisted env-check evidence. If `connected=true` exists but framebuffer or input proof is still missing, the doctor keeps the operator on the `rdp-proof-check`/smoke-test step instead of advancing to handoff.

To generate a concise Markdown brief for a human operator or LLM without parsing the doctor JSON, run:

```powershell
cargo run -- --live-gate-operator-brief --rdp-env-file .\rdp-live.env
```

The brief shows the current operator stage, blocker, acceptance criteria, exact next command, next-after-success command, RDP proof recovery-plan command, and evidence snapshot.

To generate a Markdown instruction plan for an LLM or CI assistant from the current doctor, audit, and runbook, run:

```powershell
cargo run -- --llm-live-gate-plan --rdp-env-file .\rdp-live.env
```

The plan tells the model to inspect `summary.md` for Early LLM Triage first, then the live-gate artifacts including `verification-snapshot.json` and `llm-action-contract.json`, reject proxy completion evidence, preserve redaction, and return the next operator command.

To generate a machine-readable JSON contract for an LLM or CI agent that must return only the next safe action, run:

```powershell
cargo run -- --llm-action-contract --rdp-env-file .\rdp-live.env
```

The contract saves JSON under `llm-action-contracts`, includes the exact `next_command`, allowed command sequence, acceptance criteria, required evidence files including `summary.md` for Early LLM Triage, direct live evidence requirements, required success signals, failed RDP proof recovery actions, response fields including `early_triage_artifacts`, and proxy-evidence rejection rules, and exits non-zero until direct live RDP proof is complete.

To print a redacted local checklist for filling `rdp-live.env` safely, run:

```powershell
cargo run -- --rdp-env-fill-guide
```

To print a redacted `.env` starter for the live RDP verification variables, run:

```powershell
cargo run -- --rdp-env-template
cargo run -- --save-rdp-env-template .\rdp-live.env
```

`--save-rdp-env-template` creates parent folders when needed and fails instead of overwriting an existing file, so operators can safely prepare the `.env` file used by `--rdp-env-file`.
Preflight and KI readiness checks reject unfilled starter placeholders such as `<host>`, `<user>`, and `[REDACTED]`; replace them with real endpoint values before running the live gate.
`--rdp-env-file-check` performs the same required-value validation without DNS, TCP, or RDP connection attempts and saves JSON evidence under app data in `rdp-env-file-checks`.

Timeouts are clamped to 5-600 seconds. The smoke test connects through the Rust IronRDP path, waits for a framebuffer, sends a pointer-move input probe, prints a structured JSON evidence report, and saves the same report under the Aivana app-data `rdp-smoke-tests` folder. Failures are also emitted and saved as redacted JSON evidence.

`--rdp-preflight` emits and saves a faster redacted JSON check under `rdp-preflight` with environment readiness, DNS/TCP findings, credential presence, and the effective timeout. Use it before the smoke test when validating VPN, firewall, DNS, or slow gateway issues.

## Headless KI Readiness

For CI, handoff, or preflight evidence without launching the GUI, run:

```powershell
cargo run -- --ki-readiness-report
```

The command prints and saves a redacted JSON report with OpenAI key readiness, RDP smoke-test environment status, persisted Autopilot preference status, latest preflight, smoke-test, and live-gate evidence, missing requirements, readiness score, and the next verification step. When the RDP test environment is incomplete, the report lists the exact missing `AIVANA_RDP_TEST_*` variable names.

To bundle the latest KI readiness, RDP preflight evidence, RDP smoke-test evidence, live-gate evidence, and AI brief-pack evidence for CI or handoff, run:

```powershell
cargo run -- --ki-evidence-bundle
```

The bundle command writes a redacted `bundle.md` plus `manifest.json` under the Aivana app-data `ki-evidence-bundles` folder and prints the manifest summary.

To generate a prompt-to-artifact completion audit, run:

```powershell
cargo run -- --completion-audit
```

The audit writes JSON plus Markdown, maps the current objective to concrete implementation and evidence items, marks unresolved blockers, includes the headless handoff path through `--save-ki-preferences`, `--ai-brief-pack`, `--goal-evidence-matrix`, `--goal-evidence-check`, `--command-index`, `--operator-handoff-pack`, `--operator-handoff-check`, and `--operator-handoff-risk-summary`, records the GUI LLM action-contract `summary.md` Early LLM Triage, `early_triage_artifacts`, success-signal, and proxy-rejection controls, and only treats the live gates as complete when OpenAI CUA is configured and `rdp-proof-check.ok == true` with matching env-file/preflight/smoke host-port evidence plus persisted RDP smoke-test evidence showing `connected=true`. Pass `--rdp-env-file .\rdp-live.env` to keep the embedded readiness view aligned with the local live-gate file.

To print and save the same requirement coverage as a single machine-readable matrix for LLM or CI review, run:

```powershell
cargo run -- --goal-evidence-matrix
```

The matrix lists success criteria, verification commands, each requirement's artifact and evidence, uncovered requirements, and the structured next live gate.

To make the matrix a hard CI/LLM completion assertion, run:

```powershell
cargo run -- --goal-evidence-check
```

The check prints and saves JSON with `ok`, `failed_requirements`, and the embedded matrix. It exits non-zero until `achieved=true` and no uncovered requirements remain.

To print only the first blocking live gate and the next operator commands, run:

```powershell
cargo run -- --next-live-gate
```

When RDP test variables are missing, the summary also prints the exact missing variable names, the redacted `.env` template, the goal evidence matrix/check commands, and the follow-up handoff-pack validation command. The command saves the same redacted Markdown under app data for later operator or LLM handoff.

For the same next-gate data as structured JSON, run:

```powershell
cargo run -- --next-live-gate-json
```

To print only the ordered live-gate command sequence for operators, CI, or LLM agents, run:

```powershell
cargo run -- --live-gate-sequence
```

For a direct operator handoff without parsing the full audit JSON, run:

```powershell
cargo run -- --live-gate-runbook
```

The command prints and saves a redacted Markdown runbook with the exact RDP smoke-test environment variables, verification commands, goal evidence matrix/check export, OpenAI CUA preflight step, evidence exports, operator handoff pack creation, handoff-pack validation, and current blockers.

To print and save only the LLM reviewer prompt for the current audit and live-gate runbook, run:

```powershell
cargo run -- --llm-review-prompt
```

The prompt tells a model to inspect `summary.md` for Early LLM Triage first, then the handoff artifacts including `verification-snapshot.json`, `llm-action-contract.json`, `operator-handoff-risk-summary.json`, `goal-evidence-matrix.json`, `goal-evidence-check.json`, `command-index.json`, and `live-gate-sequence.txt`; cross-check the risk summary for the LLM triage entrypoint, required evidence files, and `early_triage_artifacts`; reject proxy completion evidence; list weak or missing live-gate evidence; and call out unredacted secret-looking text before sharing.

To print and save only the GUI operator checklist for the current audit, run:

```powershell
cargo run -- --gui-operator-actions
```

The checklist gives a human operator the exact Verification Center and Mission Control actions to use before exporting a new handoff pack, including the displayed RDP env source line, evidence matrix/check JSON, visible handoff-check status, the LLM action-contract `summary.md` Early LLM Triage evidence, `direct_live_evidence_requirements`, `early_triage_artifacts`, success signals and proxy-evidence rejection rules, the doctor-selected next live-gate command, and copyable validation evidence.

To write the complete operator/LLM handoff pack in one step, run:

```powershell
cargo run -- --operator-handoff-pack --rdp-env-file .\rdp-live.env
```

The pack contains redacted `readiness.json`, `completion-audit.json`, `goal-evidence-matrix.json`, `goal-evidence-check.json`, `verification-snapshot.json`, `operator-handoff-risk-summary.json`, `command-index.json`, `rdp-env-file-check.json`, `rdp-proof-check.json`, `live-gate-doctor.json`, `live-gate-operator-brief.md`, `next-live-gate.json`, `live-gate-sequence.txt`, `next-live-gate.md`, `live-gate-runbook.md`, `gui-operator-actions.md`, `rdp-env-template.env`, `rdp-env-fill-guide.md`, `llm-review-prompt.md`, `rdp-proof-prompt.md`, `rdp-proof-recovery-plan.md`, `llm-live-gate-plan.md`, `llm-action-contract.json`, `summary.md`, and `manifest.json` under app data. Passing `--rdp-env-file` keeps the embedded readiness report aligned with the same local file used by preflight and smoke tests. The summary includes an early LLM triage hint that points from `verification-snapshot.json` to `llm-action-contract.json` and rejects proxy evidence unless contract success signals are met, and the manifest `summary.md` role advertises that same early triage path. The manifest includes a schema, file roles, and a recommended inspection order so an operator or LLM can choose the right artifact without guessing; the command-index role identifies the command catalog and live-gate sequence, the next-live-gate JSON role identifies the first blocking gate and next commands, the next-live-gate Markdown role identifies the first blocking gate and next operator commands, the live-gate sequence role identifies the ordered command sequence, the LLM review prompt and live-gate plan roles identify Early LLM Triage, risk-summary cross-checks, required evidence files, `early_triage_artifacts`, and proxy-evidence rejection, the RDP proof prompt role identifies Early LLM Triage, `llm-action-contract.json`, the recovery-plan command, framebuffer/input evidence, and proxy-evidence rejection, the recovery-plan role identifies exact commands, acceptance criteria, direct live evidence, and proxy-evidence rejection, the LLM action-contract role identifies strict next-command, direct live evidence requirements, success-signal, and proxy-evidence rejection rules, the verification-snapshot role identifies the compact GUI/latest-evidence snapshot and embedded LLM action-contract, and the recommended inspection order keeps `llm-action-contract.json` immediately after `verification-snapshot.json` for early LLM triage. The goal-evidence-matrix role identifies the requirement-to-artifact matrix and next live gate, the goal-evidence-check role identifies the hard completion assertion and failure-exit behavior, the env-file-check role identifies offline validation and `network_checked=false`, the proof-check role identifies framebuffer and input-probe evidence, and the risk-summary role identifies exact recovery commands plus the LLM triage entrypoint, required evidence files, and `early_triage_artifacts`; doctor and operator-brief roles explicitly identify the recovery command path.

To validate the latest handoff pack before sharing it, run:

```powershell
cargo run -- --operator-handoff-check
```

The check confirms the schema, expected files, file roles including the `summary.md` early-triage role, summary early-LLM-triage mentions, recommended inspection order including the verification-snapshot to LLM-action-contract adjacency, machine-readable JSON schemas including `llm-action-contract.json`, consistency between the manifest, completion audit, evidence matrix, next-gate artifact, live-gate command sequence, command-index command catalog and required step expectations including handoff-pack early-triage semantics and action-contract success signals, LLM action contract versus the doctor/proof/allowed command sequence, required action-contract evidence including `summary.md`, success-signal, and must-return/must-not-return response-rule fields including `early_triage_artifacts`, evidence-matrix GUI action-contract early-triage and success-signal coverage, the operator brief versus the live-gate doctor, GUI action mentions for action-contract success signals and proxy rejection, risk-summary recovery-plan fields versus the pack-local recovery plan, and required LLM prompt mentions. It exits non-zero when `ok=false`, so CI can fail on an invalid handoff pack.

The machine-readable command index includes this immediately after creating the handoff pack; the final recommended sequence step is the verification snapshot after the handoff risk summary.

To print and save a compact CI/LLM risk snapshot across the live-gate doctor, handoff-pack check, and goal-evidence check, run:

```powershell
cargo run -- --operator-handoff-risk-summary --rdp-env-file .\rdp-live.env
```

The summary saves JSON under `operator-handoff-risk-summaries`, includes `severity`, `blocking_reason`, `acceptance_criteria`, `next_command`, handoff validation counts, failed requirements, RDP proof failed-check actions, the canonical recovery-plan command, a recovery-plan evidence summary, and compact LLM triage fields for `summary.md`, `llm-action-contract.json`, `llm_action_contract_direct_live_evidence_requirements`, and `early_triage_artifacts`. It exits non-zero until the handoff pack and real RDP goal evidence are both valid.

To print and save one compact GUI/live-gate/handoff snapshot for an operator, CI job, or LLM reviewer, run:

```powershell
cargo run -- --verification-snapshot --rdp-env-file .\rdp-live.env
```

The snapshot saves redacted JSON under `verification-snapshots`, includes the RDP env source, readiness score, completion blocker, live-gate stage, next commands, handoff validation counts, LLM action-contract required evidence files, direct live evidence requirements, LLM review prompt triage order and risk-summary cross-check fields, `early_triage_artifacts`, success signals and proxy rejection rules, risk summary, RDP proof failed-check actions, the proof recovery-plan command, and latest evidence pointers, and exits non-zero until direct live RDP evidence is complete.

For a focused no-secrets prompt that tells an operator or LLM assistant how to finish only the direct RDP proof gate, run:

```powershell
cargo run -- --rdp-proof-check --rdp-env-file .\rdp-live.env
cargo run -- --rdp-proof-prompt --rdp-env-file .\rdp-live.env
cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\rdp-live.env
```

The proof prompt starts with the same `summary.md` Early LLM Triage path through `verification-snapshot.json` and `llm-action-contract.json`, includes the same direct `rdp-proof-check` success condition used by the doctor, risk summary, verification snapshot, and completion audit, and includes the recovery-plan export command in the local command list. The check also verifies that persisted preflight and smoke evidence match the current env-file host and port and are newer than the env file, so stale evidence from another target or before a credential/target edit cannot close the gate. Its JSON includes `failed_check_actions` so an operator, CI job, LLM, GUI handoff risk summary, verification snapshot risk block, or recovery plan can map each failed check to the exact recovery command; the risk summary and snapshot risk block also mirror the proof recovery-plan command and summary for one-file triage. The Verification Center exposes copy actions for the recovery plan, the canonical recovery-plan command, and the individual recovery commands.

To execute the live gate as one headless command, run:

```powershell
cargo run -- --live-gate --rdp-env-file .\rdp-live.env --rdp-smoke-timeout 90
```

The live gate saves RDP preflight evidence, runs the RDP smoke test only when preflight recommends connecting, refreshes readiness and completion audit evidence, then writes a redacted `live-gate-reports` JSON result with exact missing RDP env vars and an embedded redacted `.env` template. It exits non-zero until the audit has no blocking live gates.

## Project Structure

```text
src/
  main.rs            Native app bootstrap
  app.rs             egui desktop UI, framebuffer viewport, diagnostics panels
  ironrdp_client.rs  Native IronRDP connection, active-stage loop, frames, input PDUs
  services.rs        Profile persistence and RemoteDesktopEngine runtime channels
  models.rs          Public models and interface payloads
  security.rs        DPAPI-backed credential persistence and redaction
  certificate.rs     Certificate trust classification, probing, persistence
  diagnostics.rs     Preflight and typed error classification
  ai.rs              Local and optional-provider KI abstraction
  autopilot.rs       Full Autopilot loop, OpenAI Computer Use provider, safety checks
  computer_use.rs    Frame observation, action planning, policy-gated execution
  policy.rs          Computer Use safety decisions
  runbook.rs         Local diagnostic and evidence runbooks
  memory.rs          Redacted persistent host and workspace memory
  timeline.rs        Persistent session audit, blackbox snapshots, incident export
  workspace.rs       Persistent workspace cockpit model
```

## Verification

```powershell
cargo fmt
cargo check
cargo test
cargo build
cargo run -- --rdp-smoke-test
```
