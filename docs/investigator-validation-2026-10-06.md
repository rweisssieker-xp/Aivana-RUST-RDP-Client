# Investigator expansion validation — 2026-10-06

This report supersedes the process-isolation and CA-policy limitations in the October 5 report. Historical reports remain evidence of their original implementation state.

## Delivered in this continuation

- A separate authenticated `executor-serve` process and console, with a constrained HTTP/MCP command allowlist, no investigation worker, a shared persistent stop/recovery gate, and durable at-most-once dispatch fencing. Normal Investigator routes cannot execute A2 actions.
- A standalone offline `relayne_approval` tool that inspects exact canonical challenges and produces independent Ed25519 approvals. The private signing key is not needed by either service process. A2 approvals bind response policy, exact action contract and installed software component versions.
- Typed collector instances with explicit site/target mapping, ambiguity rejection and separate coverage/health records. Available evidence from one instance cannot hide another instance's missing coverage.
- A finding-specific, authenticated site matrix and browser comparison with exact linked assessments, explicit unchecked sites and separately labelled case/supplier context. General site records cannot clear unrelated findings.
- Read-only AD CS inventory with distinct LDAP and CA hosts, exact optional CA name, bounded LDAP searches with signing/sealing and without referral chasing, template DACL decoding and fixed Remote Registry reads of the active policy module and its `RequestDisposition`. Only the active Microsoft default module is interpreted. Unknown ACL/policy values remain undecidable. Searches reaching their 100-object ceiling are rejected before filtering. Child processes and temporary snapshots have cleanup guards; snapshots use the approved database directory.
- Updated browser controls, current session-derived case defaults, environment-reference checks, deployment instructions and a Windows CI workflow with explicit packaging allowlists. Provider integrations and response remain disabled in generated default configuration.

## Local verification

The local test logs and offline artifacts are under `target/`; they are disposable local evidence and are not release signatures or production acceptance.

- Strict Clippy for both Investigator binaries passes with `-D warnings`.
- 94 Investigator tests and 3 offline signing tests pass. Matrix regressions cover other-case/shared-evidence isolation, removal of approved sites, and stale negative assessments after new evidence.
- Both Investigator binaries and the native `relayne` client build. The native client retains 100 pre-existing compiler warnings.
- Inline JavaScript in both consoles passes Node syntax checks.
- A synthetic browser session verifies separate sign-in, unsigned-action rejection, shared stop visibility, optional collector-instance input, the separate executor entry point and current tenant/owner/time defaults. Test processes and browser tabs are closed afterward.
- The final matrix browser/API scenario shows `LAB: not_checked` and the explicitly recorded `REMOTE: in_progress` for the selected finding. Its **Prepare assessment** action fills the exact finding ID and target site. No provider reads, supplier messages or response actions occur.
- Synthetic replay, backup, integrity/audit-chain verification and restore pass. The receipt contains artifact hashes and local elapsed times; these do not measure production RTO/RPO.

Final receipt: `target/investigator-final-acceptance-matrix-20261006/acceptance-receipt.json`. Logs: `target/investigator-final-tests.log`, `target/investigator-final-clippy.log`, `target/investigator-final-build.log`. Workflow YAML, both browser scripts and the AD CS PowerShell script pass syntax checks. `git diff --check` passes; its line-ending notices refer to existing tracked files.

## External acceptance still required

No real provider credentials, external notifications or response actions were used. Production acceptance requires verified tenant permissions/licensing, actual source schemas/retention/coverage, approved ticket/CMDB receivers and site mappings, host identity and secret custody, volume encryption/ACLs, recovery procedures, measured pilot outcomes, and a controlled A2 test with independent approval and outcome reconciliation.

Current CA registry values are current configuration evidence, not historical issuance-policy evidence. Domain-specific enrollment groups remain outside the bounded ACL assessment. Graph beta fields can be unavailable. Same-provider acknowledgement and timestamp observations do not prove that every session or token is unusable. Optional A3 remains disabled.

## GitHub state

The fetched `origin/main` and local HEAD are both `f7d5bb8c8485ad7f05378f76f46d1df1ee16197b`. Investigator paths are local/untracked and were absent from fetched remote branches at the audit. No commit, push or GitHub Actions execution is claimed by this report. Existing unrelated RDP changes were preserved.
