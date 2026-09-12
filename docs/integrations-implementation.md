# Inventory and vault integration

Implementation: `src/integrations.rs`, `src/app/integrations_panel.rs`.

App hooks: `mod integrations` in main; `mod integrations_panel`, a default
`IntegrationsState` field, `poll_integrations()` in the update loop and
`integrations_view(ui)` in the chosen navigation destination.

## Inventory

- Explicit AD discovery runs the installed Windows PowerShell ActiveDirectory
  module under the current identity. The static command contains no user data.
  It requests at most 501 computers and rejects results above 500 before any
  DNS filtering. The existing JobQueue bounds output to 128 KiB and execution to
  120 seconds, supports cancellation and rejects truncated discovery results.
- UTF-8 JSON arrays and CSV support `name,host,port,protocol,username,domain,group`.
  Files are capped at 2 MiB and imports at 2000 rows. Extra input fields, including
  passwords, IDs and credential references, are discarded. New profiles get new
  IDs, empty passwords and no credential ID.
- Review normalizes endpoint host case and trailing DNS dots. Protocol + host +
  port identify a conflict, including different logins on one endpoint; conflicts
  are skipped rather than merged. The user reviews selectable candidates, then
  conflicts are checked again against the current profiles before ProfileStore
  saves the whole result. Failed saves do not mutate the in-memory profile list.
- Named dynamic views combine host substring and optional exact tag predicates.
  Rules persist in `inventory-rules.json`; they do not change profile membership
  or trigger any connection. Rules are limited to 100 and 64 KiB.

## Bitwarden

- Requires the official standalone `bw.exe` on PATH and an externally unlocked
  `BW_SESSION` inherited by the app. No automatic login, vault enumeration, shell,
  session-token command argument or secret display is used. KeePassXC integration
  is not implemented. Entra discovery is a separate explicit Graph PowerShell job
  using AIVANA_GRAPH_ACCESS_TOKEN; see docs/mission-control.md for prerequisites.
- A user selects a target profile, supplies a validated UUID, acknowledges login
  assignment/replacement, and clicks the deliberate fetch-and-store button.
  Target profile ID, endpoint identity and revision are captured before spawning. Cancellation drops the private
  receiver, so later worker results cannot update credentials.
- A dedicated worker launches `bw get item UUID --nointeraction`, discards stderr,
  bounds stdout to 256 KiB, applies a 45-second timeout and kills the direct child
  on cancellation/timeout/overflow. A PeekNamedPipe loop reads only available data
  on the worker itself; no blocked reader thread survives a timeout, even when a
  descendant holds the write handle. It deserializes only login fields and returns
  a SecretCredential through a private channel. Parse/process errors are fixed
  strings and cannot echo vault output. Raw output buffers are cleared on exit.
- The UI coordinator passes the returned secret directly to the existing
  PersistentCredentialStore (DPAPI on Windows), adopts the vault username and
  preserves the selected profile's domain. No secret goes to generic job outputs,
  previews, audit logs, credential exports or widgets. A removed or changed target
  discards the result. A fresh credential record is created before linking the
  saved profile; failure leaves the old linked credential intact. The coordinator
  attempts cleanup of the unlinked new record. Credential saves now atomically
  replace their file and roll back in-memory changes when persistence fails.
- Rust String allocations and the existing credential-store serializer are not
  guaranteed to be zeroized. This implementation does not claim locked memory,
  memory-forensics resistance or CLI descendant-process termination.

## Verification

Unit cases cover ignored secret/identity fields, normalized duplicate endpoints,
login conflicts, malicious hosts and vault item IDs, command construction,
CSV/RDP/SSH metadata, dynamic matching and non-echoing vault parse errors.
Verified 2026-09-11 after the app hooks were installed:
`cargo test --bin aivana_rust_rdp_client integrations::tests` — 5 passed, 0 failed.
The build emitted only the existing unused session-metrics warnings.

No live AD or Bitwarden query and no credential-store read was performed while
implementing this feature. Live behavior requires the prerequisites shown in the
panel and deliberate user actions.
