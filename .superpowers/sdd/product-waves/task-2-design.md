# Task 2: First useful diagnostic setup

## Intent and boundary

Expose a short, actionable setup checklist from Mission Control and the selected connection profile. Its destination is the existing Diagnostic Lab, carrying Task 1's exact incident and selected-profile context where available. Opening the checklist, selecting a profile, navigating, editing, and saving a diagnostic case must not connect, probe, approve, or change Windows settings. A case still starts in simulation unless the operator explicitly chooses a subsequent read-only check.

## Existing architecture to extend

`AivanaApp` owns the selected `ConnectionProfile`, `View` routing, Mission Control state, and `diagnostic_panel::State`. The diagnostic `Config` already validates service and URL syntax and binds a direct RDP `Target`; `diagnostic_lab::adapter` builds fixed read-only probes through `operations::winrm`, which launches `powershell.exe` with the current Windows identity. Stored RDP credentials are separate. Task 1 adds an exact incident handoff into the diagnostic panel; Task 2 should consume its typed context/accessors rather than construct another target or protocol path. Add a focused setup/preflight module or panel and only minimal route wiring in `app.rs` and `desktop.rs`.

## Checklist behavior

Show the exact selected saved profile name, host, port, and protocol, plus whether it is a **direct Windows RDP target** (no gateway/route). Label this as profile configuration only: RDP metadata cannot establish WinRM availability, network reachability, permissions, or application health. Missing/changed Task 1 handoff binding is a blocked/unknown item, never silently replaced with another profile. An absent profile links to Connections; an incompatible profile links to profile editing.

Show local `powershell.exe` availability by a non-executing PATH/file check on Windows. Clearly distinguish local tool presence from remote WinRM readiness, which stays **unknown until an approved read-only check returns evidence**. Show that WinRM uses the current Windows identity, not the saved RDP username/password; do not display or export credentials. If the local identity cannot be established reliably, say unknown. Do not attempt authentication or network access as part of preflight.

Show incident, service, HTTPS application URL, and HTTP(S) dependency URL using the selected Task 1 context and the diagnostic draft. Validate with existing `Config` rules, adding only the missing guard against reserved/example hosts (including `.invalid` and `example.com`) being shown as ready for a real check. Keep simulation examples usable and labeled as examples. Missing inputs have an inert navigation action to the corresponding diagnostic editor, without auto-creating a case. Explicitly show case mode, read-only check approval state, evidence status, and separate functional verification status from existing diagnostic state. Unknown, stale, simulated, or absent evidence cannot become “verified” because setup fields are complete.

Render each item as Ready, Needs input, or Unknown with a short reason and a next-action button. `Ready` means only that the named local/configuration prerequisite is present; it does not mean diagnosis is ready or target health is proven. The overall call to action opens the prepared Diagnostic Lab review; the existing frozen review/save and approved check controls remain authoritative. Keep the checklist compact and wrapped at narrow egui widths.

## State and validation

Derive checklist status from selected profile, Task 1 handoff, diagnostic draft/case, and local tool observation. Do not persist an independent readiness flag or duplicate protocol dependencies. Old profile and diagnostic stores continue loading through their current serde behavior. Store read errors, stale profile mismatch, and malformed legacy values surface as unknown/blocked. Any new saved field, if truly necessary, needs a safe serde default; prefer no schema change.

## Verification

Add focused pure status/validation tests for no profile, direct versus gateway/non-RDP profile, reserved/example URLs, missing local tool, current identity versus RDP credential distinction, simulation, stale/mismatched handoff, and absent/failed functional evidence. Test that navigation and case save enqueue no probe and cause no OS change. Inspect native Mission Control/profile/checklist/Diagnostic Lab rendering at narrow and wide widths when possible. After the coordinator's BEGIN, run scoped tests, full build/tests, formatting, and relevant lint/static checks using the shared Rust environment and Cargo target; resolve new warnings without weakening tests.
