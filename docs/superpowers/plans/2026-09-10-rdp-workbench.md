# RDP Workbench Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement independent tasks with review.

**Goal:** Implement the approved combined native GUI and daily-use RDP features.
**Architecture:** Preserve egui and IronRDP, share connection settings through serializable profile options, put channel integrations and profile exchange in dedicated modules. Only actual remote framebuffers appear in the application.
**Tech Stack:** Rust 1.95, egui/eframe 0.34, IronRDP 0.14, Windows native integrations.
**Spec:** User-approved conversation: directory (concept 1), focused session (2), optional side-by-side (3), contextual recovery (4). Full input, clipboard, dynamic display, reconnect, file/drive exchange, multimonitor, profile import/export, RD Gateway, audio/microphone, German labels and accessible scaling.

## Global Constraints
- Native Rust application; no external RDP application or browser replacement.
- Keep existing user changes and secret storage intact. Do not print local credentials.
- No fabricated connection status or simulated feature success. Unsupported server capabilities must be visible.
- User authorized implementation; proceed without asking again for design approval.

## Tasks
- [x] Input/recovery: extend held-key/button events, release on lost focus, automatic retry with bounded backoff and cancellation. Files models.rs (InputAction), policy.rs, services.rs, app.rs input/reconnect sections; tests for encoding, release and retry.
- [x] RDP channels: wire clipboard, display control, playback/capture, and filesystem redirection into actual IronRDP channel processing. Files ironrdp_client.rs, new channel modules, Cargo.toml. Verify protocol payloads and build; distinguish live verification.
- [x] Profiles/gateway: implement .rdp/CSV/JSON exchange, duplicate/multiedit through UI, validated gateway transport where supported. New focused modules with parser/transport tests.
- [x] GUI: directory/search/group filters/inspector, session strip and focus, side-by-side, contextual diagnosis, profile options and transfer controls. Files src/app/desktop.rs and dedicated child modules. Preserve existing runtime and certificate actions.
- [ ] Integration: format, compile, targeted tests and whole suite. Review feature matrix against actual wiring. Capture native UI when available and document live-server dependent verification.

## Acceptance checks
Directory selection never connects without a connect action. Only the selected remote pane receives input. Read/write clipboard and device redirection respect saved settings. Reconnect stops on user disconnect. Imports never restore plaintext passwords. Old profiles remain readable. Non-live preview explicitly labeled. All requested features tracked with honest implementation and verification status.

## Completion ledger

Implementation and static integration reviews completed. Native directory captured directly from the renderer. Integration tests/build are recorded in the task response. Live preflight passed but smoke failed on authentication before frame receipt; no credential retries. Full live acceptance remains unchecked above for this external prerequisite. See design-qa.md and docs/rdp-workbench.md for explicit compatibility limits.
