# Clone Change Trials Implementation Plan

**Goal:** Explicit, repeatable service configuration and failure experiments with checkpoint return verification.
**Architecture:** A typed trial module under test_lab reuses its locks, protected storage and bounded stdin PowerShell runner. A small panel lives in the existing lab view. A fixed PowerShell adapter performs only the documented service and checkpoint operations.
**Tech Stack:** Rust, egui, serde, DPAPI, Windows PowerShell and Hyper-V.
**Spec:** ../specs/2026-09-12-change-trials-design.md

## Constraints
Preserve existing dirty work. No commits, live infrastructure execution or new dependencies. No production execution authority. Fail closed on unreadable/incomplete evidence. Explicit recovery after interruption.

- [x] Implement request validation, immutable request/result persistence and unresolved-trial gating with regression tests.
- [x] Implement bounded checkpoint/change/fault/recovery adapter and exercise success/failure paths with command doubles.
- [x] Integrate reviewed execution, history and explicit interrupted-trial recovery in Testlabor.
- [x] Run relevant tests, build and inspect native UI; document support boundaries and results.

## Verification and open limitation

Nine new regression tests passed, including real loopback HTTP responses and unsuccessful post-restore health. Both binaries built offline. Native empty-state capture and narrow/wide panel rendering checked; formatting and diff checks passed. Initial suite excluding only the native OCR test: 425 app + 16 team tests passed, five existing ignored. The unfiltered suite exposed an OCR activation lifetime issue. Follow-up investigation and correction are tracked in `2026-09-12-ocr-runtime-lifetime.md`; no permanent test exclusion was introduced. Actual Hyper-V acceptance still requires an available test host and configured clone, as documented in `docs/relayne-change-trials.md`.
