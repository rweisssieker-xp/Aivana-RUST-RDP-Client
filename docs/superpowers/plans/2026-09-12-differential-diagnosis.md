# Differential Diagnosis Implementation Plan

**Goal:** Distinguish supported application-failure hypotheses with bounded checks and explicit uncertainty.
**Architecture:** Typed diagnostic engine and protected case store, fixed read-only adapter, and a panel integrated into the existing intelligence view. Simulation is a distinct evidence mode; AI input is only a reviewed next-check proposal.
**Tech stack:** Rust, serde, SHA-256, DPAPI, egui, existing WinRM job queue.
**Spec:** ../specs/2026-09-12-differential-diagnosis.md

## Constraints
Development only: no real host connections or model calls. Preserve existing changes; no commits or publication. No repair, arbitrary code, secret-bearing URLs or production promotion. Results expire after five minutes; each probe allows three attempts in the current evidence window. Durable history remains historical.

- [x] Implement typed cases, hypothesis comparison, next-check selection, strict AI proposal parsing and tests.
- [x] Implement fixed read-only command generation and guarded adapter tests.
- [x] Implement protected case storage, separate simulated/read-only UI flows and native rendering checks.
- [x] Complete regression checks, build, UI inspection and documentation.

## Verifikation am 12.09.2026

`cargo test --offline -- --test-threads=1`: 443 Anwendungstests und 16 Teamtests bestanden, 0 Fehler, 5 bestehende Tests ignoriert, 0 ausgefiltert. `cargo build --offline --bins` erfolgreich; bestehende Dead-Code-Warnungen bleiben bestehen. Die native Oberfläche wurde anhand der gekennzeichneten Dev-Simulation visuell geprüft (Screenshot: `docs/gui-concepts/relayne-differential-diagnosis.png`).

Ausschließlich Entwicklungsprüfungen: Simulationen, Testdoubles und lokales Loopback-HTTP. Keine Verbindung zu gespeicherten RDP-Hosts, keine Live-Hyper-V-Abnahme und keine externen Modellaufrufe.