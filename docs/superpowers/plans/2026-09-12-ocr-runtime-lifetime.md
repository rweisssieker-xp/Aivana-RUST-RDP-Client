# OCR Runtime Lifetime Correction

**Goal:** Eliminate the reproducible native OCR crash in the full suite and assess local prerequisites for clone acceptance.

## Evidence

The single OCR test and rapid sequential workers passed. Recording followed by either group of lab tests (~18 seconds) and OCR passed. Recording followed by both groups (~35 seconds) and OCR crashed. Local PDB symbol lookup resolved the fault to `OcrEngine::TryCreateFromUserProfileLanguages` activation. `windows-core` retains agile activation factories in a process-global cache, whereas `vision.rs` released the last initialized apartment after each request.

The new isolated `native_ocr_survives_idle_worker_teardown` test reproduces the crash with two short-lived OCR workers separated by 35 seconds. Its pre-fix process exited with `0xc0000005`.

- [x] Reproduce the failure without the full suite and identify the activation lifetime mismatch.
- [x] Retain one process-lifetime MTA usage cookie while preserving balanced per-worker initialization.
- [x] Verify original and idle OCR tests, the unfiltered full suite, and both binary builds.
- [x] Inspect local Hyper-V prerequisites without installing or mutating infrastructure.

## Verification result

The idle-worker regression crashed before the fix and passed after it. Both native OCR tests passed together. Final unfiltered `cargo test --offline -- --test-threads=1`: **427 application tests and 16 team tests passed**, zero failures or filtered tests; five existing tests remained ignored. Application suite: 138.86 seconds; team suite: 2.29 seconds. `cargo build --offline --bins`, formatting and diff checks passed. No test exclusion is required.

## Live acceptance prerequisites

Windows PowerShell cannot find the Hyper-V module or VMMS service. No local Relayne test-lab directory exists. Reading the optional Windows Hyper-V feature state requires elevation unavailable to this session. A real test host and Relayne clone must therefore be identified before live acceptance. No feature installation, VM creation, service mutation or checkpoint operation was performed during this inspection.
