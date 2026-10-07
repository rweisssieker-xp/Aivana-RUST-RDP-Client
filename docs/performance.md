# Frame pipeline performance

## Changes

- Rust RDP creates one complete RGBA snapshot per decoded output batch, carrying all graphics damage rectangles. Previously every rectangle triggered another copy of the same final desktop image and another sampled hash.
- GUI sessions use a single pending snapshot per session. A newer snapshot replaces the older one and retains its damage. Control, diagnostic and termination events keep their ordered channel. RDP and VNC use this handoff; command-line smoke tests still receive frame events.
- The UI converts and uploads the bounding rectangle of changed pixels. Initial images, resolution changes and missing or invalid damage use a full upload. Complete RGBA snapshots remain available for recording and evidence.
- Disconnection or failure discards pending frames, including when automatic reconnect is scheduled. A reconnect gets a fresh mailbox.

## Reproduce

```powershell
cargo test --offline --bin relayne
cargo test --offline --bin relayne-perf
cargo run --offline --release --bin relayne-perf
cargo build --offline --release --bin relayne
```

`relayne-perf` compares the former full conversion and eight independent pixel copies against the production partial conversion and one copy. It uses deterministic opaque RGBA images at 1920×1080 and 3840×2160, three warmups and 31 measured iterations per case. JSON includes median and p95 times. Damage cases cover 64×64 pixels, one quarter of the desktop and the whole desktop. The full-frame case retains the original conversion algorithm; no improvement is claimed there. Sample order, host load and allocator behavior can affect timings.

These are CPU microbenchmarks, not remote FPS, input latency or time spent decoding and uploading to the GPU. Partial updates benefit mostly unchanged desktops; video or full-screen animation can still require a full upload. The mailbox bounds queued snapshots, not total application memory, and still requires one complete pixel copy per decoded output batch. Its memory figures count pixel buffers only, excluding the currently decoded image, consumed snapshots, GPU textures and metadata.

Legacy Standard RDP Security connections use the embedded Windows RDP control
(see `mstsc-settings.md`). That control has its own rendering pipeline; these Rust
frame-pipeline measurements do not describe its performance.

## Local results, 2026-09-16

Host: Windows x64, Intel Core Ultra 7 155H (22 logical processors), Rust 1.95.0 MSVC. Results are machine-specific.

Release build, same-run median times in milliseconds:

| Operation | 1080p before | 1080p after | 4K before | 4K after |
|---|---:|---:|---:|---:|
| Convert desktop with 64×64 damage | 3.053 | 0.0035 | 13.274 | 0.0034 |
| Eight region copies → one batch copy | 10.965 | 1.474 | 52.187 | 6.655 |
| Convert desktop with quarter-screen damage | 3.053 | 0.677 | 13.274 | 2.824 |
| Convert fully changed desktop | 3.053 | 3.172 | 13.274 | 13.136 |

The release build completed successfully. The microbenchmark preserves the old algorithm as a reference within the same binary; the "before" columns are not measurements from an old release executable.

Debug build, same-run median times in milliseconds:

| Operation | 1080p before | 1080p after | 4K before | 4K after |
|---|---:|---:|---:|---:|
| Convert desktop with 64×64 damage | 59.040 | 0.105 | 242.400 | 0.105 |
| Eight region copies → one batch copy | 11.150 | 1.365 | 52.132 | 6.586 |
| Convert desktop with quarter-screen damage | 59.040 | 13.539 | 242.400 | 57.746 |
| Convert fully changed desktop | 59.040 | 62.691 | 242.400 | 249.238 |

Eight queued full RGBA buffers occupy 63.3 MiB at 1080p or 253.1 MiB at 4K. The new pending slot holds at most one such buffer: 7.9 MiB or 31.6 MiB. The former queue was unbounded; eight is the comparison scenario, not its former maximum.

Raw local reports are in `target/performance/after-debug.json` and `target/performance/after-release.json`; build and test logs are alongside them.

## Validation

- Final application suite with `--test-threads=1`: **538 passed, 0 failed, 5 ignored**. The ignored tests require explicit external or platform setup.
- Benchmark binary's six shared pipeline tests passed. Tests cover pixel-equivalent partial conversion, merged skipped damage, resolution changes, invalid input, a stalled consumer, graphics-batch coalescing, terminal-event ordering and cleanup on disconnect/cancel.
- A repeated parallel application run had **536 passed and 2 failed**: `workflow::tests::runner_persists_failure_and_never_launches_following_step` and `test_lab::change_trial::tests::trial_guest_runs_real_http_and_service_state_verification`. Both passed in the final serial run. Their parallel-run behavior remains a test-suite limitation; those unrelated implementations were not changed.
- Release compilation and a `--command-index` CLI startup smoke check succeeded. GPU presentation and authenticated remote performance still need a live session.

Full serial reproduction: `cargo test --offline --bin relayne -- --test-threads=1`.

## Live validation

The user selected **local measurements only for now**. No further authenticated live testing is part of this run; the following records the prepared endpoint and current prerequisite for a future comparison.

Selected endpoint: `52.186.183.106:3389`, account `DOMAINT\reinerw`. The previous `gbl-w6603` test profile is a different endpoint and its failed login is not a measurement of the selected server. Its credentials were not reused for the new target.

TCP port 3389 is reachable. Windows lists a saved credential for the selected endpoint but returned an empty password blob to the scoped credential lookup. The ignored file `rdp-performance.local.env` contains the selected host/account and an empty password field for local completion. No authenticated live comparison with Windows RDP is available yet.

Once populated locally:

```powershell
target/release/relayne.exe --rdp-smoke-test --rdp-env-file rdp-performance.local.env --rdp-smoke-timeout 30
```

This smoke test measures connection through first received framebuffer and sends a mouse move. It does not measure sustained FPS or input-to-display latency. Maximum end-to-end performance or parity with Windows RDP cannot be established by these local results.
