# Native Workbench Design QA

Date: 2026-09-10

Visual targets: approved combination of Rechnerzentrale, Sitzungsatelier, Arbeitsflächen and contextual Serviceplatz from the four generated concepts in this conversation. Native Rust production implementation, not a browser prototype.

## Evidence

- Native renderer capture: C:/temp/aivana-workbench-renderer-final.png (2160 x 1536 device pixels, 1440 x 1024 logical pixels).
- Windows desktop/window screenshot was black; rejected as evidence. Direct eframe screenshot succeeded and was inspected.
- Directory: readable hierarchy, consistent teal selection, no overlapping rows, no duplicate connect action when inspector is visible; real saved profiles, honest no-session state. Small-window actions verified by egui interaction tests at 640 px.
- Focus/split: automated tests cover focus/back navigation, switching selected pane without connecting, interrupted-session diagnosis and timeline, and shortcut behavior. Real remote contents have not been visually inspected in these views.
- Network preflight succeeded. Native RDP smoke test failed at CredSSP authentication with STATUS_LOGON_FAILURE (0xc000006d), before framebuffer reception. No repeated login attempt made. Result: ed20058a-30f8-453f-962a-5d107ec5e259-failed.json in the application rdp-smoke-tests directory.

## Findings addressed

- Duplicate directory actions removed when inspector is present.
- Legacy blue selection changed to teal; visible widget outlines improved.
- App shortcuts reserve Ctrl+Shift+K inside the remote session.
- Narrow diagnosis view releases remote held input/clipboard focus.
- An obsolete channel guard blocking configured folder shares was removed and regression-tested.
- Wrapped CredSSP login failure classified as authentication failure so automatic reconnect does not repeat invalid credentials.

## Remaining verification

Live focus, multi-monitor layout, clipboard/file exchange, gateway, shared folders, playback and microphone require a successful authenticated RDP session and appropriate server/device support. Protocol and component tests are not a substitute for that verification. Gateway and filesystem compatibility limits are documented in docs/rdp-workbench.md.

final result: blocked

Blocker: authenticated live-session visual/interaction verification. Directory visual check and automated GUI checks succeeded; full Product Design acceptance is not claimed.

## Mission Control extension – 11 September 2026

Native start view captured from the actual renderer at 2160×1536 device pixels (1440×1024 logical) and inspected in docs/gui-concepts/mission-control-implemented.png. Navigation, real inventory count, empty mission state and three starter actions are readable with no overlap. New views render under tests at 640 and 1440 logical pixels and do not create network sessions. Full test suite: 224 passed, 4 live tests ignored; build successful. This does not change the blocked live-session acceptance above. Separate native session windows are compiled and their focus routing reviewed, but no real connected multi-window interaction is claimed tested.
# Relayne verification update — 2026-09-11

Native renderer image: `docs/gui-concepts/relayne-implemented.png`. Relayne name and Team/OCR/Planning/Terminal navigation verified visually. The desktop, Team, OCR, planning and terminal empty states render at 640 and 1440 logical pixels in tests. Final authenticated live acceptance remains blocked as detailed in `docs/relayne-acceptance.md`; local implementation is not a substitute for that gate.

## Six USP workflows — 2026-09-11

Actual native renderer captures at 2160 × 1536 device pixels were inspected: [execution](docs/gui-concepts/relayne-execution-implemented.png) and [insights](docs/gui-concepts/relayne-insights-implemented.png). Navigation, service/health-check inputs, target selection and empty telemetry/recommendation states are readable without overlapping controls. These are local empty-state checks, not connected-session acceptance. Final suite: 279 application tests and 8 team tests passed, four live tests ignored; both binaries built successfully. Supported scope and remaining live acceptance are recorded in [the delivery record](docs/relayne-six-usps.md).

## Change history, labs, workflows and incident reconstruction — 2026-09-11

New native renderer captures were inspected at 2160 × 1536 device pixels: [changes](docs/gui-concepts/relayne-changes-implemented.png), [lab](docs/gui-concepts/relayne-lab-implemented.png), [workflow](docs/gui-concepts/relayne-workflow-implemented.png) and [incident](docs/gui-concepts/relayne-incident-implemented.png). Inputs, action controls, grouped workflow summary and empty evidence states are readable. The navigation rail and bounded workflow summary scroll; the command palette includes all four new views. Advanced JSON is collapsed, and explicit review precedes execution. Automated rendering covers 640 and 1440 logical pixel widths. Final suite: 304 application tests plus 8 team tests passed, four live tests ignored; both binaries built. These captures verify local empty/template views, not connected-session or Hyper-V acceptance; see [scope and limitations](docs/relayne-next-usps.md).

## Lab rehearsal to production — 2026-09-11

Inspected the [native promotion view](docs/gui-concepts/relayne-promotion-implemented.png) at 2160 × 1536 device pixels. Visible service/HTTP inputs, target selection, guest credentials, explicit review controls and empty evidence count are readable with no overlapping controls. The selected navigation entry is visible. Execution remains disabled without configured targets and evidence. Rendering also passes at 640 and 1440 logical pixels. Final suite: 311 application plus 8 team tests passed; four live tests ignored. Build succeeded. Scope is Windows service transitions plus HTTP without TLS, using operator-verified templates; physical Hyper-V and authenticated production acceptance remain open.

## Expanded workflows, restoration and enterprise access — 2026-09-11

Inspected four actual native renderer captures at 2160 × 1536 device pixels: [workflows](docs/gui-concepts/relayne-workflow-expanded.png), [team](docs/gui-concepts/relayne-team-expanded.png), [promotion](docs/gui-concepts/relayne-promotion-expanded.png) and [restoration](docs/gui-concepts/relayne-changes-expanded.png). Inputs, review controls, collapsed advanced settings and empty/template states are readable without overlapping controls. Workflow and team captures were refreshed after clarifying HTTP/procedure secret inputs and supported collaboration keys. These are local views without authenticated remote connections or fabricated success evidence.

Final verification: 341 application tests, 16 team tests, 8 gateway tests and the separately invoked installed Windows ActiveX control test passed. Both binaries build successfully. The control test configures the real native control without connecting; it does not establish live RemoteApp acceptance. Real infrastructure and identity-provider acceptance remain open. The [current scope and limits](docs/relayne-expanded-usps.md) supersede the earlier HTTP-only and manual-equivalence restrictions above.
