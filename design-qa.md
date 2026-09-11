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
