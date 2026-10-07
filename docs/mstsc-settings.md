# Windows Remote Desktop settings

Connection profiles now expose **Windows RDP settings** in the profile editor:

- Display: color depth, window/full screen, all local monitors, connection bar.
- Local resources: Windows key handling, all three audio playback modes, printers,
  smart cards, COM ports, supported POS / Plug and Play devices and drive selection.
- Experience: desktop background, font smoothing, composition, window dragging,
  menu animations, visual styles, persistent bitmap caching and network detection.
- Advanced: server authentication policy, CredSSP and gateway usage (including local
  bypass and Windows default gateway settings). Gateway credentials remain in the
  existing secure credential store and are never exported.

These settings are validated, saved in JSON profiles and mapped to their standard
`.rdp` property names for import/export. Missing settings retain previous defaults.
Unsupported enum values and malformed device lists produce errors.

## Connection modes

The Rust engine applies color depth and performance flags directly. Existing
clipboard, audio input/output, custom folder sharing, dynamic resolution and
custom monitor layouts continue to use their existing implementations.

Settings requiring Windows resources automatically select the **embedded Windows
RDP control**. It runs inside the application and does not launch `mstsc.exe`.
The editor shows the selected connection mode; Windows mode can also be selected
explicitly. It supports one Windows session at a time. Windows handles certificate
authentication according to the profile's authentication policy. Rust recordings,
automation and session telemetry do not apply to the embedded Windows session.

Drive lists accept `C:;D:;`, `*` (all current and future drives), or `DynamicDrives`
(future drives). Selection is applied through `IMsRdpDriveCollection`, rather
than enabling every drive for a partial selection. Plug and Play redirection
accepts all supported devices or future devices. Actual redirection remains
subject to Windows device support, drivers and server policy; this is not generic
USB tunneling.

The Windows control cannot enforce the Rust backend's custom folder/read-only
shares or arbitrary virtual monitor layouts. A conflicting profile is rejected
before connecting; it must use Windows drives/local monitor layouts or return
to Rust mode. PAA gateway cookies continue to require Rust mode. Selecting a
Windows-only feature does not silently drop these existing restrictions.

This implements the previously identified MSTSC settings gaps. It does not claim
support for every version-specific `.rdp` extension (for example camera-specific
device IDs or RemoteFX USB device filters). Unknown `.rdp` extensions are not
preserved. Custom Rust folder and monitor layouts remain portable through JSON.

## Validation

### Standard RDP Security (legacy servers)

When the unauthenticated connection probe identifies Standard RDP Security, the
Windows app routes that connection to the embedded Windows RDP control. It keeps
the profile's credentials, authentication settings and redirections unchanged;
the control handles negotiation and authentication. No TLS trust fingerprint is
invented or saved for a server without TLS.

The Rust runtime and CLI do not support legacy session encryption and stop with
an actionable message before attempting a security exchange. On other platforms,
the server must offer TLS/NLA. Unsupported settings in the Windows control remain
explicit errors, as with manually selected Windows compatibility mode.

This replaces an incomplete custom Standard Security path. That code set
`SECURE_CHECKSUM` while calculating a MAC without the encryption counter, and its
encryption context was not retained in the active session. Fixing only the initial
server error would therefore still leave an invalid session transport.

Regression coverage uses a loopback legacy negotiation fixture: the Rust runtime
must emit the Windows-control instruction and make only the initial unauthenticated
probe connection. A routing test checks that the complete profile is preserved.
The hidden ActiveX configuration test below exercises the existing Windows backend
without contacting a server. Successful authentication against a real legacy server
still requires an interactive connection test.

Unit coverage includes RDP round trips, invalid inputs, old profile defaults,
backend selection, drive matching, COM ABI offsets and Rust connector options.
The Windows integration test creates a hidden local ActiveX host, configures
RemoteApp and desktop profiles, and reads back audio, printer, monitor and drive
settings. It does not authenticate or connect to a remote server.

```powershell
cargo test --bin relayne
cargo test --bin relayne embedded_control_configures_without_network_or_external_process -- --ignored --nocapture
```

Native bindings follow Microsoft's `IMsRdpClientNonScriptable5`,
`IMsRdpDriveCollection`, `IMsRdpDrive`, `IMsRdpDeviceCollection` and `IMsRdpDevice`
interfaces. Reserved vtable slots are never invoked. All COM operations stay on
the host's UI STA thread.
