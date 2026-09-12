# RemoteApp and interactive RD Gateway

## Windows RemoteApp host

`src/native_remoteapp.rs` hosts Microsoft's installed Remote Desktop ActiveX control in-process through the Windows ATL child-window host. It does not spawn mstsc, export passwords, or change server policy. The host is STA/thread-bound; the UI owns its lifetime and must hide inactive tabs and provide physical-pixel bounds. The control runs RAIL and owns the RemoteApp seamless windows; these can be separate native application windows. This is not an implementation of RAIL/window compositing in the IronRDP renderer.

Authentication and certificate validation are owned by the Windows control. AuthenticationLevel is 1, CredSSP is enabled, and drive/printer/clipboard redirection starts disabled. RemoteApp with a nonempty working directory or the IronRDP PAA cookie mode currently fails explicitly. Legacy `remoteapp::launch` remains an explicitly external Windows-client path.

The ignored test `embedded_control_configures_without_network_or_external_process` constructs a hidden local parent, instantiates the real installed control, sets the RemoteApp properties, and checks its disconnected state. It never calls Connect. Run this test explicitly on Windows with ATL and the RDP control installed. Successful unit/host testing is not a substitute for a published RemoteApp integration test.

Microsoft API references: [ITSRemoteProgram2](https://learn.microsoft.com/en-us/windows/win32/termserv/itsremoteprogram2), [RemoteProgramMode](https://learn.microsoft.com/en-us/windows/win32/termserv/itsremoteprogram-remoteprogrammode), [IMsRdpClient10](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclient10).

## Gateway consent and provider tokens

The IronRDP gateway uses the existing TLS-validated WebSocket transport. Basic and SSPI_NTLM remain available. `GatewayStream::connect_interactive` accepts a bounded `SyncSender<GatewayInteraction>`:

- `Consent { gateway, message, reply }`: show the gateway and complete plain-text consent message. Send `true` only after explicit acceptance; false, cancellation, an unavailable UI, and timeout fail the connection before tunnel authorization.
- `PaaToken { gateway, reply }`: request a provider-issued PAA cookie in a masked input. Send `Some(cookie)` or cancel with `None`. The token is ephemeral and is never part of serialized profiles. Do not label this a generic OAuth or OTP input.

`GatewayOptions.paa` enables PAA and takes precedence over the legacy NTLM flag. The transport sends the `PAA` authentication scheme, negotiates `HTTP_EXTENDED_AUTH_PAA`, and sends the cookie as a length-prefixed UTF-16LE/null-terminated blob in the tunnel create packet. This matches the textual PAA-cookie convention used by FreeRDP. The server must explicitly support PAA; there is no fallback to another authentication method. Service messages remain notifications, not arbitrary code challenges. Interactive waits are bounded to 90 seconds within the overall 120-second connection deadline.

Sources: [custom authentication schemes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/9b57a67a-cd79-41b8-9b0a-05c7d099eb0f), [extended authentication flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/801ded3f-e14e-48f8-9b23-744914291edc), [tunnel optional fields](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/dff3285e-05de-483b-950b-8c6388e55713), [field flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/9db25d79-5e4a-4406-b72b-5429ef927b00), [FreeRDP's own gateway implementation](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/gateway/rdg.c).

The MS-TSGU procedural section 3.7.5.2 says fieldsPresent=2 for PAA, conflicting with its own field enumeration (1=PAA cookie, 2=reauthentication). The implementation follows the explicit enumeration and FreeRDP interoperability convention: 1 for a new PAA tunnel, without a reauthentication context.

## Remaining provider-specific work

Browser-based OAuth and interactive OTP require an identified gateway/provider flow, configured authorization/token endpoints, registered client identifier, redirect policy, and a documented mapping from the resulting credential to the gateway protocol. MS-TSGU PAA alone does not define token acquisition. The application does not send arbitrary OAuth access tokens or OTPs as a password/cookie, scrape browser cookies, bypass TLS, or repeatedly attempt authentication. Existing out-of-band MFA can complete while the gateway authorization remains pending. No live server authentication is included in local validation.
