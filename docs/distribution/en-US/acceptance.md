# Local readiness and live acceptance

Generate a read-only local readiness inventory with PowerShell 7:

```powershell
./scripts/acceptance/New-LocalReadinessReport.ps1 -BinaryDirectory 'C:\approved\Relayne' -OutputPath '.\readiness.json'
```

The command reads binary file-version metadata and SHA-256, Windows/OS architecture, RDP control registration, WinRM and Hyper-V management service presence, and OpenSSH command availability. It never executes the binaries, instantiates an RDP control, starts a service, enables a Windows feature, changes policy or contacts remote hosts. Some unsigned builds lack version metadata; the exact SHA-256 remains the build-content identifier. Only the supplied executable files are inventoried, not dependencies or publisher trust.

Every report sets `sale_ready` and `live_acceptance_complete` to false. RDP, RD Gateway, MFA, RemoteApp, WinRM, Hyper-V, multiple monitors, Jira and Stripe scenarios always remain **NOT RUN**, including when every tool is installed. There is no import or override that converts local presence into a live PASS. Use `-Fixture` for synthetic inputs; those reports are labeled `fixture-local-readiness` and cannot establish live evidence. Reports identify their local host scope and never claim coverage for another machine.

A full live acceptance campaign remains separate: obtain authorized test targets and accounts, define expected outcomes, bind evidence to the exact executable hashes, timestamp and host/environment scope, retain redacted results, and obtain independent review/sign-off. Production identity, gateway/MFA policies, RemoteApp access, display layouts, network execution privileges, clone recovery, ticket delivery and billing require their respective real scenarios. This inventory is preparation and support context, not completed acceptance or commercial certification. Future signed acceptance evidence should use an independently controlled reviewer identity; arbitrary imported claims must not silently promote results.

The JSON report includes local computer name, OS information and executable hashes. Review it before sharing with support. No credentials, application settings, recordings or remote host lists are collected. The output file must be new; existing evidence is never overwritten.

Run `pwsh -NoProfile -File scripts/acceptance/Test-Acceptance.ps1` for offline fixture checks that installed tools cannot produce live acceptance claims.
