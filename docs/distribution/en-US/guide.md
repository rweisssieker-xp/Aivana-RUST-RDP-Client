# Relayne — distribution and operations guide

> Historical September 13 development-package snapshot. For the current September 14 application and production-script behavior, use the [current operating guide](manual.md).

Development draft · 2026-09-13 · en-US

## Status and scope
This is an unsigned development distribution, not an approved commercial release. Remote recovery and protocol support have local tests but no completed customer-environment acceptance. The new release view and this guide are available in en-US, de, fr and it. Specialist panels and older engineering documents remain partly German; full product localization is a release requirement.

## Seller and contacts
Aivana GmbH
Paulusstr. 45a - Hinterhaus - LOFT45
33602 Bielefeld, Germany
info@aivana-gmbh.ai · +49 521 92278996
Amtsgericht Bielefeld · HRB 46421 · DE459356027
https://www.aivana-gmbh.ai
https://aivana-gmbh.ai/Imprint

Public imprint checked on 2026-09-13. Managing director: Udo Bergmann. This is the general business contact, not a promised support SLA or a separately appointed privacy officer. The website privacy page currently identifies itself as sample text. Product-specific terms and privacy review remain open.

## Requirements and installation
Windows x64. Close Relayne before installation. No administrator rights are required. The package does not install Hyper-V, enable remote access, configure hosts, or create credentials. External protocol prerequisites require separate acceptance.
Extract the whole package into a new directory. Run: powershell -File .\Test-Package.ps1 -PackageRoot .
For this unsigned development package only: powershell -File .\Install-Relayne.ps1 -Language en-US -AllowUnsignedDev
Installation copies only manifest-listed files into a new version directory under LOCALAPPDATA\Relayne\versions. Existing versions are never overwritten. Launch the returned relayne.exe path manually. Use the language selector in the app; existing specialized views may remain untranslated.

## Updates and return to an earlier version
Install each package beside the previous version. No automatic updater or download service is included. Close the application and launch the earlier executable to return. Back up application data first: binary rollback does not reverse database or configuration changes. No backward data compatibility is promised without testing. Failed verification leaves existing installations untouched.

## Uninstallation
Run powershell -File .\Uninstall-Relayne.ps1 -Version VERSION -Language en-US from a trusted package. Only that verified version directory is removed. User profiles, credentials, logs and application data are retained. Removal does not cancel a subscription. There is no active subscription in this development build.

## Integrity and security limits
Test-Package.ps1 checks a strict file list and SHA-256 digests. These detect file corruption; a self-contained unsigned manifest is not publisher authentication. Public code signing and a trusted release channel remain required. Install-Relayne.ps1 refuses this development package unless AllowUnsignedDev is explicitly supplied. No account, scheduled task, service, firewall rule or remote connection is created.

## Data and privacy — technical draft
Profiles, settings, evidence and logs are stored locally. Existing credential and protected case stores use Windows DPAPI where implemented; not all application files are encrypted. Windows account protection and disk access remain important. A configured remote host, team server or optional AI provider may receive data only through its corresponding application workflow; this installer and release view do not send it. Review incident text, screenshots and exports before sharing; automatic redaction is not a guarantee. Retention periods, legal bases, processor agreements, international transfers and deletion procedures need a product-specific privacy review. No telemetry or crash upload is added by this release work.

## Support and incident reporting
Report version, Windows version, steps to reproduce, expected/actual result and redacted logs to the general contact above. Never send passwords, tokens, customer screenshots or host details without an agreed secure channel. No response-time commitment is offered yet. Security reporting, escalation ownership and supported environments must be agreed before sales.

## Price, license and cancellation — not an offer
EUR 9.99 per user per month is a pricing proposal. Net/gross tax treatment, invoice issuer details, payment provider, refunds, cancellation and support entitlement are not finalized. Checkout and commercial activation are disabled. This guide grants no commercial license and is not a contract or legal advice. Third-party dependency notices and license compatibility require review before distribution outside development.

## Release evidence
The package manifest identifies version, source revision, dirty-tree state, development channel and exact hashes. It intentionally excludes local environments, profiles, secrets, test logs and customer evidence. Capture tested build hashes and actual test results for a future release; a green development test run alone does not establish sales readiness.
