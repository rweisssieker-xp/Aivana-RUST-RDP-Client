# Relayne — current operating guide

Development draft · September 14, 2026 · English (US)

## Scope and language

Relayne provides remote access, reviewed recovery, incident evidence and team collaboration on Windows x64. This development build is not an approved commercial release. Local tests do not establish real-host interoperability, AI provider quality or sales readiness. US English is the default for new settings; `--language en-US` and `--language us-en` explicitly select it. Existing saved language preferences remain selectable. Historical engineering documents may retain their original language.

See [US English localization coverage](localization.md) for the source audit, preserved legacy text, and visual-verification limits.

## Seller

Aivana GmbH, Paulusstr. 45a - Hinterhaus - LOFT45, 33602 Bielefeld, Germany. General contact: info@aivana-gmbh.ai · +49 521 92278996. Register: Amtsgericht Bielefeld · HRB 46421 · VAT DE459356027. Managing director: Udo Bergmann. Website: https://www.aivana-gmbh.ai. Imprint: https://aivana-gmbh.ai/Imprint (checked September 13, 2026). These are general contacts, not an approved support SLA or designated privacy officer.

## Installation and updates

Close Relayne before installation. The development package still requires `Test-Package.ps1` followed by `Install-Relayne.ps1 -Language en-US -AllowUnsignedDev`. Its unsigned-development override does not authenticate a production publisher.

The separate production path uses configured publisher pins and Authenticode signatures, bounded HTTPS downloads, strict manifest paths/hashes, immutable versions and atomic version selection. Use the verified launcher for the selected version. No signing certificate or update endpoint is invented. See [production delivery](delivery.md) for commands and prerequisites.

Application data is under APPDATA\Aivana\RustRdpClient. Back it up before changing versions. Binary rollback does not reverse database or configuration changes, and there is no universal cross-version migration guarantee. DPAPI restore generally requires the original Windows account and keys. The backup tool creates a fresh private destination and integrity inventory; this is not publisher-signed proof.

For the development package, use `Uninstall-Relayne.ps1 -Version VERSION -Language en-US`. Deinstallation preserves user data and does not cancel billing, revoke external tokens or remove separately configured background tasks. Perform those actions explicitly through the corresponding system.

## Product workflows

- Profiles: review the host, protocol, credentials, preflight findings and certificate trust before explicitly connecting.
- Recovery: review the procedure and target binding, run an isolated rehearsal when supported, inspect evidence, and explicitly approve the production step. Recommendations, warning reviews and subscriptions are not execution consent.
- Application checks: import or author HTTP/session expectations, review their exact binding, and supply secrets only through runtime credential slots. Imported expectations are not observed results. See [application checks](application-checks.md).
- Learning and outcomes: inspect exact-procedure history and measured observation-to-health intervals. These do not measure total incident duration, labor savings or ROI. See [learning](learning.md) and [outcomes](outcomes.md).
- Background operation: work remains bounded by the approved plan, target and expiry. Logged-out execution is a separately configured same-account Windows task with policy prerequisites. See [background operation](background.md).
- Tickets: review content before preparing a recovery case. Webhooks populate an evidence inbox and cannot execute or post repairs. See [ticket intake](ticket-intake.md).
- Account: explicitly connect to the configured team server, review Checkout or Customer Portal in Stripe, and verify subscription evidence. See [billing](commerce.md).

## Data, support and commercial conditions

Profiles, recordings and logs may contain sensitive information. DPAPI protects supported credential and case stores, not every file. Review exports; redaction is best effort. Optional remote hosts, team servers, ticket services, AI providers and Stripe receive data through their configured workflows. This work adds no automatic crash uploads.

Read the [privacy data-flow draft](privacy.md), [support runbook](support.md), [terms review](terms-review.md) and [third-party inventory](third-party/README.md). The proposed EUR 9.99 per-user monthly price and tax behavior require seller approval. Live commerce requires explicit configuration and commercial approval. Draft documents and configuration flags do not supply legal approval.

## Acceptance

The [acceptance inventory](acceptance.md) records local binary hashes and installed capabilities. It leaves all live scenarios NOT RUN. Actual protocol, provider, Windows-policy and customer-environment acceptance remain required before promising support or selling a release. Record exact build hashes and real results; ignored tests and mocked signatures are never live evidence.
