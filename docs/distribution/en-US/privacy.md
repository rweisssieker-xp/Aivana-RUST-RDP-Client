# Product privacy information — review draft

This document records the implemented data flows for legal review. It is not an approved privacy notice or a claim of GDPR compliance.

The proposed controller is Aivana GmbH, Paulusstr. 45a - Hinterhaus - LOFT45, 33602 Bielefeld, Germany. General contact: info@aivana-gmbh.ai. A dedicated privacy contact, lawful bases, retention schedule and applicable contractual roles must be confirmed by the seller.

## Data and destinations

| Category | Purpose | Storage or destination |
|---|---|---|
| Connection profiles, host identifiers and settings | Saved connections and workspace configuration | Local application data |
| Credentials and protected recovery cases | Explicitly configured connections and recovery | Windows DPAPI where implemented; not every app file is encrypted |
| Screen recordings, OCR and incident evidence | User-requested diagnosis and replay | Local evidence stores and explicit exports |
| Selected prompts and diagnostic text | Optional configured AI assistance | The selected AI provider only when that action is requested |
| Team identities, tokens, shared items and audit | Authenticated collaboration | Configured team server and SQLite store |
| Ticket content and delivery history | Reviewed incident intake and reporting | Local protected ticket stores, configured team inbox and explicitly requested ticket provider |
| Billing identifiers and subscription evidence | Checkout, account status and cancellation | Team server and Stripe; card details are handled by Stripe |
| Warning review notes | Local operator follow-up | DPAPI-protected warning store; not included in outcome JSON |

The installer does not configure remote access or collect telemetry. This release work does not add automatic crash uploads. Hostnames, screenshots and diagnostic evidence can still contain personal or confidential information. Automated redaction is best effort and may miss secrets. Review exports before sharing.

## Retention, deletion and access

Some feature stores have technical size or age limits; these do not constitute a complete legal retention schedule. Uninstalling binaries deliberately preserves user data and does not cancel subscriptions. Windows DPAPI-protected data generally requires the original account and its keys for restore. Backups and ticket-provider copies need separate retention/deletion handling.

Before issuing an approved notice, the seller must document deletion and access-request procedures across local data, team servers, backups, ticket systems, AI providers and Stripe; applicable processing agreements, subprocessors and international-transfer safeguards; lawful bases and retention periods; security incident response; and the correct supervisory authority. Do not substitute the website's sample privacy text for a product-specific notice.
