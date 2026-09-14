# Support and release operations

General business contact: Aivana GmbH, info@aivana-gmbh.ai, +49 521 92278996. No response-time guarantee or support SLA has been approved for this development build.

For a support request, provide the application version and binary SHA-256, Windows version, selected connection protocol, reproducible steps, expected/actual behavior and sanitized diagnostic evidence. Do not send passwords, team tokens, Stripe keys, unreviewed recordings or customer data by ordinary email. Agree on a suitable secure channel before transferring sensitive evidence.

For suspected credential exposure, revoke the affected credentials or tokens through the system that issued them, disable relevant background authorizations, preserve a sanitized timeline, and contact the operator responsible for the affected environment. Relayne's uninstall does not revoke external credentials or cancel billing.

Production owners must assign responsibility for publisher certificates, trusted update pins, Stripe webhook delivery, team-server TLS/database backups, Windows scheduled tasks, recovery authorization expiry and incident escalation. No person or binding response window is invented by this document.

Use [delivery](delivery.md), [background operation](background.md), [acceptance](acceptance.md), [billing](commerce.md), and the [dependency inventory](third-party/README.md) as technical runbooks. Full live-host interoperability and provider acceptance remain required before promising supported environments.
