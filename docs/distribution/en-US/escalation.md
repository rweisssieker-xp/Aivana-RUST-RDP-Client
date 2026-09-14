# Authorized external escalation

Development implementation · September 14, 2026 · no live delivery acceptance recorded

Relayne can queue a reviewed summary of an existing inbox ticket for delivery to a preconfigured HTTPS automation endpoint. That endpoint can represent an operator-managed Jira Automation or ServiceNow flow. This is a generic authenticated webhook, not a native Jira comment or ServiceNow incident-update API. Receiving an escalation does not authorize a Relayne repair.

## Configure and review the destination

On the team server and its separately deployed worker, configure both `RELAYNE_ESCALATION_URL` and `RELAYNE_ESCALATION_BEARER`. The URL must use HTTPS and contain no embedded credentials, query, or fragment; an endpoint path is allowed. The bearer must contain 32–4,096 printable non-space ASCII bytes. Keep it in the process environment or the deployment's protected secret configuration. Relayne does not persist the URL credential in its SQLite outbox or return it through configuration responses.

The destination must accept `Authorization: Bearer …` and the JSON contract below. No endpoint, credential, Jira rule, ServiceNow flow, public TLS listener, or scheduled task is created automatically. An administrator must configure those in the actual deployment. The server/database represents one team tenant; do not share the instance with unrelated tenants.

Before authorizing an entry, review the exact destination and its fingerprint. The fingerprint binds both the canonical destination URL and the credential, so credential rotation also invalidates queued approvals. The API checks the reviewed fingerprint before enqueueing; the worker checks it again before dispatch. A fingerprint is a configuration binding, not independent proof of the recipient's business identity.

## Authorize, cancel, and deliver

An authenticated Operator or Admin selects an existing inbox delivery, supplies a reason of up to 1,024 bytes, and chooses an explicit expiry within the next 168 hours. The authenticated identity is recorded by the server; ticket text cannot supply that identity or confer permission. Viewing configuration and queue status does not authorize delivery.

The queued summary is immutable. It contains the attempt ID, original inbox delivery ID, normalized local ticket key, sanitized title, sanitized reason, and an `evidence_only` flag. It excludes the ticket description, original provider payload, profiles, credentials, and repair commands. Titles and reasons undergo control-character cleanup and conservative marker-based redaction. This is best effort and cannot identify every confidential value; review text before authorizing it.

The team API uses these authenticated routes. Mutation bodies reject unknown fields, and only Operator/Admin roles may mutate the queue:

| Request | JSON body |
| --- | --- |
| `GET /v1/escalations/config` | None; returns destination and fingerprint |
| `GET /v1/escalations` | None; returns queue status |
| `POST /v1/escalations/enqueue` | `{"delivery":"<inbox UUID>","reason":"Reviewed reason","expires_utc":<Unix seconds>,"expected_fingerprint":"<reviewed fingerprint>"}` |
| `POST /v1/escalations/cancel` | `{"id":"<attempt UUID>"}` |
| `POST /v1/escalations/reconcile` | `{"id":"<attempt UUID>","delivered":false}` |
| `POST /v1/escalations/retry` | `{"id":"<eligible closed attempt UUID>","reason":"Reviewed new attempt reason","expires_utc":<Unix seconds>,"expected_fingerprint":"<reviewed fingerprint>"}` |

```json
{
  "schema": "relayne-escalation-v1",
  "escalation_id": "<immutable attempt UUID>",
  "delivery": "<existing inbox delivery UUID>",
  "ticket_key": "SUP-1",
  "title": "Application unavailable",
  "reason": "Escalate unresolved incident for service-owner review",
  "evidence_only": true
}
```

Repeating enqueue for the same inbox delivery returns its original entry. It does not change the reason, extend expiry, renew approval, or send again. Outbox storage is limited to 1,000 attempts, including retry history; reaching the limit requires operator retention review. Queue lists show the latest 100 entries.

Cancellation revokes only a still-queued authorization. It fails once an attempt is sending or has another terminal state. The worker claims an entry transactionally, so cancellation cannot report success after dispatch has claimed it. Canceling does not retract a message already sent.

Deploy the worker separately and invoke `relayne_team escalation-worker <database>` using the team's database and the same configured destination/credential. The deployment operator may schedule that command. Each invocation processes at most 32 entries and sends only previously authorized, unexpired entries whose destination fingerprint still matches. Starting the worker does not create new authorizations.

Before HTTP starts, the worker commits a durable `sending` state. Requests have a 10-second connection timeout and a 20-second total timeout. Redirects are disabled, the configured endpoint is used directly, and no transport retry occurs. Payloads are limited to 4 KiB; response bodies are not copied into the outbox.

Each request includes `Idempotency-Key: <escalation_id>` and `X-Relayne-Signature: sha256=<hex HMAC-SHA256>`. The signature covers the exact request body bytes using the configured bearer as the HMAC key. Configure the receiving automation to verify authorization/signature and durably deduplicate the idempotency key before any downstream action. The signature alone does not prevent replay. The original inbox `delivery` remains a correlation field; each explicitly approved retry has a new attempt ID and idempotency key.

## Interpret results and reconcile uncertainty

- `sent`: the endpoint returned HTTP 2xx, or an operator later confirmed delivery. This does not prove that a downstream ticket update or escalation completed.
- `failed`: the endpoint returned an explicit rejection status: 400, 401, 403, 404, 405, 410, 413, 415, or 422. There is no automatic retry.
- `unknown`: a transport error, timeout, redirect, server error, or another ambiguous status prevents determining the outcome. A `sending` entry left behind by a crash becomes unknown after its 60-second lease expires during a later worker invocation. It is never automatically resent.
- `expired`, `blocked`, or `canceled`: expiry, changed destination/credential, or explicit revocation prevented sending.
- `not_delivered`: an operator inspected the destination and recorded non-delivery. This records evidence; it does not queue another request.

Inspect the receiver using the attempt ID before reconciling an unknown or rejected attempt. Operator/Admin reconciliation records the checking actor and time. Confirming delivery marks the attempt sent; confirming non-delivery marks it not delivered. An in-flight attempt cannot be reconciled.

Only a separately requested authorization can create a new attempt. It is allowed after operator-confirmed non-delivery, or when the previous attempt is `expired`, `blocked`, or `canceled`: those three states prove dispatch never started, so they do not need a manual non-delivery assertion. Closing an attempt alone never creates another one. After a destination or credential change, explicitly review the new configuration before authorizing a replacement.

Each new attempt requires a newly reviewed reason, expiry, and current destination fingerprint. Relayne retains the original attempt and creates one immutable child linked by `parent_id`. Repeating a request for that parent returns the same child without changing its authorization. Queued, sending, unknown, or delivered attempts cannot create another attempt; a rejected attempt requires operator confirmation of non-delivery first. Reconciliation itself never sends. A wrong operator assertion of non-delivery can still cause a duplicate downstream action; the receiver's own records must be checked.

## Verification

Local fake-transport tests exercise expiry, destination and credential changes, duplicate authorization, cancellation, immutable retry lineage, explicit replacement after proven non-dispatch, rejection of unresolved attempts, unknown outcomes without resend, crash recovery, redaction, and durable `sending` state visible from a separate SQLite connection before transport. They make no network requests. Live endpoint authentication, receiver deduplication, Jira/ServiceNow flow behavior, scheduler identity, and end-to-end delivery still require an authorized deployment test.

See [ticket intake](ticket-intake.md), the [current operating guide](manual.md), and the [acceptance inventory](acceptance.md). Queue authorization is separate from repair approval and does not establish commercial release readiness.
