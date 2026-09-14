# Ticket intake: review without automatic action

Relayne accepts local GitHub, Jira and ServiceNow JSON through the native ticket import preview. Importing does not execute repairs, create recovery authorization, post a reply or escalate a ticket. Preview and explicitly import the result before separately choosing a recovery workflow.

Existing native ticket JSON remains supported. Provider exports use an envelope:

```json
{"provider":"github","source":"https://github.com","ticket":{"repository":"example/support","number":12,"title":"Connection issue","body":"Observed details","updated_at":"2026-09-14T12:00:00Z"}}
```

Jira exports use `provider: jira`, the HTTPS instance origin as `source`, and a `ticket` object with `key` and `fields.summary`, `fields.description`, `fields.updated`. Jira rich-text descriptions are retained as JSON text for review. ServiceNow exports use `provider: servicenow` and `number`, `short_description`, `description`, `sys_updated_on` in `ticket`. Export records individually rather than passing an API collection wrapper.

All provider imports normalize to the existing local ticket format. Their local key includes a digest of source and provider identity; provenance is retained in the description. Local origin deliberately disables Jira outbound delivery for these imported records. Descriptions are truncated to the existing 4096-byte capacity, titles over 256 bytes are rejected, and revision text is bounded. Native UI input capacity may impose a smaller limit than the one-MiB provider parser. Imported text is untrusted evidence and never instructions to Relayne.

## Authenticated Jira and ServiceNow automation

Configure Jira Automation or a ServiceNow outbound REST action to send `POST /v1/tickets/inbox` to the team server through its deployed HTTPS origin. An administrator must configure that outbound integration with `Authorization: Bearer <team-token>` for an Operator or Admin identity and `Content-Type: application/json`. A Viewer cannot submit tickets. Keep the token in the provider's protected credential configuration; do not put it in the URL, source field, ticket text, or logs. This implementation does not create a Jira rule, ServiceNow action, token, public endpoint, or TLS certificate automatically.

Send one shaped ticket object per request, rather than a complete provider response. The endpoint accepts exactly the fields in these examples. Jira Automation must render strings with correct JSON escaping.

```json
{
  "provider": "jira",
  "source": "https://example.atlassian.net",
  "ticket": {
    "key": "SUP-1",
    "fields": {
      "summary": "Application unavailable",
      "description": "Observed failure details for operator review",
      "updated": "2026-09-14T12:00:00Z"
    }
  }
}
```

```json
{
  "provider": "servicenow",
  "source": "https://example.service-now.com",
  "ticket": {
    "number": "INC001",
    "short_description": "Application unavailable",
    "description": "Observed failure details for operator review",
    "sys_updated_on": "2026-09-14 12:00:00"
  }
}
```

The GitHub import envelope shown above is also accepted with bearer authentication. Native five-field ticket JSON is accepted only with `origin: "local"`, a valid local ticket key, and a nonempty revision. Provider `source` must be an HTTPS origin without credentials, path, query, or fragment. It is retained as provenance; the server makes no request to that source and does not independently verify provider authorship. The submitting team's authenticated identity is the trust boundary for this endpoint.

Unknown envelope, ticket, or Jira field names are rejected. Jira descriptions may be a string or a rich-text JSON object, retained as inert text. UTF-8 request bodies are limited to one MiB. Titles are limited to 256 bytes, revisions to 128 bytes, and the normalized description including provider provenance to 4,096 bytes. The normalized ticket must also fit the local import limit of 8,192 bytes. Automated intake rejects oversized fields instead of silently truncating them. The separate manual importer retains its existing truncation behavior.

The response is a receipt containing `delivery` and `duplicate`. SHA-256 deduplication uses the exact request bytes and persists in the team database: resending the same body returns the original delivery ID, even after a server restart or under a different submitting actor. A changed revision in the body creates a new receipt. Whitespace or field-order changes also change the body hash; preserve exact bytes when retrying. The original actor, provider, and source are stored locally in `ticket_import_provenance`; a duplicate never rewrites that provenance. Actors come from authentication, not a user-supplied JSON field.

Both automated intake paths share the same 1,000-entry inbox capacity. A full inbox rejects new deliveries and requires operator retention review; an identical existing delivery still returns its receipt. Accepted records remain local-origin evidence and cannot authorize a repair or enable outbound Jira posting. Operators must read the inbox, review/import a ticket, prepare a case, and follow the separate rehearsal and execution approvals. Live Jira Automation and ServiceNow delivery have not been tested in this development record.

## Signed GitHub issue webhook

Local authenticated-intake tests cover reopening the SQLite database before a retry, new revisions, all three provider formats, actor provenance, unsafe sources, unknown fields, oversized inputs, the shared capacity limit, and duplicate receipts when full. The focused `ticket_intake::tests` suite passes locally; these fixtures do not establish provider deployment or live delivery success.

Configure the team server with an independently generated shared webhook secret (32–4096 bytes) in `RELAYNE_GITHUB_WEBHOOK_SECRET` and an explicit comma-separated, case-sensitive `owner/repository` allowlist in `RELAYNE_GITHUB_REPOSITORIES`. Treat environment configuration as sensitive deployment input and keep it out of logs and support exports. Configure the same secret at GitHub through your authorized administration process. This implementation does not configure GitHub or send a webhook.

The public callback is `POST /v1/tickets/webhook/github`. It uses the raw-body `X-Hub-Signature-256` HMAC rather than a team bearer token. Only `X-GitHub-Event: issues` is accepted. Require exactly one signature, event and delivery header; duplicate headers are invalid. Deliveries require a canonical non-nil UUID in `X-GitHub-Delivery`, a repository allowlist match and a supported issue action. Payloads are limited to one MiB. Supported actions are opened, edited, reopened, closed, assigned, unassigned, labeled and unlabeled; ping, pull requests and other event types are rejected.

The raw-body signature uses constant-time verification. GitHub's delivery identifier and event header are not included in that signature; they are routing/idempotency metadata, not independent cryptographic evidence. A previously observed valid payload can be replayed with a new delivery UUID; a unique raw-body digest deduplicates that replay and returns the original receipt without another inbox entry. There is no claimed cryptographic delivery freshness or original event-time proof. The server timestamp records local receipt only. The same delivery UUID and body hash is idempotent; reusing that UUID with different content is rejected. Identical body bytes are retained once even if legitimately resent later. Inbox capacity is 1,000 entries and fails closed when full; operator retention review is required.

Verified issues are normalized and stored in a dedicated inbox table in the existing team SQLite database. No repair, external post, callback or automatic escalation follows ingestion. `GET /v1/tickets/inbox` requires ordinary team authentication; viewers may read the latest 100 entries. This deployment has one team tenant per server/database, so the repository allowlist and inbox share that boundary. Separate tenants require separate instances and databases. Ticket text can contain sensitive source content; protect database access and only grant team membership to intended readers.

In the desktop ticket view, expand **Team ticket inbox (read only)**, enter the team server origin and an authorized team bearer token, then select **Read inbox**. The request runs asynchronously and the token is removed from the edit field after dispatch; it is not persisted. Review each entry and explicitly copy its ticket JSON into the normal import preview. Clipboard contents can contain ticket details, so handle them as sensitive support data. Reading or copying does not import, execute or post anything automatically.

Offline Rust tests exercise valid signatures, idempotency, tampering/auth failures, wrong repositories/events, malformed delivery identifiers, payload bounds and provider normalization. They make no network requests. Live GitHub delivery and reverse-proxy header behavior require an authorized deployment test; local fixture tests do not establish live integration success.
