# Investigator P1 integrations

CMDB, ticket, storage, and network integrations are disabled by default. They
are internal, bounded adapters; the command payload never selects a URL,
credential, tenant, or role. Configuration rejects unknown properties.
Enabling any integration also requires the investigator's
`operations.encrypted_volume_confirmed` and `operations.retention_approved`
controls, so imported evidence cannot bypass the normal storage policy.

```json
{
  "integrations": {
    "enabled": false,
    "cmdb": {
      "enabled": false,
      "endpoint": "https://cmdb.internal.example/api/investigator",
      "secret_env": "RELAYNE_CMDB_TOKEN",
      "allowed_hosts": ["cmdb.internal.example"],
      "approved_by": "integration-owner",
      "approved_at": "2026-09-20T08:00:00Z",
      "idempotency_confirmed": true,
      "timeout_seconds": 15,
      "max_response_bytes": 65536
    },
    "tickets": {
      "enabled": false,
      "endpoint": "https://tickets.internal.example/api/relayne",
      "secret_env": "RELAYNE_TICKET_TOKEN",
      "allowed_hosts": ["tickets.internal.example"],
      "approved_by": "integration-owner",
      "approved_at": "2026-09-20T08:00:00Z",
      "idempotency_confirmed": true,
      "timeout_seconds": 15,
      "max_response_bytes": 65536,
      "write_enabled": false,
      "write_approved_by": "",
      "write_approved_at": "",
      "write_idempotency_confirmed": false
    },
    "sources": [
      {
        "name": "object-audit",
        "kind": "storage",
        "enabled": false,
        "approved_by": "data-owner",
        "approved_at": "2026-09-20T08:00:00Z",
        "max_rows": 1000,
        "max_bytes": 1048576
      }
    ]
  }
}
```

Enabled HTTP adapters require an HTTPS, port-443, credential-free fixed
endpoint whose host exactly matches the allowlist. Redirects are off; timeouts
are one to fifteen seconds; response limits are 1 KiB to 16 MiB. Secrets are
read only from the named uppercase environment variable and are never stored
in receipts, audit entries, status output, or ticket payloads. Source imports
are local normalized-provider input, so their configuration records provider
approval and bounds but has no network destination.

Every transport call first consumes the same persistent per-case runtime, API,
cost, and result-byte ledger as the read-only worker, then checks the service
stop switch again. A full configured response limit is reserved before the
connection. `integrations.probe`, `cmdb.sync`, and `tickets.sync` therefore
require a case ID. Probe uses `HEAD` and sends no ticket data, so it cannot
create or update a ticket. Adapter health becomes stale when its configuration
changes and a failed probe replaces earlier successful probe state.

`cmdb.sync` accepts `{ "case_id": "…", "asset_id": "…" }`. The CMDB result
must contain an external ID, case tenant, matching site, and an `updated_at`
timestamp no older than 24 hours. Only then is a bounded attributes object
written as case context. The update carries the case version observed before
the request, preventing a concurrent context overwrite.

`tickets.sync` accepts `{ "case_id": "…" }`, requires the `admin` or
`incident_lead` role, and requires all of the ticket adapter's separate write
approval fields. It sends only stable external case ID, case version, site,
title, state, and approval metadata. Source evidence, source records,
credentials, and arbitrary caller fields are excluded. The response must echo
the stable external case ID and provide a provider ticket ID. A successful
receipt means `externally_delivered`; it never means the action was technically
verified.

Outbound actions use a durable SQLite receipt keyed by tenant, operation, and
a deterministic idempotency key over the minimal adapter payload. The external
case ID remains stable as case history changes. A concurrent duplicate sees an
in-progress fenced lease; a retry uses the same key; an expired lease can only
be retried with that same receiver-supported key; and a delivered CMDB response
is retained and applied locally without a second transport.
Receipts are preserved during backup/restore and prevent duplicate ticket
creation across process restarts.

`sources.import` accepts a configured `provider`, case ID, records, and
coverage. All records need provider `event_id`, `native_id`, tenant, site, and
event time inside the case window. A storage record normalizes to
`object_access` and requires `object_id`, `principal`, `destination`,
`operation` (`read` or `download`), `outcome`, a positive successful
`object_count`, and the provider's `native_action`. A network record
normalizes to outbound `network_flow` with valid IPs, `principal`,
`destination`, `outcome`, bounded `bytes_out`, and `native_action`. Blocked,
denied, and failed records may have zero counts or bytes and remain valid
counterevidence.

Coverage must include a status and a case-bounded time interval.
`unavailable`, `outside_retention`, `permission_denied`, `partial`, and
`schema_invalid` require a reason. In particular, a missing storage audit log
is retained as a coverage gap; it cannot clear or exclude exfiltration.

CMDB refresh: `cmdb.sync` also accepts an optional `refresh_id`. Reusing it retries the same immutable response. A new value requests a fresh read; omission uses the current UTC hour. The identifier is bounded to 128 characters. Adapter receipt keys bind the complete configured integration contract, so changing the endpoint invalidates the prior cache. The receiver must upsert tickets by the stable external case ID as well as deduplicating request keys.

Provider coverage carries both the original provider name and its normalized source kind. Playbooks consume this mapping, preserving source provenance while recognizing storage/network coverage. Correlation only uses successful object access and network traffic; blocked/denied records remain counterevidence.
