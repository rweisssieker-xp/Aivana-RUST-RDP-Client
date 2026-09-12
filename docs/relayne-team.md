# Relayne Team server

Relayne includes an explicitly launched, persistent central team service and a native **Team** panel. It shares workspaces, credential-free connection endpoints, and mission handoff summaries. Sharing a handoff does not run a mission or change its local execution state. Existing Aivana local profile and mission data paths remain unchanged.

## Local setup

Build `cargo build --bin relayne_team`. Choose a private directory for the SQLite database and protect its directory ACLs for the service account. Bootstrap is an explicit, once-only operation:

```powershell
.\target\debug\relayne_team.exe bootstrap C:\private\relayne-team.sqlite administrator
.\target\debug\relayne_team.exe serve C:\private\relayne-team.sqlite
```

Bootstrap prints a randomly generated administrator bearer token **once**. Save it securely; the database stores only its SHA-256 digest. Running bootstrap against an initialized database fails, including when previous tokens have been revoked. Normal server startup never issues a token or creates an administrator. Startup defaults to `127.0.0.1:47831`. No background service is installed or started automatically.

Open Relayne's Team panel, enter the origin and token, then click **Verbinden / neu laden**. Tokens remain in client memory and are cleared by sign-out; they are not persisted in profiles or preferences. An admin creates a workspace. An operator can share the selected local profile, publish a handoff, or update an existing record. A viewer can read records and import a shared endpoint as a new local profile. Credentials must be supplied locally. Import creates a fresh local ID and cannot overwrite a local credential binding.

Handoffs have a title, operator-authored note and optional source mission ID. **Aus ausgewähltem Auftrag übernehmen** copies the mission objective and handoff text into the reviewable draft. Evidence attachments, recordings, passwords, remote credentials and mission execution state are not transferred. The native edit UI sends the fetched revision; a conflicting save fails with HTTP 409 and requires a reload before retrying.

## Authorization and administration

Each installation represents **one team security boundary**. A token's viewer/operator/admin role applies to every workspace on that installation; workspaces are organizational containers, not separate ACL boundaries. Deploy separate databases/services for isolated teams.

| Operation | Viewer | Operator | Admin |
|---|---|---|---|
| Read shared workspaces, profiles, handoffs | Yes | Yes | Yes |
| Create/update profiles and handoffs | No | Yes | Yes |
| Create/update workspaces | No | No | Yes |
| Issue/list/revoke tokens and read audit | No | No | Yes |

Roles are looked up from the server database for **every request**. Client controls are only conveniences. New tokens are generated server-side and shown once in the native admin panel (masked, with explicit copy). Give each person a separate actor name/token for meaningful audit attribution. Actor names are administrator-defined labels, not verified external identities. Revocation applies to the next request. The currently authenticated token cannot revoke itself; issue a replacement admin token before rotating the old one.

Audit events append in the same SQLite transaction as each successful mutation. They contain a monotonically increasing sequence, actor label, action, target UUID and UTC timestamp, never request bodies, endpoint contents or bearer tokens. The API displays the latest 500 events; the full audit remains in the database. Audit is not tamper-evident against a database administrator. Protect backups and ACLs. Authorization failures and reads are not recorded as business audit events.

## Remote deployment

The embedded server speaks HTTP. **Remote deployment requires a TLS reverse proxy** with a trusted certificate. Keep the service bound to loopback, expose only the proxy, configure proxy request timeouts, body limits and rate limits, and avoid logging authorization headers. The native client rejects remote plain HTTP and HTTP redirects. Do not expose the embedded HTTP listener directly to the Internet. SQLite and the proxy are operator-managed; this change does not deploy a server, configure DNS, install certificates or create cloud accounts.

Back up the SQLite database using SQLite's backup tooling (or stop the server before copying the database and its WAL files). Restore into a private directory. There is no SSO, per-workspace membership, automatic background sync, encrypted credential distribution, deletion endpoint or multi-instance HA in this service.

## API

All routes require `Authorization: Bearer <token>`. JSON responses use `Cache-Control: no-store`.

| Route | Result |
|---|---|
| `GET /v1/state` | Actor, current server role and shared items |
| `POST /v1/items` | Create/update one `SharedItem` using expected `revision` (0 for create) |
| `GET /v1/tokens` | Admin-only token metadata, no token hashes/secrets |
| `POST /v1/tokens` | Admin-only `{ "actor": "name", "role": "viewer\|operator\|admin" }`; returns new ID/token once |
| `POST /v1/revoke` | Admin-only `{ "id": "token-uuid" }` |
| `GET /v1/audit` | Admin-only most recent 500 events |

`SharedItem` fields: `id`, `workspace` (UUIDs), `kind` (`workspace`, `profile`, `handoff`), `name`, `host`, `port`, `protocol`, `note`, optional `source_id`, and integer `revision`. Workspace records have `id == workspace`. Child records must reference an existing workspace. Record kind and workspace are immutable. Only profile records have endpoint fields, with protocol `RDP`, `SSH`, or `VNC`. No credential field is accepted; unknown fields fail validation. Notes remain user-authored text: never put secrets into them.

Bodies are limited to 32 KiB; names to 200 bytes, hosts to 253 bytes, notes to 8192 bytes, actor names to 100 printable bytes, and stores to 10,000 items. Mutations use an SQLite immediate transaction with revision comparison and audit insertion. Responses distinguish 400 validation, 401 missing/revoked authentication, 403 authorization, 404 missing route/token, and 409 revision/protected-operation conflicts.

Dependencies: `tiny_http 0.12` for the embedded listener, `rusqlite 0.32` with bundled SQLite for transactional persistence, and `sha2 0.10` for random token digests. The native client uses the existing blocking reqwest client inside a worker thread with a 15-second timeout.

## Verification

`cargo test --bin relayne_team` exercises a real loopback HTTP listener on an ephemeral port and a temporary SQLite store. It checks unauthenticated requests, all three roles, workspace permissions, profile and handoff persistence, revision conflicts, privilege escalation denial, token revocation, invalid/unknown/oversized input, repeated bootstrap rejection and metadata-only audit events. `cargo test --bin relayne team_client` checks client URL/token restrictions. The root application compile also verifies native Team panel integration.

Verification recorded on 2026-09-11: `cargo test --bin relayne_team -- --nocapture` passed all 3 tests (server integration, client origin restrictions, and a loopback redirect test confirming bearer requests never reach the redirect target). No production server was launched or bootstrapped.
