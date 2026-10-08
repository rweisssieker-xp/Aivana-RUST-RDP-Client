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

Back up the SQLite database using SQLite's backup tooling (or stop the server before copying the database and its WAL files). Restore into a private directory. Optional OIDC sign-in is available when configured by the team server administrator. There is no per-workspace membership, automatic background sync, encrypted credential distribution, deletion endpoint or multi-instance HA in this service.

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

## Optional team repair approvals

The execution panel starts in **Standalone local review** for existing installations. An operator explicitly enables **Team-controlled repair** for future runs after a live Team identity check. Once enabled, this journal setting is retained; an in-progress Team-controlled run cannot be changed to Standalone to skip approval. Every production service change needs its own request, a decision by a different authenticated actor, and an atomic one-use consume immediately before Apply. Local target review, a current initial finding (less than 120 seconds old), exact profile match, rehearsal or lab proof, and the protected journal save are still required. If the human decision takes longer than the initial finding stays fresh, capture a new initial state and baseline and request again. An outage, ambiguous consume response, sign-out, expired proof or changed digest blocks Apply. The control is enforced by the managed Relayne client; direct WinRM access, a modified client or a local database administrator can bypass it.

Legacy bearer tokens identify administrator-assigned actor labels. Two tokens with the same actor label do not count as two people; the server requires distinct authenticated actor labels and keeps the **original requester and approver token IDs** active and authorized until consume. The server cannot independently prove that two labels are two humans. With OIDC, the server uses the configured issuer, audience, required claims (including a configured scope claim if supplied), signed JWT expiry and its current local subject-role binding. Both subjects must differ. External IdP revocation is not observed instantly without introspection; no such guarantee is claimed. Roles are global to the service, not per workspace.

`POST /v1/repair-approvals` creates a pending, versioned metadata-only binding. `POST /v1/repair-approvals/{id}/decision` approves or denies it, `POST /v1/repair-approvals/{id}/consume` consumes it once, and `GET /v1/repair-approvals?limit=20&offset=0` lists bounded recent records. Requests expire in at most 10 minutes and no later than the selected proof or original requester JWT. The binding names a run, target index and profile ID, service, before/desired state, capture time, proof reference and SHA-256 digests of the exact local plan, endpoint, baseline, health check and proof. The **full fingerprint** is a digest of that entire typed binding. The approver must compare that fingerprint and the intended change with the requester through the team's review channel. A digest does not display or validate the actual command by itself.

`POST /v1/repair-outcomes` accepts a metadata-only event for a consumed approval. It is idempotent by event UUID; the same ID with different content is rejected. The server records the authenticated sender, original approval and outcome in one transaction with an audit entry. If delivery fails, the protected local journal keeps the event pending for an explicit retry with the same ID. Relayne shows central delivery only after acknowledgement. A post-Apply service-state Restore remains available even if the team service or token has become unavailable. Unknown remote or restore results are reported as Unknown and stop rollout.

Approval and outcome tables retain at most 50,000 and 200,000 rows respectively and reject new records at capacity. There is no silent audit pruning. They store actor keys, original legacy token IDs or OIDC expiry metadata, digests, state and event IDs. They do not store commands, raw endpoints, HTTP response bodies, secret slots, bearer tokens, passwords or credential IDs. Repair request and decision actions use the existing 32 KiB request-body limit; repair responses have a 256 KiB client cap. The existing admin audit list remains limited to its latest 500 rows while the SQLite audit table retains its entries. Protect that database and its backups.

## Repair status and operator acceptance

The Team panel identifies the connected actor and global server role. A viewer can read shared workspace records but cannot load repair approvals or decide them. An operator can load a bounded approval page, request approval from Execution, and decide a **different** authenticated actor's pending request. An admin has the same repair rights plus token administration and access to the latest 500 metadata audit entries. The server checks identity, role, expiry and exact binding on each request; enabled buttons alone grant nothing. The approval list contains the requester's own records, records decided by the connected approver, and other actors' still-pending requests. A viewer's list request is rejected. Use Previous/Next to page through at most 20 records at a time; the API rejects an offset above 1000. A former approver can review an approved, denied, expired or consumed decision without exposing another operator's completed history.

Each row shows pending, approved, consumed, expired or denied state; requester and approver labels; run and target reference; service transition; expiry; and the full binding fingerprint on expansion. An approved record is not permission to skip local review. A consumed record records authorization for one matching Apply attempt, not successful repair. A decision can outlive the 120-second initial finding; capture a new finding and make a new request when it has gone stale. The list derives expiry at read time even before an expiry audit row has been written. An unavailable list means status is unknown; it must not be treated as approval.

For audit, an admin loads the existing Team administration list. Successful request, approve/deny, expiry, consume and outcome acceptance append metadata-only audit entries in the same server transaction as their stored change. Audit shows actor label, action, UUID and UTC time; it does not prove the actor label represents a unique human or that a remote Apply succeeded. The native Execution panel shows a local outcome event as **Central outcome delivery pending** until the protected journal records an acknowledged server response. It then shows **Central acknowledgement recorded locally**. A failed or ambiguous send remains pending with its original event UUID for explicit idempotent retry. The server's receipt is audit acceptance, not proof that application function or restoration succeeded.

For an offline acceptance rehearsal, use a temporary SQLite file and loopback listener with synthetic profiles and identities. Exercise viewer denial, two actor labels and same-label token rejection, denial/expiry, exact binding, one-use consumption, and an outcome retry. Inspect both Team status and Execution outcome text. Run the Windows all-binary build and serial tests from `.github/workflows/relayne-product-windows.yml`; they cover local and loopback behavior only. Real customer WinRM, RDP, OIDC-provider behavior, TLS proxy and organizational identity proof require separate operator validation. Team repair controls apply to the managed Relayne client. Direct WinRM access, a modified client, or local database administration can bypass this client-side control.
