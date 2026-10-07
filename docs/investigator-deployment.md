# Investigator Windows deployment

This guide describes a controlled Windows deployment of the local Investigator service and its optional A2 executor. It does not claim that a tenant, provider, source permission, production restore objective, or response action has passed live acceptance. Keep that evidence in the approved operational process.

## Processes and endpoints

Build the two binaries with the repository's Windows build workflow. The Investigator service is started with:

```powershell
.\target\release\relayne_investigator.exe serve .\config\investigator.json .\data\investigator.sqlite
```

The configured default bind is loopback port `47841`; the authenticated HTTP MCP endpoint is `/mcp`. Keep it loopback-only on a single host. If remote users need access, place an authenticated TLS reverse proxy in front of the service and preserve its origin and host protections. Do not bind the application directly to a public interface.

The optional response executor is a separate process and requires a different numeric loopback bind from `config.bind`:

```powershell
.\target\release\relayne_investigator.exe executor-serve .\config\investigator.json .\data\investigator.sqlite 127.0.0.1:47842
```

Both processes use the same SQLite database so the executor can enforce the service's proposal, approval, budget, stop, restore-reconciliation, and dispatch ledgers. Do not place independent database copies behind the two processes. SQLite also creates WAL and shared-memory files alongside the database, so both process identities need the required read/write/create/delete rights on the database directory. Grant those rights only to the dedicated service identities and administrators. Keep the directory on a local filesystem that supports SQLite locking; include its WAL state in a supported backup procedure rather than copying the database file while it is live.

## Windows identities and secrets

Run the Investigator and executor with dedicated least-privilege Windows identities. They may be separate identities; in that case, grant both narrowly scoped access to the shared database directory and required configuration files. Do not run either process as an interactive administrator. Limit access to the executable directory, configuration, data directory, logs, and the service user's environment. Review logon-right, network egress, update, backup, and incident-response controls with the host owner.

Configuration contains environment-variable **names**, not secret values. Provision each process's required environment independently using the organization's secret-management method, and verify that the corresponding service identity can read the expected values without printing them. Do not put tokens, passwords, private keys, or populated environment dumps in configuration files, command lines, CI artifacts, or logs. The source integrations and response connector remain disabled unless an operator deliberately configures and approves them.

The A2 signer private key must remain off both service hosts. `relayne_approval` is a separate offline signing utility: transfer only the bounded challenge to an authorized signer workstation, review the exact tenant, target, action, expiry, and parameters, then return the signature file through the approved channel. The service and executor receive only configured public keys. Follow the approval operations guide at [investigator-approvals.md](investigator-approvals.md) for signer provisioning, two-person controls, key rotation, and evidence handling.

## Process supervision

These binaries are console applications, not native Windows Service Control Manager services. Do not register them with `New-Service` as if they implemented the Windows service protocol. Use Task Scheduler with a dedicated service identity and a carefully reviewed at-start trigger, or an organization-approved service wrapper that supports ordinary console processes. Configure the supervisor to retain logs, stop/restart deliberately, avoid overlapping instances, and alert on repeated failures. Test restart and database-lock behavior in a nonproduction environment before enabling automatic recovery.

Keep service shutdown, restore, and restart procedures coordinated. The restore workflow creates a new paused database and requires review of data loss and external effects before the restored service resumes. Do not run old and restored processes against different snapshots as if they were one consistent service.

## CI and local acceptance

The `Investigator Windows readiness` workflow builds and tests only `relayne_investigator` and `relayne_approval`, runs Clippy on those targets, and executes the synthetic offline backup/verify/restore harness. Its separate release-package step builds those two binaries in release mode, uses the CLI `init` command to generate the default disabled example configuration, exports the connector contract, and packages an explicit file allowlist of binaries, config, contract, and deployment/approval/operator docs. The package includes `SHA256SUMS.txt` with SHA-256 digests for those files; this is a checksum list, not a digital signature. No runtime database, service state, credential value, or signing key is included. Both package and synthetic report/manifest/receipt artifacts are retained for 14 days. The workflow does not receive production secrets, contact providers, build or duplicate the main desktop application's release workflow, or establish live operational readiness. See [security-investigator-acceptance.md](security-investigator-acceptance.md) and [investigator-pilot.md](investigator-pilot.md).
