# Disposable Helper acceptance database fixture

`bootstrap.ps1` prepares synthetic PostgreSQL data inside **Windows Sandbox**. It creates `C:\RelayneHelperAcceptance\pgsql`, database `relayne_helper_acceptance`, and a loopback TLS listener on `127.0.0.1:55433`. It does not configure or copy the old `C:\RelayneSqlLab` data directory, service, logs, or database on port `55432`.

## Prerequisites

- Start Windows Sandbox with a read-only mapped folder containing a PostgreSQL 18 Windows distribution (`bin`, `lib`, `share`). A local guest path such as `C:\FixtureInput\pgsql` is valid. A UNC path is also valid. The runtime source must be explicit; the script reads from it and copies only those three runtime folders. Do not map customer data or a PostgreSQL cluster as the runtime source. An existing guest copy at `C:\RelayneSqlLab\pgsql` is usable only if it contains those runtime folders and is supplied as a read-only input; its `data` and `logs` are never copied.
- Make the copied PostgreSQL runtime self-contained before mapping it read-only. The tested PostgreSQL 18 binaries require the official Microsoft Visual C++ runtime DLLs `vcruntime140.dll`, `vcruntime140_1.dll`, and `msvcp140.dll`; the original distribution used for this fixture lacked them in `bin`. Stage matching official installed copies from `C:\Windows\System32` into the **staged copy's** `bin`, verify their signatures and hashes, then map that staged copy into Sandbox. Do not modify the original PostgreSQL installation, the old database/service, host `System32`, or guest `System32`. Other PostgreSQL builds may have different dependencies; validate their runtime before bootstrap. A missing DLL can make `initdb.exe` fail before a cluster exists.
- Supply an explicit PostgreSQL server certificate, private key, and CA certificate accessible in the guest. The server certificate must have an IP subject alternative name for `127.0.0.1`; the CA must verify it. Prefer a separate read-only mapped input. No TLS trust fallback is attempted. The certificate/key are copied to the new guest cluster; the CA is copied to its root.
- PowerShell, CIM, and the PostgreSQL executables must work in the Sandbox. The bootstrap runs as `WDAGUtilityAccount` and checks Windows virtual-machine identity. The host account cannot opt in through a flag. Do not run it from an ordinary VM or host shell.
- `C:\RelayneHelperAcceptance` must not exist before execution. Any failed run leaves that root intact for inspection. Discard the Sandbox and start a new one to retry; the script never deletes or overwrites the root.

For a `.wsb` mapped folder, set `<ReadOnly>true</ReadOnly>` and choose a guest `<SandboxFolder>` such as `C:\FixtureInput`. Keep the mapped source outside `C:\RelayneHelperAcceptance`. The script deliberately performs no write probe or ACL change against the source. Read-only share configuration is an operator prerequisite.

From a guest PowerShell window, validate the inputs first:

```powershell
& C:\FixtureInput\scripts\bootstrap.ps1 `
  -RuntimeSource C:\FixtureInput\pgsql `
  -TlsCertificate C:\FixtureInput\tls\server.crt `
  -TlsPrivateKey C:\FixtureInput\tls\server.key `
  -TlsCaCertificate C:\FixtureInput\tls\root.crt `
  -ValidateOnly
```

Validation returns `Valid`, `GuestEligible`, the fixed target contract, and errors. It creates no directories, runs no PostgreSQL process, and opens no database connection. Validation on the host reports `GuestEligible = False`. Remove `-ValidateOnly` to run the one-shot bootstrap inside Sandbox. Passwords for the admin, fixture owner, and read-only role are generated there using the operating system random source and saved only at `C:\RelayneHelperAcceptance\credentials.txt`; the root ACL is limited to the guest account and SYSTEM. PostgreSQL uses SCRAM authentication for loopback connections. The fixture has no external listener.

The bootstrap writes its temporary role-provisioning and grant SQL as UTF-8 without a byte-order mark, including under Windows PowerShell 5.1. This matters when `psql -f` reads the first SQL command. Temporary SQL files remain inside the guarded guest root and are removed after successful use.

The three `psql` steps retain native stderr in guest-local `provision.stderr.log`, `seed.stderr.log`, and `grant.stderr.log` under `C:\RelayneHelperAcceptance`. A failure message reports the program, exit status, and guest diagnostic path without printing raw stderr, which may contain SQL or credentials. Inspect these files inside the guest and redact any diagnostic shared outside it. `pg_ctl` is not redirected by this capture path.

## Synthetic cases

The `fixture` schema contains:

- `orders`: 60,000 baseline rows, then 15,000 skewed rows after `ANALYZE`; `customer_id` intentionally lacks an index. Autovacuum is disabled on this disposable table so the stale-statistics case remains available until reviewed maintenance runs. A query for `customer_id = 424242` gives a selective estimate/actual comparison. The product's reviewed `ANALYZE` and exact index action should be measured and verified on this table.
- `spill_events`: wide payload rows for a measured sort with a small `work_mem`. Example: `SET work_mem = '64kB'; EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM fixture.spill_events ORDER BY payload;`. Inspect actual temp I/O; the mere presence of rows does not prove a spill.
- `blocker_rows`: two rows for a controlled two-session lock wait. In session A, run `BEGIN; UPDATE fixture.blocker_rows SET owner_label = 'session A' WHERE row_id = 1;` and leave the transaction open. In session B, run `BEGIN; SET LOCAL statement_timeout = '30s'; UPDATE fixture.blocker_rows SET owner_label = 'session B' WHERE row_id = 1;`. Observe the live wait from another connection, then `ROLLBACK` both sessions. This produces blocker evidence only while both sessions are active.

Connect with host `127.0.0.1`, port `55433`, database `relayne_helper_acceptance`, `sslmode=verify-full`, and CA file `C:\RelayneHelperAcceptance\root.crt`. The owner role can run the controlled mutation examples. The reader role has `SELECT` on the fixture schema. `seed.sql` refuses the wrong database, owner, port, or server address before creating the schema.

This folder supplies database prerequisites only. Task 18 still needs the product binary's explicit fixture/acceptance mode, real PostgreSQL adapter and action flow, shared API coordinator, and two separate portal origins. Those components must be wired through product code and tested; this script does not claim their behavior, flag spelling, live acceptance, SQL Server, Linux, cloud, or customer-environment verification.

Run the focused host-side validation test with `pwsh -NoProfile -File tests/helper-sandbox/test-bootstrap.ps1`. It parses the script and invokes validation for path, fixed port, database, schema, TLS, and host refusal. It does not start a guest or modify either PostgreSQL cluster.
