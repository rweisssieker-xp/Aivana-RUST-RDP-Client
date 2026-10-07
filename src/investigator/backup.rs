//! Consistent local snapshots and explicit, paused restore. No live database is overwritten.
use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

fn checksum(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn readonly(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(db)
}
fn inspect(db: &Connection) -> Result<Value> {
    let result: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if result != "ok" {
        bail!("Snapshot SQLite integrity check failed");
    }
    let cases: u64 = db.query_row("SELECT COUNT(*) FROM investigator_cases", [], |r| r.get(0))?;
    let jobs: u64 = db.query_row("SELECT COUNT(*) FROM investigator_jobs", [], |r| r.get(0))?;
    let mut tenants = Vec::new();
    let mut statement = db.prepare("SELECT tenant FROM investigator_cases UNION SELECT tenant FROM investigator_audit UNION SELECT tenant FROM investigator_jobs ORDER BY tenant")?;
    for row in statement.query_map([], |r| r.get::<_, String>(0))? {
        tenants.push(row?);
    }
    let mut audited = 0u64;
    for tenant in &tenants {
        let mut previous = String::new();
        let mut q = db.prepare("SELECT a.actor,a.action,a.target,a.time,a.previous_hash,a.hash,p.payload_hash FROM investigator_audit a LEFT JOIN investigator_audit_payload p ON p.seq=a.seq WHERE a.tenant=?1 ORDER BY a.seq")?;
        let rows = q.query_map([tenant], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?;
        for row in rows {
            let (actor, action, target, time, linked, stored, payload) = row?;
            let payload =
                payload.context("Missing audit payload hash; cannot verify this snapshot")?;
            let calculated = format!(
                "{:x}",
                Sha256::digest(
                    json!([tenant, actor, action, target, time, linked, payload])
                        .to_string()
                        .as_bytes()
                )
            );
            if linked != previous || calculated != stored {
                bail!("Snapshot audit chain verification failed");
            }
            previous = stored;
            audited += 1;
        }
    }
    Ok(
        json!({"cases":cases,"jobs":jobs,"audit_events":audited,"tenants":tenants,"sqlite_integrity":"ok","audit_chain":"verified"}),
    )
}
fn snapshot(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!("Destination already exists; overwriting is forbidden");
    }
    let db = readonly(source)?;
    db.execute(
        "VACUUM main INTO ?1",
        [destination.to_str().context("Non-Unicode destination")?],
    )?;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)?
        .sync_all()?;
    Ok(())
}
pub fn create(database: &Path, new_directory: &Path) -> Result<Value> {
    // Confirm the source before creating any output. VACUUM INTO snapshots WAL content too.
    let source = fs::canonicalize(database).context("Existing source database required")?;
    fs::create_dir(new_directory).context("Backup directory must be new and parent must exist")?;
    let destination = new_directory.join("investigator.sqlite");
    snapshot(&source, &destination)?;
    let manifest = json!({"format":"relayne-investigator-backup-v1","created_at":Utc::now(),"database_sha256":checksum(&destination)?,"validation":inspect(&readonly(&destination)?)?,"installed_components":super::releases::components(),"scope":"Full local database including minimized evidence; configuration and environment secrets are excluded"});
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(new_directory.join("manifest.json"))?;
    file.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    file.sync_all()?;
    Ok(manifest)
}
pub fn verify(directory: &Path) -> Result<Value> {
    let path = directory.join("manifest.json");
    if fs::metadata(&path)?.len() > 65536 {
        bail!("Backup manifest exceeds limit");
    }
    let manifest: Value = serde_json::from_slice(&fs::read(path)?)?;
    if manifest["format"] != "relayne-investigator-backup-v1" {
        bail!("Unknown backup format");
    }
    let database = directory.join("investigator.sqlite");
    for suffix in ["-wal", "-journal"] {
        let sidecar = directory.join(format!("investigator.sqlite{suffix}"));
        if sidecar.exists() && fs::metadata(sidecar)?.len() > 0 {
            bail!("Backup must be an immutable standalone snapshot without active journals");
        }
    }
    if manifest["database_sha256"] != checksum(&database)? {
        bail!("Backup content hash mismatch");
    }
    if manifest["validation"] != inspect(&readonly(&database)?)? {
        bail!("Backup validation summary mismatch");
    }
    Ok(manifest)
}
pub fn restore(directory: &Path, new_database: &Path) -> Result<Value> {
    let manifest = verify(directory)?;
    // Copy exactly the verified file, without SQLite's possible journal overlays.
    // create_new also protects against a destination created concurrently.
    let mut input = fs::File::open(directory.join("investigator.sqlite"))?;
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(new_database)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    if checksum(new_database)? != manifest["database_sha256"] {
        bail!("Restore content changed while copying; do not use the incomplete destination");
    }
    (|| -> Result<Value> {
        let mut db = Connection::open(new_database)?;
        // Validate the copy again: a source changing between verify and copy must not pass.
        if inspect(&db)? != manifest["validation"] {
            bail!("Restore snapshot changed while copying");
        }
        let tx = db.transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS investigator_service_state(tenant TEXT NOT NULL,key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(tenant,key));")?;
        let mut tenants = manifest["validation"]["tenants"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        {
            let mut q = tx.prepare("SELECT DISTINCT tenant FROM investigator_service_state")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                let tenant = json!(row?);
                if !tenants.contains(&tenant) {
                    tenants.push(tenant);
                }
            }
        }
        for tenant in &tenants {
            let tenant = tenant.as_str().context("Invalid tenant in snapshot")?;
            // Preserve delivered outbox receipts and budgets. Recovery never resets case budgets.
            tx.execute("UPDATE investigator_service_state SET value='null' WHERE tenant=?1 AND (key IN ('worker:active','worker:lease','release:active','notification:health') OR key LIKE 'health:%' OR key LIKE 'collector:%')", [tenant])?;
            tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,'stopped','true') ON CONFLICT(tenant,key) DO UPDATE SET value='true'", [tenant])?;
            tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,'recovery:last',?2) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value", params![tenant,json!({"restored_at":Utc::now(),"snapshot_at":manifest["created_at"],"snapshot_hash":manifest["database_sha256"],"reconciliation_required":true,"note":"Reconcile effects since snapshot; restore is paused and connector/release readiness invalidated"}).to_string()])?;
            tx.execute("UPDATE investigator_jobs SET state='queued',lease=NULL WHERE tenant=?1 AND state IN ('running','deferred')", [tenant])?;
        }
        tx.commit()?;
        drop(db);
        let restored = inspect(&readonly(new_database)?)?;
        Ok(
            json!({"status":"restored_paused","snapshot":manifest,"validation":restored,"reconciliation_required":true}),
        )
    })()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigator::core::{Core, Principal};
    fn setup() -> (std::path::PathBuf, Core, Principal) {
        let dir = std::env::temp_dir().join(format!("relayne-backup-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "reviewer".into(),
            role: "analyst".into(),
        };
        let core = Core::open(&dir.join("source.sqlite"), json!({"tenant":"DEMO"})).unwrap();
        (dir, core, p)
    }
    #[test]
    fn live_wal_snapshot_restores_jobs_budgets_and_pauses() {
        let (dir, mut core, p) = setup();
        let case = core.execute(&p,"cases.create",json!({"title":"Synthetic","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"}),Utc::now()).unwrap();
        let db = Connection::open(dir.join("source.sqlite")).unwrap();
        db.execute("INSERT INTO investigator_jobs(tenant,id,case_id,dedupe,state,lease,body) VALUES('DEMO','job',?1,'job','running','2099-01-01T00:00:00Z','{}')",[case["id"].as_str().unwrap()]).unwrap();
        db.execute("INSERT INTO investigator_budget(tenant,id,case_id,month,amount,state) VALUES('DEMO','r',?1,'2026-09',100,'reserved')",[case["id"].as_str().unwrap()]).unwrap();
        let backup = dir.join("snapshot");
        assert_eq!(
            create(&dir.join("source.sqlite"), &backup).unwrap()["validation"]["cases"],
            1
        );
        verify(&backup).unwrap();
        let target = dir.join("restored.sqlite");
        assert_eq!(
            restore(&backup, &target).unwrap()["status"],
            "restored_paused"
        );
        let copied = readonly(&target).unwrap();
        assert_eq!(
            copied
                .query_row("SELECT state FROM investigator_jobs", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "queued"
        );
        assert_eq!(
            copied
                .query_row(
                    "SELECT value FROM investigator_service_state WHERE key='stopped'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "true"
        );
        assert_eq!(
            copied
                .query_row("SELECT amount FROM investigator_budget", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            100
        );
        assert!(restore(&backup, &target).is_err());
        assert!(create(&dir.join("source.sqlite"), &backup).is_err());
    }
    #[test]
    fn modified_backup_and_broken_audit_are_rejected() {
        let (dir, mut core, p) = setup();
        core.execute(&p,"cases.create",json!({"title":"Synthetic","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"}),Utc::now()).unwrap();
        let backup = dir.join("snapshot");
        create(&dir.join("source.sqlite"), &backup).unwrap();
        let db = Connection::open(backup.join("investigator.sqlite")).unwrap();
        db.execute("UPDATE investigator_audit SET action='forged'", [])
            .unwrap();
        assert!(verify(&backup).is_err());
        let source = Connection::open(dir.join("source.sqlite")).unwrap();
        source
            .execute("UPDATE investigator_audit SET action='forged'", [])
            .unwrap();
        assert!(create(&dir.join("source.sqlite"), &dir.join("broken")).is_err());
    }
}
