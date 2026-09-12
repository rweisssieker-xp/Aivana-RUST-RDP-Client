//! Bounded, ephemeral co-working protocol. No credential or arbitrary command fields.
use super::Role;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SharedKey {
    Enter,
    Tab,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    F5,
}
impl SharedKey {
    pub fn scan_code(self) -> u16 {
        match self {
            Self::Enter => 0x1c,
            Self::Tab => 0x0f,
            Self::Escape => 0x01,
            Self::Up => 0x148,
            Self::Down => 0x150,
            Self::Left => 0x14b,
            Self::Right => 0x14d,
            Self::Home => 0x147,
            Self::End => 0x14f,
            Self::PageUp => 0x149,
            Self::PageDown => 0x151,
            Self::F5 => 0x3f,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    #[serde(with = "compressed_rgb")]
    pub rgb: Vec<u8>,
    pub source_hash: u64,
}
mod compressed_rgb {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    use std::io::{Read, Write};
    const MAX: usize = 640 * 360 * 3;
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.len() > MAX {
            return Err(serde::ser::Error::custom("frame size"));
        }
        let mut writer = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        writer.write_all(bytes).map_err(serde::ser::Error::custom)?;
        let zipped = writer.finish().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&format!("zlib64:{}", STANDARD.encode(zipped)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() > MAX * 2 {
            return Err(serde::de::Error::custom("encoded frame size"));
        }
        let data = STANDARD
            .decode(
                text.strip_prefix("zlib64:")
                    .ok_or_else(|| serde::de::Error::custom("frame codec"))?,
            )
            .map_err(serde::de::Error::custom)?;
        let mut decoder = flate2::read::ZlibDecoder::new(data.as_slice());
        let mut raw = Vec::new();
        decoder
            .by_ref()
            .take((MAX + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(serde::de::Error::custom)?;
        if raw.len() > MAX || decoder.total_in() != data.len() as u64 {
            return Err(serde::de::Error::custom(
                "frame decompression limit or trailing data",
            ));
        }
        Ok(raw)
    }
}
#[cfg(test)]
mod codec_tests {
    use super::*;
    #[test]
    fn compressed_frame_roundtrip_and_bomb_limit() {
        let frame = Frame {
            width: 640,
            height: 360,
            rgb: vec![17; 640 * 360 * 3],
            source_hash: 19,
        };
        let text = serde_json::to_string(&frame).unwrap();
        assert!(text.len() < 12000);
        assert_eq!(serde_json::from_str::<Frame>(&text).unwrap().rgb, frame.rgb);
        use base64::Engine;
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&vec![0; 640 * 360 * 3 + 1]).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(z.finish().unwrap());
        let bomb = serde_json::json!({"width":640,"height":360,"source_hash":0,"rgb":format!("zlib64:{encoded}")});
        assert!(serde_json::from_value::<Frame>(bomb).is_err());
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub actor: String,
    pub x: u16,
    pub y: u16,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub actor: String,
    pub generation: u64,
    pub expires: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    #[serde(default)]
    pub key: Option<SharedKey>,
    pub id: Uuid,
    pub digest: String,
    pub session: Uuid,
    pub generation: u64,
    pub frame_hash: u64,
    pub x: u16,
    pub y: u16,
    pub approvals: Vec<String>,
    pub consumed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Room {
    pub id: Uuid,
    pub owner: String,
    pub session: Uuid,
    pub members: Vec<String>,
    pub expires: i64,
    pub generation: u64,
    pub lease: Option<Lease>,
    pub frame: Option<Frame>,
    pub annotations: Vec<Annotation>,
    pub proposals: Vec<Proposal>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Command {
    Create {
        session: Uuid,
        members: Vec<String>,
    },
    Poll {
        room: Uuid,
    },
    Close {
        room: Uuid,
    },
    Leave {
        room: Uuid,
    },
    Publish {
        room: Uuid,
        frame: Frame,
    },
    Annotate {
        room: Uuid,
        x: u16,
        y: u16,
        text: String,
    },
    Grant {
        room: Uuid,
        actor: String,
    },
    Revoke {
        room: Uuid,
    },
    Propose {
        #[serde(default)]
        key: Option<SharedKey>,
        room: Uuid,
        generation: u64,
        frame_hash: u64,
        x: u16,
        y: u16,
    },
    Approve {
        room: Uuid,
        id: Uuid,
        digest: String,
    },
    Consume {
        room: Uuid,
        id: Uuid,
        digest: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub room: Option<Room>,
    pub execute: Option<Proposal>,
}
fn reject<T>(s: &str) -> Result<T, String> {
    Err(s.into())
}
fn printable(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
pub fn apply(
    db: &rusqlite::Connection,
    actor: &str,
    role: &Role,
    command: Command,
    now: i64,
) -> Result<Reply, String> {
    if *role == Role::Viewer
        && !matches!(
            &command,
            Command::Poll { .. } | Command::Annotate { .. } | Command::Leave { .. }
        )
    {
        return reject("operator required");
    }
    db.execute_batch("CREATE TEMP TABLE IF NOT EXISTS live_rooms(id TEXT PRIMARY KEY,payload TEXT NOT NULL,expires INTEGER NOT NULL)").map_err(|_|"storage")?;
    db.execute("DELETE FROM live_rooms WHERE expires<=?1", [now])
        .map_err(|_| "storage")?;
    if let Command::Create { session, members } = command {
        if *role == Role::Viewer {
            return reject("operator required");
        }
        if members.len() > 16 || members.iter().any(|s| !printable(s, 100)) {
            return reject("invalid membership");
        }
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM live_rooms", [], |r| r.get(0))
            .map_err(|_| "storage")?;
        if count >= 32 {
            return reject("room limit");
        }
        let room = Room {
            id: Uuid::new_v4(),
            owner: actor.into(),
            session,
            members,
            expires: now + 30,
            generation: 0,
            lease: None,
            frame: None,
            annotations: vec![],
            proposals: vec![],
        };
        save(db, &room)?;
        return Ok(Reply {
            room: Some(room),
            execute: None,
        });
    }
    let id = match &command {
        Command::Create { .. } => unreachable!(),
        Command::Poll { room }
        | Command::Close { room }
        | Command::Leave { room }
        | Command::Publish { room, .. }
        | Command::Annotate { room, .. }
        | Command::Grant { room, .. }
        | Command::Revoke { room }
        | Command::Propose { room, .. }
        | Command::Approve { room, .. }
        | Command::Consume { room, .. } => *room,
    };
    let payload: String = db
        .query_row(
            "SELECT payload FROM live_rooms WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .map_err(|_| "room unavailable")?;
    let mut r: Room = serde_json::from_str(&payload).map_err(|_| "storage")?;
    let owner = r.owner == actor;
    if !owner && !r.members.iter().any(|s| s == actor) {
        return reject("membership required");
    }
    let controller_revoked = if let Some(l) = &r.lease {
        db.query_row("SELECT COUNT(*) FROM tokens WHERE actor=?1 AND revoked=0 AND role IN ('operator','admin')",[&l.actor],|r|r.get::<_,i64>(0)).map_err(|_|"storage")? == 0
    } else {
        false
    };
    if controller_revoked || r.lease.as_ref().is_some_and(|l| l.expires <= now) {
        r.generation += 1;
        r.lease = None;
        r.proposals.clear();
    }
    let mut execute = None;
    match command {
        Command::Poll { .. } => {}
        Command::Close { .. } => {
            if !owner {
                return reject("owner required");
            }
            db.execute("DELETE FROM live_rooms WHERE id=?1", [id.to_string()])
                .map_err(|_| "storage")?;
            return Ok(Reply {
                room: None,
                execute: None,
            });
        }
        Command::Leave { .. } => {
            if owner {
                db.execute("DELETE FROM live_rooms WHERE id=?1", [id.to_string()])
                    .map_err(|_| "storage")?;
            } else {
                r.members.retain(|s| s != actor);
                for p in &mut r.proposals {
                    p.approvals.retain(|s| s != actor);
                }
                if r.lease.as_ref().is_some_and(|l| l.actor == actor) {
                    r.generation += 1;
                    r.lease = None;
                    r.proposals.clear();
                }
                save(db, &r)?;
            }
            return Ok(Reply {
                room: None,
                execute: None,
            });
        }
        Command::Publish { frame, .. } => {
            if !owner {
                return reject("owner required");
            }
            if frame.width == 0
                || frame.height == 0
                || frame.width > 640
                || frame.height > 360
                || frame.rgb.len() != usize::from(frame.width) * usize::from(frame.height) * 3
            {
                return reject("invalid frame");
            }
            if r.frame
                .as_ref()
                .is_some_and(|f| f.source_hash != frame.source_hash)
            {
                r.proposals.clear();
                r.annotations.clear();
            }
            r.frame = Some(frame);
        }
        Command::Annotate { x, y, text, .. } => {
            if x > 10000 || y > 10000 || !printable(&text, 200) {
                return reject("invalid annotation");
            }
            if r.annotations.len() >= 64 {
                r.annotations.remove(0);
            }
            r.annotations.push(Annotation {
                actor: actor.into(),
                x,
                y,
                text,
            });
        }
        Command::Grant { actor: target, .. } => {
            if !owner {
                return reject("owner required");
            }
            if !r.members.contains(&target) {
                return reject("membership required");
            }
            if !super::actor_can_operate(db, &target).map_err(|_| "identity configuration")? {
                return reject("operator required");
            }
            r.generation += 1;
            r.proposals.clear();
            r.lease = Some(Lease {
                actor: target,
                generation: r.generation,
                expires: now + 20,
            });
        }
        Command::Revoke { .. } => {
            if !owner {
                return reject("owner required");
            }
            r.generation += 1;
            r.lease = None;
            r.proposals.clear();
        }
        Command::Propose {
            key,
            generation,
            frame_hash,
            x,
            y,
            ..
        } => {
            if *role == Role::Viewer
                || !r.lease.as_ref().is_some_and(|l| {
                    l.actor == actor && l.generation == generation && l.expires > now
                })
            {
                return reject("active exclusive lease required");
            }
            if x > 10000
                || y > 10000
                || !r
                    .frame
                    .as_ref()
                    .is_some_and(|f| f.source_hash == frame_hash)
                || r.proposals.len() >= 16
            {
                return reject("invalid or stale target");
            }
            let pid = Uuid::new_v4();
            let digest = format!(
                "{:x}",
                Sha256::digest(
                    format!(
                        "{}:{}:{}:{}:{}:{}:{}:{:?}",
                        r.id, pid, r.session, generation, frame_hash, x, y, key
                    )
                    .as_bytes()
                )
            );
            r.proposals.push(Proposal {
                key,
                id: pid,
                digest,
                session: r.session,
                generation,
                frame_hash,
                x,
                y,
                approvals: vec![],
                consumed: false,
            });
        }
        Command::Approve { id, digest, .. } => {
            if *role == Role::Viewer {
                return reject("operator required");
            }
            let p = r
                .proposals
                .iter_mut()
                .find(|p| p.id == id && p.digest == digest && !p.consumed)
                .ok_or("request unavailable")?;
            if !p.approvals.iter().any(|s| s == actor) {
                p.approvals.push(actor.into());
            }
        }
        Command::Consume { id, digest, .. } => {
            if !owner {
                return reject("owner required");
            }
            let p = r
                .proposals
                .iter_mut()
                .find(|p| p.id == id && p.digest == digest && !p.consumed)
                .ok_or("request unavailable")?;
            if p.approvals.len() < 2
                || !r
                    .lease
                    .as_ref()
                    .is_some_and(|l| l.generation == p.generation && l.expires > now)
                || !r
                    .frame
                    .as_ref()
                    .is_some_and(|f| f.source_hash == p.frame_hash)
            {
                return reject("two identities and current target/lease required");
            }
            // Revoked approver identities invalidate approval before execution.
            for who in &p.approvals {
                if *who != r.owner && !r.members.contains(who) {
                    return reject("approver left room");
                }
                if !super::actor_can_operate(db, who).map_err(|_| "identity configuration")? {
                    return reject("approver revoked");
                }
            }
            p.consumed = true;
            execute = Some(p.clone());
        }
        Command::Create { .. } => unreachable!(),
    }
    if owner {
        r.expires = now + 30;
    }
    save(db, &r)?;
    Ok(Reply {
        room: Some(r),
        execute,
    })
}
/// Any token revocation invalidates that actor's existing grants/votes, even when another token exists.
pub fn invalidate_actor(db: &rusqlite::Connection, actor: &str) -> anyhow::Result<()> {
    let exists: i64 = db.query_row(
        "SELECT COUNT(*) FROM sqlite_temp_master WHERE type='table' AND name='live_rooms'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(());
    }
    let mut statement = db.prepare("SELECT payload FROM live_rooms")?;
    let payloads = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for payload in payloads {
        let mut room: Room = serde_json::from_str(&payload)?;
        if room.owner == actor {
            db.execute("DELETE FROM live_rooms WHERE id=?1", [room.id.to_string()])?;
            continue;
        }
        if room.lease.as_ref().is_some_and(|l| l.actor == actor) {
            room.generation += 1;
            room.lease = None;
            room.proposals.clear();
        }
        for p in &mut room.proposals {
            p.approvals.retain(|a| a != actor);
        }
        save(db, &room).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}
fn save(db: &rusqlite::Connection, r: &Room) -> Result<(), String> {
    let payload = serde_json::to_string(r).map_err(|_| "storage")?;
    db.execute("INSERT INTO live_rooms(id,payload,expires) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,expires=excluded.expires",rusqlite::params![r.id.to_string(),payload,r.expires]).map_err(|_|"storage")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> rusqlite::Connection {
        let db = super::super::open_store(std::path::Path::new(":memory:")).unwrap();
        for (actor, role) in [
            ("owner", Role::Admin),
            ("alice", Role::Operator),
            ("bob", Role::Operator),
            ("viewer", Role::Viewer),
        ] {
            super::super::issue(&db, actor, &role).unwrap();
        }
        db
    }
    fn room(db: &rusqlite::Connection) -> Room {
        apply(
            db,
            "owner",
            &Role::Admin,
            Command::Create {
                session: Uuid::new_v4(),
                members: vec!["alice".into(), "bob".into(), "viewer".into()],
            },
            100,
        )
        .unwrap()
        .room
        .unwrap()
    }
    #[test]
    fn room_membership_roles_bounds_expiry() {
        let db = fixture();
        let r = room(&db);
        assert!(
            apply(
                &db,
                "stranger",
                &Role::Admin,
                Command::Poll { room: r.id },
                101
            )
            .is_err()
        );
        assert!(
            apply(
                &db,
                "viewer",
                &Role::Viewer,
                Command::Grant {
                    room: r.id,
                    actor: "alice".into()
                },
                101
            )
            .is_err()
        );
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Grant {
                    room: r.id,
                    actor: "viewer".into()
                },
                101
            )
            .is_err()
        );
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Publish {
                    room: r.id,
                    frame: Frame {
                        width: 641,
                        height: 1,
                        rgb: vec![],
                        source_hash: 1
                    }
                },
                101
            )
            .is_err()
        );
        assert!(
            apply(
                &db,
                "viewer",
                &Role::Viewer,
                Command::Annotate {
                    room: r.id,
                    x: 10001,
                    y: 0,
                    text: "x".into()
                },
                101
            )
            .is_err()
        );
        assert!(
            apply(
                &db,
                "alice",
                &Role::Operator,
                Command::Poll { room: r.id },
                131
            )
            .is_err()
        );
    }
    #[test]
    fn two_distinct_approvals_once_and_revoke_clears_stale_inputs() {
        let db = fixture();
        let r = room(&db);
        apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Publish {
                room: r.id,
                frame: Frame {
                    width: 1,
                    height: 1,
                    rgb: vec![0; 3],
                    source_hash: 7,
                },
            },
            101,
        )
        .unwrap();
        let lease = apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Grant {
                room: r.id,
                actor: "alice".into(),
            },
            102,
        )
        .unwrap()
        .room
        .unwrap()
        .lease
        .unwrap();
        let p = apply(
            &db,
            "alice",
            &Role::Operator,
            Command::Propose {
                key: Some(SharedKey::Enter),
                room: r.id,
                generation: lease.generation,
                frame_hash: 7,
                x: 100,
                y: 200,
            },
            103,
        )
        .unwrap()
        .room
        .unwrap()
        .proposals[0]
            .clone();
        let approve = Command::Approve {
            room: r.id,
            id: p.id,
            digest: p.digest.clone(),
        };
        let consume = Command::Consume {
            room: r.id,
            id: p.id,
            digest: p.digest.clone(),
        };
        apply(&db, "alice", &Role::Operator, approve.clone(), 104).unwrap();
        apply(&db, "alice", &Role::Operator, approve.clone(), 104).unwrap();
        assert!(apply(&db, "owner", &Role::Admin, consume.clone(), 105).is_err());
        assert!(apply(&db, "viewer", &Role::Viewer, approve.clone(), 105).is_err());
        assert!(
            apply(
                &db,
                "bob",
                &Role::Operator,
                Command::Approve {
                    room: r.id,
                    id: p.id,
                    digest: "altered".into()
                },
                105
            )
            .is_err()
        );
        apply(&db, "bob", &Role::Operator, approve, 105).unwrap();
        assert_eq!(
            apply(&db, "owner", &Role::Admin, consume.clone(), 106)
                .unwrap()
                .execute
                .unwrap()
                .key,
            Some(SharedKey::Enter)
        );
        assert!(apply(&db, "owner", &Role::Admin, consume, 106).is_err());
        apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Revoke { room: r.id },
            107,
        )
        .unwrap();
        assert!(
            apply(
                &db,
                "alice",
                &Role::Operator,
                Command::Propose {
                    key: None,
                    room: r.id,
                    generation: lease.generation,
                    frame_hash: 7,
                    x: 1,
                    y: 1
                },
                108
            )
            .is_err()
        );
    }
    #[test]
    fn leaving_or_revoking_an_approver_invalidates_existing_vote() {
        let db = fixture();
        let r = room(&db);
        apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Publish {
                room: r.id,
                frame: Frame {
                    width: 1,
                    height: 1,
                    rgb: vec![0; 3],
                    source_hash: 9,
                },
            },
            101,
        )
        .unwrap();
        let lease = apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Grant {
                room: r.id,
                actor: "alice".into(),
            },
            102,
        )
        .unwrap()
        .room
        .unwrap()
        .lease
        .unwrap();
        let p = apply(
            &db,
            "alice",
            &Role::Operator,
            Command::Propose {
                key: None,
                room: r.id,
                generation: lease.generation,
                frame_hash: 9,
                x: 0,
                y: 0,
            },
            103,
        )
        .unwrap()
        .room
        .unwrap()
        .proposals[0]
            .clone();
        for actor in ["alice", "bob"] {
            apply(
                &db,
                actor,
                &Role::Operator,
                Command::Approve {
                    room: r.id,
                    id: p.id,
                    digest: p.digest.clone(),
                },
                104,
            )
            .unwrap();
        }
        invalidate_actor(&db, "bob").unwrap();
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Consume {
                    room: r.id,
                    id: p.id,
                    digest: p.digest.clone()
                },
                105
            )
            .is_err()
        );
        apply(
            &db,
            "bob",
            &Role::Operator,
            Command::Approve {
                room: r.id,
                id: p.id,
                digest: p.digest.clone(),
            },
            106,
        )
        .unwrap();
        apply(
            &db,
            "bob",
            &Role::Operator,
            Command::Leave { room: r.id },
            107,
        )
        .unwrap();
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Consume {
                    room: r.id,
                    id: p.id,
                    digest: p.digest.clone()
                },
                108
            )
            .is_err()
        );
        invalidate_actor(&db, "alice").unwrap();
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Poll { room: r.id },
                109
            )
            .unwrap()
            .room
            .unwrap()
            .lease
            .is_none()
        );
        invalidate_actor(&db, "owner").unwrap();
        assert!(
            apply(
                &db,
                "owner",
                &Role::Admin,
                Command::Poll { room: r.id },
                110
            )
            .is_err()
        );
    }
    #[test]
    fn leave_and_lease_expiry_revoke_control() {
        let db = fixture();
        let r = room(&db);
        apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Grant {
                room: r.id,
                actor: "alice".into(),
            },
            101,
        )
        .unwrap();
        let after = apply(
            &db,
            "bob",
            &Role::Operator,
            Command::Poll { room: r.id },
            122,
        )
        .unwrap()
        .room
        .unwrap();
        assert!(after.lease.is_none());
        apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Grant {
                room: r.id,
                actor: "alice".into(),
            },
            123,
        )
        .unwrap();
        apply(
            &db,
            "alice",
            &Role::Operator,
            Command::Leave { room: r.id },
            124,
        )
        .unwrap();
        let after = apply(
            &db,
            "owner",
            &Role::Admin,
            Command::Poll { room: r.id },
            125,
        )
        .unwrap()
        .room
        .unwrap();
        assert!(after.lease.is_none());
        assert!(
            apply(
                &db,
                "alice",
                &Role::Operator,
                Command::Poll { room: r.id },
                125
            )
            .is_err()
        );
    }
}
