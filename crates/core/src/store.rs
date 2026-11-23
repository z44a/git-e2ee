//! Per-device SQLite state: libsignal stores, pinned identities, verified
//! device lists, and per-repo replication state.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord,
    PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use rusqlite::{Connection, OptionalExtension, params};

/// Directory holding this device's state. `GIT_E2EE_HOME` overrides the default.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("GIT_E2EE_HOME") {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(d).join("git-e2ee"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share/git-e2ee"))
}

/// The account key for a relay: its host, without port, path or scheme, so
/// the same relay reached directly or through a proxy is one account.
/// `https://relay.example:8443/x` → `relay.example`; `http://[::1]:8470` → `___1_`.
pub fn relay_host(relay_url: &str) -> Result<String> {
    let rest = relay_url.split_once("://").map(|x| x.1).ok_or_else(|| anyhow!("not a relay URL: {relay_url:?}"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("").to_ascii_lowercase();
    let authority = authority.rsplit_once('@').map_or(authority.as_str(), |x| x.1);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        format!("[{}]", v6.split(']').next().unwrap_or(""))
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    // (A directory name: no "..", nothing hidden, only host characters.)
    let first_ok = host.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '[');
    if !first_ok || host == "[]" || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_[]:".contains(c)) {
        bail!("not a relay URL: {relay_url:?}");
    }
    Ok(host.replace([':', '[', ']'], "_"))
}

/// The state directory of the account on this relay. Each relay has its own
/// account (master key, devices, contacts, repos), so accounts on different
/// relays share nothing and can't be linked by the relays.
///
/// State from before accounts were per relay (one identity, at the top of
/// the data directory) stays the account for the relays it registered with.
pub fn account_dir(relay_url: &str) -> Result<PathBuf> {
    let base = data_dir()?;
    let host = relay_host(relay_url)?;
    let dir = base.join("accounts").join(&host);
    if dir.exists() {
        return Ok(dir);
    }
    if legacy_hosts(&base)?.contains(&host) {
        return Ok(base);
    }
    Ok(dir)
}

/// Every account on this machine: (relay host, state directory).
pub fn accounts() -> Result<Vec<(String, PathBuf)>> {
    let base = data_dir()?;
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(base.join("accounts")) {
        for e in rd.flatten() {
            if e.path().join("device.sqlite").exists() {
                out.push((e.file_name().to_string_lossy().into_owned(), e.path()));
            }
        }
    }
    for h in legacy_hosts(&base)? {
        if !out.iter().any(|(x, _)| *x == h) {
            out.push((h, base.clone()));
        }
    }
    out.sort();
    Ok(out)
}

/// Relay hosts the pre-accounts identity (if any) is registered with.
fn legacy_hosts(base: &Path) -> Result<Vec<String>> {
    let db = base.join("device.sqlite");
    if !db.exists() {
        return Ok(vec![]);
    }
    let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut st = match conn.prepare("SELECT url FROM relays") {
        Ok(st) => st,
        Err(_) => return Ok(vec![]),
    };
    let urls: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(urls.iter().filter_map(|u| relay_host(u).ok()).collect())
}

/// Per-connection settings (not part of the schema).
// secure_delete: deleted rows (disappearing push-log entries, used keys)
// are overwritten, not just unlinked.
const PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;";

/// Schema migrations, in order (see `e2ee_proto::migrate`). Append new ones;
/// never edit a released one.
const MIGRATIONS: &[&str] = &[SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6];

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
-- Master keys we trust. verified = 1 for contacts (`git e2ee contact add`);
-- 0 for members we only know from a repo's roster.
CREATE TABLE IF NOT EXISTS pinned (user BLOB PRIMARY KEY, master_key BLOB NOT NULL, verified INTEGER NOT NULL, delivery_token BLOB);
-- Unspent anonymous access tokens, per relay.
CREATE TABLE IF NOT EXISTS access_tokens (nonce BLOB PRIMARY KEY, relay_url TEXT NOT NULL, epoch INTEGER NOT NULL, output BLOB NOT NULL, generation INTEGER NOT NULL DEFAULT 0);
-- What proves the current refs and roster to someone we send history to: the
-- last push and the roster changes since (see HistoryBundle.proof_*).
CREATE TABLE IF NOT EXISTS view_proof (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, push BLOB, roster_change BLOB, PRIMARY KEY (repo_id, seq));
-- History catch-up coordination (see engine.rs, answer_history_requests).
-- Claim entries we applied, with their nonce (to verify announcements):
CREATE TABLE IF NOT EXISTS claim_entries (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, nonce BLOB NOT NULL, PRIMARY KEY (repo_id, seq));
-- Verified claims: who is sending history to which device, since when (local time):
CREATE TABLE IF NOT EXISTS history_claims (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, claimant_user BLOB NOT NULL, claimant_dev INTEGER NOT NULL, target_user BLOB NOT NULL, target_dev INTEGER NOT NULL, at_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, seq));
-- Outstanding requests from stuck member devices:
CREATE TABLE IF NOT EXISTS history_requests (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, from_seq INTEGER NOT NULL, exclude BLOB NOT NULL, received_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, user, device_id));
-- Claims made for us while we're stuck (to exclude claimants who don't deliver):
CREATE TABLE IF NOT EXISTS claims_for_me (repo_id BLOB NOT NULL, claimant_user BLOB NOT NULL, claimant_dev INTEGER NOT NULL, received_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, claimant_user, claimant_dev));
-- Our pseudonymous mailboxes, per repo: the current one (retired_ms NULL) and
-- retired ones still read until they expire.
CREATE TABLE IF NOT EXISTS own_mailboxes (repo_id BLOB NOT NULL, mailbox BLOB NOT NULL, key BLOB NOT NULL, created_ms INTEGER NOT NULL, retired_ms INTEGER, PRIMARY KEY (repo_id, mailbox));
-- Other devices' current pseudonymous mailbox per repo.
CREATE TABLE IF NOT EXISTS peer_mailboxes (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, mailbox BLOB NOT NULL, PRIMARY KEY (repo_id, user, device_id));
-- Access-token public keys each relay gave us, per day and key generation.
CREATE TABLE IF NOT EXISTS token_keys (relay_url TEXT NOT NULL, epoch INTEGER NOT NULL, generation INTEGER NOT NULL, key BLOB NOT NULL, PRIMARY KEY (relay_url, epoch, generation));
-- The keys other member devices report being given (checked = compared).
CREATE TABLE IF NOT EXISTS peer_token_keys (relay_url TEXT NOT NULL, epoch INTEGER NOT NULL, generation INTEGER NOT NULL, key_hash BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, checked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (relay_url, epoch, generation, key_hash, user, device_id));
CREATE TABLE IF NOT EXISTS device_lists (user BLOB PRIMARY KEY, version INTEGER NOT NULL, body_hash BLOB NOT NULL, signed BLOB NOT NULL);
-- Only populated from verified device lists; this is the session gate.
CREATE TABLE IF NOT EXISTS devices (user BLOB NOT NULL, device_id INTEGER NOT NULL, identity_key BLOB NOT NULL, PRIMARY KEY (user, device_id));
-- Changes to known device lists, surfaced to the user once (shown = 1 after).
CREATE TABLE IF NOT EXISTS device_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user BLOB NOT NULL, device_id INTEGER NOT NULL, added INTEGER NOT NULL, version INTEGER NOT NULL, at_ms INTEGER NOT NULL, shown INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (address TEXT PRIMARY KEY, record BLOB NOT NULL);
-- Post-quantum authentication (see pqauth.rs). Peers' verified KEM keys:
CREATE TABLE IF NOT EXISTS pq_peer_kem (user BLOB NOT NULL, device_id INTEGER NOT NULL, kem_key BLOB NOT NULL, PRIMARY KEY (user, device_id));
-- Established pairwise keys, by handshake id. confirmed = 0: derived from an
-- init only (classically authenticated), until a data frame decrypts under it.
CREATE TABLE IF NOT EXISTS pq_keys (user BLOB NOT NULL, device_id INTEGER NOT NULL, hs_id BLOB NOT NULL, key BLOB NOT NULL, created_ms INTEGER NOT NULL, confirmed INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (user, device_id, hs_id));
-- Handshakes we started and await the response to:
CREATE TABLE IF NOT EXISTS pq_pending (user BLOB NOT NULL, device_id INTEGER NOT NULL, hs_id BLOB NOT NULL, ss BLOB NOT NULL, ct BLOB NOT NULL, peer_kem BLOB NOT NULL, created_ms INTEGER NOT NULL, PRIMARY KEY (user, device_id, hs_id));
-- Handshake responses waiting to be sent (on the relay the init came from):
CREATE TABLE IF NOT EXISTS pq_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, relay_url TEXT NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, frame BLOB NOT NULL);
-- Messages under a handshake we started that arrived before its response:
CREATE TABLE IF NOT EXISTS pq_held (msg_id TEXT PRIMARY KEY, user BLOB NOT NULL, device_id INTEGER NOT NULL, frame BLOB NOT NULL, received_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS identities (address TEXT PRIMARY KEY, identity BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS signed_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_ms INTEGER NOT NULL, superseded_ms INTEGER);
-- one_time = 1: deleted on first use; 0: last-resort (replays tracked in kyber_used).
CREATE TABLE IF NOT EXISTS kyber_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_ms INTEGER NOT NULL, one_time INTEGER NOT NULL DEFAULT 0, superseded_ms INTEGER);
CREATE TABLE IF NOT EXISTS kyber_used (kyber_id INTEGER NOT NULL, ec_id INTEGER NOT NULL, base_key BLOB NOT NULL, PRIMARY KEY (kyber_id, ec_id, base_key));
-- spk_id: the signed prekey this relay currently serves for us.
CREATE TABLE IF NOT EXISTS relays (url TEXT PRIMARY KEY, registered_at INTEGER NOT NULL, spk_id INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS repos (
  repo_id BLOB PRIMARY KEY,
  relay_url TEXT NOT NULL,
  roster BLOB NOT NULL,
  seq INTEGER NOT NULL,
  head BLOB NOT NULL,
  view BLOB NOT NULL,
  refs BLOB NOT NULL,
  head_ref TEXT NOT NULL,
  conflict TEXT,
  last_heartbeat_ms INTEGER NOT NULL DEFAULT 0,
  last_log_at_ms INTEGER NOT NULL DEFAULT 0
);
-- Every repo secret we have seen, newest first by `added`.
CREATE TABLE IF NOT EXISTS repo_secrets (repo_id BLOB NOT NULL, secret BLOB NOT NULL, added INTEGER NOT NULL, PRIMARY KEY (repo_id, secret));
-- Our own view and log head after each seq, for comparing acks.
CREATE TABLE IF NOT EXISTS history (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, view BLOB NOT NULL, head BLOB NOT NULL, PRIMARY KEY (repo_id, seq));
-- Decrypted envelopes not yet fully processed.
CREATE TABLE IF NOT EXISTS inbox (repo_id BLOB NOT NULL, msg_id TEXT NOT NULL, sender_user BLOB NOT NULL, sender_device INTEGER NOT NULL, envelope BLOB NOT NULL, received_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (repo_id, msg_id));
-- Plaintext envelopes waiting to be encrypted and delivered.
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, envelope BLOB NOT NULL, created_ms INTEGER NOT NULL DEFAULT 0);
-- Devices whose deliveries keep failing: retry with exponential backoff
-- instead of spending tokens on every sync.
CREATE TABLE IF NOT EXISTS device_backoff (user BLOB NOT NULL, device_id INTEGER NOT NULL, failures INTEGER NOT NULL, next_try_ms INTEGER NOT NULL, first_failure_ms INTEGER NOT NULL, PRIMARY KEY (user, device_id));
-- Our own pushes, kept until every recipient acked (needed for resends).
CREATE TABLE IF NOT EXISTS own_entries (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, envelope BLOB NOT NULL, blob_id TEXT NOT NULL, recipients BLOB NOT NULL, fanned_out INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (repo_id, seq));
CREATE TABLE IF NOT EXISTS acks (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, view BLOB NOT NULL, head BLOB NOT NULL, PRIMARY KEY (repo_id, seq, user, device_id));
CREATE TABLE IF NOT EXISTS resend_requests (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, at_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, seq));
-- When we last received authenticated mail for a repo from each other device
-- (local clock). Freeze detection rests on this, not on log entries, which
-- the relay can fabricate.
CREATE TABLE IF NOT EXISTS peer_contact (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, last_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, user, device_id));
-- When we last delivered anything for a repo to each device (skips gossip).
CREATE TABLE IF NOT EXISTS peer_sent (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, last_ms INTEGER NOT NULL, PRIMARY KEY (repo_id, user, device_id));
-- Who made each log entry and what it changed, as this device saw it
-- (inherited = 1: taken from an inviter's history bundle).
-- inherited = 1: taken from another member's history bundle; source = who.
CREATE TABLE IF NOT EXISTS push_log (repo_id BLOB NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, inherited INTEGER NOT NULL, source BLOB, PRIMARY KEY (repo_id, seq));
-- Names the user gave contacts (local only, never sent anywhere).
CREATE TABLE IF NOT EXISTS contact_names (user BLOB PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_heartbeats (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, at_ms INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (repo_id, user, device_id));
"#;

/// Version 2 (protocol 2, the first release; version 1 is frozen from
/// here on): `pq_keys` rebuilt with only the columns this version uses (the
/// last prototype builds also stored a delivery token there).
const SCHEMA_V2: &str = r#"
CREATE TABLE pq_keys_v2 (user BLOB NOT NULL, device_id INTEGER NOT NULL, hs_id BLOB NOT NULL, key BLOB NOT NULL, created_ms INTEGER NOT NULL, confirmed INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (user, device_id, hs_id));
INSERT INTO pq_keys_v2 (user, device_id, hs_id, key, created_ms, confirmed) SELECT user, device_id, hs_id, key, created_ms, confirmed FROM pq_keys;
DROP TABLE pq_keys;
ALTER TABLE pq_keys_v2 RENAME TO pq_keys;
"#;

/// Version 3: a pending handshake remembers the version its init carried
/// (the key derivation binds it, and the peer's list may change meanwhile).
const SCHEMA_V3: &str = r#"
-- 2: the protocol of the builds that wrote earlier rows. A fixed fact
-- about the past; keep it when PROTOCOL_VERSION moves on.
ALTER TABLE pq_pending ADD COLUMN version INTEGER NOT NULL DEFAULT 2;
"#;

/// Version 4: disappearing push-log entries (when each disappears, and
/// which one is the current timer's notice).
const SCHEMA_V4: &str = r#"
ALTER TABLE push_log ADD COLUMN expires_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE push_log ADD COLUMN timer INTEGER NOT NULL DEFAULT 0;
"#;

/// Version 5: invitations this device sent that haven't been taken up yet
/// (re-sent until the newcomer's device clones; see `resend_invites`), with
/// the latest copy's blobs, deleted when it's replaced.
const SCHEMA_V5: &str = r#"
-- The handshake reply sent for a key not yet confirmed, to send again if it
-- was lost (an invitation re-sent after the relay expired the first one).
ALTER TABLE pq_keys ADD COLUMN resp BLOB;
CREATE TABLE pending_invites (repo_id BLOB NOT NULL, user BLOB NOT NULL, device_id INTEGER NOT NULL, first_ms INTEGER NOT NULL, sent_ms INTEGER NOT NULL, sends INTEGER NOT NULL, blob_ids TEXT NOT NULL, pack_key BLOB NOT NULL, PRIMARY KEY (repo_id, user, device_id));
"#;

const SCHEMA_V6: &str = r#"
-- Our own other devices this device has seen without the repo (first_ms) and
-- whether it sent them the repo (offered), so it's offered once, not forever.
CREATE TABLE own_offers (repo_id BLOB NOT NULL, device_id INTEGER NOT NULL, first_ms INTEGER NOT NULL, offered INTEGER NOT NULL, PRIMARY KEY (repo_id, device_id));
"#;

/// Exclusive lock on the device state, held for a whole CLI or helper run so
/// two processes can never fork ratchet state.
pub struct DeviceLock {
    _file: std::fs::File,
}

impl DeviceLock {
    pub fn acquire(dir: &Path) -> Result<Self> {
        create_private_dir(dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        file.lock().context("locking device state")?;
        Ok(Self { _file: file })
    }
}

/// Create `dir` (and missing parents) as 0700 from the start, so there is no
/// moment where another local user could put something in it; an existing
/// one is made private.
fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Parents (like ~/.local/share) as usual; only our own directory
        // private.
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
            _ => {}
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    set_private(dir)
}

#[cfg(unix)]
fn set_private(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private(_: &Path) -> Result<()> {
    Ok(())
}

/// (device id, KEM key hash, ML-DSA key hash) of every device in a signed list.
fn pq_hashes_of(signed: &[u8]) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    <e2ee_proto::SignedDeviceList as e2ee_proto::Message>::decode(signed)
        .ok()
        .and_then(|s| <e2ee_proto::DeviceListBody as e2ee_proto::Message>::decode(s.body.as_slice()).ok())
        .map(|b| b.devices.into_iter().map(|d| (d.device_id, d.kem_key_hash, d.pq_key_hash)).collect())
        .unwrap_or_default()
}

/// A device-list change: (user, device id, added (else removed), list version).
pub type DeviceEvent = (Vec<u8>, u32, bool, u64);

#[derive(Clone)]
pub struct Db(pub Rc<Connection>);

impl Db {
    pub fn open(dir: &Path) -> Result<Self> {
        create_private_dir(dir)?;
        // Keys live in this file: owner-only (not just the directory), so a
        // copy or backup of the folder doesn't widen access. SQLite gives its
        // -wal and -shm files the database file's permissions.
        let path = dir.join("device.sqlite");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path)?;
            for f in ["device.sqlite", "device.sqlite-wal", "device.sqlite-shm"] {
                let p = dir.join(f);
                if p.exists() {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        let mut conn = Connection::open(&path)?;
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch(PRAGMAS)?;
        e2ee_proto::migrate::migrate(&mut conn, "device", MIGRATIONS)?;
        Ok(Self(Rc::new(conn)))
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(PRAGMAS)?;
        e2ee_proto::migrate::migrate(&mut conn, "device", MIGRATIONS)?;
        Ok(Self(Rc::new(conn)))
    }

    pub fn conn(&self) -> &Connection {
        &self.0
    }

    /// Run `f` inside an IMMEDIATE transaction; rolls back on error.
    pub async fn transaction<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        match f().await {
            Ok(v) => {
                self.conn().execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn().execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn meta_get(&self, k: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, k: &str, v: &[u8]) -> Result<()> {
        self.conn().execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn meta_u64(&self, k: &str) -> Result<Option<u64>> {
        Ok(self
            .meta_get(k)?
            .map(|v| u64::from_be_bytes(v.try_into().unwrap_or([0; 8]))))
    }

    pub fn meta_set_u64(&self, k: &str, v: u64) -> Result<()> {
        self.meta_set(k, &v.to_be_bytes())
    }

    /// Allocate `n` consecutive ids from a named counter (starting at 1).
    pub fn next_ids(&self, counter: &str, n: u64) -> Result<u64> {
        let key = format!("counter:{counter}");
        let start = self.meta_u64(&key)?.unwrap_or(1);
        self.meta_set_u64(&key, start + n)?;
        Ok(start)
    }

    // -- pinned master keys --------------------------------------------------

    /// Forget an unverified pin (and its device list), e.g. one taken from a
    /// roster change that was then rejected. Verified pins are kept.
    pub fn unpin_unverified(&self, user: &[u8]) -> Result<()> {
        if self.conn().execute("DELETE FROM pinned WHERE user = ?1 AND verified = 0", [user])? > 0 {
            self.conn().execute("DELETE FROM device_lists WHERE user = ?1", [user])?;
            self.conn().execute("DELETE FROM devices WHERE user = ?1", [user])?;
            for t in ["pq_keys", "pq_pending", "pq_peer_kem", "pq_held", "pq_outbox"] {
                self.conn().execute(&format!("DELETE FROM {t} WHERE user = ?1"), [user])?;
            }
            // And the handshake bookkeeping (see pqauth.rs).
            for p in ["pq-stale", "pq-awaiting"] {
                self.conn().execute("DELETE FROM meta WHERE k LIKE ?1", [format!("{p}:{}.%", hex::encode(user))])?;
            }
        }
        Ok(())
    }

    /// Give a contact a local name (shown instead of its user id).
    pub fn set_name(&self, user: &[u8], name: &str) -> Result<()> {
        let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
        let name = name.trim();
        if name.is_empty() {
            self.conn().execute("DELETE FROM contact_names WHERE user = ?1", [user])?;
        } else {
            self.conn().execute("INSERT OR REPLACE INTO contact_names (user, name) VALUES (?1, ?2)", params![user, name])?;
        }
        Ok(())
    }

    /// Your contacts (`git e2ee contact add`): (user id, name), by name.
    pub fn contacts(&self) -> Result<Vec<(Vec<u8>, String)>> {
        let mut st = self.conn().prepare(
            "SELECT p.user, COALESCE(n.name, '') FROM pinned p LEFT JOIN contact_names n ON n.user = p.user WHERE p.verified = 1 ORDER BY 2, 1",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The users with this contact name (names are unique, so at most one).
    pub fn user_named(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.conn().query_row("SELECT user FROM contact_names WHERE name = ?1", [name.trim()], |r| r.get(0)).optional()?)
    }

    /// Stop treating this user as a contact: drop the name, and the pin too
    /// unless a repo's roster still needs it.
    pub fn remove_contact(&self, user: &[u8]) -> Result<()> {
        self.conn().execute("DELETE FROM contact_names WHERE user = ?1", [user])?;
        self.conn().execute("UPDATE pinned SET verified = 0 WHERE user = ?1", [user])?;
        Ok(())
    }

    pub fn name_of(&self, user: &[u8]) -> Result<Option<String>> {
        Ok(self.conn().query_row("SELECT name FROM contact_names WHERE user = ?1", [user], |r| r.get(0)).optional()?)
    }

    pub fn pin(&self, user: &[u8], master_key: &[u8], verified: bool) -> Result<()> {
        // A user id *is* the hash of its master key. Without this check a
        // roster or history bundle could bind someone's id to another key.
        if user != e2ee_proto::user_id_of(master_key) {
            return Err(anyhow!("user id {} does not belong to the given master key", hex::encode(user)));
        }
        let existing: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT master_key FROM pinned WHERE user = ?1", [user], |r| r.get(0))
            .optional()?;
        if let Some(k) = existing
            && k != master_key
        {
            return Err(anyhow!(
                "a different master key is already pinned for user {}",
                hex::encode(user)
            ));
        }
        self.conn().execute(
            "INSERT INTO pinned (user, master_key, verified) VALUES (?1, ?2, ?3)
             ON CONFLICT(user) DO UPDATE SET verified = MAX(verified, excluded.verified)",
            params![user, master_key, verified as i64],
        )?;
        Ok(())
    }

    /// A contact's delivery token: the latest one they sent us themselves,
    /// or one an inviter passed on.
    pub fn delivery_token(&self, user: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row("SELECT delivery_token FROM pinned WHERE user = ?1", [user], |r| r.get(0))
            .optional()?
            .flatten())
    }

    pub fn set_delivery_token(&self, user: &[u8], token: &[u8]) -> Result<()> {
        self.conn().execute("UPDATE pinned SET delivery_token = ?2 WHERE user = ?1", params![user, token])?;
        Ok(())
    }

    pub fn pinned(&self, user: &[u8]) -> Result<Option<(Vec<u8>, bool)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT master_key, verified FROM pinned WHERE user = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?)
    }

    // -- verified device lists -----------------------------------------------

    pub fn device_list_state(&self, user: &[u8]) -> Result<Option<(u64, Vec<u8>)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT version, body_hash FROM device_lists WHERE user = ?1",
                [user],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn signed_device_list(&self, user: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row("SELECT signed FROM device_lists WHERE user = ?1", [user], |r| r.get(0))
            .optional()?)
    }

    /// Replace a user's device set. Callers must have verified the list.
    pub fn add_device_event(&self, user: &[u8], device_id: u32, added: bool, version: u64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO device_events (user, device_id, added, version, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user, device_id as i64, added as i64, version as i64, crate::now_ms() as i64],
        )?;
        Ok(())
    }

    pub fn store_device_list(
        &self,
        user: &[u8],
        version: u64,
        body_hash: &[u8],
        signed: &[u8],
        devices: &[(u32, Vec<u8>)],
        notify: bool,
    ) -> Result<()> {
        let c = self.conn();
        // The list we had, before this one replaces it.
        let prev_signed: Option<Vec<u8>> = c.query_row("SELECT signed FROM device_lists WHERE user = ?1", [user], |r| r.get(0)).optional()?;
        // Record additions and removals relative to a list we already had
        // (the first list we see for a user is not news).
        if notify && self.device_list_state(user)?.is_some() {
            let old = self.devices_of(user)?;
            let (now, ver) = (crate::now_ms() as i64, version as i64);
            // A device whose post-quantum keys (ML-DSA, KEM) changed under the
            // same id and identity key is news too: it counts as added.
            let (before, after) = (prev_signed.as_deref().map(pq_hashes_of).unwrap_or_default(), pq_hashes_of(signed));
            let pq_changed = |id: &u32| {
                let find = |l: &[(u32, Vec<u8>, Vec<u8>)]| l.iter().find(|(d, _, _)| d == id).map(|(_, k, p)| (k.clone(), p.clone()));
                matches!((find(&before), find(&after)), (Some(a), Some(b)) if a != b)
            };
            for (id, key) in devices {
                if !old.iter().any(|(o, k)| o == id && k == key) || pq_changed(id) {
                    c.execute(
                        "INSERT INTO device_events (user, device_id, added, version, at_ms) VALUES (?1, ?2, 1, ?3, ?4)",
                        params![user, *id as i64, ver, now],
                    )?;
                }
            }
            for (id, _) in &old {
                if !devices.iter().any(|(d, _)| d == id) {
                    c.execute(
                        "INSERT INTO device_events (user, device_id, added, version, at_ms) VALUES (?1, ?2, 0, ?3, ?4)",
                        params![user, *id as i64, ver, now],
                    )?;
                }
            }
        }
        c.execute(
            "INSERT INTO device_lists (user, version, body_hash, signed) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user) DO UPDATE SET version = excluded.version, body_hash = excluded.body_hash, signed = excluded.signed",
            params![user, version as i64, body_hash, signed],
        )?;
        // Devices that left the list, or whose post-quantum keys changed:
        // their pairwise post-quantum keys go too (a revoked or rekeyed
        // device's old key must not keep authenticating anything).
        let (old, new) = (prev_signed.as_deref().map(pq_hashes_of).unwrap_or_default(), pq_hashes_of(signed));
        let rekeyed = |id: u32| {
            let find = |l: &[(u32, Vec<u8>, Vec<u8>)]| l.iter().find(|(d, _, _)| *d == id).map(|(_, k, p)| (k.clone(), p.clone()));
            matches!((find(&old), find(&new)), (Some(a), Some(b)) if a != b)
        };
        for (id, _) in self.devices_of(user)? {
            if !devices.iter().any(|(d, _)| *d == id) || rekeyed(id) {
                for p in ["pq-stale", "pq-awaiting"] {
                    c.execute("DELETE FROM meta WHERE k = ?1", [format!("{p}:{}.{id}", hex::encode(user))])?;
                }
                for t in ["pq_keys", "pq_pending", "pq_peer_kem", "pq_held", "pq_outbox"] {
                    c.execute(&format!("DELETE FROM {t} WHERE user = ?1 AND device_id = ?2"), params![user, id as i64])?;
                }
            }
        }
        c.execute("DELETE FROM devices WHERE user = ?1", [user])?;
        for (id, key) in devices {
            c.execute(
                "INSERT INTO devices (user, device_id, identity_key) VALUES (?1, ?2, ?3)",
                params![user, *id as i64, key],
            )?;
        }
        Ok(())
    }

    /// Device-list changes not yet shown to the user.
    pub fn take_device_events(&self) -> Result<Vec<DeviceEvent>> {
        let mut st = self
            .conn()
            .prepare("SELECT id, user, device_id, added, version FROM device_events WHERE shown = 0 ORDER BY id")?;
        let rows: Vec<(i64, Vec<u8>, u32, bool, u64)> = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32, r.get::<_, i64>(3)? != 0, r.get::<_, i64>(4)? as u64))
            })?
            .collect::<rusqlite::Result<_>>()?;
        for (id, ..) in &rows {
            self.conn().execute("UPDATE device_events SET shown = 1 WHERE id = ?1", [id])?;
        }
        Ok(rows.into_iter().map(|(_, u, d, a, v)| (u, d, a, v)).collect())
    }

    pub fn devices_of(&self, user: &[u8]) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut st = self
            .conn()
            .prepare("SELECT device_id, identity_key FROM devices WHERE user = ?1 ORDER BY device_id")?;
        let rows = st.query_map([user], |r| Ok((r.get::<_, i64>(0)? as u32, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn device_key(&self, user: &[u8], device_id: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT identity_key FROM devices WHERE user = ?1 AND device_id = ?2",
                params![user, device_id as i64],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Drop sessions with devices no longer in a verified list.
    pub fn drop_sessions_except(&self, user_hex: &str, keep: &[u32]) -> Result<()> {
        let mut st = self.conn().prepare("SELECT address FROM sessions")?;
        let addrs: Vec<String> = st
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for a in addrs {
            if let Some((u, d)) = a.rsplit_once('.')
                && u == user_hex
                && !keep.iter().any(|k| k.to_string() == d)
            {
                self.conn().execute("DELETE FROM sessions WHERE address = ?1", [&a])?;
            }
        }
        Ok(())
    }

    pub fn relay_registered(&self, url: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row("SELECT 1 FROM relays WHERE url = ?1", [url], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn set_relay_registered(&self, url: &str, spk_id: u32) -> Result<()> {
        self.conn().execute(
            "INSERT INTO relays (url, registered_at, spk_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(url) DO UPDATE SET spk_id = excluded.spk_id",
            params![url, crate::now_ms() as i64, spk_id],
        )?;
        Ok(())
    }

    /// The signed prekey id this relay serves for us, if registered.
    pub fn relay_spk(&self, url: &str) -> Result<Option<u32>> {
        Ok(self
            .conn()
            .query_row("SELECT spk_id FROM relays WHERE url = ?1", [url], |r| r.get::<_, i64>(0))
            .optional()?
            .map(|v| v as u32))
    }

    pub fn relays(&self) -> Result<Vec<String>> {
        let mut st = self.conn().prepare("SELECT url FROM relays")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

// ---------------------------------------------------------------------------
// libsignal store trait implementations

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StoreError(String);

fn cb<E: std::fmt::Display>(method: &'static str) -> impl FnOnce(E) -> SignalProtocolError {
    move |e| SignalProtocolError::ApplicationCallbackError(method, Box::new(StoreError(e.to_string())))
}

/// Parse a libsignal address name (hex user id) back into raw bytes.
pub fn address_user(addr: &ProtocolAddress) -> Option<Vec<u8>> {
    hex::decode(addr.name()).ok()
}

fn addr_key(addr: &ProtocolAddress) -> String {
    format!("{}.{}", addr.name(), u32::from(addr.device_id()))
}

/// Bundle of store handles over one connection. libsignal wants separate
/// `&mut dyn` borrows, so each trait gets its own (cheap) handle.
#[derive(Clone)]
pub struct Stores {
    pub identity: SqlIdentityStore,
    pub sessions: SqlSessionStore,
    pub prekeys: SqlPreKeyStore,
    pub signed_prekeys: SqlSignedPreKeyStore,
    pub kyber: SqlKyberStore,
}

impl Stores {
    pub fn new(db: &Db, identity: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity: SqlIdentityStore { db: db.clone(), identity, registration_id },
            sessions: SqlSessionStore { db: db.clone() },
            prekeys: SqlPreKeyStore { db: db.clone() },
            signed_prekeys: SqlSignedPreKeyStore { db: db.clone() },
            kyber: SqlKyberStore { db: db.clone() },
        }
    }
}

#[derive(Clone)]
pub struct SqlIdentityStore {
    db: Db,
    identity: IdentityKeyPair,
    registration_id: u32,
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqlIdentityStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.identity)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let key = addr_key(address);
        let ser = identity.serialize();
        let old: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row("SELECT identity FROM identities WHERE address = ?1", [&key], |r| r.get(0))
            .optional()
            .map_err(cb("save_identity"))?;
        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO identities (address, identity) VALUES (?1, ?2)",
                params![key, &ser[..]],
            )
            .map_err(cb("save_identity"))?;
        Ok(IdentityChange::from_changed(old.is_some_and(|o| o != ser[..])))
    }

    /// The session gate: a remote identity is trusted only if it appears in a
    /// verified, cross-signed device list for the address's user.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let Some(user) = address_user(address) else {
            return Ok(false);
        };
        let dev = u32::from(address.device_id());
        let known = self.db.device_key(&user, dev).map_err(cb("is_trusted_identity"))?;
        Ok(known.is_some_and(|k| k == identity.serialize()[..]))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let Some(user) = address_user(address) else {
            return Ok(None);
        };
        let dev = u32::from(address.device_id());
        match self.db.device_key(&user, dev).map_err(cb("get_identity"))? {
            Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
            None => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct SqlSessionStore {
    db: Db,
}

#[async_trait(?Send)]
impl SessionStore for SqlSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let rec: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row("SELECT record FROM sessions WHERE address = ?1", [addr_key(address)], |r| {
                r.get(0)
            })
            .optional()
            .map_err(cb("load_session"))?;
        rec.map(|b| SessionRecord::deserialize(&b)).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO sessions (address, record) VALUES (?1, ?2)",
                params![addr_key(address), record.serialize()?],
            )
            .map_err(cb("store_session"))?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlPreKeyStore {
    db: Db,
}

#[async_trait(?Send)]
impl PreKeyStore for SqlPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let rec: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row("SELECT record FROM prekeys WHERE id = ?1", [u32::from(id)], |r| r.get(0))
            .optional()
            .map_err(cb("get_pre_key"))?;
        PreKeyRecord::deserialize(&rec.ok_or(SignalProtocolError::InvalidPreKeyId)?)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO prekeys (id, record) VALUES (?1, ?2)",
                params![u32::from(id), record.serialize()?],
            )
            .map_err(cb("save_pre_key"))?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.db
            .conn()
            .execute("DELETE FROM prekeys WHERE id = ?1", [u32::from(id)])
            .map_err(cb("remove_pre_key"))?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlSignedPreKeyStore {
    db: Db,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqlSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let rec: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row("SELECT record FROM signed_prekeys WHERE id = ?1", [u32::from(id)], |r| {
                r.get(0)
            })
            .optional()
            .map_err(cb("get_signed_pre_key"))?;
        SignedPreKeyRecord::deserialize(&rec.ok_or(SignalProtocolError::InvalidSignedPreKeyId)?)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO signed_prekeys (id, record, created_ms) VALUES (?1, ?2, ?3)",
                params![u32::from(id), record.serialize()?, crate::now_ms() as i64],
            )
            .map_err(cb("save_signed_pre_key"))?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlKyberStore {
    db: Db,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqlKyberStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let rec: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row("SELECT record FROM kyber_prekeys WHERE id = ?1", [u32::from(id)], |r| {
                r.get(0)
            })
            .optional()
            .map_err(cb("get_kyber_pre_key"))?;
        KyberPreKeyRecord::deserialize(&rec.ok_or(SignalProtocolError::InvalidKyberPreKeyId)?)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO kyber_prekeys (id, record, created_ms) VALUES (?1, ?2, ?3)",
                params![u32::from(id), record.serialize()?, crate::now_ms() as i64],
            )
            .map_err(cb("save_kyber_pre_key"))?;
        Ok(())
    }

    /// One-time Kyber prekeys are deleted on first use. Last-resort ones may
    /// be reused, but never with the same (kyber, ec, base key) triple twice,
    /// which would be a replay.
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_id: KyberPreKeyId,
        ec_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let one_time: Option<i64> = self
            .db
            .conn()
            .query_row("SELECT one_time FROM kyber_prekeys WHERE id = ?1", [u32::from(kyber_id)], |r| r.get(0))
            .optional()
            .map_err(cb("mark_kyber_pre_key_used"))?;
        if one_time == Some(1) {
            self.db
                .conn()
                .execute("DELETE FROM kyber_prekeys WHERE id = ?1", [u32::from(kyber_id)])
                .map_err(cb("mark_kyber_pre_key_used"))?;
            return Ok(());
        }
        let inserted = self
            .db
            .conn()
            .execute(
                "INSERT OR IGNORE INTO kyber_used (kyber_id, ec_id, base_key) VALUES (?1, ?2, ?3)",
                params![u32::from(kyber_id), u32::from(ec_id), &base_key.serialize()[..]],
            )
            .map_err(cb("mark_kyber_pre_key_used"))?;
        if inserted == 0 {
            return Err(SignalProtocolError::InvalidMessage(
                libsignal_protocol::CiphertextMessageType::PreKey,
                "replayed pre-key message".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_keyed_by_relay_host() {
        for (url, host) in [
            ("https://relay.example", "relay.example"),
            ("https://Relay.Example:8443/x", "relay.example"),
            ("http://127.0.0.1:8470", "127.0.0.1"),
            ("http://[::1]:8470/r", "___1_"),
        ] {
            assert_eq!(relay_host(url).unwrap(), host, "{url}");
        }
        assert!(relay_host("relay.example").is_err());
        for bad in ["https://../x", "https://./x", "https://.hidden", "https://", "https://a/b"] {
            let r = relay_host(bad);
            assert!(r.as_ref().map_or(true, |h| h == "a"), "{bad}: {r:?}");
        }
        assert!(relay_host("https://../x").is_err());
    }

    /// The last prototype shape (a delivery token column on `pq_keys`)
    /// migrates to version 2 with its keys.
    #[test]
    fn prototype_device_database_migrates() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(
            "ALTER TABLE pq_keys ADD COLUMN delivery_token BLOB;
             INSERT INTO pq_keys VALUES (x'01', 1, x'02', x'03', 5, 0, x'04');
             PRAGMA user_version = 1;",
        )
        .unwrap();
        e2ee_proto::migrate::migrate(&mut conn, "device", MIGRATIONS).unwrap();
        let (key, confirmed): (Vec<u8>, bool) =
            conn.query_row("SELECT key, confirmed FROM pq_keys WHERE hs_id = x'02'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((key, confirmed), (vec![3], false));
        assert!(conn.prepare("SELECT delivery_token FROM pq_keys").is_err());
    }

    #[test]
    fn newer_device_database_is_refused() {
        let dir = std::env::temp_dir().join(format!("e2ee-db-test-{}", rand::random::<u64>()));
        drop(Db::open(&dir).unwrap());
        Connection::open(dir.join("device.sqlite")).unwrap().pragma_update(None, "user_version", 99).unwrap();
        let err = Db::open(&dir).err().unwrap().to_string();
        assert!(err.contains("newer version"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fresh_device_database_is_at_the_latest_schema() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(e2ee_proto::migrate::schema_version(db.conn()).unwrap(), MIGRATIONS.len() as u32);
    }
}
