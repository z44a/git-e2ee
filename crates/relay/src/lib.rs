//! The relay: an untrusted store-and-forward server. It holds prekeys, signed
//! device lists, sealed mailboxes, encrypted blobs, and a hash-chained
//! commitment log. It never sees plaintext, keys, ref names, or senders.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::middleware::{self, Next};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use e2ee_proto::api::{self, headers};
use e2ee_proto::{DeviceListBody, LogEntry, Message, SignedDeviceList, ZERO_HASH, tokens};
use libsignal_protocol::IdentityKey;
use rusqlite::{Connection, OptionalExtension, params};

/// Per-connection settings (not part of the schema). Secure delete
/// overwrites deleted content, so delivered mail and expired rows are gone.
const PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;";

/// Schema migrations, in order (see `e2ee_proto::migrate`). Append new ones;
/// never edit a released one.
const MIGRATIONS: &[&str] = &[SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4];

const SCHEMA_V1: &str = r#"
-- Every table is WITHOUT ROWID: rowids would record the order rows arrived
-- in (and a REPLACE gets a fresh, higher one), which the design avoids.
CREATE TABLE IF NOT EXISTS device_keys (user TEXT NOT NULL, device INTEGER NOT NULL, identity BLOB NOT NULL, pq_key BLOB NOT NULL, kem_key BLOB NOT NULL, registration INTEGER NOT NULL, signed_prekey TEXT, kyber_prekey TEXT, PRIMARY KEY (user, device)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS one_time (user TEXT NOT NULL, device INTEGER NOT NULL, id INTEGER NOT NULL, public BLOB NOT NULL, PRIMARY KEY (user, device, id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS device_lists (user TEXT PRIMARY KEY, version INTEGER NOT NULL, signed BLOB NOT NULL, gen INTEGER NOT NULL) WITHOUT ROWID;
-- A repo exists once its log has a first entry. No creator, no creation time
-- beyond the first entry's own timestamp.
CREATE TABLE IF NOT EXISTS repos (rid TEXT PRIMARY KEY) WITHOUT ROWID;
-- New logs per hour window, for the global creation cap (no per-user record).
CREATE TABLE IF NOT EXISTS one_time_kyber (user TEXT NOT NULL, device INTEGER NOT NULL, id INTEGER NOT NULL, key TEXT NOT NULL, PRIMARY KEY (user, device, id)) WITHOUT ROWID;
-- A repo's one token (hash). Rotations replace it in the same step as the
-- log append that announces the new secret.
CREATE TABLE IF NOT EXISTS repo_tokens (rid TEXT NOT NULL, token_hash TEXT NOT NULL, PRIMARY KEY (rid, token_hash)) WITHOUT ROWID;
-- WITHOUT ROWID: rows are stored in key order, not insertion order, so the
-- table's layout doesn't reveal which repos were active in which order.
CREATE TABLE IF NOT EXISTS logs (rid TEXT NOT NULL, branch INTEGER NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, head BLOB NOT NULL, PRIMARY KEY (rid, branch, seq)) WITHOUT ROWID;
-- One global blob store: blobs are not attributable to a repo. Deleting needs
-- a token derived from the pack key, so only members can delete.
-- `gen` is the expiry generation (see `Relay::gc`), not a time.
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL, delete_hash TEXT NOT NULL, gen INTEGER NOT NULL) WITHOUT ROWID;
-- One mailbox per device, shared by all repos: no repo id is stored or sent.
-- Pseudonymous mailboxes (one per device per repo): a random id that names
-- no user, and the hash of the secret that reads it. gen: last generation it
-- was read in; unused ones expire like mail.
CREATE TABLE IF NOT EXISTS pmailboxes (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, gen INTEGER NOT NULL) WITHOUT ROWID;
-- Random ids and a per-mailbox sequence (order within a mailbox only): no
-- global insertion order, which would show which mailboxes got mail at the
-- same moment (one fan-out, one repo's members).
CREATE TABLE IF NOT EXISTS mailbox (user TEXT NOT NULL, device INTEGER NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL UNIQUE, data BLOB NOT NULL, gen INTEGER NOT NULL, PRIMARY KEY (user, device, seq)) WITHOUT ROWID;
-- Anonymous access tokens: issued per device per day (budget), and spent
-- nonces per epoch (double-spend protection). Spent nonces can't be linked
-- to the issuance they came from.
CREATE TABLE IF NOT EXISTS spent_tokens (nonce BLOB PRIMARY KEY, gen INTEGER NOT NULL) WITHOUT ROWID;
-- Per-user delivery token hashes (normal lane) and request-lane counters.
CREATE TABLE IF NOT EXISTS delivery_tokens (user TEXT PRIMARY KEY, token_hash TEXT NOT NULL) WITHOUT ROWID;

-- Users allowed on an invite-only relay; their later devices need no token.
CREATE TABLE IF NOT EXISTS relay_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS registered_users (user TEXT PRIMARY KEY) WITHOUT ROWID;
-- Operator-issued single-use registration tokens (hash only).
CREATE TABLE IF NOT EXISTS registration_tokens (token_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS banned_users (user TEXT PRIMARY KEY) WITHOUT ROWID;
"#;

/// Version 2 (protocol 2, the first release; version 1 is frozen from here
/// on). Prototype builds wrote version 1 databases in several shapes, so
/// nothing here assumes a prototype column:
/// - Blobs get rowids (an explicit random key), so uploads and downloads
///   can stream them (SQLite's incremental blob I/O needs a rowid). Keys are
///   random, never sequential, so they don't record upload order.
/// - Nonces of recent signed requests are kept (see `consume_nonce`). Old blobs are dropped: they only serve
///   protocol 1 repos, which protocol 2 clients can't open.
/// - Repo tokens are dropped for the same reason (one token per repo now).
/// - Invites are kept, with only the columns this version uses.
const SCHEMA_V2: &str = r#"
DROP TABLE IF EXISTS blobs;
-- k: a random key (an explicit INTEGER PRIMARY KEY, so VACUUM keeps it).
-- complete = 0 while an upload streams in; never served.
CREATE TABLE blobs (k INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, data BLOB NOT NULL, delete_hash TEXT NOT NULL, gen INTEGER NOT NULL, complete INTEGER NOT NULL DEFAULT 1);
-- Nonces of verified signed requests, so a captured request can't be
-- replayed even across a restart. slot: which of four 5-minute slots the
-- request's own time falls in (time / window mod 4), not a time: rows are
-- kept only while such a request could still be accepted (see consume_nonce).
CREATE TABLE request_nonces (slot INTEGER NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY (slot, nonce)) WITHOUT ROWID;
DROP TABLE IF EXISTS repo_tokens;
CREATE TABLE repo_tokens (rid TEXT NOT NULL, token_hash TEXT NOT NULL, PRIMARY KEY (rid, token_hash)) WITHOUT ROWID;
CREATE TABLE registration_tokens_v2 (token_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL) WITHOUT ROWID;
INSERT OR IGNORE INTO registration_tokens_v2 (token_hash, expires) SELECT token_hash, expires FROM registration_tokens;
DROP TABLE registration_tokens;
ALTER TABLE registration_tokens_v2 RENAME TO registration_tokens;
"#;

/// Version 3: mail and blob payloads move out of SQLite into the slot store
/// (see `slots`), which records no order of arrival; these rows only name
/// the slot. Waiting mail and stored blobs are dropped (they're short-lived;
/// senders' resend requests cover undelivered mail).
const SCHEMA_V3: &str = r#"
DROP TABLE IF EXISTS mailbox;
CREATE TABLE mailbox (user TEXT NOT NULL, device INTEGER NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL UNIQUE, class INTEGER NOT NULL, slot INTEGER NOT NULL, tag INTEGER NOT NULL, len INTEGER NOT NULL, gen INTEGER NOT NULL, PRIMARY KEY (user, device, seq)) WITHOUT ROWID;
DROP TABLE IF EXISTS blobs;
CREATE TABLE blobs (id TEXT PRIMARY KEY, class INTEGER NOT NULL, slot INTEGER NOT NULL, tag INTEGER NOT NULL, len INTEGER NOT NULL, delete_hash TEXT NOT NULL, gen INTEGER NOT NULL) WITHOUT ROWID;
"#;

/// Version 4: an invite can serve several users (`invite --uses N`): how
/// many more first registrations it allows. Existing invites keep one.
const SCHEMA_V4: &str = r#"
ALTER TABLE registration_tokens ADD COLUMN uses_left INTEGER NOT NULL DEFAULT 1;
"#;

pub const DEFAULT_TTL: Duration = Duration::from_secs(14 * 24 * 3600);

/// Abuse limits. The relay cannot judge content, only volume.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_blob_bytes: usize,
    /// Total stored blob bytes across all repos.
    pub max_total_blob_bytes: u64,
    pub max_mail_bytes: usize,
    pub max_mailbox_messages: u64,
    /// Per device, for each of EC and Kyber one-time prekeys.
    pub max_one_time_keys: u64,
    /// One-time prekeys handed out per target device per hour.
    pub max_one_time_handouts_per_hour: u64,
    /// New repo logs per hour, relay-wide (creation is anonymous).
    pub max_new_logs_per_hour: u64,
    /// Sustained requests per second per client IP (0 disables rate limiting).
    pub rate_per_sec: f64,
    pub rate_burst: f64,
    /// Rate-limit by the last `X-Forwarded-For` hop (only behind a trusted proxy).
    pub trust_forwarded_for: bool,
    /// New users need an operator-issued registration token (`git-e2ee-relay invite`).
    pub invite_only: bool,
    /// Anonymous access tokens each device may obtain per day.
    pub access_tokens_per_day: u64,
    /// Messages per device per day without the recipient's delivery token.
    pub request_lane_per_day: u64,
    /// All waiting mail together (both mailbox kinds).
    pub max_total_mail_bytes: u64,
    pub max_pmailboxes: u64,
    /// Concurrent client connections (TLS listener); more are dropped.
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    /// Most disk the mail and blob slot files may take (they never shrink,
    /// and a slot can be up to a quarter bigger than what it holds).
    pub max_storage_bytes: u64,
    /// New identities (first device lists) and new device registrations
    /// per address and hour, and in total (open relays: they cost no tokens).
    pub new_identities_per_ip_hour: u64,
    pub new_devices_per_ip_hour: u64,
    pub max_users: u64,
    pub max_devices: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 32 << 20,
            max_total_blob_bytes: 64 << 30,
            max_mail_bytes: 256 << 10,
            max_mailbox_messages: 20_000,
            max_one_time_keys: 200,
            max_one_time_handouts_per_hour: 20,
            max_new_logs_per_hour: 1000,
            rate_per_sec: 100.0,
            rate_burst: 1000.0,
            trust_forwarded_for: false,
            invite_only: false,
            access_tokens_per_day: 5000,
            request_lane_per_day: 20,
            max_total_mail_bytes: 16 << 30,
            max_pmailboxes: 1_000_000,
            max_connections: 1024,
            max_connections_per_ip: 32,
            max_storage_bytes: 128 << 30,
            new_identities_per_ip_hour: 10,
            new_devices_per_ip_hour: 30,
            max_users: 1_000_000,
            max_devices: 2_000_000,
        }
    }
}

/// Test-only misbehaviour, used to check that clients detect a lying relay.
#[derive(Debug, Default, Clone)]
pub struct Adversary {
    /// Hide log entries after this seq from every reader.
    pub freeze_log_at: Option<u64>,
    /// Serve listeners with branch > 0 a forked log diverging after this seq.
    pub fork_at: Option<u64>,
    /// Silently drop mailbox deliveries to these (user hex, device) pairs.
    pub drop_mail_to: Vec<(String, u32)>,
    /// Store but hide mail for these devices until removed from the list
    /// (delayed delivery).
    pub hold_mail_to: Vec<(String, u32)>,
    /// Answer every blob download with 404 (a flaky or withholding relay).
    pub hide_blobs: bool,
    /// Serve this user's device list with an extra, unsigned "ghost" device.
    pub ghost_device_for: Option<String>,
    /// Keep serving these snapshots of device lists (hiding revocations and
    /// new devices), and keep revoked devices registered: a relay colluding
    /// with the thief of a revoked device.
    pub frozen_device_lists: HashMap<String, Vec<u8>>,
}

/// Counters and caches kept only in memory, so a seized database holds no
/// record of who did what when. They reset when the relay restarts (which
/// briefly resets the per-device limits; nothing else depends on them).
#[derive(Default)]
struct Volatile {
    /// One-time prekey handouts per device: (hour, count).
    handouts: HashMap<(String, u32), (u64, u64)>,
    /// Request-lane messages per device: (day, count).
    lane: HashMap<(String, u32), (u64, u64)>,
    /// New logs this hour: (hour, count).
    creations: (u64, u64),
    /// Access tokens issued per device: (epoch, count).
    issued: HashMap<(String, u32), (u64, u64)>,
    /// New identities (first device lists) and new device registrations per
    /// address (IPv6: /64) this hour: (hour, count).
    new_ids: HashMap<IpAddr, (u64, u64)>,
    new_devices: HashMap<IpAddr, (u64, u64)>,
}

impl Volatile {
    /// Add `by` to a key's count for the current window.
    fn bump(map: &mut HashMap<(String, u32), (u64, u64)>, key: (String, u32), window: u64, by: u64) {
        let e = map.entry(key).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += by;
    }

    fn get(map: &HashMap<(String, u32), (u64, u64)>, key: &(String, u32), window: u64) -> u64 {
        map.get(key).filter(|e| e.0 == window).map_or(0, |e| e.1)
    }
}

pub struct Relay {
    vol: Mutex<Volatile>,
    /// When this process started. A
    /// signed request from before a restart could be replayed once; such
    /// requests are refused instead (clients just sign a fresh one).
    started_ms: u64,
    /// The relay's public URL as clients use it. Device signatures cover the
    /// origin the client connected to, and are checked against this (never
    /// against the Host header, which a replaying relay controls).
    public_origin: std::sync::OnceLock<String>,
    /// The operator's policy text, shown to users when they register.
    policy: std::sync::OnceLock<String>,
    db: Mutex<Connection>,
    pub adversary: Mutex<Adversary>,
    ttl: Duration,
    pub limits: Limits,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    /// Device-list GETs served (tests check clients don't leak rosters).
    pub device_list_gets: std::sync::atomic::AtomicU64,
    /// Bundle requests for devices that aren't registered (tests check
    /// clients back off instead of retrying on every sync).
    pub bundle_misses: std::sync::atomic::AtomicU64,
    /// Sizes of token issuance requests (tests check they reveal nothing).
    pub issuance_sizes: Mutex<Vec<usize>>,
    /// Per client connection (remote address): whether it carried
    /// device-signed requests and anonymous ones (tests check never both).
    pub connection_kinds: Mutex<HashMap<SocketAddr, (bool, bool)>>,
    /// Record `issuance_sizes` and `connection_kinds` (tests only: they grow
    /// without bound, and the latter maps connections to request kinds).
    instrument: std::sync::atomic::AtomicBool,
    /// Bytes of stored mail (`None`: recount) and of posts in progress.
    mail_bytes: Mutex<(Option<u64>, u64)>,
    buckets_swept: Mutex<Option<Instant>>,
    row_counts: Mutex<HashMap<&'static str, u64>>,
    /// Mail and blob payloads (see `slots`).
    slots: slots::SlotStore,
    /// Bytes of stored blobs (`None`: recount) and of uploads in progress.
    blob_bytes: Mutex<(Option<u64>, u64)>,
}

impl Relay {
    pub fn open(path: &std::path::Path, ttl: Duration, limits: Limits) -> anyhow::Result<Arc<Self>> {
        let mut conn = Connection::open(path)?;
        conn.execute_batch(PRAGMAS)?;
        e2ee_proto::migrate::migrate(&mut conn, "relay", MIGRATIONS)?;
        let used = used_slots(&conn)?;
        let mut dir = path.as_os_str().to_owned();
        dir.push(".slots");
        let slots = slots::SlotStore::open(std::path::Path::new(&dir), &used, limits.max_storage_bytes)?;
        Ok(Self::new(conn, ttl, limits, slots))
    }

    pub fn open_in_memory() -> anyhow::Result<Arc<Self>> {
        Self::open_in_memory_with(Limits::default())
    }

    pub fn open_in_memory_with(limits: Limits) -> anyhow::Result<Arc<Self>> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(PRAGMAS)?;
        e2ee_proto::migrate::migrate(&mut conn, "relay", MIGRATIONS)?;
        let slots = slots::SlotStore::temp(limits.max_storage_bytes)?;
        Ok(Self::new(conn, DEFAULT_TTL, limits, slots))
    }

    fn new(conn: Connection, ttl: Duration, limits: Limits, slots: slots::SlotStore) -> Arc<Self> {
        Arc::new(Self {
            slots,
            vol: Mutex::default(),
            started_ms: now_ms(),
            public_origin: std::sync::OnceLock::new(),
            policy: std::sync::OnceLock::new(),
            db: Mutex::new(conn),
            adversary: Mutex::default(),
            ttl,
            limits,
            buckets: Mutex::default(),
            device_list_gets: Default::default(),
            bundle_misses: Default::default(),
            connection_kinds: Default::default(),
            instrument: Default::default(),
            mail_bytes: Mutex::default(),
            buckets_swept: Mutex::default(),
            row_counts: Mutex::default(),
            blob_bytes: Mutex::default(),
            issuance_sizes: Mutex::default(),
        })
    }

    /// Bytes of all waiting mail, kept as a running count (summing the table
    /// on every post would scan it under the database lock).
    /// Posts in progress count too, kept apart from what's stored (so a
    /// recount of the table never double-counts or drops them).
    fn mail_total(&self, db: &Connection) -> rusqlite::Result<u64> {
        let mut t = self.mail_bytes.lock().unwrap();
        if t.0.is_none() {
            t.0 = Some(db.query_row("SELECT COALESCE(SUM(len), 0) FROM mailbox", [], |r| r.get::<_, i64>(0))? as u64);
        }
        Ok(t.0.unwrap_or(0) + t.1)
    }

    /// A post of `n` bytes passed its checks and is being stored.
    fn mail_reserved(&self, n: u64) {
        self.mail_bytes.lock().unwrap().1 += n;
    }

    /// That post ended: stored, or not.
    fn mail_reservation_done(&self, n: u64, stored: bool) {
        let mut t = self.mail_bytes.lock().unwrap();
        t.1 = t.1.saturating_sub(n);
        if stored && let Some(s) = t.0.as_mut() {
            *s += n;
        }
    }

    fn mail_removed(&self, n: u64) {
        if let Some(t) = self.mail_bytes.lock().unwrap().0.as_mut() {
            *t = t.saturating_sub(n);
        }
    }

    /// Delete the payload rows of `table` (mailbox or blobs) matching `cond`,
    /// then free their slots. Returns the payload bytes freed.
    fn delete_payloads(&self, db: &Connection, table: &str, cond: &str, p: &[&dyn rusqlite::ToSql]) -> anyhow::Result<u64> {
        let refs: Vec<(slots::SlotRef, i64)> = {
            let mut st = db.prepare(&format!("SELECT class, slot, tag, len FROM {table} WHERE {cond}"))?;
            st.query_map(p, |r| Ok((slot_ref(r, 0)?, r.get(3)?)))?.collect::<Result<_, _>>()?
        };
        db.execute(&format!("DELETE FROM {table} WHERE {cond}"), p)?;
        let mut freed = 0;
        for (r, len) in refs {
            self.slots.free(r)?;
            freed += len as u64;
        }
        Ok(freed)
    }

    /// Rows in a table that only the cap checks count, kept in memory
    /// (recounted after each expiry run) so the checks don't scan it under
    /// the database lock. Callers that add a row bump it with `counted`.
    fn count(&self, db: &Connection, table: &'static str) -> rusqlite::Result<u64> {
        let mut c = self.row_counts.lock().unwrap();
        if let Some(n) = c.get(table) {
            return Ok(*n);
        }
        let n = db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))? as u64;
        c.insert(table, n);
        Ok(n)
    }

    fn counted(&self, table: &'static str) {
        if let Some(n) = self.row_counts.lock().unwrap().get_mut(table) {
            *n += 1;
        }
    }

    /// Reserve room for an upload of `len` bytes replacing `old` bytes, if
    /// stored blobs plus uploads in progress stay within the quota. The
    /// reservation ends when the returned guard drops.
    fn reserve_blob(self: &Arc<Self>, db: &Connection, len: u64, old: u64) -> rusqlite::Result<Option<BlobReservation>> {
        let mut b = self.blob_bytes.lock().unwrap();
        if b.0.is_none() {
            b.0 = Some(db.query_row("SELECT COALESCE(SUM(len), 0) FROM blobs", [], |r| r.get::<_, i64>(0))? as u64);
        }
        if b.0.unwrap_or(0).saturating_sub(old) + b.1 + len > self.limits.max_total_blob_bytes {
            return Ok(None);
        }
        b.1 += len;
        Ok(Some(BlobReservation { relay: self.clone(), len }))
    }

    fn blob_stored(&self, added: u64, removed: u64) {
        if let Some(t) = self.blob_bytes.lock().unwrap().0.as_mut() {
            *t = (*t + added).saturating_sub(removed);
        }
    }

    /// Turn on the test-only counters (`issuance_sizes`, `connection_kinds`).
    pub fn enable_test_instrumentation(&self) {
        self.instrument.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn instrumented(&self) -> bool {
        self.instrument.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set the policy text served at `GET /policy` (default: `default_policy`).
    pub fn set_policy(&self, text: String) -> anyhow::Result<()> {
        if text.len() > MAX_POLICY_BYTES {
            anyhow::bail!("policy text is over {MAX_POLICY_BYTES} bytes");
        }
        self.policy.set(text).map_err(|_| anyhow::anyhow!("policy already set"))
    }

    pub fn policy_text(&self) -> String {
        self.policy.get().cloned().unwrap_or_else(|| default_policy(None))
    }

    /// Set the public URL clients use for this relay (scheme, host, port).
    pub fn set_public_url(&self, url: &str) -> anyhow::Result<()> {
        let origin = api::origin_of(url).ok_or_else(|| anyhow::anyhow!("invalid public url {url:?}"))?;
        self.public_origin.set(origin).map_err(|_| anyhow::anyhow!("public url already set"))
    }

    /// The origin signatures must name on a listener at `addr`.
    fn origin_for(&self, scheme: &str, addr: SocketAddr) -> String {
        self.public_origin.get().cloned().unwrap_or_else(|| format!("{scheme}://{addr}"))
    }

    /// Token bucket per client IP.
    fn allow(&self, ip: IpAddr) -> bool {
        let (rate, burst) = (self.limits.rate_per_sec, self.limits.rate_burst);
        if rate <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap();
        // Idle buckets are swept at most once a second (not on every
        // request), so spraying addresses can't make each request scan.
        let mut swept = self.buckets_swept.lock().unwrap();
        if b.len() > 100_000 && swept.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1)) {
            b.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
            *swept = Some(now);
        }
        // Per address, IPv6 per /64 (one host usually has a whole /64).
        let (tokens, last) = b.entry(IpSlot::key(ip)).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * rate).min(burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Expire blobs and undelivered mail without storing when anything
    /// arrived: rows carry the current *generation*, which advances every
    /// half TTL; rows two generations old are deleted. So a row lives between
    /// half a TTL and a full TTL, and reveals only which half it arrived in.
    pub fn gc(&self) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        let half = (self.ttl.as_millis() as u64 / 2).max(1);
        let started: u64 = meta_u64(&db, "gen_started")?.unwrap_or(0);
        let mut generation = meta_u64(&db, "gen")?.unwrap_or(0);
        let now = now_ms();
        if started == 0 {
            set_meta_u64(&db, "gen_started", now)?;
        } else if now.saturating_sub(started) >= half {
            generation += 1;
            set_meta_u64(&db, "gen", generation)?;
            set_meta_u64(&db, "gen_started", now)?;
        }
        let g = generation as i64;
        self.delete_payloads(&db, "blobs", "gen + 1 < ?1", &[&g])?;
        self.blob_bytes.lock().unwrap().0 = None; // recounted on next use
        self.delete_payloads(&db, "mailbox", "gen + 1 < ?1", &[&g])?;
        db.execute("DELETE FROM pmailboxes WHERE gen + 1 < ?1", [g])?;
        self.delete_payloads(&db, "mailbox", "device = 0 AND user NOT IN (SELECT id FROM pmailboxes)", &[])?;
        self.mail_bytes.lock().unwrap().0 = None; // recounted on next use
        // Spent tokens only need remembering while they could still be valid
        // (two days); storing the expiry generation, not the day, keeps less.
        db.execute("DELETE FROM spent_tokens WHERE gen + 1 < ?1", [generation as i64])?;
        // Device lists of users that never registered a device expire.
        db.execute(
            "DELETE FROM device_lists WHERE gen + 1 < ?1 AND user NOT IN (SELECT user FROM device_keys)",
            [generation as i64],
        )?;
        db.execute("DELETE FROM registration_tokens WHERE expires < ?1", [now as i64])?;
        self.row_counts.lock().unwrap().clear(); // recounted on next use
        // Move everything out of the write-ahead log so deleted rows don't
        // linger there either.
        let _ = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        let hour = now / 3_600_000;
        let mut v = self.vol.lock().unwrap();
        v.new_ids.retain(|_, (h, _)| *h == hour);
        v.new_devices.retain(|_, (h, _)| *h == hour);
        drop(v);
        Ok(())
    }

    /// Adversary: put a raw entry on fork `branch` after the current head of
    /// that fork (tests: an entry only some members are shown).
    pub fn append_raw_to_fork_for_tests(&self, rid: &str, branch: u32, make: impl FnOnce(u64, &[u8]) -> Vec<u8>) {
        let db = self.db.lock().unwrap();
        let adv = self.adversary.lock().unwrap().clone();
        let log = visible_log(&db, rid, branch, &adv).map_err(|e| e.1).unwrap();
        let (seq, head) = log.last().map(|e| (e.0, e.2.clone())).unwrap_or((0, ZERO_HASH.to_vec()));
        let entry = make(seq + 1, &head);
        db.execute(
            "INSERT INTO logs (rid, branch, seq, entry, head) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![rid, branch, (seq + 1) as i64, entry, e2ee_proto::log_head(&entry).as_slice()],
        )
        .unwrap();
    }

    /// Advance the expiry generation by hand (tests).
    pub fn advance_generation_for_tests(&self) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        let g = meta_u64(&db, "gen")?.unwrap_or(0);
        set_meta_u64(&db, "gen", g + 1)?;
        Ok(())
    }

    /// Column names of every table (tests check nothing time-like is stored).
    pub fn schema_columns(&self) -> Vec<(String, String)> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").unwrap();
        let tables: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        let mut out = Vec::new();
        for t in tables {
            let mut st = db.prepare(&format!("PRAGMA table_info({t})")).unwrap();
            for c in st.query_map([], |r| r.get::<_, String>(1)).unwrap() {
                out.push((t.clone(), c.unwrap()));
            }
        }
        out
    }

    /// Tables that keep rowids (tests check there are none: rowids record
    /// arrival order).
    pub fn rowid_tables(&self) -> Vec<String> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table'").unwrap();
        st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .filter(|(_, sql)| !sql.contains("WITHOUT ROWID"))
            .map(|(n, _)| n)
            .collect()
    }

    /// Raw log entries of every repo (tests).
    pub fn log_entries_raw(&self) -> Vec<Vec<u8>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT entry FROM logs").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    }

    // -- operator actions --------------------------------------------------


    /// Adversary: freeze every currently stored device list.
    pub fn freeze_device_lists(&self) {
        let rows = self.device_lists_snapshot();
        self.serve_device_lists(rows);
    }

    /// Every currently stored device list (for `serve_device_lists`).
    pub fn device_lists_snapshot(&self) -> HashMap<String, Vec<u8>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT user, signed FROM device_lists").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }

    /// Adversary: from now on serve these (older) lists instead of the
    /// stored ones, and don't act on uploads.
    pub fn serve_device_lists(&self, lists: HashMap<String, Vec<u8>>) {
        self.adversary.lock().unwrap().frozen_device_lists = lists;
    }

    /// Test hook: forget a device's keys, as if it had never registered.
    pub fn drop_device_keys(&self, user_hex: &str, device: u32) {
        let db = self.db.lock().unwrap();
        for t in ["device_keys", "one_time", "one_time_kyber"] {
            db.execute(&format!("DELETE FROM {t} WHERE user = ?1 AND device = ?2"), params![user_hex, device]).unwrap();
        }
    }

    /// Ban a user: drop their device registrations and prekeys, refuse them
    /// from now on, and rotate the access-token seed so every outstanding
    /// token (including theirs) dies; honest clients just get new ones.
    pub fn ban(&self, user: &str) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("INSERT OR IGNORE INTO banned_users (user) VALUES (?1)", [user])?;
        db.execute("DELETE FROM registered_users WHERE user = ?1", [user])?;
        for t in ["device_keys", "one_time", "one_time_kyber"] {
            db.execute(&format!("DELETE FROM {t} WHERE user = ?1"), [user])?;
        }
        // A new key generation: every outstanding token dies at once. The
        // generation number is public, so members can tell this rotation,
        // which everyone sees, from a key shown to one device only.
        let next = token_gen(&db).map_err(|e| anyhow::anyhow!(e.1))? + 1;
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        db.execute("INSERT INTO relay_meta (k, v) VALUES (?1, ?2)", params![format!("token_seed:{next}"), hex::encode(seed)])?;
        db.execute("INSERT OR REPLACE INTO relay_meta (k, v) VALUES ('token_gen', ?1)", [next.to_string()])?;
        self.vol.lock().unwrap().issued.clear();
        Ok(())
    }

    /// Adversary: issue `user`'s access tokens under a key of their own (to
    /// recognize them when spent), and, while `fetches` is set, also answer
    /// anonymous key fetches with it, as a relay that recognizes the
    /// fetching connection would. `None` stops tagging.
    pub fn tag_tokens(&self, user: Option<&str>, fetches: bool) {
        TAGGING.store(true, std::sync::atomic::Ordering::Relaxed);
        let db = self.db.lock().unwrap();
        match user {
            Some(u) => {
                db.execute("INSERT OR REPLACE INTO relay_meta (k, v) VALUES ('adv_tag_user', ?1)", [u]).unwrap();
                db.execute("INSERT OR IGNORE INTO relay_meta (k, v) VALUES ('adv_tag_seed', ?1)", [hex::encode([9u8; 32])]).unwrap();
            }
            None => {
                db.execute("DELETE FROM relay_meta WHERE k = 'adv_tag_user'", []).unwrap();
            }
        }
        db.execute("INSERT OR REPLACE INTO relay_meta (k, v) VALUES ('adv_tag_fetches', ?1)", [if fetches { "1" } else { "0" }]).unwrap();
    }

    /// Lift a ban. On an invite-only relay the user then needs a new token.
    pub fn unban(&self, user: &str) -> anyhow::Result<()> {
        self.db.lock().unwrap().execute("DELETE FROM banned_users WHERE user = ?1", [user])?;
        Ok(())
    }

    /// Issue a single-use registration token valid for `ttl`.
    pub fn issue_registration_token(&self, ttl: Duration) -> anyhow::Result<String> {
        self.issue_invite(ttl, 1)
    }

    /// An invite for up to `uses` different new users: each one's first
    /// registration takes one use; the relay keeps only the count left, not
    /// who used it.
    pub fn issue_invite(&self, ttl: Duration, uses: u32) -> anyhow::Result<String> {
        anyhow::ensure!(uses >= 1, "an invite needs at least one use");
        let mut t = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut t);
        let token = hex::encode(t);
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM registration_tokens WHERE expires < ?1", [now_ms() as i64])?;
        db.execute(
            "INSERT INTO registration_tokens (token_hash, expires, uses_left) VALUES (?1, ?2, ?3)",
            params![hex::encode(e2ee_proto::sha256(token.as_bytes())), (now_ms() + ttl.as_millis() as u64) as i64, uses],
        )?;
        Ok(token)
    }

    /// Number of stored blobs (tests).
    pub fn blob_count(&self) -> usize {
        self.db.lock().unwrap().query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get::<_, i64>(0)).unwrap() as usize
    }

    /// Sizes of queued mail per (user hex, device), for traffic-shape tests.
    pub fn mailbox_sizes(&self) -> HashMap<(String, u32), Vec<usize>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT user, device, len FROM mailbox ORDER BY user, device, seq").unwrap();
        let mut out: HashMap<(String, u32), Vec<usize>> = HashMap::new();
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?, r.get::<_, i64>(2)? as usize)))
            .unwrap();
        for row in rows {
            let (u, d, n) = row.unwrap();
            out.entry((u, d)).or_default().push(n);
        }
        out
    }

    /// Raw dump of every stored byte, for tests asserting no plaintext leaks.
    pub fn dump_all_bytes(&self) -> Vec<u8> {
        let mut out = self.dump_tables(&["device_keys", "one_time", "one_time_kyber", "device_lists", "repos", "repo_tokens", "logs", "blobs", "mailbox"]);
        out.extend(self.slots.dump_for_tests());
        out
    }

    /// Raw dump of the given tables (what a seized database would show).
    pub fn dump_tables(&self, tables: &[&str]) -> Vec<u8> {
        let db = self.db.lock().unwrap();
        let mut out = Vec::new();
        for table in tables {
            let mut st = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let n = st.column_count();
            let mut rows = st.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                for i in 0..n {
                    match r.get_ref(i).unwrap() {
                        rusqlite::types::ValueRef::Blob(b) => out.extend_from_slice(b),
                        rusqlite::types::ValueRef::Text(t) => out.extend_from_slice(t),
                        _ => {}
                    }
                }
            }
        }
        out
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct Ctx {
    relay: Arc<Relay>,
    branch: u32,
    /// Origin device signatures must name (see `Relay::set_public_url`).
    origin: String,
}

mod slots;

pub fn router(relay: Arc<Relay>, branch: u32, origin: String) -> Router {
    // Bodies over a route's limit are refused while being read, before they
    // are buffered: small by default, bigger only where needed.
    // A route's body limit: a declared Content-Length over it is refused
    // before anything is read; an undeclared body is cut off at the limit.
    let limit = |n: usize| {
        let declared = middleware::from_fn(move |req: Request, next: Next| async move {
            let len = req.headers().get(axum::http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
            if len.is_some_and(|l| l > n as u64) {
                return too_large("request body too large").into_response();
            }
            next.run(req).await
        });
        (DefaultBodyLimit::max(n), declared)
    };
    let mail_limit = relay.limits.max_mail_bytes + 4096;
    Router::new()
        .route("/users/{user}/device-list", put(put_device_list).layer(limit(64 << 10)).get(get_device_list))
        .route("/devices/{user}/{device}/keys", post(post_keys).layer(limit(1 << 20)))
        .route("/devices/{user}/{device}/keys/count", get(get_key_count))
        .route("/devices/{user}/{device}/bundle", get(get_bundle))
        .route("/repos/{rid}/log", get(get_log).post(append_log))
        .route("/blobs/{id}", put(put_blob).layer(limit(relay.limits.max_blob_bytes + 4096)).get(get_blob).delete(delete_blob))
        .route("/tokens/{user}/{device}", post(issue_tokens))
        .route("/token-key/{epoch}", get(get_token_key))
        .route("/users/{user}/{device}/delivery-token", put(put_delivery_token))
        .route("/mailbox/{user}/{device}", post(post_mail).layer(limit(mail_limit)).get(get_mail))
        .route("/mailbox/{user}/{device}/{id}", delete(delete_mail))
        .route("/pmail/{id}", put(create_pmail).post(post_pmail).layer(limit(mail_limit)).get(get_pmail).delete(delete_pmailbox))
        .route("/pmail/{id}/{msg}", delete(delete_pmail))
        .layer(middleware::from_fn(protocol_version))
        .route("/info", get(get_info))
        .route("/policy", get(get_policy))
        .layer(DefaultBodyLimit::max(16 << 10))
        .layer(middleware::from_fn(body_rate))
        .layer(middleware::from_fn(deadline))
        .layer(middleware::from_fn_with_state(relay.clone(), rate_limit))
        .with_state(Ctx { relay, branch, origin })
}

/// Every API request names its protocol version; one this relay doesn't
/// speak gets a clear refusal. Responses name ours.
async fn protocol_version(req: Request, next: Next) -> Response {
    let v = req.headers().get(headers::PROTOCOL).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u32>().ok());
    let mut resp = match v {
        None => (StatusCode::BAD_REQUEST, format!("missing {} header", headers::PROTOCOL)).into_response(),
        Some(v) => match e2ee_proto::check_protocol("this client", v) {
            Ok(()) => next.run(req).await,
            Err(e) => (StatusCode::BAD_REQUEST, format!("{e} (relay speaks {}..={})", e2ee_proto::MIN_PROTOCOL_VERSION, e2ee_proto::PROTOCOL_VERSION))
                .into_response(),
        },
    };
    resp.headers_mut().insert(headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.into());
    resp
}

/// The operator's policy, as plain text (shown by `git e2ee register`).
async fn get_policy(State(ctx): State<Ctx>) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], ctx.relay.policy_text())
}

/// Largest policy text a relay serves (clients cut longer ones off).
pub const MAX_POLICY_BYTES: usize = 64 << 10;

/// The policy a relay serves unless its operator provides one: a
/// repeat-infringer policy (which DMCA safe harbors expect providers to adopt
/// and tell users about) and how to reach the operator.
pub fn default_policy(contact: Option<&str>) -> String {
    let contact = match contact {
        Some(c) => format!("Contact: {c}"),
        None => "Contact: the operator of this relay has not published a contact address.".to_string(),
    };
    format!(
        "Policy of this relay\n\n\
         This relay carries end-to-end encrypted git data between its users. Its\n\
         operator cannot read that data.\n\n\
         Repeat infringers: in appropriate circumstances, the operator will suspend\n\
         or terminate (ban) the registration of any user who repeatedly infringes\n\
         copyright or other rights of others. Reports of infringement should name the\n\
         user ID concerned and go to the contact address below.\n\n\
         {contact}\n"
    )
}

/// Every request, body included, must complete in time, so a stalled
/// upload can't hold a connection forever: blob uploads get 30 minutes,
/// everything else a minute.
async fn deadline(req: Request, next: Next) -> Response {
    let blob_put = req.method() == Method::PUT && req.uri().path().starts_with("/blobs/");
    let limit = Duration::from_secs(if blob_put { 30 * 60 } else { 60 });
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request took too long").into_response(),
    }
}

/// Request bodies must keep arriving: at most 10 s without data, and after
/// the first 10 s at least 16 KiB/s on average. Together with the per-
/// address connection cap, a client can't hold connections by trickling.
async fn body_rate(req: Request, next: Next) -> Response {
    use futures_util::StreamExt as _;
    const IDLE: Duration = Duration::from_secs(10);
    const GRACE: Duration = Duration::from_secs(10);
    const MIN_RATE: u64 = 16 << 10;
    let (parts, body) = req.into_parts();
    let start = Instant::now();
    let stream = futures_util::stream::unfold((body.into_data_stream(), 0u64, false), move |(mut st, total, done)| async move {
        if done {
            return None;
        }
        let fail = |what: &str| Some((Err(std::io::Error::new(std::io::ErrorKind::TimedOut, what.to_string())), (st_dummy(), 0, true)));
        match tokio::time::timeout(IDLE, st.next()).await {
            Err(_) => fail("request body stalled"),
            Ok(None) => None,
            Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e)), (st, total, true))),
            Ok(Some(Ok(chunk))) => {
                let total = total + chunk.len() as u64;
                let elapsed = start.elapsed();
                if elapsed > GRACE && total < (elapsed - GRACE).as_secs() * MIN_RATE {
                    return fail("request body too slow");
                }
                Some((Ok(chunk), (st, total, false)))
            }
        }
    });
    next.run(Request::from_parts(parts, axum::body::Body::from_stream(stream))).await
}

fn st_dummy() -> axum::body::BodyDataStream {
    axum::body::Body::empty().into_data_stream()
}

/// What this relay speaks (unauthenticated, unversioned).
async fn get_info(State(ctx): State<Ctx>) -> axum::Json<api::RelayInfo> {
    axum::Json(api::RelayInfo {
        protocol_min: e2ee_proto::MIN_PROTOCOL_VERSION,
        protocol_max: e2ee_proto::PROTOCOL_VERSION,
        software: format!("git-e2ee-relay {}", env!("CARGO_PKG_VERSION")),
        mail_ttl_secs: ctx.relay.ttl.as_secs(),
    })
}

async fn rate_limit(State(relay): State<Arc<Relay>>, req: Request, next: Next) -> Response {
    let forwarded = relay
        .limits
        .trust_forwarded_for
        .then(|| req.headers().get("x-forwarded-for"))
        .flatten()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    if let Some(peer) = peer.filter(|_| relay.instrumented()) {
        let signed = req.headers().contains_key(headers::SIGNATURE);
        let anonymous = req.headers().contains_key(headers::ACCESS) || req.headers().contains_key(headers::TOKEN);
        let mut k = relay.connection_kinds.lock().unwrap();
        let e = k.entry(peer).or_default();
        e.0 |= signed;
        e.1 |= anonymous;
    }
    let ip = forwarded.or_else(|| peer.map(|p| p.ip()));
    if let Some(ip) = ip
        && !relay.allow(ip)
    {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let mut req = req;
    if let Some(ip) = ip {
        req.extensions_mut().insert(ClientIp(ip));
    }
    let before = relay.db.lock().unwrap().total_changes();
    let resp = next.run(req).await;
    // Whatever the method (fetching a bundle or blob spends tokens and may
    // delete a prekey), move any write out of the write-ahead log right away:
    // the WAL keeps rows in arrival order, which the tables deliberately don't.
    let db = relay.db.lock().unwrap();
    if db.total_changes() != before {
        let _ = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }
    drop(db);
    resp
}

/// Serve plaintext HTTP on `listener` (loopback or behind a TLS proxy).
/// `branch` selects which log fork this listener shows
/// when the adversary's `fork_at` is set (0 = the real log).
pub async fn serve(listener: tokio::net::TcpListener, relay: Arc<Relay>, branch: u32) -> anyhow::Result<()> {
    let app = router(relay.clone(), branch, relay.origin_for("http", listener.local_addr()?));
    let limits = relay.limits.clone();
    spawn_gc(relay);
    accept_loop(listener, app, &limits, None).await
}

/// Constant-time equality (for comparing secrets' hashes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A payload row's slot, from columns `at` (class), `at + 1` (slot) and
/// `at + 2` (tag).
fn slot_ref(r: &rusqlite::Row, at: usize) -> rusqlite::Result<slots::SlotRef> {
    Ok(slots::SlotRef { class: r.get(at)?, slot: r.get::<_, i64>(at + 1)? as u64, tag: r.get::<_, i64>(at + 2)? as u64 })
}

/// Every slot the database refers to (all others are free).
fn used_slots(db: &Connection) -> rusqlite::Result<Vec<(u8, u64)>> {
    let mut out = Vec::new();
    for table in ["mailbox", "blobs"] {
        let mut st = db.prepare(&format!("SELECT class, slot FROM {table}"))?;
        for row in st.query_map([], |r| Ok((r.get::<_, u8>(0)?, r.get::<_, i64>(1)? as u64)))? {
            out.push(row?);
        }
    }
    Ok(out)
}

/// The client's address (behind a trusted proxy: the forwarded one).
#[derive(Clone, Copy)]
struct ClientIp(IpAddr);

/// Count one more `what` from this address this hour, if under `max`.
fn per_ip_hourly(relay: &Relay, ip: Option<ClientIp>, max: u64, devices: bool) -> ApiResult<()> {
    let Some(ClientIp(ip)) = ip else { return Ok(()) };
    if ip.is_loopback() {
        return Ok(()); // a local proxy (which limits per client) or tests
    }
    let ip = IpSlot::key(ip);
    let hour = now_ms() / 3_600_000;
    let mut v = relay.vol.lock().unwrap();
    let map = if devices { &mut v.new_devices } else { &mut v.new_ids };
    let e = map.entry(ip).or_insert((hour, 0));
    if e.0 != hour {
        *e = (hour, 0);
    }
    if e.1 >= max {
        return Err(quota(if devices { "too many new devices from this address this hour" } else { "too many new users from this address this hour" }));
    }
    e.1 += 1;
    Ok(())
}

/// Room reserved for a blob upload in progress.
struct BlobReservation {
    relay: Arc<Relay>,
    len: u64,
}

impl Drop for BlobReservation {
    fn drop(&mut self) {
        let mut b = self.relay.blob_bytes.lock().unwrap();
        b.1 = b.1.saturating_sub(self.len);
    }
}

/// One open connection counted against its IP; released on drop.
struct IpSlot {
    map: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl IpSlot {
    /// What counts as one address: IPv4 addresses, and IPv6 /64s (one
    /// customer usually gets a whole /64).
    fn key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
            },
            v4 => v4,
        }
    }

    fn take(map: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, max: usize) -> Option<Self> {
        let ip = Self::key(ip);
        let mut m = map.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Self { map: map.clone(), ip })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap();
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// TLS settings for `serve_tls`.
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// Also accept classical-only key exchange (otherwise X25519MLKEM768 only).
    pub allow_classical: bool,
}

/// Serve over TLS 1.3. Unless `allow_classical`, only the hybrid
/// post-quantum key exchange X25519MLKEM768 is accepted.
pub async fn serve_tls(listener: tokio::net::TcpListener, relay: Arc<Relay>, branch: u32, tls: TlsConfig) -> anyhow::Result<()> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_slice_iter(&tls.cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&tls.key_pem)?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !tls.allow_classical {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // HTTP/1.1 only: its header timeout (below) covers every connection, and
    // clients make one request per anonymous connection anyway.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let app = router(relay.clone(), branch, relay.origin_for("https", listener.local_addr()?));
    let limits = relay.limits.clone();
    spawn_gc(relay);
    accept_loop(listener, app, &limits, Some(acceptor)).await
}

/// Accept connections and serve one HTTP/1.1 request on each (clients use a
/// fresh connection per request anyway). Bounds, so that idle or slow
/// clients can't hold every connection:
/// - concurrent connections, in total and per address (IPv6: per /64).
///   Loopback peers are exempt from the per-address cap: they are a local
///   reverse proxy (which must limit per client itself) or tests.
/// - TLS handshake and request headers: 10 s each, so a connection that
///   hasn't spent a token holds its slot for at most 20 s.
/// - request bodies: see `body_rate`; handlers: see `deadline`.
/// - responses: see `WriteStall`.
/// - the whole connection: `CONNECTION_LIFETIME`.
///
/// Accept errors (e.g. out of file descriptors) pause instead of ending
/// the process.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: &Limits,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> anyhow::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream); // at capacity
            continue;
        };
        let ip_slot = if peer.ip().is_loopback() {
            None
        } else {
            let Some(s) = IpSlot::take(&per_ip, peer.ip(), limits.max_connections_per_ip) else {
                drop(stream);
                continue;
            };
            Some(s)
        };
        let tls = tls.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _slot = (slot, ip_slot);
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                tower::ServiceExt::oneshot(app.clone(), req.map(axum::body::Body::new))
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).keep_alive(false);
            let serve = async {
                match tls {
                    Some(acceptor) => {
                        // Failed or slow handshakes (e.g. classical-only clients) just drop.
                        let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await else { return };
                        let _ = builder.serve_connection(hyper_util::rt::TokioIo::new(WriteStall::new(tls)), svc).await;
                    }
                    None => {
                        let _ = builder.serve_connection(hyper_util::rt::TokioIo::new(WriteStall::new(stream)), svc).await;
                    }
                }
            };
            let _ = tokio::time::timeout(CONNECTION_LIFETIME, serve).await;
        });
    }
}

/// No connection lives longer than this: the longest request (a blob
/// upload, 30 minutes) plus a margin.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(35 * 60);

/// A connection whose writes fail once the peer has stopped reading for
/// `WRITE_STALL`, or reads the response slower than `MIN_SEND_RATE` on
/// average (after `SEND_GRACE`). A slow reader can't hold a slot for long.
struct WriteStall<T> {
    inner: T,
    stalled: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    first_write: Option<Instant>,
    written: u64,
}

const WRITE_STALL: Duration = Duration::from_secs(30);
const SEND_GRACE: Duration = Duration::from_secs(10);
const MIN_SEND_RATE: u64 = 16 << 10;

impl<T> WriteStall<T> {
    fn new(inner: T) -> Self {
        Self { inner, stalled: None, first_write: None, written: 0 }
    }

    fn too_slow(&self) -> bool {
        let Some(t) = self.first_write else { return false };
        let elapsed = t.elapsed();
        elapsed > SEND_GRACE && self.written < (elapsed - SEND_GRACE).as_secs() * MIN_SEND_RATE
    }

    fn check<R>(&mut self, cx: &mut std::task::Context<'_>, r: std::task::Poll<std::io::Result<R>>) -> std::task::Poll<std::io::Result<R>> {
        use std::task::Poll;
        match r {
            Poll::Ready(r) => {
                self.stalled = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let sleep = self.stalled.get_or_insert_with(|| Box::pin(tokio::time::sleep(WRITE_STALL)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Err(std::io::ErrorKind::TimedOut.into())),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WriteStall<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WriteStall<T> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        self.first_write.get_or_insert_with(Instant::now);
        if self.too_slow() {
            return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "client reads too slowly")));
        }
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.written += *n as u64;
        }
        self.check(cx, r)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_flush(cx);
        self.check(cx, r)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run `gc` hourly, off the async runtime.
fn spawn_gc(relay: Arc<Relay>) {
    tokio::spawn(async move {
        loop {
            let r = relay.clone();
            match tokio::task::spawn_blocking(move || r.gc()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("expiry run failed: {e:#}"),
                Err(e) => tracing::warn!("expiry run panicked: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// errors

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

// Internal errors are logged, not sent: clients get a generic message.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        if e.downcast_ref::<slots::Full>().is_some() {
            return quota("the relay's storage is full");
        }
        tracing::error!("internal error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("database error: {e}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn unauthorized(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}
fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not found".into())
}
fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}
fn too_large(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::PAYLOAD_TOO_LARGE, msg.into())
}
fn quota(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INSUFFICIENT_STORAGE, msg.into())
}

fn check_hex_id(s: &str, len: usize) -> ApiResult<()> {
    if s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(bad("malformed id"))
    }
}

// ---------------------------------------------------------------------------
// auth

/// Verify a device-signed request against `identity` (or the stored key).
/// The parts of an HTTP request covered by a device signature.
struct SignedRequest<'a> {
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: &'a [u8],
}

/// Check both request signatures: Curve25519 (`identity`) and ML-DSA (`pq_key`).
fn verify_device_sig(relay: &Relay, origin: &str, req: SignedRequest, user: &str, device: u32, identity: &[u8], pq_key: &[u8]) -> ApiResult<()> {
    let SignedRequest { method, uri, headers, body } = req;
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).ok_or_else(|| unauthorized(format!("missing {n}")));
    if h(headers::USER)? != user || h(headers::DEVICE)?.parse::<u32>().ok() != Some(device) {
        return Err(unauthorized("auth headers do not match path"));
    }
    let time: u64 = h(headers::TIME)?.parse().map_err(|_| unauthorized("bad time"))?;
    if now_ms().abs_diff(time) > api::AUTH_WINDOW_MS {
        return Err(unauthorized("request time outside window"));
    }
    if time < relay.started_ms {
        return Err(unauthorized("request signed before the relay restarted; sign a fresh one"));
    }
    let nonce = h(headers::NONCE)?;
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(unauthorized("bad nonce"));
    }
    let sig = hex::decode(h(headers::SIGNATURE)?).map_err(|_| unauthorized("bad signature encoding"))?;
    let key = IdentityKey::try_from(identity).map_err(|_| unauthorized("bad identity key"))?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or(uri.path());
    let payload = api::auth_payload(origin, method.as_str(), path, time, nonce, body);
    if !key.public_key().verify_signature(&payload, &sig) {
        return Err(unauthorized("bad request signature"));
    }
    let pq_sig = base64::engine::general_purpose::STANDARD.decode(h(headers::PQ_SIGNATURE)?).map_err(|_| unauthorized("bad pq signature encoding"))?;
    if !e2ee_proto::pq::verify(pq_key, e2ee_proto::domain::RELAY_AUTH, &payload, &pq_sig) {
        return Err(unauthorized("bad post-quantum request signature"));
    }
    Ok(())
}

fn is_banned(db: &Connection, user: &str) -> ApiResult<bool> {
    Ok(db.query_row("SELECT 1 FROM banned_users WHERE user = ?1", [user], |_| Ok(())).optional()?.is_some())
}

/// Registered: redeemed an invite, or has a registered device. The second
/// covers users who registered while the relay was open, so turning on
/// `--invite-only` later doesn't lock them out. (A ban deletes a user's
/// devices, so a banned-then-unbanned user needs an invite again.)
fn is_registered(db: &Connection, user: &str) -> ApiResult<bool> {
    Ok(db
        .query_row(
            "SELECT 1 WHERE EXISTS (SELECT 1 FROM registered_users WHERE user = ?1) OR EXISTS (SELECT 1 FROM device_keys WHERE user = ?1)",
            [user],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// May this user use the relay (register devices, post, create repos)?
fn check_user_allowed(ctx: &Ctx, db: &Connection, user: &str) -> ApiResult<()> {
    if is_banned(db, user)? {
        return Err(ApiError(StatusCode::FORBIDDEN, "this user is banned from this relay; contact its operator (the address is in the policy \
             `git e2ee register` shows)".into()));
    }
    if ctx.relay.limits.invite_only && !is_registered(db, user)? {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "this relay is invite-only: register with a token from the operator (git e2ee register <url> --token <token>)".into(),
        ));
    }
    Ok(())
}

/// Take one use of an invite, if it's valid and has any left (the last use
/// deletes it). Only a new user's first registration gets here, so an invite
/// for N uses serves N different users. Nothing records who used it.
fn redeem_invite(db: &Connection, token: &str) -> ApiResult<bool> {
    let th = hex::encode(e2ee_proto::sha256(token.as_bytes()));
    let took = db.execute(
        "UPDATE registration_tokens SET uses_left = uses_left - 1 WHERE token_hash = ?1 AND expires >= ?2 AND uses_left > 0",
        params![th, now_ms() as i64],
    )? > 0;
    db.execute("DELETE FROM registration_tokens WHERE token_hash = ?1 AND uses_left <= 0", [&th])?;
    Ok(took)
}

/// On an invite-only relay, a user's first registration redeems a token.
fn redeem_registration_token(ctx: &Ctx, db: &Connection, user: &str, headers: &HeaderMap) -> ApiResult<()> {
    if !ctx.relay.limits.invite_only || is_registered(db, user)? || is_banned(db, user)? {
        return Ok(());
    }
    let Some(token) = headers.get(headers::REGISTRATION_TOKEN).and_then(|v| v.to_str().ok()) else {
        return Ok(()); // check_user_allowed reports the problem
    };
    if !redeem_invite(db, token)? {
        return Err(ApiError(StatusCode::FORBIDDEN, "registration token is invalid, expired or already used".into()));
    }
    db.execute("INSERT OR IGNORE INTO registered_users (user) VALUES (?1)", [user])?;
    Ok(())
}

fn stored_identity(db: &Connection, user: &str, device: u32) -> ApiResult<Option<Vec<u8>>> {
    Ok(stored_keys(db, user, device)?.map(|k| k.0))
}

/// A registered device's (identity key, ML-DSA key).
fn stored_keys(db: &Connection, user: &str, device: u32) -> ApiResult<Option<(Vec<u8>, Vec<u8>)>> {
    Ok(db
        .query_row(
            "SELECT identity, pq_key FROM device_keys WHERE user = ?1 AND device = ?2",
            params![user, device],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

fn device_auth(ctx: &Ctx, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8], user: &str, device: u32) -> ApiResult<()> {
    let db = ctx.relay.db.lock().unwrap();
    let (id, pq) = stored_keys(&db, user, device)?.ok_or_else(|| unauthorized("unknown device"))?;
    verify_device_sig(&ctx.relay, &ctx.origin, SignedRequest { method, uri, headers, body }, user, device, &id, &pq)?;
    consume_nonce(&db, headers)
}

/// Record a verified request's nonce; a repeat within the auth window is a
/// replay (e.g. by something that sees requests after TLS ends).
fn consume_nonce(db: &Connection, headers: &HeaderMap) -> ApiResult<()> {
    let nonce = headers.get(headers::NONCE).and_then(|v| v.to_str().ok()).ok_or_else(|| unauthorized("missing nonce"))?;
    let time: u64 = headers.get(headers::TIME).and_then(|v| v.to_str().ok()).and_then(|t| t.parse().ok()).ok_or_else(|| unauthorized("bad time"))?;
    // Kept in the database, so a restart doesn't reopen the window for
    // requests captured before it, but only as long as needed: a request is
    // accepted within one window of now, so its slot is now's or a
    // neighbour's, and the slot two away holds only requests too old to
    // accept. That one is cleared, so the table holds about 15 minutes of
    // nonces, whatever the traffic.
    let w = api::AUTH_WINDOW_MS;
    let now_slot = now_ms() / w;
    db.execute("DELETE FROM request_nonces WHERE slot = ?1", [((now_slot + 2) % 4) as i64])?;
    let fresh = db.execute(
        "INSERT OR IGNORE INTO request_nonces (slot, nonce) VALUES (?1, ?2)",
        params![((time / w) % 4) as i64, nonce],
    )?;
    if fresh == 0 {
        return Err(unauthorized("replayed request"));
    }
    Ok(())
}

fn repo_exists(db: &Connection, rid: &str) -> ApiResult<bool> {
    Ok(db.query_row("SELECT 1 FROM repos WHERE rid = ?1", [rid], |_| Ok(())).optional()?.is_some())
}

fn meta_u64(db: &Connection, k: &str) -> rusqlite::Result<Option<u64>> {
    let v: Option<String> = db.query_row("SELECT v FROM relay_meta WHERE k = ?1", [k], |r| r.get(0)).optional()?;
    Ok(v.and_then(|v| v.parse().ok()))
}

fn set_meta_u64(db: &Connection, k: &str, v: u64) -> rusqlite::Result<()> {
    db.execute("INSERT OR REPLACE INTO relay_meta (k, v) VALUES (?1, ?2)", params![k, v.to_string()])?;
    Ok(())
}

/// The current expiry generation stored on new blobs and mail.
fn generation(db: &Connection) -> ApiResult<i64> {
    Ok(meta_u64(db, "gen")?.unwrap_or(0) as i64)
}

/// The current access-token key generation (bumped by every ban).
fn token_gen(db: &Connection) -> ApiResult<u32> {
    Ok(meta_u64(db, "token_gen")?.unwrap_or(0) as u32)
}

/// The secret seed of a key generation (created for generation 0).
fn token_seed_for(db: &Connection, generation: u32) -> ApiResult<Option<Vec<u8>>> {
    let k = format!("token_seed:{generation}");
    let seed: Option<String> = db.query_row("SELECT v FROM relay_meta WHERE k = ?1", [&k], |r| r.get(0)).optional()?;
    if let Some(s) = seed {
        return Ok(Some(hex::decode(s).map_err(|e| anyhow::anyhow!(e))?));
    }
    if generation != 0 {
        return Ok(None);
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
    db.execute("INSERT INTO relay_meta (k, v) VALUES (?1, ?2)", params![k, hex::encode(seed)])?;
    Ok(Some(seed.to_vec()))
}

fn token_seed(db: &Connection) -> ApiResult<Vec<u8>> {
    let generation = token_gen(db)?;
    Ok(token_seed_for(db, generation)?.ok_or_else(|| anyhow::anyhow!("token seed missing"))?)
}

/// Adversary state for `Relay::tag_tokens`: (tagged user, seed, fetches too).
/// Set only by `Relay::tag_tokens` (tests): nothing in a database can turn
/// tagging on, so a production relay never accepts tokens under the test key.
static TAGGING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn token_tagging(db: &Connection) -> ApiResult<(Option<String>, Option<Vec<u8>>, bool)> {
    if !TAGGING.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok((None, None, false));
    }
    let get = |k: &str| -> ApiResult<Option<String>> {
        Ok(db.query_row("SELECT v FROM relay_meta WHERE k = ?1", [k], |r| r.get(0)).optional()?)
    };
    let seed = get("adv_tag_seed")?.and_then(|s| hex::decode(s).ok());
    Ok((get("adv_tag_user")?, seed, get("adv_tag_fetches")?.as_deref() == Some("1")))
}

/// Spend `cost` anonymous access tokens from the request headers. Tokens
/// from today's or yesterday's key are accepted, each at most once.
fn spend(db: &Connection, headers: &HeaderMap, cost: usize) -> ApiResult<()> {
    let tokens: Vec<tokens::Token> = headers
        .get(headers::ACCESS)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').filter_map(tokens::Token::decode).collect())
        .unwrap_or_default();
    if tokens.len() < cost {
        return Err(ApiError(StatusCode::PAYMENT_REQUIRED, format!("this action needs {cost} access token(s)")));
    }
    let seed = token_seed(db)?;
    let tag_seed = token_tagging(db)?.1;
    let now = tokens::epoch_now();
    let mut nonces: Vec<&[u8]> = Vec::new();
    for t in &tokens[..cost] {
        let fresh = t.epoch == now || t.epoch.checked_add(1) == Some(now);
        let valid = tokens::Issuer::new(&seed, t.epoch).check(&t.nonce, &t.output)
            || tag_seed.as_ref().is_some_and(|s| tokens::Issuer::new(s, t.epoch).check(&t.nonce, &t.output));
        if !fresh || !valid || nonces.contains(&t.nonce.as_slice()) {
            return Err(unauthorized("invalid access token"));
        }
        let spent = db.query_row("SELECT 1 FROM spent_tokens WHERE nonce = ?1", [&t.nonce], |_| Ok(())).optional()?.is_some();
        if spent {
            return Err(unauthorized("access token already spent"));
        }
        nonces.push(&t.nonce);
    }
    for t in &tokens[..cost] {
        db.execute("INSERT INTO spent_tokens (nonce, gen) VALUES (?1, ?2)", params![t.nonce, generation(db)?])?;
    }
    Ok(())
}

fn token_auth(db: &Connection, rid: &str, headers: &HeaderMap) -> ApiResult<()> {
    let token = headers
        .get(headers::TOKEN)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| hex::decode(t).ok())
        .ok_or_else(|| unauthorized("missing repo token"))?;
    let th = hex::encode(e2ee_proto::sha256(&token));
    let ok = db
        .query_row("SELECT 1 FROM repo_tokens WHERE rid = ?1 AND token_hash = ?2", params![rid, th], |_| Ok(()))
        .optional()?
        .is_some();
    if ok { Ok(()) } else { Err(unauthorized(api::BAD_REPO_TOKEN)) }
}

// ---------------------------------------------------------------------------
// device lists and keys

async fn put_device_list(
    State(ctx): State<Ctx>,
    Path(user): Path<String>,
    ip: Option<axum::Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    check_hex_id(&user, 64)?;
    // Defense in depth: clients verify lists themselves, but the relay refuses
    // to store lists that are invalid or older than what it has.
    let signed = SignedDeviceList::decode(body.as_ref()).map_err(|_| bad("malformed device list"))?;
    let list = DeviceListBody::decode(signed.body.as_slice()).map_err(|_| bad("malformed device list body"))?;
    if hex::encode(&list.user_id) != user || e2ee_proto::user_id_of(&list.master_key).as_slice() != list.user_id {
        return Err(bad("device list user mismatch"));
    }
    let (classical, _) = e2ee_proto::split_master_id(&list.master_key).ok_or_else(|| bad("bad master key"))?;
    let master = IdentityKey::try_from(classical).map_err(|_| bad("bad master key"))?;
    if signed.verify_pq().is_none() {
        return Err(bad("bad device list post-quantum signature"));
    }
    if !master.public_key().verify_signature(
        &e2ee_proto::signing_input(e2ee_proto::domain::DEVICE_LIST, &signed.body),
        &signed.signature,
    ) {
        return Err(bad("bad device list signature"));
    }
    // At most 127 devices with ids 1..=127 (each device has its own mailbox
    // and keys here), and revoked ones are tombstones only.
    if list.devices.len() > 127 || list.revoked.len() > 127 || list.devices.iter().any(|d| !(1..=127).contains(&d.device_id)) {
        return Err(bad("device list has too many devices or device ids outside 1..=127"));
    }
    let guard = ctx.relay.db.lock().unwrap();
    // One transaction, so a refused list doesn't use up the invite.
    let db = guard.unchecked_transaction()?;
    if is_banned(&db, &user)? {
        return Err(ApiError(StatusCode::FORBIDDEN, "this user is banned from this relay; contact its operator (the address is in the policy \
             `git e2ee register` shows)".into()));
    }
    // On an invite-only relay, a user who isn't registered yet must show a
    // valid invite, which this redeems: no storing lists for anyone who asks,
    // and one invite makes one identity. (The list is signed by the user's
    // master key, so only its owner can redeem for it.) The invite is
    // deleted, so nothing links the user to it.
    if ctx.relay.limits.invite_only && !is_registered(&db, &user)? {
        let token = headers.get(headers::REGISTRATION_TOKEN).and_then(|v| v.to_str().ok()).unwrap_or("");
        if redeem_invite(&db, token)? {
            db.execute("INSERT OR IGNORE INTO registered_users (user) VALUES (?1)", [&user])?;
        } else {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "this relay is invite-only: register with a token from the operator (git e2ee register <url> --token <token>)".into(),
            ));
        }
    }
    let cur: Option<i64> = db
        .query_row("SELECT version FROM device_lists WHERE user = ?1", [&user], |r| r.get(0))
        .optional()?;
    if cur.is_none() {
        // A new identity costs no tokens (it has none yet), so it is bounded
        // per address and in total instead.
        if ctx.relay.count(&db, "device_lists")? >= ctx.relay.limits.max_users {
            return Err(quota("this relay has no room for new users"));
        }
        per_ip_hourly(&ctx.relay, ip.map(|e| e.0), ctx.relay.limits.new_identities_per_ip_hour, false)?;
    }
    if let Some(v) = cur
        && (list.version as i64) < v
    {
        return Err(conflict("older device list"));
    }
    db.execute(
        "INSERT OR REPLACE INTO device_lists (user, version, signed, gen) VALUES (?1, ?2, ?3, ?4)",
        params![user, list.version as i64, body.as_ref(), generation(&db)?],
    )?;
    if cur.is_none() {
        ctx.relay.counted("device_lists");
    }
    if !ctx.relay.adversary.lock().unwrap().frozen_device_lists.is_empty() {
        db.commit()?;
        return Ok(StatusCode::NO_CONTENT);
    }
    // Devices dropped from the list lose their relay registration.
    let ids: Vec<i64> = list.devices.iter().map(|d| d.device_id as i64).collect();
    let mut st = db.prepare("SELECT device FROM device_keys WHERE user = ?1")?;
    let have: Vec<i64> = st.query_map([&user], |r| r.get(0))?.collect::<Result<_, _>>()?;
    for d in have.into_iter().filter(|d| !ids.contains(d)) {
        db.execute("DELETE FROM device_keys WHERE user = ?1 AND device = ?2", params![user, d])?;
        db.execute("DELETE FROM one_time WHERE user = ?1 AND device = ?2", params![user, d])?;
        db.execute("DELETE FROM one_time_kyber WHERE user = ?1 AND device = ?2", params![user, d])?;
    }
    drop(st);
    db.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_device_list(State(ctx): State<Ctx>, Path(user): Path<String>) -> ApiResult<Vec<u8>> {
    check_hex_id(&user, 64)?;
    ctx.relay.device_list_gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db = ctx.relay.db.lock().unwrap();
    let signed: Vec<u8> = db
        .query_row("SELECT signed FROM device_lists WHERE user = ?1", [&user], |r| r.get(0))
        .optional()?
        .ok_or_else(not_found)?;
    if let Some(frozen) = ctx.relay.adversary.lock().unwrap().frozen_device_lists.get(&user) {
        return Ok(frozen.clone());
    }
    if ctx.relay.adversary.lock().unwrap().ghost_device_for.as_deref() == Some(user.as_str()) {
        return Ok(add_ghost_device(&signed));
    }
    Ok(signed)
}

/// Adversary: append a device the user never signed, keeping the old signature.
fn add_ghost_device(signed: &[u8]) -> Vec<u8> {
    let mut s = SignedDeviceList::decode(signed).unwrap();
    let mut body = DeviceListBody::decode(s.body.as_slice()).unwrap();
    let ghost = libsignal_protocol::IdentityKeyPair::generate(&mut rand::rng());
    body.devices.push(e2ee_proto::DeviceEntry {
        device_id: 99,
        identity_key: ghost.identity_key().serialize().to_vec(),
        added_at_ms: 0,
        pq_key_hash: vec![0; 32],
        kem_key_hash: vec![0; 32],
        max_protocol: e2ee_proto::PROTOCOL_VERSION,
        added_in: 0,
    });
    s.body = body.encode_to_vec();
    s.encode_to_vec()
}

async fn post_keys(
    State(ctx): State<Ctx>,
    Path((user, device)): Path<(String, u32)>,
    ip: Option<axum::Extension<ClientIp>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    check_hex_id(&user, 64)?;
    let up: api::KeyUpload = serde_json::from_slice(&body).map_err(|e| bad(e.to_string()))?;
    // Keys have fixed sizes (Curve25519: 33 bytes, Kyber1024: 1569, XEdDSA
    // signatures: 64); refuse anything bigger rather than store it.
    // Likewise the device's own keys (Curve25519, ML-DSA-87: 2592 bytes,
    // Kyber1024), which are kept for as long as the device is registered.
    let signed_ok = |k: &api::SignedKey| k.public.len() <= 1600 && k.signature.len() <= 64;
    if up.identity_key.len() > 33
        || up.pq_key.len() > 2600
        || up.kem_auth_key.len() > 1600
        || up.one_time.iter().any(|k| k.public.len() > 33)
        || !up.kyber_one_time.iter().all(signed_ok)
        || !up.signed_prekey.iter().all(signed_ok)
        || !up.kyber_prekey.iter().all(signed_ok)
    {
        return Err(bad("oversized prekey"));
    }
    let db = ctx.relay.db.lock().unwrap();
    // Only devices in the user's master-signed device list may register, so
    // nobody can squat device slots or mailboxes for another user.
    if !device_listed(&db, &user, device, &up.identity_key, &up.pq_key, &up.kem_auth_key)? {
        return Err(unauthorized("device is not in the user's signed device list (publish it first)"));
    }
    let req = SignedRequest { method: &method, uri: &uri, headers: &headers, body: &body };
    verify_device_sig(&ctx.relay, &ctx.origin, req, &user, device, &up.identity_key, &up.pq_key)?;
    consume_nonce(&db, &headers)?;
    redeem_registration_token(&ctx, &db, &user, &headers)?;
    check_user_allowed(&ctx, &db, &user)?;
    let existing = stored_keys(&db, &user, device)?;
    match existing {
        Some((id, pq)) if id != up.identity_key || pq != up.pq_key => {
            return Err(conflict("device already registered with another key"));
        }
        Some(_) => {}
        None => {
            let (Some(spk), Some(kpk)) = (&up.signed_prekey, &up.kyber_prekey) else {
                return Err(bad("first registration needs signed and kyber prekeys"));
            };
            // Registering costs no tokens (a new device has none), so new
            // devices are bounded per address and in total.
            if ctx.relay.count(&db, "device_keys")? >= ctx.relay.limits.max_devices {
                return Err(quota("this relay has no room for new devices"));
            }
            per_ip_hourly(&ctx.relay, ip.map(|e| e.0), ctx.relay.limits.new_devices_per_ip_hour, true)?;
            db.execute(
                "INSERT INTO device_keys (user, device, identity, pq_key, kem_key, registration, signed_prekey, kyber_prekey) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![user, device, up.identity_key, up.pq_key, up.kem_auth_key, up.registration_id, serde_json::to_string(spk).unwrap(), serde_json::to_string(kpk).unwrap()],
            )?;
            ctx.relay.counted("device_keys");
        }
    }
    if let Some(spk) = &up.signed_prekey {
        db.execute("UPDATE device_keys SET signed_prekey = ?3 WHERE user = ?1 AND device = ?2", params![user, device, serde_json::to_string(spk).unwrap()])?;
    }
    if let Some(kpk) = &up.kyber_prekey {
        db.execute("UPDATE device_keys SET kyber_prekey = ?3 WHERE user = ?1 AND device = ?2", params![user, device, serde_json::to_string(kpk).unwrap()])?;
    }
    let count = |table: &str| -> rusqlite::Result<u64> {
        db.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE user = ?1 AND device = ?2"), params![user, device], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    };
    let max = ctx.relay.limits.max_one_time_keys;
    if count("one_time")? + up.one_time.len() as u64 > max || count("one_time_kyber")? + up.kyber_one_time.len() as u64 > max {
        return Err(quota(format!("at most {max} one-time prekeys of each kind per device")));
    }
    for k in &up.one_time {
        db.execute(
            "INSERT OR REPLACE INTO one_time (user, device, id, public) VALUES (?1, ?2, ?3, ?4)",
            params![user, device, k.id, k.public],
        )?;
    }
    for k in &up.kyber_one_time {
        db.execute(
            "INSERT OR REPLACE INTO one_time_kyber (user, device, id, key) VALUES (?1, ?2, ?3, ?4)",
            params![user, device, k.id, serde_json::to_string(k).unwrap()],
        )?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Whether `identity` and the ML-DSA key `pq_key` are listed for (user,
/// device) in the stored signed list. The list's signatures were checked
/// against its master key on upload.
fn device_listed(db: &Connection, user: &str, device: u32, identity: &[u8], pq_key: &[u8], kem_key: &[u8]) -> ApiResult<bool> {
    let signed: Option<Vec<u8>> = db
        .query_row("SELECT signed FROM device_lists WHERE user = ?1", [user], |r| r.get(0))
        .optional()?;
    let Some(signed) = signed else { return Ok(false) };
    let list = SignedDeviceList::decode(signed.as_slice())
        .ok()
        .and_then(|s| DeviceListBody::decode(s.body.as_slice()).ok())
        .ok_or_else(|| bad("stored device list is corrupt"))?;
    let pq_hash = e2ee_proto::pq::key_hash(pq_key);
    let kem_hash = e2ee_proto::kem_key_hash(kem_key);
    Ok(list.devices.iter().any(|d| {
        d.device_id == device && d.identity_key == identity && d.pq_key_hash == pq_hash && d.kem_key_hash == kem_hash
    }))
}

async fn get_key_count(
    State(ctx): State<Ctx>,
    Path((user, device)): Path<(String, u32)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<axum::Json<api::KeyCount>> {
    device_auth(&ctx, &method, &uri, &headers, b"", &user, device)?;
    let db = ctx.relay.db.lock().unwrap();
    let count = |table: &str| -> rusqlite::Result<u64> {
        db.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE user = ?1 AND device = ?2"), params![user, device], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    };
    Ok(axum::Json(api::KeyCount { one_time: count("one_time")?, kyber_one_time: count("one_time_kyber")? }))
}

/// Hand out a prekey bundle. Only registered devices may ask (access
/// token), and one-time keys are handed out at most
/// `max_one_time_handouts_per_hour` times per target device; beyond that the
/// bundle carries only the signed and last-resort keys. So nobody can drain a
/// device's one-time keys faster than that.
async fn get_bundle(State(ctx): State<Ctx>, Path((user, device)): Path<(String, u32)>, headers: HeaderMap) -> ApiResult<axum::Json<api::Bundle>> {
    let db = ctx.relay.db.lock().unwrap();
    let hour = now_ms() / 3_600_000;
    let key = (user.clone(), device);
    let handed = Volatile::get(&ctx.relay.vol.lock().unwrap().handouts, &key, hour);
    let allow_one_time = handed < ctx.relay.limits.max_one_time_handouts_per_hour;
    type KeysRow = (Vec<u8>, u32, String, String, Vec<u8>);
    let row: Option<KeysRow> = db
        .query_row(
            "SELECT identity, registration, signed_prekey, kyber_prekey, kem_key FROM device_keys WHERE user = ?1 AND device = ?2",
            params![user, device],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((identity_key, registration_id, spk, kpk, kem_auth_key)) = row else {
        ctx.relay.bundle_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(not_found());
    };
    // Charge only once the request can succeed.
    spend(&db, &headers, api::cost::BUNDLE)?;
    let ot: Option<(u32, Vec<u8>)> = if allow_one_time {
        db.query_row(
            "SELECT id, public FROM one_time WHERE user = ?1 AND device = ?2 ORDER BY id LIMIT 1",
            params![user, device],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    } else {
        None
    };
    if let Some((id, _)) = &ot {
        db.execute("DELETE FROM one_time WHERE user = ?1 AND device = ?2 AND id = ?3", params![user, device, id])?;
    }
    // Prefer a one-time Kyber key; fall back to the last-resort one.
    let okyber: Option<(u32, String)> = if allow_one_time {
        db.query_row(
            "SELECT id, key FROM one_time_kyber WHERE user = ?1 AND device = ?2 ORDER BY id LIMIT 1",
            params![user, device],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    } else {
        None
    };
    if allow_one_time && (ot.is_some() || okyber.is_some()) {
        Volatile::bump(&mut ctx.relay.vol.lock().unwrap().handouts, key, hour, 1);
    }
    let kpk = match okyber {
        Some((id, key)) => {
            db.execute("DELETE FROM one_time_kyber WHERE user = ?1 AND device = ?2 AND id = ?3", params![user, device, id])?;
            key
        }
        None => kpk,
    };
    Ok(axum::Json(api::Bundle {
        identity_key,
        registration_id,
        signed_prekey: serde_json::from_str(&spk).map_err(|e| anyhow::anyhow!(e))?,
        kyber_prekey: serde_json::from_str(&kpk).map_err(|e| anyhow::anyhow!(e))?,
        one_time: ot.map(|(id, public)| api::OneTimeKey { id, public }),
        kem_auth_key,
    }))
}

// ---------------------------------------------------------------------------
// repos, tokens, log



/// The log as seen through this listener: (seq, entry bytes, head).
/// A stored log row: (seq, entry bytes, head).
type LogRow = (u64, Vec<u8>, Vec<u8>);

fn visible_log(db: &Connection, rid: &str, branch: u32, adv: &Adversary) -> ApiResult<Vec<LogRow>> {
    let mut st = db.prepare("SELECT seq, entry, head FROM logs WHERE rid = ?1 AND branch = ?2 ORDER BY seq")?;
    let mut read = |b: u32| -> ApiResult<Vec<LogRow>> {
        Ok(st
            .query_map(params![rid, b], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?)
    };
    let mut log = read(0)?;
    if branch > 0
        && let Some(f) = adv.fork_at
    {
        log.retain(|e| e.0 <= f);
        log.extend(read(branch)?.into_iter().filter(|e| e.0 > f));
    }
    Ok(log)
}

fn log_branch_for_write(branch: u32, seq: u64, adv: &Adversary) -> u32 {
    match adv.fork_at {
        Some(f) if branch > 0 && seq > f => branch,
        _ => 0,
    }
}

#[derive(serde::Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
}

async fn get_log(State(ctx): State<Ctx>, Path(rid): Path<String>, Query(q): Query<Since>, headers: HeaderMap) -> ApiResult<axum::Json<api::LogEntries>> {
    check_hex_id(&rid, 32)?;
    let db = ctx.relay.db.lock().unwrap();
    // A repo whose first entry was never appended simply has an empty log.
    if !repo_exists(&db, &rid)? {
        return Ok(axum::Json(api::LogEntries { entries: vec![] }));
    }
    token_auth(&db, &rid, &headers)?;
    let adv = ctx.relay.adversary.lock().unwrap().clone();
    let entries = visible_log(&db, &rid, ctx.branch, &adv)?
        .into_iter()
        .filter(|e| e.0 > q.since && adv.freeze_log_at.is_none_or(|f| e.0 <= f))
        .map(|e| e.1)
        .collect();
    Ok(axum::Json(api::LogEntries { entries }))
}
/// Append with compare-and-swap: the entry must extend the current head.
async fn append_log(State(ctx): State<Ctx>, Path(rid): Path<String>, headers: HeaderMap, body: Bytes) -> ApiResult<axum::Json<api::AppendResult>> {
    check_hex_id(&rid, 32)?;
    // Entries are small and fixed in shape; anything else is refused (logs
    // are kept for good, so they mustn't be a place to store data).
    let entry = LogEntry::decode(body.as_ref()).map_err(|_| bad("malformed log entry"))?;
    if body.len() > 256 || entry.prev_head.len() != 32 || entry.commitment.len() != 32 || entry.nonce.len() > 32 {
        return Err(bad("malformed log entry"));
    }
    let guard = ctx.relay.db.lock().unwrap();
    // One transaction: the token swap, the charge and the entry happen
    // together or not at all (a crash in between can't leave the repo
    // without a token).
    let db = guard.unchecked_transaction()?;
    let existed = repo_exists(&db, &rid)?;
    // Counted once the transaction commits.
    let mut creation = None;
    if existed {
        token_auth(&db, &rid, &headers)?;
    } else {
        // The first append creates the log. It is authorized only by
        // anonymous access tokens, so the relay never learns who created
        // the repo; the repo token presented becomes the log's token.
        if entry.seq != 1 || entry.prev_head != ZERO_HASH {
            return Err(conflict("log is at seq 0"));
        }
        let token = headers
            .get(headers::TOKEN)
            .and_then(|v| v.to_str().ok())
            .and_then(|t| hex::decode(t).ok())
            .ok_or_else(|| bad("first append must carry the repo token"))?;
        if hex::encode(e2ee_proto::repo_id_for_token(&token)) != rid {
            return Err(ApiError(StatusCode::FORBIDDEN, "repo id is not derived from this repo token".into()));
        }
        let hour = now_ms() / 3_600_000;
        let created = { let c = ctx.relay.vol.lock().unwrap().creations; if c.0 == hour { c.1 } else { 0 } };
        if created >= ctx.relay.limits.max_new_logs_per_hour {
            return Err(quota("too many new repos this hour on this relay"));
        }
        // Charge only once every check passed.
        spend(&db, &headers, api::cost::LOG_CREATE)?;
        creation = Some((hour, created + 1));
        db.execute("INSERT INTO repos (rid) VALUES (?1)", [&rid])?;
        db.execute(
            "INSERT INTO repo_tokens (rid, token_hash) VALUES (?1, ?2)",
            params![rid, hex::encode(e2ee_proto::sha256(&token))],
        )?;
    }
    let adv = ctx.relay.adversary.lock().unwrap().clone();
    let log = visible_log(&db, &rid, ctx.branch, &adv)?;
    let (cur_seq, cur_head) = log.last().map(|e| (e.0, e.2.clone())).unwrap_or((0, ZERO_HASH.to_vec()));
    if entry.seq != cur_seq + 1 || entry.prev_head != cur_head {
        return Err(conflict(format!("log is at seq {cur_seq}")));
    }
    if existed {
        // Charged only once the append will succeed (a lost race is free).
        spend(&db, &headers, api::cost::LOG_APPEND)?;
        // A rotation: the repo's token is replaced in the same step as this
        // append, so it happens exactly when the append wins the race. There
        // is never more than one token, so nothing planted can outlive it.
        if let Some(h) = headers.get(headers::REPLACE_TOKEN).and_then(|v| v.to_str().ok()) {
            check_hex_id(h, 64)?;
            db.execute("DELETE FROM repo_tokens WHERE rid = ?1", [&rid])?;
            db.execute("INSERT INTO repo_tokens (rid, token_hash) VALUES (?1, ?2)", params![rid, h])?;
        }
    }
    let head = e2ee_proto::log_head(&body);
    db.execute(
        "INSERT INTO logs (rid, branch, seq, entry, head) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![rid, log_branch_for_write(ctx.branch, entry.seq, &adv), entry.seq as i64, body.as_ref(), head.as_slice()],
    )?;
    db.commit()?;
    if let Some(c) = creation {
        ctx.relay.vol.lock().unwrap().creations = c;
    }
    Ok(axum::Json(api::AppendResult { seq: entry.seq, head: hex::encode(head) }))
}
// ---------------------------------------------------------------------------
// blobs

/// Store a blob in the global store (access tokens). The header carries the
/// hash of a delete token derived from the pack key.
async fn put_blob(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap, body: axum::body::Body) -> ApiResult<StatusCode> {
    check_hex_id(&id, 32)?;
    let delete_hash = headers
        .get(headers::BLOB_DELETE_HASH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| bad("missing blob delete hash"))?;
    check_hex_id(&delete_hash, 64)?;
    // Check and charge from the declared length *before* reading the body,
    // so a large upload costs its tokens up front (and nothing is buffered
    // for someone without them). The body must then be exactly that long.
    let len: usize = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| ApiError(StatusCode::LENGTH_REQUIRED, "blob uploads need a Content-Length".into()))?;
    let _reservation = {
        let db = ctx.relay.db.lock().unwrap();
        if len > ctx.relay.limits.max_blob_bytes {
            return Err(too_large("blob too large"));
        }
        // Blob ids are random; refuse to overwrite someone else's blob.
        let existing: Option<(String, i64)> = db
            .query_row("SELECT delete_hash, len FROM blobs WHERE id = ?1", [&id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        if existing.as_ref().is_some_and(|(h, _)| *h != delete_hash) {
            return Err(conflict("blob id in use"));
        }
        // Counted with uploads still in progress, so concurrent uploads
        // can't together overshoot the quota.
        let old = existing.map(|e| e.1 as u64).unwrap_or(0);
        let Some(r) = ctx.relay.reserve_blob(&db, len as u64, old)? else {
            return Err(quota("relay blob storage is full"));
        };
        spend(&db, &headers, api::cost::blob_put(len))?;
        r
    };
    // Streamed into a slot as it arrives, so an upload holds one piece in
    // memory, not the blob, and never holds the database while it waits.
    // Until complete no row names it, so nothing can ask for it.
    // (Allocating may grow a file: on a blocking thread.)
    let partial = {
        let (relay, id, dh) = (ctx.relay.clone(), id.clone(), delete_hash.clone());
        tokio::task::spawn_blocking(move || PartialBlob::create(&relay, &id, &dh, len))
            .await
            .map_err(|e| anyhow::anyhow!("blob upload: {e}"))??
    };
    // Shared with the blocking writes; if the upload is cut off, the last of
    // them to finish drops it, which frees its slot.
    let partial = Arc::new(partial);
    let mut stream = body.into_data_stream();
    let (mut buf, mut written) = (Vec::with_capacity(PIECE), 0usize);
    loop {
        use futures_util::StreamExt as _;
        let chunk = stream.next().await.transpose().map_err(|_| bad("blob upload cut off"))?;
        if let Some(c) = &chunk {
            if written + buf.len() + c.len() > len {
                return Err(bad("blob body longer than its Content-Length"));
            }
            buf.extend_from_slice(c);
        }
        if buf.len() >= PIECE || (chunk.is_none() && !buf.is_empty()) {
            let (p, piece, at) = (partial.clone(), std::mem::replace(&mut buf, Vec::with_capacity(PIECE)), written);
            written += piece.len();
            tokio::task::spawn_blocking(move || p.write_at(at, &piece)).await.map_err(|e| anyhow::anyhow!("blob upload: {e}"))??;
        }
        if chunk.is_none() {
            break;
        }
    }
    if written != len {
        return Err(bad("blob body shorter than its Content-Length"));
    }
    let partial = Arc::try_unwrap(partial).map_err(|_| anyhow::anyhow!("blob upload still being written"))?;
    let old = tokio::task::spawn_blocking(move || partial.finish()).await.map_err(|e| anyhow::anyhow!("blob upload: {e}"))??;
    ctx.relay.blob_stored(len as u64, old);
    Ok(StatusCode::NO_CONTENT)
}

/// Blobs are written and read in pieces of this size.
const PIECE: usize = 64 << 10;

/// A blob upload in progress: its slot is freed unless `finish`ed.
struct PartialBlob {
    relay: Arc<Relay>,
    slot: slots::SlotRef,
    len: usize,
    id: String,
    delete_hash: String,
    done: bool,
}

impl PartialBlob {
    fn create(relay: &Arc<Relay>, id: &str, delete_hash: &str, len: usize) -> ApiResult<Self> {
        let slot = relay.slots.alloc(len as u64)?;
        Ok(Self { relay: relay.clone(), slot, len, id: id.to_string(), delete_hash: delete_hash.to_string(), done: false })
    }

    fn write_at(&self, at: usize, data: &[u8]) -> ApiResult<()> {
        Ok(self.relay.slots.write_at(self.slot, at as u64, data)?)
    }

    /// Publish under the real id, replacing the owner's older upload.
    /// Returns the bytes that replaced.
    fn finish(mut self) -> ApiResult<u64> {
        // On disk before any row names it.
        self.relay.slots.sync(self.slot)?;
        let old = {
            let guard = self.relay.db.lock().unwrap();
            let db = guard.unchecked_transaction()?;
            // Someone else's upload to the same id may have finished first.
            let old: Option<(String, slots::SlotRef, i64)> = db
                .query_row("SELECT delete_hash, class, slot, tag, len FROM blobs WHERE id = ?1", [&self.id], |r| {
                    Ok((r.get(0)?, slot_ref(r, 1)?, r.get(4)?))
                })
                .optional()?;
            if old.as_ref().is_some_and(|(h, _, _)| *h != self.delete_hash) {
                return Err(conflict("blob id in use"));
            }
            db.execute("DELETE FROM blobs WHERE id = ?1", [&self.id])?;
            db.execute(
                "INSERT INTO blobs (id, class, slot, tag, len, delete_hash, gen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![self.id, self.slot.class, self.slot.slot as i64, self.slot.tag as i64, self.len as i64, self.delete_hash, generation(&db)?],
            )?;
            db.commit()?;
            old
        };
        self.done = true;
        let Some((_, slot, len)) = old else { return Ok(0) };
        self.relay.slots.free(slot)?;
        Ok(len as u64)
    }
}

impl Drop for PartialBlob {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.relay.slots.free(self.slot);
        }
    }
}

/// Download a blob, streamed out of the database 64 KiB at a time: a slow
/// reader holds one piece in memory, not the blob. The token is spent before
/// any of the data is read.
async fn get_blob(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<Response> {
    if ctx.relay.adversary.lock().unwrap().hide_blobs {
        return Err(not_found());
    }
    check_hex_id(&id, 32)?;
    let (slot, len) = {
        let db = ctx.relay.db.lock().unwrap();
        let row: (slots::SlotRef, i64) = db
            .query_row("SELECT class, slot, tag, len FROM blobs WHERE id = ?1", [&id], |r| Ok((slot_ref(r, 0)?, r.get(3)?)))
            .optional()?
            .ok_or_else(not_found)?;
        spend(&db, &headers, api::cost::BLOB_GET)?;
        row
    };
    // Read from the slot without the database: a slow download holds
    // neither the lock nor more than one piece.
    let relay = ctx.relay.clone();
    let pieces = futures_util::stream::unfold(0usize, move |at| {
        let relay = relay.clone();
        async move {
            if at >= len as usize {
                return None;
            }
            let piece = tokio::task::spawn_blocking(move || -> anyhow::Result<Bytes> {
                // The tag check refuses a slot freed (and maybe reused)
                // since: never another blob's data.
                let buf = relay.slots.read_at(slot, at as u64, PIECE)?.ok_or_else(|| anyhow::anyhow!("blob deleted while downloading"))?;
                anyhow::ensure!(!buf.is_empty(), "blob shorter than recorded");
                Ok(Bytes::from(buf))
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
            match piece {
                Ok(p) => {
                    let next = at + p.len();
                    Some((Ok::<_, std::io::Error>(p), next))
                }
                // Ends the response early: the client sees a cut-off body.
                Err(e) => Some((Err(std::io::Error::other(e.to_string())), usize::MAX)),
            }
        }
    });
    Ok(([(axum::http::header::CONTENT_LENGTH, len.to_string())], axum::body::Body::from_stream(pieces)).into_response())
}
/// Delete a blob: requires the delete token whose hash was set at upload.
async fn delete_blob(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let token = headers
        .get(headers::BLOB_DELETE_TOKEN)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| hex::decode(t).ok())
        .ok_or_else(|| unauthorized("missing blob delete token"))?;
    let db = ctx.relay.db.lock().unwrap();
    let th = hex::encode(e2ee_proto::sha256(&token));
    let freed = ctx.relay.delete_payloads(&db, "blobs", "id = ?1 AND delete_hash = ?2", &[&id, &th])?;
    ctx.relay.blob_stored(0, freed);
    Ok(StatusCode::NO_CONTENT)
}
// ---------------------------------------------------------------------------
// access tokens, delivery tokens and mailboxes

/// Issue anonymous access tokens to a registered device, within its daily
/// budget. The relay sees how many tokens a device takes, never which
/// tokens are later spent by whom.
async fn issue_tokens(
    State(ctx): State<Ctx>,
    Path((user, device)): Path<(String, u32)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<axum::Json<api::TokenResponse>> {
    device_auth(&ctx, &method, &uri, &headers, &body, &user, device)?;
    let req: api::TokenRequest = serde_json::from_slice(&body).map_err(|e| bad(e.to_string()))?;
    let db = ctx.relay.db.lock().unwrap();
    check_user_allowed(&ctx, &db, &user)?;
    let epoch = tokens::epoch_now();
    if req.epoch != epoch {
        return Err(bad("tokens are only issued for the current epoch"));
    }
    if req.blinded.is_empty() || req.blinded.len() > 500 {
        return Err(bad("request between 1 and 500 tokens"));
    }
    // The budget is per user (however many devices it lists), per day and
    // key generation: a ban starts a new generation, so it also resets what
    // the running relay counted, even when done from the CLI.
    let key = (user.clone(), 0u32);
    let window = (epoch << 20) | token_gen(&db)? as u64;
    let issued = Volatile::get(&ctx.relay.vol.lock().unwrap().issued, &key, window);
    if issued + req.blinded.len() as u64 > ctx.relay.limits.access_tokens_per_day {
        return Err(quota("daily access-token budget used up"));
    }
    let generation = token_gen(&db)?;
    let issuer = match token_tagging(&db)? {
        (Some(u), Some(seed), _) if u == user => tokens::Issuer::new(&seed, epoch),
        _ => tokens::Issuer::new(&token_seed(&db)?, epoch),
    };
    let (evaluations, proof) = issuer.issue(&req.blinded).ok_or_else(|| bad("malformed blinded elements"))?;
    if ctx.relay.instrumented() {
        ctx.relay.issuance_sizes.lock().unwrap().push(req.blinded.len());
    }
    Volatile::bump(&mut ctx.relay.vol.lock().unwrap().issued, key, window, req.blinded.len() as u64);
    Ok(axum::Json(api::TokenResponse { evaluations, proof, public_key: issuer.public_key(), generation }))
}

/// The token key for an epoch, fetched anonymously so clients can check the
/// relay used the same key for them as for everyone.
/// The access-token public key for an epoch: of the current generation, or
/// of `?gen=N` (any past or current generation), so members can check each
/// other's keys.
async fn get_token_key(
    State(ctx): State<Ctx>,
    Path(epoch): Path<u64>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<axum::Json<api::TokenKey>> {
    let db = ctx.relay.db.lock().unwrap();
    let now = tokens::epoch_now();
    if epoch != now && epoch.checked_add(1) != Some(now) {
        return Err(not_found());
    }
    let current = token_gen(&db)?;
    let generation = match q.get("gen") {
        Some(g) => g.parse::<u32>().map_err(|_| bad("bad generation"))?,
        None => current,
    };
    if generation > current {
        return Err(not_found());
    }
    let seed = match token_tagging(&db)? {
        (_, Some(seed), true) if generation == current => seed,
        _ => token_seed_for(&db, generation)?.ok_or_else(not_found)?,
    };
    Ok(axum::Json(api::TokenKey { public_key: tokens::Issuer::new(&seed, epoch).public_key(), generation, current }))
}

/// Register the hash of a user's delivery token (any registered device of
/// that user). Mail presenting the token goes to the normal lane.
async fn put_delivery_token(
    State(ctx): State<Ctx>,
    Path((user, device)): Path<(String, u32)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    device_auth(&ctx, &method, &uri, &headers, &body, &user, device)?;
    let req: api::DeliveryTokenHash = serde_json::from_slice(&body).map_err(|e| bad(e.to_string()))?;
    check_hex_id(&req.token_hash, 64)?;
    let db = ctx.relay.db.lock().unwrap();
    check_user_allowed(&ctx, &db, &user)?;
    db.execute(
        "INSERT OR REPLACE INTO delivery_tokens (user, token_hash) VALUES (?1, ?2)",
        params![user, req.token_hash],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deliver a sealed-sender message, paid for with an anonymous access token.
/// With the recipient user's delivery token it goes to the normal lane;
/// without it (first contact, or a stranger) only into a small daily request
/// lane. The relay learns neither the sender nor the repo.
async fn post_mail(State(ctx): State<Ctx>, Path((user, device)): Path<(String, u32)>, headers: HeaderMap, body: Bytes) -> ApiResult<StatusCode> {
    if admit_mail(&ctx, &user, device, &headers, &body)? {
        store_mail(&ctx.relay, &user, device, body).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The checks and the charge for `post_mail`, with the database held (and
/// let go before the payload is written). False: drop it (test adversary).
fn admit_mail(ctx: &Ctx, user: &String, device: u32, headers: &HeaderMap, body: &Bytes) -> ApiResult<bool> {
    let db = ctx.relay.db.lock().unwrap();
    if stored_identity(&db, user, device)?.is_none() {
        return Err(not_found());
    }
    if body.len() > ctx.relay.limits.max_mail_bytes {
        return Err(too_large("message too large"));
    }
    let stored: Option<String> =
        db.query_row("SELECT token_hash FROM delivery_tokens WHERE user = ?1", [&user], |r| r.get(0)).optional()?;
    let presented = headers
        .get(headers::DELIVERY)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| hex::decode(t).ok())
        .map(|t| hex::encode(e2ee_proto::sha256(&t)));
    let authorized = matches!((&stored, &presented), (Some(s), Some(p)) if ct_eq(s.as_bytes(), p.as_bytes()));
    let day = now_ms() / 86_400_000;
    let key = (user.clone(), device);
    if !authorized {
        let n = Volatile::get(&ctx.relay.vol.lock().unwrap().lane, &key, day);
        if n >= ctx.relay.limits.request_lane_per_day {
            return Err(quota("request lane full: this recipient takes few messages from senders without its delivery token"));
        }
    }
    let queued: i64 = db.query_row(
        "SELECT COUNT(*) FROM mailbox WHERE user = ?1 AND device = ?2",
        params![user, device],
        |r| r.get(0),
    )?;
    if queued as u64 >= ctx.relay.limits.max_mailbox_messages {
        return Err(quota("mailbox full"));
    }
    if ctx.relay.mail_total(&db)? + body.len() as u64 > ctx.relay.limits.max_total_mail_bytes {
        return Err(quota("the relay's mail storage is full"));
    }
    // Every check passed: only now charge the token and count the request.
    spend(&db, headers, api::cost::mail(body.len()))?;
    if !authorized {
        Volatile::bump(&mut ctx.relay.vol.lock().unwrap().lane, key, day, 1);
    }
    if ctx.relay.adversary.lock().unwrap().drop_mail_to.iter().any(|(u, d)| u == user && *d == device) {
        return Ok(false);
    }
    // Counted against the total before the lock goes, so concurrent posts
    // can't together pass it.
    ctx.relay.mail_reserved(body.len() as u64);
    Ok(true)
}

/// Read a device's mailbox (device-authenticated), oldest first. Messages
/// stay until explicitly deleted, so a crash never loses one.
/// One page of a mailbox, after `after` (a mailbox seq): at most
/// `MAIL_PAGE_BYTES` (but at least one message), so a full mailbox is
/// never loaded at once.
/// `mail_page`, on a blocking thread (it reads up to a page of payloads).
async fn mail_page_blocking(relay: &Arc<Relay>, user: String, device: u32, q: HashMap<String, String>) -> ApiResult<api::Mailbox> {
    let relay = relay.clone();
    tokio::task::spawn_blocking(move || {
        let db = relay.db.lock().unwrap();
        mail_page(&relay, db, &user, device, &q)
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("mail page: {e}")))?
}

/// The rows come from `db`, which is released before the payloads are read.
fn mail_page(relay: &Relay, db: std::sync::MutexGuard<'_, Connection>, user: &str, device: u32, q: &HashMap<String, String>) -> ApiResult<api::Mailbox> {
    let after: i64 = q.get("after").map(|a| a.parse().map_err(|_| bad("bad cursor"))).transpose()?.unwrap_or(0);
    let rows: Vec<(i64, String, slots::SlotRef, i64)> = {
        let mut st = db.prepare(
            "SELECT seq, id, class, slot, tag, len FROM mailbox WHERE user = ?1 AND device = ?2 AND seq > ?3 ORDER BY seq LIMIT 1001",
        )?;
        st.query_map(params![user, device, after], |r| Ok((r.get(0)?, r.get(1)?, slot_ref(r, 2)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?
    };
    drop(db);
    let (mut messages, mut bytes, mut next, mut lost) = (Vec::new(), 0usize, None, Vec::new());
    for (i, (_, id, slot, len)) in rows.iter().enumerate() {
        if i > 0 && (i == 1000 || bytes + *len as usize > api::MAIL_PAGE_BYTES) {
            next = Some(rows[i - 1].0 as u64);
            break;
        }
        match relay.slots.read(*slot, *len as u64)? {
            Some(data) => {
                bytes += data.len();
                messages.push(api::MailboxMessage { id: id.clone(), data });
            }
            // Deleted meanwhile (fine), or its write never reached the disk
            // before a crash: then the row is useless, and goes.
            None => lost.push(id.clone()),
        }
    }
    if !lost.is_empty() {
        let db = relay.db.lock().unwrap();
        for id in lost {
            if db.execute("DELETE FROM mailbox WHERE id = ?1 AND user = ?2 AND device = ?3", params![id, user, device])? > 0 {
                tracing::warn!("dropped a mail row whose content was lost (a crash before it reached the disk?)");
            }
        }
    }
    Ok(api::Mailbox { messages, next })
}

/// Put a message in a mailbox: payload into a random slot, then its row.
/// The caller has done the checks and reserved the bytes (`mail_reserved`),
/// and holds no lock. All of it runs on one blocking thread, start to finish:
/// it holds no async worker, and completes (or cleans up after itself) even
/// if the client goes away meanwhile, so no slot or reservation is stranded.
async fn store_mail(relay: &Arc<Relay>, user: &str, device: u32, body: Bytes) -> ApiResult<()> {
    let (relay, user) = (relay.clone(), user.to_string());
    tokio::task::spawn_blocking(move || store_mail_now(&relay, &user, device, &body))
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("mail store: {e}")))?
}

/// Ends the post's reservation in every case; on success while still
/// holding the database that inserted the row, so a recount (which runs under
/// it) sees either the reservation or the row, never both.
fn store_mail_now(relay: &Relay, user: &str, device: u32, body: &[u8]) -> ApiResult<()> {
    let len = body.len() as u64;
    let r = match relay.slots.alloc(len) {
        Ok(r) => r,
        Err(e) => {
            relay.mail_reservation_done(len, false);
            return Err(e.into());
        }
    };
    if let Err(e) = relay.slots.write_at(r, 0, body).and_then(|()| relay.slots.sync(r)) {
        let _ = relay.slots.free(r);
        relay.mail_reservation_done(len, false);
        return Err(e.into());
    }
    let db = relay.db.lock().unwrap();
    let stored = db.execute(
        "INSERT INTO mailbox (user, device, seq, id, class, slot, tag, len, gen) VALUES (?1, ?2,
         (SELECT COALESCE(MAX(seq), 0) + 1 FROM mailbox WHERE user = ?1 AND device = ?2), ?3, ?4, ?5, ?6, ?7, ?8)",
        params![user, device, hex::encode(rand::random::<[u8; 16]>()), r.class, r.slot as i64, r.tag as i64, body.len() as i64, generation(&db)?],
    );
    if let Err(e) = stored {
        let _ = relay.slots.free(r);
        relay.mail_reservation_done(len, false);
        return Err(e.into());
    }
    relay.mail_reservation_done(len, true);
    drop(db);
    Ok(())
}

async fn get_mail(
    State(ctx): State<Ctx>,
    Path((user, device)): Path<(String, u32)>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<axum::Json<api::Mailbox>> {
    device_auth(&ctx, &method, &uri, &headers, b"", &user, device)?;
    if ctx.relay.adversary.lock().unwrap().hold_mail_to.iter().any(|(u, d)| *u == user && *d == device) {
        return Ok(axum::Json(api::Mailbox { messages: vec![], next: None }));
    }
    Ok(axum::Json(mail_page_blocking(&ctx.relay, user, device, q).await?))
}

async fn delete_mail(
    State(ctx): State<Ctx>,
    Path((user, device, id)): Path<(String, u32, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    device_auth(&ctx, &method, &uri, &headers, b"", &user, device)?;
    let db = ctx.relay.db.lock().unwrap();
    let freed = ctx.relay.delete_payloads(&db, "mailbox", "id = ?1 AND user = ?2 AND device = ?3", &[&id, &user, &device])?;
    ctx.relay.mail_removed(freed);
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Pseudonymous mailboxes: addressed by a random id only members of one repo
// know, read with a secret, never with a device signature. So the relay sees
// mail to "mailbox 3f9c…", not to a user, and can't link one device's
// mailboxes for different repos from what it stores. Messages live in the
// `mailbox` table under (id, device 0).

fn pmail_key_ok(db: &Connection, id: &str, headers: &HeaderMap) -> ApiResult<()> {
    let presented = headers
        .get(headers::MAILBOX_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|k| hex::decode(k).ok())
        .map(|k| hex::encode(e2ee_proto::sha256(&k)))
        .ok_or_else(|| unauthorized("missing mailbox key"))?;
    let stored: Option<String> =
        db.query_row("SELECT key_hash FROM pmailboxes WHERE id = ?1", [id], |r| r.get(0)).optional()?;
    match stored {
        None => Err(not_found()),
        Some(h) if ct_eq(h.as_bytes(), presented.as_bytes()) => Ok(()),
        Some(_) => Err(unauthorized("wrong mailbox key")),
    }
}

/// Create a pseudonymous mailbox (anonymous, one access token).
async fn create_pmail(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<StatusCode> {
    check_hex_id(&id, 32)?;
    let key = headers
        .get(headers::MAILBOX_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|k| hex::decode(k).ok())
        .filter(|k| k.len() == 32)
        .ok_or_else(|| bad("missing or malformed mailbox key"))?;
    let db = ctx.relay.db.lock().unwrap();
    if db.query_row("SELECT 1 FROM pmailboxes WHERE id = ?1", [&id], |_| Ok(())).optional()?.is_some() {
        return Err(conflict("mailbox exists"));
    }
    let n: i64 = db.query_row("SELECT COUNT(*) FROM pmailboxes", [], |r| r.get(0))?; // indexed count, cheap
    if n as u64 >= ctx.relay.limits.max_pmailboxes {
        return Err(quota("the relay has too many mailboxes"));
    }
    spend(&db, &headers, api::cost::MAIL)?;
    db.execute(
        "INSERT INTO pmailboxes (id, key_hash, gen) VALUES (?1, ?2, ?3)",
        params![id, hex::encode(e2ee_proto::sha256(&key)), generation(&db)?],
    )?;
    Ok(StatusCode::CREATED)
}

/// Post to a pseudonymous mailbox (anonymous, one access token). Knowing the
/// random address is what members have; no delivery token is needed.
async fn post_pmail(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap, body: Bytes) -> ApiResult<StatusCode> {
    if admit_pmail(&ctx, &id, &headers, &body)? {
        store_mail(&ctx.relay, &id, 0, body).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The checks and the charge for `post_pmail` (see `admit_mail`).
fn admit_pmail(ctx: &Ctx, id: &String, headers: &HeaderMap, body: &Bytes) -> ApiResult<bool> {
    check_hex_id(id, 32)?;
    let db = ctx.relay.db.lock().unwrap();
    if db.query_row("SELECT 1 FROM pmailboxes WHERE id = ?1", [&id], |_| Ok(())).optional()?.is_none() {
        return Err(not_found());
    }
    if body.len() > ctx.relay.limits.max_mail_bytes {
        return Err(too_large("message too large"));
    }
    let queued: i64 = db.query_row("SELECT COUNT(*) FROM mailbox WHERE user = ?1 AND device = 0", [&id], |r| r.get(0))?;
    if queued as u64 >= ctx.relay.limits.max_mailbox_messages {
        return Err(quota("mailbox full"));
    }
    if ctx.relay.mail_total(&db)? + body.len() as u64 > ctx.relay.limits.max_total_mail_bytes {
        return Err(quota("the relay's mail storage is full"));
    }
    spend(&db, headers, api::cost::mail(body.len()))?;
    if ctx.relay.adversary.lock().unwrap().drop_mail_to.iter().any(|(u, d)| u == id && *d == 0) {
        return Ok(false);
    }
    ctx.relay.mail_reserved(body.len() as u64);
    Ok(true)
}

/// Read a pseudonymous mailbox (with its key), oldest first. Reading keeps
/// the mailbox alive; one nobody reads expires.
async fn get_pmail(
    State(ctx): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult<axum::Json<api::Mailbox>> {
    check_hex_id(&id, 32)?;
    {
        let db = ctx.relay.db.lock().unwrap();
        pmail_key_ok(&db, &id, &headers)?;
        db.execute("UPDATE pmailboxes SET gen = ?2 WHERE id = ?1", params![id, generation(&db)?])?;
    }
    if ctx.relay.adversary.lock().unwrap().hold_mail_to.iter().any(|(u, d)| *u == id && *d == 0) {
        return Ok(axum::Json(api::Mailbox { messages: vec![], next: None }));
    }
    Ok(axum::Json(mail_page_blocking(&ctx.relay, id, 0, q).await?))
}

async fn delete_pmail(State(ctx): State<Ctx>, Path((id, msg)): Path<(String, String)>, headers: HeaderMap) -> ApiResult<StatusCode> {
    check_hex_id(&id, 32)?;
    let db = ctx.relay.db.lock().unwrap();
    pmail_key_ok(&db, &id, &headers)?;
    let freed = ctx.relay.delete_payloads(&db, "mailbox", "id = ?1 AND user = ?2 AND device = 0", &[&msg, &id])?;
    ctx.relay.mail_removed(freed);
    Ok(StatusCode::NO_CONTENT)
}

/// Retire a pseudonymous mailbox and anything still in it.
async fn delete_pmailbox(State(ctx): State<Ctx>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<StatusCode> {
    check_hex_id(&id, 32)?;
    let db = ctx.relay.db.lock().unwrap();
    pmail_key_ok(&db, &id, &headers)?;
    let freed = ctx.relay.delete_payloads(&db, "mailbox", "user = ?1 AND device = 0", &[&id])?;
    db.execute("DELETE FROM pmailboxes WHERE id = ?1", [&id])?;
    ctx.relay.mail_removed(freed);
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database in a prototype version-1 shape (two-slot repo tokens,
    /// bound invites, blobs from before delete tokens) migrates: invites
    /// survive, the rest is rebuilt in the new shape.
    #[test]
    fn prototype_databases_migrate() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(
            "DROP TABLE repo_tokens;
             CREATE TABLE repo_tokens (rid TEXT NOT NULL, token_hash TEXT NOT NULL, current INTEGER NOT NULL, PRIMARY KEY (rid, token_hash)) WITHOUT ROWID;
             INSERT INTO repo_tokens VALUES ('r', 't', 1);
             DROP TABLE registration_tokens;
             CREATE TABLE registration_tokens (token_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL, bound_to TEXT) WITHOUT ROWID;
             INSERT INTO registration_tokens VALUES ('i', 5, NULL);
             DROP TABLE blobs;
             CREATE TABLE blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL, gen INTEGER NOT NULL) WITHOUT ROWID;
             INSERT INTO blobs VALUES ('b', x'0102', 0);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        e2ee_proto::migrate::migrate(&mut conn, "relay", MIGRATIONS).unwrap();
        let one = |q: &str| conn.query_row(q, [], |r| r.get::<_, String>(0)).unwrap();
        assert_eq!(one("SELECT token_hash FROM registration_tokens"), "i");
        conn.execute("INSERT INTO repo_tokens (rid, token_hash) VALUES ('r2', 't2')", []).unwrap();
        conn.execute("INSERT INTO blobs (id, class, slot, tag, len, delete_hash, gen) VALUES ('b2', 0, 7, 1, 1, 'h', 0)", []).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    /// Seen nonces are in the database: a replay is refused even after a
    /// restart.
    #[test]
    fn replays_are_refused_across_restarts() {
        let dir = std::env::temp_dir().join(format!("e2ee-relay-nonce-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.sqlite");
        let mut h = HeaderMap::new();
        h.insert(headers::NONCE, "ab".repeat(16).parse().unwrap());
        h.insert(headers::TIME, now_ms().to_string().parse().unwrap());
        {
            let r = Relay::open(&path, DEFAULT_TTL, Limits::default()).unwrap();
            let db = r.db.lock().unwrap();
            consume_nonce(&db, &h).unwrap();
            assert!(consume_nonce(&db, &h).is_err());
        }
        let r = Relay::open(&path, DEFAULT_TTL, Limits::default()).unwrap();
        assert!(consume_nonce(&r.db.lock().unwrap(), &h).is_err(), "replay accepted after a restart");
        // Nonces of requests too old to accept are cleared: the table stays small.
        let mut old = HeaderMap::new();
        old.insert(headers::NONCE, "cd".repeat(16).parse().unwrap());
        old.insert(headers::TIME, (now_ms() - 3 * api::AUTH_WINDOW_MS).to_string().parse().unwrap());
        let db = r.db.lock().unwrap();
        db.execute("INSERT INTO request_nonces (slot, nonce) VALUES (?1, 'x')", [((now_ms() / api::AUTH_WINDOW_MS + 2) % 4) as i64]).unwrap();
        consume_nonce(&db, &old).unwrap();
        let stale: i64 = db.query_row("SELECT COUNT(*) FROM request_nonces WHERE nonce = 'x'", [], |r| r.get(0)).unwrap();
        assert_eq!(stale, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// New identities are bounded per address (IPv6 per /64) and hour.
    #[test]
    fn new_identities_are_bounded_per_address() {
        let r = Relay::open_in_memory().unwrap();
        let ip = |s: &str| Some(ClientIp(s.parse().unwrap()));
        for i in 0..r.limits.new_identities_per_ip_hour {
            per_ip_hourly(&r, ip(&format!("2001:db8::{i}")), r.limits.new_identities_per_ip_hour, false).unwrap();
        }
        assert!(per_ip_hourly(&r, ip("2001:db8::ffff"), r.limits.new_identities_per_ip_hour, false).is_err());
        per_ip_hourly(&r, ip("2001:db9::1"), r.limits.new_identities_per_ip_hour, false).unwrap();
        per_ip_hourly(&r, ip("::1"), 0, false).unwrap(); // loopback: a local proxy
    }

    /// Users who registered a device while the relay was open stay
    /// registered when it becomes invite-only; strangers don't get in.
    #[test]
    fn turning_on_invite_only_keeps_existing_users() {
        let r = Relay::open_in_memory_with(Limits { invite_only: true, ..Default::default() }).unwrap();
        let db = r.db.lock().unwrap();
        db.execute(
            "INSERT INTO device_keys (user, device, identity, pq_key, kem_key, registration) VALUES ('old', 1, x'01', x'02', x'03', 1)",
            [],
        )
        .unwrap();
        assert!(is_registered(&db, "old").unwrap());
        assert!(!is_registered(&db, "new").unwrap());
    }

    #[test]
    fn connection_caps_group_ipv6_by_64() {
        let key = |s: &str| IpSlot::key(s.parse().unwrap());
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:192.0.2.1"), key("192.0.2.1"));
        assert_ne!(key("192.0.2.1"), key("192.0.2.2"));
    }
}
