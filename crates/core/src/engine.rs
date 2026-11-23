//! Replication: turning the relay's log and mailboxes into a verified repo
//! view, and pushes into encrypted packs plus pairwise envelopes.

use anyhow::{Context, Result, anyhow, bail};
use e2ee_proto::envelope::Body;
use e2ee_proto::{
    Ack, DeviceRef, Envelope, Heartbeat, HistoryBundle, HistoryClaim, HistoryRequest, LogEntry, PushLogEntry, Member, Message, Push, RefEntry, ResendRequest,
    Roster, RosterChange, SignedDeviceList, ZERO_HASH, log_head, log_kind, push_view, recipients_hash,
    roster_hash, roster_view, sha256, log_commitment,
};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};

use crate::client::{Append, DeviceAuth, RelayClient};
use e2ee_proto::api;
use e2ee_proto::tokens::{self, Token};
use crate::device::{Device, KYBER_ONE_TIME_BATCH, ONE_TIME_BATCH, ONE_TIME_LOW_WATER, short};
use crate::git::{self, Git};
use crate::pqauth::PqIn;
use crate::{now_ms, pack};

#[derive(Clone, PartialEq, prost::Message)]
pub struct RefList {
    #[prost(message, repeated, tag = "1")]
    pub refs: Vec<RefEntry>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RecipientList {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub users: Vec<Vec<u8>>,
    #[prost(uint32, repeated, tag = "2")]
    pub devices: Vec<u32>,
}

/// A decrypted envelope waiting in the inbox: (message id, sender user, sender device, envelope).
type InboxItem = (String, Vec<u8>, u32, Envelope);
/// A device as (user id, device id).
type DeviceAddr = (Vec<u8>, u32);

/// Locally verified state of one repo.
#[derive(Debug, Clone)]
pub struct RepoState {
    pub relay_url: String,
    pub roster: Roster,
    pub seq: u64,
    pub head: Vec<u8>,
    pub view: Vec<u8>,
    pub refs: Vec<RefEntry>,
    pub head_ref: String,
    pub conflict: Option<String>,
    pub last_heartbeat_ms: u64,
    pub last_log_at_ms: u64,
}

/// Outcome of a sync, for user-facing reporting.
#[derive(Debug, Default)]
pub struct SyncReport {
    pub applied: u64,
    /// A log entry whose envelope has not arrived yet.
    pub waiting_for: Option<u64>,
    /// Things that need attention.
    pub warnings: Vec<String>,
    /// Information (good news, explanations).
    pub notes: Vec<String>,
    /// Why this device is behind and what to do, if it is stuck.
    pub behind: Option<String>,
}

pub fn parse_url(url: &str) -> Result<(String, Vec<u8>)> {
    let url = url.strip_prefix("e2ee::").unwrap_or(url).trim_end_matches('/');
    let (base, rid) = url.rsplit_once('/').ok_or_else(|| anyhow!("remote url must be <relay-url>/<repo-id>"))?;
    let rid = hex::decode(rid).ok().filter(|r| r.len() == 16).ok_or_else(|| anyhow!("bad repo id in url"))?;
    Ok((base.to_string(), rid))
}

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

fn failpoint(name: &str) {
    if cfg!(debug_assertions) && std::env::var("E2EE_FAILPOINT").ok().as_deref() == Some(name) {
        eprintln!("e2ee: failpoint {name} hit, aborting");
        std::process::exit(99);
    }
}

pub struct Engine {
    pub dev: Device,
    /// Bare SHA-256 repo holding every object of the verified view.
    pub mirror: Git,
    pub relay: RelayClient,
    pub relay_url: String,
    pub repo_id: Vec<u8>,
    pub rid: String,
    /// Operator-issued token for this user's first registration on an
    /// invite-only relay.
    pub registration_token: Option<String>,
    /// Entries were applied since our last ack.
    pending_ack: bool,
    /// This sync follows an absence longer than the relay keeps mail.
    long_absence: bool,
    /// The relay accepts none of our repo tokens: it was rotated in a
    /// membership change we never got (or we were removed).
    token_lost: bool,
    /// Keep a local log of who pushed what (`git config e2ee.pushLog false`
    /// turns it off).
    pub push_log: bool,
}

impl Engine {
    pub fn new(dev: Device, url: &str) -> Result<Self> {
        let (relay_url, repo_id) = parse_url(url)?;
        let rid = hex::encode(&repo_id);
        // Created on first use (see `mirror()`), so read-only commands like
        // `status` leave no trace.
        let mirror = Git::new(crate::store::account_dir(&relay_url)?.join("mirrors").join(format!("{rid}.git")));
        Ok(Self {
            relay: RelayClient::new(&relay_url)?,
            mirror,
            rid,
            relay_url,
            repo_id,
            dev,
            registration_token: None,
            pending_ack: false,
            long_absence: false,
            token_lost: false,
            push_log: true,
        })
    }

    pub fn url(&self) -> String {
        format!("{}/{}", self.relay_url, self.rid)
    }

    fn auth(&self) -> DeviceAuth<'_> {
        DeviceAuth { user_hex: hex::encode(&self.dev.user), device_id: self.dev.device_id, identity: &self.dev.identity, pq_seed: &self.dev.pq_seed }
    }

    fn db(&self) -> &rusqlite::Connection {
        self.dev.db.conn()
    }

    // -- repo state persistence ---------------------------------------------

    pub fn state(&self) -> Result<Option<RepoState>> {
        self.db()
            .query_row(
                "SELECT relay_url, roster, seq, head, view, refs, head_ref, conflict, last_heartbeat_ms, last_log_at_ms FROM repos WHERE repo_id = ?1",
                [&self.repo_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, i64>(8)?,
                        r.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?
            .map(|(relay_url, roster, seq, head, view, refs, head_ref, conflict, hb, la)| {
                Ok(RepoState {
                    relay_url,
                    roster: Roster::decode(roster.as_slice())?,
                    seq: seq as u64,
                    head,
                    view,
                    refs: RefList::decode(refs.as_slice())?.refs,
                    head_ref,
                    conflict,
                    last_heartbeat_ms: hb as u64,
                    last_log_at_ms: la as u64,
                })
            })
            .transpose()
    }

    pub fn require_state(&self) -> Result<RepoState> {
        self.state()?.ok_or_else(|| anyhow!("this device has no state for repo {}", self.rid))
    }

    fn save_state(&self, s: &RepoState) -> Result<()> {
        self.db().execute(
            "INSERT INTO repos (repo_id, relay_url, roster, seq, head, view, refs, head_ref, conflict, last_heartbeat_ms, last_log_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(repo_id) DO UPDATE SET relay_url = excluded.relay_url, roster = excluded.roster,
               seq = excluded.seq, head = excluded.head, view = excluded.view, refs = excluded.refs, head_ref = excluded.head_ref,
               conflict = excluded.conflict, last_heartbeat_ms = excluded.last_heartbeat_ms, last_log_at_ms = excluded.last_log_at_ms",
            params![
                self.repo_id,
                s.relay_url,
                s.roster.encode_to_vec(),
                s.seq as i64,
                s.head,
                s.view,
                RefList { refs: s.refs.clone() }.encode_to_vec(),
                s.head_ref,
                s.conflict,
                s.last_heartbeat_ms as i64,
                s.last_log_at_ms as i64,
            ],
        )?;
        self.db().execute(
            "INSERT OR REPLACE INTO history (repo_id, seq, view, head) VALUES (?1, ?2, ?3, ?4)",
            params![self.repo_id, s.seq as i64, s.view, s.head],
        )?;
        Ok(())
    }

    fn set_conflict(&self, msg: String) -> Result<()> {
        self.db().execute(
            "UPDATE repos SET conflict = COALESCE(conflict, ?2) WHERE repo_id = ?1",
            params![self.repo_id, msg],
        )?;
        Ok(())
    }

    pub fn clear_conflict(&self) -> Result<()> {
        self.db().execute("UPDATE repos SET conflict = NULL WHERE repo_id = ?1", [&self.repo_id])?;
        Ok(())
    }

    fn add_secret(&self, secret: &[u8]) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO repo_secrets (repo_id, secret, added) VALUES (?1, ?2, ?3)",
            params![self.repo_id, secret, now_ms() as i64],
        )?;
        Ok(())
    }

    /// Candidate delivery tokens, newest first: known secrets plus secrets in
    /// not-yet-applied roster changes (the token may have been rotated).
    fn tokens(&self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        if let Some(s) = self.state()? {
            out.push(e2ee_proto::delivery_token(&s.roster.repo_secret).to_vec());
        }
        // Only from members: a contact's message mustn't pick which token
        // we present to the relay.
        let members: Vec<Vec<u8>> = self.state()?.map(|s| s.roster.members.into_iter().map(|m| m.user_id).collect()).unwrap_or_default();
        for (_, sender, _, env) in self.inbox()? {
            if !members.contains(&sender) {
                continue;
            }
            match env.body {
                Some(Body::RosterChange(RosterChange { roster: Some(r), .. })) => {
                    out.insert(0, e2ee_proto::delivery_token(&r.repo_secret).to_vec());
                }
                Some(Body::HistoryBundle(HistoryBundle { roster: Some(r), .. })) => {
                    out.push(e2ee_proto::delivery_token(&r.repo_secret).to_vec());
                }
                _ => {}
            }
        }
        let mut st = self.db().prepare("SELECT secret FROM repo_secrets WHERE repo_id = ?1 ORDER BY added DESC")?;
        for s in st.query_map([&self.repo_id], |r| r.get::<_, Vec<u8>>(0))? {
            out.push(e2ee_proto::delivery_token(&s?).to_vec());
        }
        out.dedup();
        Ok(out)
    }

    fn token(&self) -> Result<Vec<u8>> {
        let s = self.require_state()?;
        Ok(e2ee_proto::delivery_token(&s.roster.repo_secret).to_vec())
    }

    fn inbox(&self) -> Result<Vec<InboxItem>> {
        let mut st = self.db().prepare(
            "SELECT msg_id, sender_user, sender_device, envelope FROM inbox WHERE repo_id = ?1 ORDER BY rowid",
        )?;
        let rows = st.query_map([&self.repo_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)? as u32, r.get::<_, Vec<u8>>(3)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, u, d, e) = row?;
            out.push((id, u, d, Envelope::decode(e.as_slice())?));
        }
        Ok(out)
    }

    fn delete_inbox(&self, msg_id: &str) -> Result<()> {
        self.db().execute("DELETE FROM inbox WHERE repo_id = ?1 AND msg_id = ?2", params![self.repo_id, msg_id])?;
        Ok(())
    }

    fn history_at(&self, seq: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .db()
            .query_row(
                "SELECT view, head FROM history WHERE repo_id = ?1 AND seq = ?2",
                params![self.repo_id, seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    // -- registration and device lists ---------------------------------------

    /// Publish our device list and prekeys to this relay, topping up
    /// one-time prekeys when they run low.
    pub async fn ensure_registered(&mut self) -> Result<()> {
        // Upload our list; if the relay has a newer one (the master device
        // added or revoked a device), take it: so every device of ours learns
        // of the change on its next sync, not only from messages of the
        // device that made it. (The upload already tells the relay we're
        // active, so the fetch reveals nothing more.)
        if let Some(own) = self.dev.db.signed_device_list(&self.dev.user)?
            && self.relay.put_device_list_with_token(&hex::encode(&self.dev.user), &own, self.registration_token.as_deref()).await?
            && let Some(bytes) = self.relay.get_device_list(&hex::encode(&self.dev.user)).await?
            && let Ok(signed) = SignedDeviceList::decode(bytes.as_slice())
        {
            let _ = self.dev.accept_device_list(&self.dev.user.clone(), &signed);
        }
        self.dev.rotate_prekeys_if_due().await?;
        let spk = self.dev.signed_prekey_id()?;
        match self.dev.db.relay_spk(&self.relay_url)? {
            None => {
                let up = self.dev.key_upload(ONE_TIME_BATCH, KYBER_ONE_TIME_BATCH, true).await?;
                self.relay.upload_keys(&self.auth(), &up, self.registration_token.as_deref()).await?;
            }
            Some(served) => {
                let count = self.relay.key_count(&self.auth()).await?;
                let ec = if count.one_time < ONE_TIME_LOW_WATER { ONE_TIME_BATCH } else { 0 };
                let kyber = if count.kyber_one_time < ONE_TIME_LOW_WATER { KYBER_ONE_TIME_BATCH } else { 0 };
                // Re-publish after a rotation so the relay serves the new prekeys.
                if served != spk || ec > 0 || kyber > 0 {
                    let up = self.dev.key_upload(ec, kyber, served != spk).await?;
                    self.relay.upload_keys(&self.auth(), &up, self.registration_token.as_deref()).await?;
                }
            }
        }
        self.dev.db.set_relay_registered(&self.relay_url, spk)?;
        // Register (the hash of) our delivery token, after rotations too.
        let token = self.dev.delivery_token()?;
        let key = format!("delivery-registered:{}", self.relay_url);
        if self.dev.db.meta_get(&key)?.as_deref() != Some(sha256(&token).as_slice()) {
            self.relay.put_delivery_token(&self.auth(), &token).await?;
            self.dev.db.meta_set(&key, &sha256(&token))?;
        }
        Ok(())
    }

    /// Fetch and verify the device lists of these users.
    pub async fn refresh_device_lists(&self, users: &[Vec<u8>], warnings: &mut Vec<String>) -> Result<()> {
        for u in users {
            if self.dev.db.pinned(u)?.is_none() {
                continue;
            }
            let Some(bytes) = self.relay.get_device_list(&hex::encode(u)).await? else {
                continue;
            };
            let signed = SignedDeviceList::decode(bytes.as_slice())?;
            if let Err(e) = self.dev.accept_device_list(u, &signed) {
                warnings.push(format!(
                    "ignored a device list from the relay for user {} ({e:#}); nothing to do. If this keeps \
                     happening, the relay is trying to add devices to that user or hide a revocation",
                    short(u)
                ));
            }
        }
        Ok(())
    }


    /// Every (user, device, key) in the roster per our verified lists.
    fn recipients(&self, roster: &Roster) -> Result<Vec<e2ee_proto::Recipient>> {
        let mut out = Vec::new();
        for m in &roster.members {
            for (d, k) in self.dev.db.devices_of(&m.user_id)? {
                out.push((m.user_id.clone(), d, k));
            }
        }
        Ok(out)
    }

    fn others(&self, recipients: &[e2ee_proto::Recipient]) -> Vec<(Vec<u8>, u32)> {
        recipients
            .iter()
            .filter(|(u, d, _)| !(*u == self.dev.user && *d == self.dev.device_id))
            .map(|(u, d, _)| (u.clone(), *d))
            .collect()
    }

    // -- outbox ----------------------------------------------------------------

    /// Queue an envelope for these devices, plus a cover message to our own
    /// mailbox. Otherwise the relay could spot the sender of any fan-out as
    /// the one device that received nothing.
    fn queue(&self, to: &[(Vec<u8>, u32)], env: &Envelope) -> Result<()> {
        let bytes = e2ee_proto::pad_envelope(env);
        let me = (self.dev.user.clone(), self.dev.device_id);
        let cover = (!to.is_empty() && !to.contains(&me)).then_some(&me);
        for (u, d) in to.iter().chain(cover) {
            self.db().execute(
                "INSERT INTO outbox (repo_id, user, device_id, envelope, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![self.repo_id, u, *d as i64, bytes, now_ms() as i64],
            )?;
        }
        Ok(())
    }

    fn envelope(&self, body: Body) -> Envelope {
        Envelope {
            repo_id: self.repo_id.clone(),
            body: Some(body),
            sender_delivery_token: self.dev.delivery_token().unwrap_or_default(),
            token_keys: self.token_keys_seen(),
            reply_mailbox: self.own_mailbox().ok().flatten().map(|(m, _)| m).unwrap_or_default(),
            ..Default::default()
        }
    }

    /// Encrypt and deliver queued envelopes. Failures stay queued.
    ///
    /// Rows addressed to this device become cover traffic (see `queue`): a
    /// dummy sized like a real copy of the same envelope. Deliveries go out in
    /// a random interleaving, preserving order per recipient.
    pub async fn flush_outbox(&mut self, warnings: &mut Vec<String>) -> Result<()> {
        // Mail older than the relay keeps undelivered mail is pointless to send.
        let cutoff = now_ms().saturating_sub(outbox_ttl_ms()) as i64;
        self.db().execute(
            "DELETE FROM outbox WHERE repo_id = ?1 AND created_ms < ?2",
            params![self.repo_id, cutoff],
        )?;
        let rows: Vec<(i64, Vec<u8>, u32, Vec<u8>)> = {
            let mut st = self
                .db()
                .prepare("SELECT id, user, device_id, envelope FROM outbox WHERE repo_id = ?1 ORDER BY id")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32, r.get(3)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let (my_user, my_dev) = (self.dev.user.clone(), self.dev.device_id);
        let is_self = |u: &[u8], d: u32| u == my_user.as_slice() && d == my_dev;

        let pq_rows = self.dev.pq_outbox(&self.relay_url)?;
        if rows.is_empty() && pq_rows.is_empty() {
            return Ok(());
        }
        let mut sealed: Vec<(Sent, Vec<u8>, u32, Vec<u8>)> = Vec::new();
        // Phase 0: post-quantum handshake responses go first, so that each
        // recipient gets them before anything MACed under the new key.
        for (id, user, device, frame) in pq_rows {
            if self.dev.db.device_key(&user, device)?.is_none() {
                self.dev.pq_outbox_done(id)?; // revoked since
                continue;
            }
            let r: Result<Vec<u8>> = async {
                self.ensure_session(&user, device).await?;
                self.dev.seal_to(&user, device, &frame).await
            }
            .await;
            match r {
                Ok(m) => sealed.push((Sent::PqResponse(id), user, device, m)),
                // Stays queued; retried on the next flush.
                Err(e) => {
                    if self.record_failure(&user, device)? {
                        warnings.push(format!("handshake response to {}.{device} deferred: {e:#}", short(&user)));
                    }
                }
            }
        }
        // Phase 1: seal real messages; remember their sizes per envelope.
        let mut sizes: std::collections::HashMap<Vec<u8>, Vec<usize>> = Default::default();
        let mut pending_envs: std::collections::HashSet<Vec<u8>> = Default::default();
        let mut dummies = Vec::new();
        let mut carries_head: std::collections::HashSet<i64> = Default::default();
        for (id, user, device, env) in rows {
            if is_self(&user, device) {
                dummies.push((id, env));
                continue;
            }
            if self.dev.db.device_key(&user, device)?.is_none() {
                // Device revoked since queuing: drop.
                self.db().execute("DELETE FROM outbox WHERE id = ?1", [id])?;
                continue;
            }
            // Stamp the send time now, at encryption, not when it was queued
            // (delivery may have been deferred while we were offline). Cover
            // mail is matched to real copies by the *queued* bytes.
            let queued = env.clone();
            if self.backed_off(&user, device)? {
                // Recent failures: don't spend tokens on this device yet.
                pending_envs.insert(queued);
                continue;
            }
            let env = match Envelope::decode(env.as_slice()) {
                Ok(mut e) => {
                    // Only messages that carry our log head stand in for
                    // gossip (see `gossip`); requests and claims don't.
                    if matches!(e.body, Some(Body::Push(_) | Body::RosterChange(_) | Body::Ack(_) | Body::Heartbeat(_))) {
                        carries_head.insert(id);
                    }
                    e.sent_ms = now_ms();
                    e2ee_proto::pad_envelope(&e)
                }
                Err(_) => env,
            };
            let r: Result<Option<(Sent, Vec<u8>)>> = async {
                self.ensure_session(&user, device).await?;
                if !self.dev.pq_ready(&user, device)? {
                    // No post-quantum key with this device yet: start (or
                    // keep waiting for) the handshake; the message waits.
                    if !self.dev.has_peer_kem(&user, device)? {
                        let access = self.take_tokens(api::cost::BUNDLE).await?;
                        let bundle = self.relay.bundle(&access, &hex::encode(&user), device).await?;
                        self.dev.store_peer_kem(&user, device, &bundle.kem_auth_key)?;
                    }
                    return match self.dev.pq_init(&user, device)? {
                        Some(init) => Ok(Some((Sent::PqInit, self.dev.seal_to(&user, device, &init).await?))),
                        None => Ok(None),
                    };
                }
                // The session state advances now; if delivery fails the
                // receiver just sees a skipped message key, which the ratchet
                // tolerates, and the row is re-sealed next time.
                let frame = self.dev.pq_wrap(&user, device, &env)?;
                Ok(Some((Sent::Outbox(id), self.dev.seal_to(&user, device, &frame).await?)))
            }
            .await;
            match r {
                Ok(Some((what @ Sent::Outbox(_), m))) => {
                    sizes.entry(queued).or_default().push(m.len());
                    sealed.push((what, user, device, m));
                }
                Ok(Some((what, m))) => {
                    pending_envs.insert(queued);
                    sealed.push((what, user, device, m));
                }
                Ok(None) => {
                    pending_envs.insert(queued);
                }
                Err(e) => {
                    pending_envs.insert(queued);
                    if self.record_failure(&user, device)? {
                        warnings.push(format!("delivery to {}.{device} deferred: {e:#}", short(&user)));
                    }
                }
            }
        }
        // Phase 2: dummies mimic a random real copy of the same envelope.
        for (id, env) in dummies {
            match sizes.get(&env) {
                Some(lens) => {
                    let target = lens[rand::random_range(0..lens.len())];
                    let m = self.dev.dummy_to_self(target).await?;
                    sealed.push((Sent::Outbox(id), self.dev.user.clone(), self.dev.device_id, m));
                }
                // Real copies still pending: send the dummy alongside them later.
                None if pending_envs.contains(&env) => {}
                // Nothing else to hide among (sole device): drop it.
                None => {
                    self.db().execute("DELETE FROM outbox WHERE id = ?1", [id])?;
                }
            }
        }
        // Phase 3: random interleaving, per-recipient order kept.
        for (what, user, device, m) in shuffle_per_recipient(sealed) {
            // Handshakes aren't tied to a repo: they use the user-id mailbox.
            let r = match what {
                Sent::Outbox(_) => self.post_repo_mail(&user, device, m).await,
                _ => self.post_mail(&user, device, m).await,
            };
            match (r, what) {
                (Ok(()), Sent::PqResponse(id)) => self.dev.pq_outbox_done(id)?,
                (Ok(()), Sent::PqInit) => {}
                (Err(e), Sent::PqInit) => {
                    // Let the next flush start a fresh handshake.
                    self.dev.pq_forget_pending(&user, device)?;
                    if self.record_failure(&user, device)? {
                        warnings.push(format!("delivery to {}.{device} deferred: {e:#}", short(&user)));
                    }
                }
                (Ok(()), Sent::Outbox(id)) => {
                    self.db().execute("DELETE FROM outbox WHERE id = ?1", [id])?;
                    self.clear_failures(&user, device)?;
                    if !carries_head.contains(&id) {
                        continue;
                    }
                    self.db().execute(
                        "INSERT OR REPLACE INTO peer_sent (repo_id, user, device_id, last_ms) VALUES (?1, ?2, ?3, ?4)",
                        params![self.repo_id, user, device as i64, now_ms() as i64],
                    )?;
                }
                (Err(e), _) => {
                    if self.record_failure(&user, device)? {
                        warnings.push(format!("delivery to {}.{device} deferred: {e:#}", short(&user)));
                    }
                }
            }
        }
        Ok(())
    }

    fn backed_off(&self, user: &[u8], device: u32) -> Result<bool> {
        let next: Option<i64> = self
            .db()
            .query_row(
                "SELECT next_try_ms FROM device_backoff WHERE user = ?1 AND device_id = ?2",
                params![user, device as i64],
                |r| r.get(0),
            )
            .optional()?;
        Ok(next.is_some_and(|t| (now_ms() as i64) < t))
    }

    /// Note a failed delivery; the next attempt waits 1, 2, 4, ... minutes
    /// (at most a day). Returns whether this is the first failure in a row
    /// (worth a warning; later ones are summarized as "unreachable").
    fn record_failure(&self, user: &[u8], device: u32) -> Result<bool> {
        let now = now_ms() as i64;
        let failures: i64 = self
            .db()
            .query_row(
                "SELECT failures FROM device_backoff WHERE user = ?1 AND device_id = ?2",
                params![user, device as i64],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0)
            + 1;
        let base = env_secs("E2EE_BACKOFF_BASE_SECS", 60) as i64 * 1000;
        let wait = (base << (failures - 1).min(20)).min(86_400_000);
        self.db().execute(
            "INSERT INTO device_backoff (user, device_id, failures, next_try_ms, first_failure_ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user, device_id) DO UPDATE SET failures = excluded.failures, next_try_ms = excluded.next_try_ms",
            params![user, device as i64, failures, now + wait, now],
        )?;
        Ok(failures == 1)
    }

    fn clear_failures(&self, user: &[u8], device: u32) -> Result<()> {
        self.db()
            .execute("DELETE FROM device_backoff WHERE user = ?1 AND device_id = ?2", params![user, device as i64])?;
        Ok(())
    }

    /// Tell the user (at most once a day per device) about member devices we
    /// can't deliver to, or haven't heard from in a long time. Such devices
    /// are probably gone; their owner should revoke them.
    fn report_unreachable(&self, report: &mut SyncReport) -> Result<()> {
        let Some(s) = self.state()? else { return Ok(()) };
        let now = now_ms();
        let failing_for = env_secs("E2EE_UNREACHABLE_REPORT_SECS", 24 * 3600) * 1000;
        let silent_for = env_secs("E2EE_SILENT_REPORT_SECS", 7 * 24 * 3600) * 1000;
        for (u, d) in self.others(&self.recipients(&s.roster)?) {
            let first_failure: Option<i64> = self
                .db()
                .query_row(
                    "SELECT first_failure_ms FROM device_backoff WHERE user = ?1 AND device_id = ?2",
                    params![u, d as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let heard: Option<i64> = self
                .db()
                .query_row(
                    "SELECT last_ms FROM peer_contact WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                    params![self.repo_id, u, d as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let silent_since = heard.map_or(self.joined_ms()?, |h| h as u64);
            let msg = match first_failure {
                Some(f) if now.saturating_sub(f as u64) >= failing_for => format!(
                    "device {d} of user {} has been unreachable for {} (deliveries keep failing); \
                     if it's gone, ask its owner to revoke it (`git e2ee device revoke {d}` on their master device)",
                    short(&u),
                    fmt_age(now.saturating_sub(f as u64))
                ),
                _ if now.saturating_sub(silent_since) >= silent_for => format!(
                    "device {d} of user {} hasn't been heard from in {}; if it's gone, ask its owner to revoke it \
                     (`git e2ee device revoke {d}` on their master device)",
                    short(&u),
                    fmt_age(now.saturating_sub(silent_since))
                ),
                _ => continue,
            };
            let key = format!("unreachable-reported:{}:{}.{d}", self.rid, hex::encode(&u));
            if self.dev.db.meta_u64(&key)?.is_some_and(|t| now.saturating_sub(t) < 86_400_000) {
                continue;
            }
            self.dev.db.meta_set_u64(&key, now)?;
            report.warnings.push(msg);
        }
        Ok(())
    }

    /// Spend `n` anonymous access tokens for this relay, obtaining more
    /// (within the device's daily budget) when the wallet runs low.
    async fn take_tokens(&mut self, n: usize) -> Result<Vec<Token>> {
        if n == 0 {
            return Ok(vec![]);
        }
        // Normally the reserve (topped up at the start of each sync) covers
        // this. If not, refill in fixed-size batches: requesting exactly the
        // shortfall right before a large upload would let the relay match the
        // (device-signed) issuance to the (anonymous) spend by count.
        while (self.wallet_size()? as usize) < n {
            self.refill_tokens(TOKEN_BATCH).await?;
        }
        let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = {
            let mut st = self.db().prepare(
                "SELECT nonce, epoch, output FROM access_tokens WHERE relay_url = ?1 ORDER BY epoch LIMIT ?2",
            )?;
            st.query_map(params![self.relay_url, n as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut out = Vec::new();
        for (nonce, epoch, output) in rows {
            self.db().execute("DELETE FROM access_tokens WHERE nonce = ?1", [&nonce])?;
            out.push(Token { epoch: epoch as u64, nonce, output });
        }
        Ok(out)
    }

    /// Unspent tokens for this relay (expired epochs dropped).
    fn wallet_size(&self) -> Result<i64> {
        self.db().execute(
            "DELETE FROM access_tokens WHERE relay_url = ?1 AND epoch + 1 < ?2",
            params![self.relay_url, tokens::epoch_now() as i64],
        )?;
        Ok(self.db().query_row(
            "SELECT COUNT(*) FROM access_tokens WHERE relay_url = ?1",
            [&self.relay_url],
            |r| r.get(0),
        )?)
    }

    /// Keep a standing reserve, refilled at the start of a sync in fixed-size
    /// batches, so issuance happens apart from the actions that spend it.
    fn own_token_key(&self, epoch: u64, generation: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db()
            .query_row(
                "SELECT key FROM token_keys WHERE relay_url = ?1 AND epoch = ?2 AND generation = ?3",
                params![self.relay_url, epoch as i64, generation as i64],
                |r| r.get(0),
            )
            .optional()?)
    }

    fn record_token_key(&self, epoch: u64, generation: u32, key: &[u8]) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO token_keys (relay_url, epoch, generation, key) VALUES (?1, ?2, ?3, ?4)",
            params![self.relay_url, epoch as i64, generation as i64, key],
        )?;
        Ok(())
    }

    fn max_token_generation(&self) -> Result<u32> {
        Ok(self
            .db()
            .query_row("SELECT MAX(generation) FROM token_keys WHERE relay_url = ?1", [&self.relay_url], |r| r.get::<_, Option<i64>>(0))?
            .unwrap_or(0) as u32)
    }

    /// Our token keys for this relay from the current and previous day, as
    /// reported in envelopes.
    fn token_keys_seen(&self) -> Vec<e2ee_proto::TokenKeySeen> {
        let since = tokens::epoch_now().saturating_sub(1) as i64;
        let Ok(mut st) = self.db().prepare("SELECT epoch, generation, key FROM token_keys WHERE relay_url = ?1 AND epoch >= ?2") else {
            return vec![];
        };
        st.query_map(params![self.relay_url, since], |r| {
            let (e, g, k): (i64, i64, Vec<u8>) = (r.get(0)?, r.get(1)?, r.get(2)?);
            Ok(e2ee_proto::TokenKeySeen {
                epoch: e as u64,
                generation: g as u32,
                key_hash: e2ee_proto::token_key_hash(e as u64, g as u32, &k).to_vec(),
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// Compare the token keys other members report with ours. For a key
    /// generation we have no key of, ask the relay (anonymously) what it
    /// says that generation's key is: it must match the report, and the
    /// relay must not claim a lower current generation. A mismatch means the
    /// relay gave someone a key of their own: a conflict, as with logs.
    async fn check_token_keys(&mut self) -> Result<()> {
        let now = tokens::epoch_now();
        // (epoch, generation, key hash, user, device)
        type Report = (i64, i64, Vec<u8>, Vec<u8>, i64);
        let rows: Vec<Report> = {
            let mut st = self.db().prepare(
                "SELECT epoch, generation, key_hash, user, device_id FROM peer_token_keys WHERE relay_url = ?1 AND checked = 0",
            )?;
            st.query_map([&self.relay_url], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (epoch, generation, hash, user, dev) in rows {
            let (epoch, generation) = (epoch as u64, generation as u32);
            let mark = || {
                self.db().execute(
                    "UPDATE peer_token_keys SET checked = 1 WHERE relay_url = ?1 AND epoch = ?2 AND generation = ?3 AND key_hash = ?4 AND user = ?5 AND device_id = ?6",
                    params![self.relay_url, epoch as i64, generation as i64, hash, user, dev],
                )
            };
            if epoch + 1 < now {
                mark()?; // too old for the relay to answer about
                continue;
            }
            let ours = match self.own_token_key(epoch, generation)? {
                Some(k) => k,
                None => {
                    let current = self.relay.token_key(epoch, None).await?;
                    if current.generation < generation {
                        self.set_conflict(format!(
                            "{}.{dev} was given access-token key generation {generation} for day {epoch}, but the relay says the newest is {}: \
                             the relay gave someone a key of their own to recognize their tokens",
                            short(&user),
                            current.generation
                        ))?;
                        return Ok(());
                    }
                    let tk = self.relay.token_key(epoch, Some(generation)).await?;
                    self.record_token_key(epoch, generation, &tk.public_key)?;
                    tk.public_key
                }
            };
            if e2ee_proto::token_key_hash(epoch, generation, &ours).as_slice() != hash {
                self.set_conflict(format!(
                    "{}.{dev} was given a different access-token key than this device for day {epoch} (generation {generation}): \
                     the relay gave someone a key of their own to recognize their tokens",
                    short(&user)
                ))?;
                return Ok(());
            }
            mark()?;
        }
        Ok(())
    }

    async fn top_up_tokens(&mut self) -> Result<()> {
        self.check_token_generation().await?;
        let reserve = env_secs("E2EE_TOKEN_RESERVE", TOKEN_RESERVE as u64) as i64;
        while self.wallet_size()? < reserve {
            self.refill_tokens(TOKEN_BATCH).await?;
        }
        Ok(())
    }

    /// At most every 15 minutes, ask the relay (anonymously) for today's key.
    /// A new generation means a ban voided all tokens: drop ours of older
    /// generations so we don't spend dead ones. A lower generation, or a
    /// different key for a generation we know, is a tagging attempt.
    async fn check_token_generation(&mut self) -> Result<()> {
        let mark = format!("tokengen-checked:{}", self.relay_url);
        let last = self.dev.db.meta_u64(&mark)?.unwrap_or(0);
        if now_ms().saturating_sub(last) < env_secs("E2EE_TOKEN_GEN_CHECK_SECS", 15 * 60) * 1000 {
            return Ok(());
        }
        let epoch = tokens::epoch_now();
        let cur = self.relay.token_key(epoch, None).await?;
        if cur.generation < self.max_token_generation()? {
            bail!("the relay's access-token key generation went backwards (tagging attempt?)");
        }
        match self.own_token_key(epoch, cur.generation)? {
            Some(k) if k != cur.public_key => {
                bail!("the relay now publishes a different access-token key than it gave this device (tagging attempt?)")
            }
            Some(_) => {}
            None => self.record_token_key(epoch, cur.generation, &cur.public_key)?,
        }
        self.db().execute(
            "DELETE FROM access_tokens WHERE relay_url = ?1 AND generation < ?2",
            params![self.relay_url, cur.generation as i64],
        )?;
        self.dev.db.meta_set_u64(&mark, now_ms())?;
        Ok(())
    }

    async fn refill_tokens(&mut self, n: usize) -> Result<()> {
        let epoch = tokens::epoch_now();
        let (pending, blinded) = tokens::blind(n, epoch);
        let resp = self.relay.issue_tokens(&self.auth(), &api::TokenRequest { epoch, blinded }).await?;
        // The relay must evaluate under the key everyone gets: a key of our
        // own would let it recognize our tokens when we spend them. Check it
        // against an anonymous fetch here, and against what other members
        // were given in `check_token_keys` (envelopes report our keys).
        if resp.generation < self.max_token_generation()? {
            bail!("the relay's access-token key generation went backwards (tagging attempt?)");
        }
        let key = match self.own_token_key(epoch, resp.generation)? {
            Some(k) => k,
            None => {
                let tk = self.relay.token_key(epoch, None).await?;
                if tk.generation != resp.generation || tk.public_key != resp.public_key {
                    bail!("the relay issued access tokens under a different key than it publishes (tagging attempt?)");
                }
                self.record_token_key(epoch, tk.generation, &tk.public_key)?;
                tk.public_key
            }
        };
        if resp.public_key != key {
            bail!("the relay issued access tokens under a different key than it publishes (tagging attempt?)");
        }
        let toks = tokens::finalize(pending, &resp.evaluations, &resp.proof, &key)
            .ok_or_else(|| anyhow!("the relay's access-token proof did not verify"))?;
        for t in toks {
            self.db().execute(
                "INSERT INTO access_tokens (nonce, relay_url, epoch, output, generation) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![t.nonce, self.relay_url, t.epoch as i64, t.output, resp.generation as i64],
            )?;
        }
        Ok(())
    }

    /// Deliver one sealed message, paying one access token and presenting
    /// the recipient's delivery token if we know it (else the request lane).
    /// Start post-quantum handshakes with every device of `user` we don't
    /// share a key with yet, so later messages between us aren't held up by
    /// one. Run when someone is verified, and for our own devices when this
    /// one registers. Fetches the user's device list from the relay (anyone
    /// may fetch it; the request isn't tied to us). Returns how many started.
    pub async fn pq_introduce(&mut self, user: &[u8]) -> Result<usize> {
        if user != self.dev.user.as_slice()
            && let Some(list) = self.relay.get_device_list(&hex::encode(user)).await?
        {
            let signed = e2ee_proto::SignedDeviceList::decode(list.as_slice())?;
            if let Err(e) = self.dev.accept_device_list(user, &signed)
                && format!("{e:#}").contains("fork")
            {
                return Err(e);
            }
        }
        let mut started = 0;
        for (device, _) in self.dev.db.devices_of(user)? {
            if user == self.dev.user.as_slice() && device == self.dev.device_id {
                continue;
            }
            if self.send_pq_init(user, device).await? {
                started += 1;
            }
        }
        Ok(started)
    }

    /// Start handshakes with member devices we have no key or handshake in
    /// flight with (new members and devices), so their first messages to us
    /// and ours to them don't wait long.
    async fn pq_catch_up(&mut self, warnings: &mut Vec<String>) {
        let Ok(Some(s)) = self.state() else { return };
        let mut targets = vec![];
        for m in &s.roster.members {
            for (d, _) in self.dev.db.devices_of(&m.user_id).unwrap_or_default() {
                if !(m.user_id == self.dev.user && d == self.dev.device_id) {
                    targets.push((m.user_id.clone(), d));
                }
            }
        }
        for (u, d) in targets {
            if self.backed_off(&u, d).unwrap_or(true) {
                continue;
            }
            if let Err(e) = self.send_pq_init(&u, d).await
                && self.record_failure(&u, d).unwrap_or(false)
            {
                warnings.push(format!("handshake with {}.{d} deferred: {e:#}", short(&u)));
            }
        }
    }

    /// Make sure we have a libsignal session with a device (starting one
    /// from a fresh prekey bundle if not).
    async fn ensure_session(&mut self, user: &[u8], device: u32) -> Result<()> {
        if !self.dev.has_session(user, device).await? {
            let access = self.take_tokens(api::cost::BUNDLE).await?;
            let bundle = self.relay.bundle(&access, &hex::encode(user), device).await?;
            self.dev.start_session(user, device, &bundle).await?;
        }
        Ok(())
    }

    async fn send_pq_init(&mut self, user: &[u8], device: u32) -> Result<bool> {
        if self.dev.pq_ready(user, device)? && !self.dev.pq_needs_handshake(user, device)? {
            return Ok(false);
        }
        if !self.dev.has_session(user, device).await? || !self.dev.has_peer_kem(user, device)? {
            let access = self.take_tokens(api::cost::BUNDLE).await?;
            let bundle = self.relay.bundle(&access, &hex::encode(user), device).await?;
            if self.dev.has_session(user, device).await? {
                self.dev.store_peer_kem(user, device, &bundle.kem_auth_key)?;
            } else {
                self.dev.start_session(user, device, &bundle).await?;
            }
        }
        let Some(init) = self.dev.pq_init(user, device)? else { return Ok(false) };
        let m = self.dev.seal_to(user, device, &init).await?;
        if let Err(e) = self.post_mail(user, device, m).await {
            self.dev.pq_forget_pending(user, device)?;
            return Err(e);
        }
        Ok(true)
    }

    /// Deliver repo traffic: to the recipient's pseudonymous mailbox for this
    /// repo if we know it (our own, for cover traffic to ourselves), else to
    /// the mailbox named by its user id.
    async fn post_repo_mail(&mut self, user: &[u8], device: u32, data: Vec<u8>) -> Result<()> {
        let mailbox = if user == self.dev.user.as_slice() && device == self.dev.device_id {
            self.own_mailbox()?.map(|(m, _)| m)
        } else {
            self.peer_mailbox(user, device)?
        };
        if let Some(mb) = mailbox {
            let access = self.take_tokens(api::cost::mail(data.len())).await?;
            match self.relay.send_pmail(&access, &hex::encode(&mb), data.clone()).await {
                Ok(()) => return Ok(()),
                // Gone (rotated away and expired): forget it, use the user mailbox.
                Err(e) if format!("{e:#}").contains("404") => {
                    self.db().execute(
                        "DELETE FROM peer_mailboxes WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                        params![self.repo_id, user, device as i64],
                    )?;
                }
                Err(e) => return Err(e),
            }
        }
        self.post_mail(user, device, data).await
    }

    /// Keep what proves the current state: a push replaces everything, a
    /// roster change is added after it.
    fn record_proof(&self, seq: u64, env: &Envelope) -> Result<()> {
        match &env.body {
            Some(Body::Push(p)) => {
                // Without the pack key: pack keys don't outlive the import,
                // and the view only needs its hash.
                let p = Push { pack_key: vec![], ..p.clone() };
                self.db().execute("DELETE FROM view_proof WHERE repo_id = ?1", [&self.repo_id])?;
                self.db().execute(
                    "INSERT INTO view_proof (repo_id, seq, push) VALUES (?1, ?2, ?3)",
                    params![self.repo_id, seq as i64, p.encode_to_vec()],
                )?;
            }
            Some(Body::RosterChange(rc)) => {
                self.db().execute(
                    "INSERT OR REPLACE INTO view_proof (repo_id, seq, roster_change) VALUES (?1, ?2, ?3)",
                    params![self.repo_id, seq as i64, rc.encode_to_vec()],
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn view_proof(&self) -> Result<(Option<Push>, Vec<RosterChange>)> {
        let mut st = self.db().prepare("SELECT push, roster_change FROM view_proof WHERE repo_id = ?1 ORDER BY seq")?;
        // (encoded push, encoded roster change), one of them set per row
        type ProofRow = (Option<Vec<u8>>, Option<Vec<u8>>);
        let rows: Vec<ProofRow> =
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut push = None;
        let mut rosters = vec![];
        for (p, rc) in rows {
            if let Some(p) = p {
                push = Some(Push::decode(p.as_slice())?);
            }
            if let Some(rc) = rc {
                rosters.push(RosterChange::decode(rc.as_slice())?);
            }
        }
        Ok((push, rosters))
    }

    /// Every member device's current pseudonymous mailbox we know, ours too.
    fn known_mailboxes(&self) -> Result<Vec<e2ee_proto::PeerMailbox>> {
        let mut st = self.db().prepare("SELECT user, device_id, mailbox FROM peer_mailboxes WHERE repo_id = ?1")?;
        let mut out: Vec<e2ee_proto::PeerMailbox> = st
            .query_map([&self.repo_id], |r| {
                Ok(e2ee_proto::PeerMailbox { user: r.get(0)?, device: r.get::<_, i64>(1)? as u32, mailbox: r.get(2)? })
            })?
            .collect::<rusqlite::Result<_>>()?;
        if let Some((mb, _)) = self.own_mailbox()? {
            out.push(e2ee_proto::PeerMailbox { user: self.dev.user.clone(), device: self.dev.device_id, mailbox: mb });
        }
        Ok(out)
    }

    fn peer_mailbox(&self, user: &[u8], device: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db()
            .query_row(
                "SELECT mailbox FROM peer_mailboxes WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                params![self.repo_id, user, device as i64],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Our current pseudonymous mailbox for this repo: (address, key).
    fn own_mailbox(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .db()
            .query_row(
                "SELECT mailbox, key FROM own_mailboxes WHERE repo_id = ?1 AND retired_ms IS NULL",
                [&self.repo_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Have a current pseudonymous mailbox for this repo, rotating it when
    /// it's old or a member was removed; retire old ones once nothing can
    /// still be on its way to them.
    async fn maintain_mailboxes(&mut self) -> Result<()> {
        let rotate_key = format!("mailbox-rotate:{}", hex::encode(&self.repo_id));
        let age = env_secs("E2EE_MAILBOX_ROTATE_SECS", 7 * 24 * 3600) * 1000;
        let due = match self
            .db()
            .query_row(
                "SELECT created_ms FROM own_mailboxes WHERE repo_id = ?1 AND retired_ms IS NULL",
                [&self.repo_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            None => true,
            Some(created) => {
                now_ms().saturating_sub(created as u64) >= age || self.dev.db.meta_get(&rotate_key)?.is_some()
            }
        };
        if due {
            let (mb, key) = (random_bytes::<16>().to_vec(), random_bytes::<32>().to_vec());
            let access = self.take_tokens(api::cost::MAIL).await?;
            self.relay.create_pmail(&access, &hex::encode(&mb), &key).await?;
            let now = now_ms() as i64;
            self.db().execute(
                "UPDATE own_mailboxes SET retired_ms = ?2 WHERE repo_id = ?1 AND retired_ms IS NULL",
                params![self.repo_id, now],
            )?;
            self.db().execute(
                "INSERT INTO own_mailboxes (repo_id, mailbox, key, created_ms) VALUES (?1, ?2, ?3, ?4)",
                params![self.repo_id, mb, key, now],
            )?;
            self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [&rotate_key])?;
        }
        // Senders may still use a retired address until they hear the new
        // one; keep reading it as long as undelivered mail could live.
        let cutoff = now_ms().saturating_sub(outbox_ttl_ms()) as i64;
        let old: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut st = self
                .db()
                .prepare("SELECT mailbox, key FROM own_mailboxes WHERE repo_id = ?1 AND retired_ms IS NOT NULL AND retired_ms < ?2")?;
            st.query_map(params![self.repo_id, cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (mb, key) in old {
            let _ = self.relay.retire_pmail(&hex::encode(&mb), &key).await;
            self.db().execute("DELETE FROM own_mailboxes WHERE repo_id = ?1 AND mailbox = ?2", params![self.repo_id, mb])?;
        }
        Ok(())
    }

    async fn post_mail(&mut self, user: &[u8], device: u32, data: Vec<u8>) -> Result<()> {
        let access = self.take_tokens(api::cost::mail(data.len())).await?;
        let delivery =
            if user == self.dev.user { Some(self.dev.delivery_token()?) } else { self.dev.db.delivery_token(user)? };
        self.relay.send_mail(&access, delivery.as_deref(), &hex::encode(user), device, data).await
    }

    // -- mailbox -----------------------------------------------------------------

    /// Decrypt pending mail into the inbox. Each message is decrypted and
    /// persisted in one transaction, then deleted from the relay.
    async fn pull_mailbox(&mut self, warnings: &mut Vec<String>) -> Result<()> {
        // One mailbox per device for all repos on this relay: each message is
        // filed under the repo named inside its encrypted envelope.
        // Plus this repo's pseudonymous mailboxes (current and retired ones
        // still in use), read anonymously with their keys.
        let mut sources: Vec<(MailSource, Vec<api::MailboxMessage>)> =
            vec![(None, self.relay.mailbox(&self.auth()).await?)];
        let own: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut st = self.db().prepare("SELECT mailbox, key FROM own_mailboxes WHERE repo_id = ?1")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        for (mb, key) in own {
            match self.relay.pmail(&hex::encode(&mb), &key).await {
                Ok(msgs) => sources.push((Some((mb, key)), msgs)),
                // Expired on the relay (nobody read it for a long time):
                // forget it, and get a new current one this sync.
                Err(e) if format!("{e:#}").contains("404") => {
                    self.db().execute("DELETE FROM own_mailboxes WHERE repo_id = ?1 AND mailbox = ?2", params![self.repo_id, mb])?;
                }
                Err(e) => warnings.push(format!("could not read a mailbox of this repo: {e:#}")),
            }
        }
        let mut dropped_unknown = 0;
        for (src, m) in sources.into_iter().flat_map(|(src, msgs)| msgs.into_iter().map(move |m| (src.clone(), m))) {
            let inbox_id = format!("{}#{}", self.relay_url, m.id);
            let seen: bool = self
                .db()
                .query_row("SELECT 1 FROM inbox WHERE msg_id = ?1", [&inbox_id], |_| Ok(()))
                .optional()?
                .is_some();
            if seen {
                self.delete_from(&src, &m.id).await?;
                continue;
            }
            let (sender_user, sender_dev) = match self.dev.peek_sender(&m.data).await {
                Ok(s) => s,
                Err(e) => {
                    warnings.push(format!("discarding unreadable message: {e:#}"));
                    self.delete_from(&src, &m.id).await?;
                    continue;
                }
            };
            if sender_user == self.dev.user && sender_dev == self.dev.device_id {
                // Our own cover traffic.
                self.delete_from(&src, &m.id).await?;
                continue;
            }
            if self.dev.db.pinned(&sender_user)?.is_none() {
                // Possibly a member we will learn about from a roster change
                // later in the log; keep it on the relay and retry.
                continue;
            }
            // An unknown sender device is fine: its message carries its user's
            // signed device list, which open_sealed verifies and adopts.
            let dev = &mut self.dev;
            let db = dev.db.clone();
            let id = inbox_id;
            let current = self.repo_id.clone();
            let relay_url = self.relay_url.clone();
            let res = db
                .transaction(|| async move {
                    // Decrypting advances the ratchet, so it is committed even
                    // when the envelope itself is then not kept.
                    let (u, d, frame) = dev.open_sealed(&m.data).await?;
                    // Post-quantum authentication: handshake frames are
                    // handled here; data must carry a valid MAC.
                    let pt = match dev.pq_receive(&u, d, &frame, &relay_url, &id)? {
                        PqIn::Payload(p) => p,
                        PqIn::Handled | PqIn::Held => return Ok((None, 0)),
                        PqIn::HandledInit => {
                            dev.reset_session(&u, d).await?;
                            return Ok((None, 0));
                        }
                    };
                    admit(dev, &relay_url, &current, &id, &u, d, &pt)
                })
                .await;
            self.after_admit(res, &sender_user, sender_dev, &mut dropped_unknown, warnings);
            failpoint("after_decrypt");
            self.delete_from(&src, &m.id).await?;
        }
        // Messages that waited for a handshake response we now have.
        for (id, u, d, pt) in self.dev.pq_release_held(env_secs("E2EE_INBOX_TTL_SECS", 14 * 24 * 3600) * 1000)? {
            let res = admit(&self.dev, &self.relay_url, &self.repo_id, &id, &u, d, &pt);
            self.after_admit(res, &u, d, &mut dropped_unknown, warnings);
        }
        if dropped_unknown > 0 {
            warnings.push(format!("ignored {dropped_unknown} message(s) for repos this device is not in"));
        }
        self.expire_inbox()?;
        Ok(())
    }

    /// Delete a processed message from where it came from.
    async fn delete_from(&self, src: &MailSource, id: &str) -> Result<()> {
        match src {
            None => self.relay.delete_mail(&self.auth(), id).await,
            Some((mb, key)) => self.relay.delete_pmail(&hex::encode(mb), key, id).await,
        }
    }

    fn after_admit(
        &self,
        res: Result<(Option<InboxDrop>, u64)>,
        sender_user: &[u8],
        sender_dev: u32,
        dropped_unknown: &mut usize,
        warnings: &mut Vec<String>,
    ) {
        let max_delay = env_secs("E2EE_MAX_DELAY_SECS", 6 * 3600) * 1000;
        match res {
            Ok((None, delay)) if delay > max_delay => warnings.push(format!(
                "mail from {}.{sender_dev} was sent {} before it arrived: the relay may be delaying mail \
                 (nothing to do unless it keeps happening)",
                short(sender_user),
                fmt_age(delay)
            )),
            Ok((None, _)) => {}
            Ok((Some(InboxDrop::UnknownRepo), _)) => *dropped_unknown += 1,
            Ok((Some(InboxDrop::Full), _)) => warnings.push(format!(
                "dropped a message from {}.{sender_dev}: too much mail waiting for one repo",
                short(sender_user)
            )),
            Err(e) => warnings.push(format!("discarding message from {}.{sender_dev}: {e:#}", short(sender_user))),
        }
    }

    /// Forget history bundles for repos this device never cloned once they
    /// are older than `E2EE_INBOX_TTL_SECS` (default 14 days, the relay's mail
    /// TTL). This also deletes the pack keys they carry.
    fn expire_inbox(&self) -> Result<()> {
        let cutoff = now_ms().saturating_sub(env_secs("E2EE_INBOX_TTL_SECS", 14 * 24 * 3600) * 1000);
        self.db().execute(
            "DELETE FROM inbox WHERE received_ms < ?1 AND repo_id != ?2 AND repo_id NOT IN (SELECT repo_id FROM repos)",
            params![cutoff as i64, self.repo_id],
        )?;
        // Envelopes for this repo from people who still aren't members after
        // that long (say, a removed member's) won't become useful: drop them.
        if let Some(s) = self.state()? {
            let ids: Vec<(String, Vec<u8>)> = {
                let mut st = self.db().prepare("SELECT msg_id, sender_user FROM inbox WHERE repo_id = ?1 AND received_ms < ?2")?;
                st.query_map(params![self.repo_id, cutoff as i64], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
            };
            for (id, sender) in ids {
                if !s.roster.members.iter().any(|m| m.user_id == sender) {
                    self.delete_inbox(&id)?;
                }
            }
        }
        Ok(())
    }

    // -- sync --------------------------------------------------------------------

    /// Bring local state up to date with the relay. Imports packs into git.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        self.ensure_registered().await?;
        self.detect_absence(&mut report).await;
        if let Err(e) = self.top_up_tokens().await {
            report.warnings.push(format!("could not obtain access tokens: {e:#}"));
        }
        // Device lists are deliberately *not* fetched from the relay here:
        // fetching every member's list next to the repo's log would tell the
        // relay who is in the repo. They arrive in-band instead (with every
        // message, and inside pushes, roster changes and history bundles).
        // Mail may come from members added later in the log, so alternate
        // until nothing changes.
        for round in 0..4 {
            let before = self.state()?.map(|s| (s.seq, s.roster.version));
            self.pull_mailbox(&mut report.warnings).await?;
            if round == 0 {
                self.test_inject(&mut report).await?;
            }
            if self.state()?.is_none() {
                self.bootstrap(&mut report).await?;
            } else {
                self.catch_up(&mut report).await?;
            }
            if self.state()?.is_none() {
                // Still answer post-quantum handshakes: the history we are
                // waiting for may be held back until ours completes.
                self.flush_outbox(&mut report.warnings).await?;
                return Ok(report);
            }
            // The mirror is created in the repo's object format, known now.
            self.process_log(&self.mirror()?, &mut report).await?;
            if self.state()?.map(|s| (s.seq, s.roster.version)) == before {
                break;
            }
        }
        if let Err(e) = self.check_token_keys().await {
            report.warnings.push(format!("could not compare access-token keys with members: {e:#}"));
        }
        self.note_revoked_devices()?;
        self.warn_outdated_devices(&mut report)?;
        self.rotate_if_pending(&mut report).await;
        if let Err(e) = self.maintain_mailboxes().await {
            report.warnings.push(format!("could not set up this repo's mailbox: {e:#}"));
        }
        self.send_pending_ack()?;
        self.pq_catch_up(&mut report.warnings).await;
        for (u, d) in self.process_misc(&mut report)? {
            self.dev.reset_session(&u, d).await?;
        }
        if let Err(e) = self.answer_history_requests(&mut report).await {
            report.warnings.push(format!("could not answer a history request: {e:#}"));
        }
        if let Err(e) = self.resend_invites(&mut report).await {
            report.warnings.push(format!("could not re-send an invitation: {e:#}"));
        }
        self.freshness(&mut report).await?;
        self.gossip()?;
        self.flush_outbox(&mut report.warnings).await?;
        self.gc_blobs().await?;
        self.report_device_changes(&mut report)?;
        self.report_unreachable(&mut report)?;
        if let Some(seq) = report.waiting_for {
            report.behind = self.behind_note(seq)?;
        }
        self.prune_push_log()?;
        self.dev.db.meta_set_u64(&format!("last-sync:{}", hex::encode(&self.repo_id)), now_ms())?;
        Ok(report)
    }

    /// Initialize from a history bundle sent to this device.
    async fn bootstrap(&mut self, report: &mut SyncReport) -> Result<()> {
        let mut deferred: Option<anyhow::Error> = None;
        for (msg_id, sender, sender_dev, env) in self.inbox()? {
            let Some(Body::HistoryBundle(hb)) = env.body else { continue };
            let Some(roster) = hb.roster.clone() else { continue };
            let in_roster = |u: &[u8]| roster.members.iter().any(|m| m.user_id == u);
            if !in_roster(&sender) || !in_roster(&self.dev.user) {
                report.warnings.push("ignoring history bundle from a non-member".into());
                self.delete_inbox(&msg_id)?;
                continue;
            }
            if roster.genesis_secret.is_empty() {
                report.warnings.push(format!(
                    "ignoring a history bundle from {}.{sender_dev}: the repo was made by a pre-release build that \
                     didn't record its genesis secret, so newcomers can't check it's really this repo. Ask a member \
                     to recreate the repo with a current build (see CHANGELOG.md)",
                    short(&sender)
                ));
                self.delete_inbox(&msg_id)?;
                continue;
            }
            // Only someone who has been a member knows the secret the repo id
            // comes from: a contact (even with the relay's help) can't pass
            // off a repo of its own as this one.
            if !e2ee_proto::roster_is_for(&roster, &self.repo_id) {
                report.warnings.push(format!(
                    "ignoring a history bundle from {}.{sender_dev} that isn't for this repo (its roster doesn't match the repo id)",
                    short(&sender)
                ));
                self.delete_inbox(&msg_id)?;
                continue;
            }
            match self.apply_bundle(hb, roster, &sender, report).await {
                Ok(()) => {
                    self.delete_inbox(&msg_id)?;
                    return Ok(());
                }
                Err(e) if e.downcast_ref::<BadBundle>().is_some() => {
                    // A bad bundle must not block every later sync: drop it
                    // (with its pack key) and let a good one arrive.
                    report.warnings.push(format!(
                        "discarded a history bundle from {}.{sender_dev}: {e:#}",
                        short(&sender)
                    ));
                    self.delete_inbox(&msg_id)?;
                }
                // Not this bundle's fault (e.g. the repo needs a newer
                // build, or the network failed): keep it, but still try
                // the others.
                Err(e) => {
                    deferred.get_or_insert(e);
                }
            }
        }
        match deferred {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Verify a history bundle and initialize the repo from it. Problems
    /// with the bundle itself are `BadBundle`; anything else is transient.
    /// `sender`: the member it came from (recorded on its push log entries).
    async fn apply_bundle(&mut self, hb: HistoryBundle, roster: Roster, sender: &[u8], report: &mut SyncReport) -> Result<()> {
        let bad = |m: String| anyhow::Error::new(BadBundle(m));
        // A device with state that's catching up keeps what it already knows
        // about members (their mailboxes and delivery tokens).
        let catching_up = self.state()?.is_some();
        // The refs, default branch and roster must be the ones the view
        // commits to: recompute the chain of views from the proof.
        verify_bundle_proof(&self.repo_id, &hb, &roster).map_err(|e| bad(format!("{e:#}")))?;
        let (proof_push, proof_rosters) = (hb.proof_push.clone(), hb.proof_rosters.clone());
        let format = roster.object_format.clone();
        if e2ee_proto::object_format::oid_len(&format).is_none() {
            return Err(bad(format!("unknown object format {format:?}")));
        }
        // Not a bad bundle if our git lacks SHA-1 collision detection: keep it.
        let git = &Git::init_mirror(self.mirror.path(), &format)?;
        // Validate every roster entry before pinning any of them.
        for m in &roster.members {
            if m.user_id != e2ee_proto::user_id_of(&m.master_key) {
                return Err(bad(format!("roster binds user {} to the wrong master key", short(&m.user_id))));
            }
            if let Some((k, _)) = self.dev.db.pinned(&m.user_id)?
                && k != m.master_key
            {
                return Err(bad(format!("roster has a different master key for pinned user {}", short(&m.user_id))));
            }
        }
        let token = e2ee_proto::delivery_token(&roster.repo_secret).to_vec();
        // Check the bundle's claimed position against the relay log. A
        // bundle always describes some entry (a repo is shared by a roster
        // change at the earliest).
        if hb.seq == 0 {
            return Err(bad("it names no log position".into()));
        }
        {
            let entries = self
                .relay
                .log_since(&self.rid, &token, hb.seq.saturating_sub(1))
                .await?
                .ok_or_else(|| bad("the relay rejects the repo token in the bundle".into()))?;
            let first = entries.first().ok_or_else(|| anyhow!("relay log is shorter than the history bundle"))?;
            let e = LogEntry::decode(first.as_slice())?;
            // Entries are written at the repo's protocol (see apply_entries).
            // Checked first: an entry newer than its own roster is bad, not a
            // reason to "upgrade" (a relay could keep a clone failing so).
            if e.version > roster.protocol {
                return Err(bad(format!("the log entry it's anchored at claims protocol {}, newer than its roster's {}", e.version, roster.protocol)));
            }
            check_protocol_or_upgrade("the repo's log", e.version)?;
            let commits_to_view = [log_kind::PUSH, log_kind::ROSTER, log_kind::HEARTBEAT, log_kind::CLAIM]
                .iter()
                .any(|k| log_commitment(&self.repo_id, e.seq, *k, &hb.view, &e.nonce, e.version).as_slice() == e.commitment);
            if e.seq != hb.seq || !commits_to_view || log_head(first).as_slice() != hb.log_head {
                return Err(bad(format!("it does not match the relay log at seq {}", hb.seq)));
            }
        }
        // A repo on a newer protocol: keep the bundle (an upgrade can use it).
        check_protocol_or_upgrade("this repo", hb.roster.as_ref().map_or(0, |r| r.protocol))?;
        check_refs(&hb.refs, &hb.head_ref, &format, None).map_err(|e| bad(format!("{e:#}")))?;
        // Bad data comes back as BadBundle; network trouble stays transient.
        self.download_pack(git, &hb.pack_key, &hb.blob_ids, &hb.chunk_hashes, &hb.pack_hash).await?;
        if let Some(r) = hb.refs.iter().find(|r| !git.has_object(&r.oid)) {
            return Err(bad(format!("it references missing object {} ({})", r.oid, r.name)));
        }
        for m in &roster.members {
            self.dev.db.pin(&m.user_id, &m.master_key, false).context("pinning roster member")?;
        }
        for ut in &hb.delivery_tokens {
            if ut.user_id != self.dev.user
                && roster.members.iter().any(|m| m.user_id == ut.user_id)
                && !(catching_up && self.dev.db.delivery_token(&ut.user_id)?.is_some())
            {
                self.dev.db.set_delivery_token(&ut.user_id, &ut.token)?;
            }
        }
        // Adopt the inviter's (newest known) device lists before ever
        // asking the relay, so the relay cannot feed us a stale first one.
        for signed in &hb.device_lists {
            let Ok(body) = e2ee_proto::DeviceListBody::decode(signed.body.as_slice()) else { continue };
            if roster.members.iter().any(|m| m.user_id == body.user_id)
                && let Err(e) = self.dev.accept_device_list(&body.user_id, signed)
            {
                report.warnings.push(format!("device list in history bundle: {e:#}"));
            }
        }
        // Members' pseudonymous mailboxes, from the inviter (members' own
        // envelopes later confirm or replace them).
        for m in hb.mailboxes.iter().take(1000) {
            if m.mailbox.len() == 16 && !(m.user == self.dev.user && m.device == self.dev.device_id) {
                self.db().execute(
                    if catching_up {
                        "INSERT OR IGNORE INTO peer_mailboxes (repo_id, user, device_id, mailbox) VALUES (?1, ?2, ?3, ?4)"
                    } else {
                        "INSERT OR REPLACE INTO peer_mailboxes (repo_id, user, device_id, mailbox) VALUES (?1, ?2, ?3, ?4)"
                    },
                    params![self.repo_id, m.user, m.device as i64, m.mailbox],
                )?;
            }
        }
        if self.push_log {
            for e in hb.push_log.iter().take(100_000) {
                // Another member's word: keep only well-formed entries, with
                // printable notes (they're shown in a terminal).
                let well_formed = e.changes.iter().all(|c| {
                    git::valid_ref_name(&c.name)
                        && (c.old_oid.is_empty() || git::valid_oid(&c.old_oid, &format))
                        && (c.new_oid.is_empty() || git::valid_oid(&c.new_oid, &format))
                });
                if !well_formed {
                    continue;
                }
                let mut e = e.clone();
                e.note = e.note.chars().filter(|c| !c.is_control()).take(500).collect();
                // Already gone, or past what we know: skip. Its expiry is the
                // sender's word, like the rest of it.
                if e.seq <= hb.seq && (e.expires_ms == 0 || e.expires_ms > now_ms()) {
                    let ours: bool = self
                        .db()
                        .query_row("SELECT 1 FROM push_log WHERE repo_id = ?1 AND seq = ?2", params![self.repo_id, e.seq as i64], |_| Ok(()))
                        .optional()?
                        .is_some();
                    if !ours {
                        if e.timer {
                            self.db().execute("DELETE FROM push_log WHERE repo_id = ?1 AND timer = 1 AND seq < ?2", params![self.repo_id, e.seq as i64])?;
                        }
                        self.store_log_row(&e, Some(sender))?;
                    }
                }
            }
        }
        self.add_secret(&roster.repo_secret)?;
        let state = RepoState {
            relay_url: self.relay_url.clone(),
            roster,
            seq: hb.seq,
            head: hb.log_head.clone(),
            view: hb.view.clone(),
            refs: hb.refs.clone(),
            head_ref: hb.head_ref.clone(),
            conflict: None,
            last_heartbeat_ms: now_ms(),
            last_log_at_ms: now_ms(),
        };
        self.save_state(&state)?;
        // Keep the proof, to pass on when we send history ourselves.
        self.db().execute("DELETE FROM view_proof WHERE repo_id = ?1", [&self.repo_id])?;
        if let Some(p) = &proof_push {
            let p = Push { pack_key: vec![], ..p.clone() };
            self.db().execute(
                "INSERT INTO view_proof (repo_id, seq, push) VALUES (?1, ?2, ?3)",
                params![self.repo_id, p.seq as i64, p.encode_to_vec()],
            )?;
        }
        for rc in &proof_rosters {
            self.db().execute(
                "INSERT OR REPLACE INTO view_proof (repo_id, seq, roster_change) VALUES (?1, ?2, ?3)",
                params![self.repo_id, rc.seq as i64, rc.encode_to_vec()],
            )?;
        }
        Ok(())
    }

    /// `None`: the relay accepts none of the repo tokens we know.
    async fn fetch_log(&self, since: u64) -> Result<Option<Vec<Vec<u8>>>> {
        for t in self.tokens()? {
            if let Some(entries) = self.relay.log_since(&self.rid, &t, since).await? {
                return Ok(Some(entries));
            }
        }
        Ok(None)
    }

    async fn process_log(&mut self, git: &Git, report: &mut SyncReport) -> Result<()> {
        let s = self.require_state()?;
        if s.conflict.is_some() {
            return Ok(());
        }
        let Some(entries) = self.fetch_log(s.seq).await? else {
            // The token was rotated in a membership change this device never
            // received (it expired, or the relay dropped it). Members answer
            // a history request with the current state, secret included; a
            // removed device gets no answer.
            self.token_lost = true;
            report.waiting_for = Some(s.seq.saturating_add(1));
            self.maybe_request_history(s.seq.saturating_add(1), &s)?;
            return Ok(());
        };
        self.apply_entries(git, entries, report).await
    }

    /// Verify and apply log entries in order, stopping at the first gap.
    async fn apply_entries(&mut self, git: &Git, entries: Vec<Vec<u8>>, report: &mut SyncReport) -> Result<()> {
        for bytes in entries {
            let mut s = self.require_state()?;
            let Ok(e) = LogEntry::decode(bytes.as_slice()) else {
                self.set_conflict(format!("the relay served a malformed log entry after seq {}", s.seq))?;
                return Ok(());
            };
            // The chain first: an entry that doesn't extend our log is the
            // relay's doing, whatever version it claims.
            if e.seq != s.seq.saturating_add(1) || e.prev_head != s.head {
                self.set_conflict(format!(
                    "relay log does not extend our view at seq {} (fork or tampering)",
                    s.seq
                ))?;
                return Ok(());
            }
            // Entries are written at the repo's protocol, and the protocol
            // only rises once every member device (this one included) says
            // it supports the new one. So while we're a member, an entry
            // claiming a newer version than the repo uses can't come from an
            // honest member: the relay made it, or showed us another log.
            if e.version > s.roster.protocol {
                self.set_conflict(format!(
                    "log entry {} claims protocol {}, but this repo uses {} and can't move past what every member \
                     (this device included) supports: the relay is showing us a log members didn't write",
                    e.seq, e.version, s.roster.protocol
                ))?;
                return Ok(());
            }
            // Older than the repo now uses is never valid.
            if e.version < e2ee_proto::MIN_PROTOCOL_VERSION || e.version < s.roster.protocol {
                self.set_conflict(format!(
                    "log entry {} uses protocol {}, older than this repo's {}",
                    e.seq, e.version, s.roster.protocol
                ))?;
                return Ok(());
            }
            let head = log_head(&bytes).to_vec();
            // The relay can't tell what an entry is. A heartbeat commits to
            // our current view; anything else must match an envelope.
            let commit = |kind: u32, view: &[u8]| log_commitment(&self.repo_id, e.seq, kind, view, &e.nonce, e.version).as_slice() == e.commitment;
            let kind = if commit(log_kind::HEARTBEAT, &s.view) {
                log_kind::HEARTBEAT
            } else if commit(log_kind::CLAIM, &s.view) {
                log_kind::CLAIM
            } else {
                log_kind::PUSH
            };
            match kind {
                log_kind::PUSH => {
                    let Some(EntryEnvelope { msg_id, own, author, env }) = self.envelope_for(&e)? else {
                        report.waiting_for = Some(e.seq);
                        self.request_resend(e.seq, &s)?;
                        self.maybe_request_history(e.seq, &s)?;
                        return Ok(());
                    };
                    // The view the entry commits to, if this envelope is it
                    // (an empty view never matches: equivocation is caught).
                    let (env_kind, env_view) = envelope_kind_view(&env).unwrap_or((0, vec![]));
                    // The view also binds the author, which must be who sent it.
                    let by_author = envelope_author(&env).is_some_and(|a| a == author);
                    let view = if by_author && commit(env_kind, &env_view) { env_view } else { vec![] };
                    let e = Resolved { seq: e.seq, view };
                    let (refs_before, roster_before) = (s.refs.clone(), s.roster.clone());
                    let result = match env.body.clone() {
                        Some(Body::Push(p)) => self.apply_push(git, &mut s, &e, &p, own).await,
                        Some(Body::RosterChange(rc)) => self.apply_roster(&mut s, &e, &rc, own, report).await,
                        _ => Err(anyhow!("envelope kind does not match log entry {}", e.seq)),
                    };
                    if let Err(err) = result {
                        // The relay failing to serve a chunk is not evidence
                        // of misbehaviour by a member: retry on the next sync.
                        if crate::client::is_transient(&err) && err.downcast_ref::<BadBundle>().is_none() {
                            // A pack that expired while we were away is
                            // explained by the "behind" note, not a warning.
                            let expired = format!("{err:#}").contains("404")
                                && (self.long_absence || self.history_requested()?);
                            if !expired {
                                report.warnings.push(format!("could not apply entry {} yet: {err:#}", e.seq));
                            }
                            report.waiting_for = Some(e.seq);
                            return Ok(());
                        }
                        self.set_conflict(format!("rejected entry {}: {err:#}", e.seq))?;
                        return Ok(());
                    }
                    s.seq = e.seq;
                    s.head = head.clone();
                    s.view = e.view.clone();
                    s.last_log_at_ms = now_ms();
                    self.save_state(&s)?;
                    self.clear_stuck()?;
                    // Someone new now receives everything pushed: say so.
                    if !own {
                        self.announce_new_members(&roster_before, &s.roster, Some(&author.0), report)?;
                    }
                    // Force pushes are flagged whether or not the push log
                    // is kept (it only records them).
                    let mut changes = ref_changes(&refs_before, &s.refs);
                    self.mark_forced(git, &mut changes)?;
                    if !own {
                        for c in changes.iter().filter(|c| c.forced) {
                            report.warnings.push(format!(
                                "user {} force-pushed {} ({} commit(s) no longer reachable from it); your old commits are still \
                                 in your local repo{}",
                                short(&author.0),
                                c.name,
                                c.dropped,
                                if self.push_log { ", and `git e2ee log` shows who changed what" } else { "" }
                            ));
                        }
                    }
                    if self.push_log {
                        // Log entries carry no time (the relay stores them);
                        // use the authenticated send time of the envelope.
                        let at_ms = if env.sent_ms > 0 { env.sent_ms.min(now_ms()) } else { now_ms() };
                        let entry = PushLogEntry {
                            seq: e.seq,
                            at_ms,
                            user_id: author.0,
                            device_id: author.1,
                            changes,
                            note: roster_note(&roster_before, &s.roster),
                            ..Default::default()
                        };
                        let timer_change = roster_before.log_ttl_secs != s.roster.log_ttl_secs;
                        self.record_log_entry(entry, s.roster.log_ttl_secs, timer_change)?;
                    }
                    self.record_proof(e.seq, &env)?;
                    if let Some(id) = msg_id {
                        self.delete_inbox(&id)?;
                    }
                    if own {
                        self.fan_out_own(e.seq, &env)?;
                    }
                    // Everyone acks, the author included (so the one device
                    // not acking doesn't reveal the author), but only once per
                    // sync, for the newest entry: views chain, so that ack
                    // confirms every earlier entry too.
                    self.pending_ack = true;
                    report.applied += 1;
                }
                log_kind::HEARTBEAT => {
                    s.seq = e.seq;
                    s.head = head;
                    s.last_log_at_ms = now_ms();
                    self.save_state(&s)?;
                }
                log_kind::CLAIM => {
                    // Someone is sending history to a stuck device. Its
                    // announcement (who, for whom) is checked against this
                    // nonce when it arrives.
                    s.seq = e.seq;
                    s.head = head;
                    s.last_log_at_ms = now_ms();
                    self.save_state(&s)?;
                    self.db().execute(
                        "INSERT OR REPLACE INTO claim_entries (repo_id, seq, nonce) VALUES (?1, ?2, ?3)",
                        params![self.repo_id, e.seq as i64, e.nonce],
                    )?;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    /// The envelope describing log entry `seq`: our own, or from the inbox.
    /// Prefers one whose view matches the log; a mismatching one is returned
    /// only if nothing matches, so applying it records the conflict.
    fn envelope_for(&self, e: &LogEntry) -> Result<Option<EntryEnvelope>> {
        let seq = e.seq;
        let matches = |env: &Envelope| {
            envelope_kind_view(env).is_some_and(|(k, v)| {
                log_commitment(&self.repo_id, seq, k, &v, &e.nonce, e.version).as_slice() == e.commitment
            })
        };
        let own: Option<Vec<u8>> = self
            .db()
            .query_row(
                "SELECT envelope FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                params![self.repo_id, seq as i64],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(b) = own {
            let env = Envelope::decode(b.as_slice())?;
            if matches(&env) {
                return Ok(Some(EntryEnvelope { msg_id: None, own: true, author: (self.dev.user.clone(), self.dev.device_id), env }));
            }
            // Our append for this seq never landed (crash or lost race).
            self.db().execute(
                "DELETE FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                params![self.repo_id, seq as i64],
            )?;
        }
        let roster = self.require_state()?.roster;
        let mut fallback = None;
        for (id, author, author_dev, env) in self.inbox()? {
            if !roster.members.iter().any(|m| m.user_id == author) {
                continue; // only current members can author the next entry
            }
            if envelope_author(&env).is_some_and(|a| a != (author.clone(), author_dev)) {
                continue; // someone else's entry, forwarded: not evidence of anything
            }
            let item = |env| EntryEnvelope { msg_id: Some(id.clone()), own: false, author: (author.clone(), author_dev), env };
            match envelope_seq_view(&env) {
                Some((s, _)) if s == seq && matches(&env) => return Ok(Some(item(env))),
                Some((s, _)) if s == seq && fallback.is_none() => fallback = Some(item(env)),
                _ => {}
            }
        }
        Ok(fallback)
    }

    /// Send our own applied entry to its recipients, once.
    fn fan_out_own(&self, seq: u64, env: &Envelope) -> Result<()> {
        let row: Option<(Vec<u8>, i64)> = self
            .db()
            .query_row(
                "SELECT recipients, fanned_out FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                params![self.repo_id, seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((recips, 0)) = row else { return Ok(()) };
        let list = RecipientList::decode(recips.as_slice())?;
        let to: Vec<(Vec<u8>, u32)> = list.users.into_iter().zip(list.devices).collect();
        let (honest, targeted) = test_hooks::split_equivocation(&to);
        self.queue(&honest, env)?;
        if !targeted.is_empty() {
            self.queue(&targeted, &test_hooks::equivocate(&self.repo_id, env))?;
        }
        self.db().execute(
            "UPDATE own_entries SET fanned_out = 1 WHERE repo_id = ?1 AND seq = ?2",
            params![self.repo_id, seq as i64],
        )?;
        Ok(())
    }

    fn request_resend(&self, seq: u64, s: &RepoState) -> Result<()> {
        let last: Option<i64> = self
            .db()
            .query_row(
                "SELECT at_ms FROM resend_requests WHERE repo_id = ?1 AND seq = ?2",
                params![self.repo_id, seq as i64],
                |r| r.get(0),
            )
            .optional()?;
        let interval = env_secs("E2EE_RESEND_SECS", 30) * 1000;
        if last.is_some_and(|t| now_ms().saturating_sub(t as u64) < interval) {
            return Ok(());
        }
        self.db().execute(
            "INSERT OR REPLACE INTO resend_requests (repo_id, seq, at_ms) VALUES (?1, ?2, ?3)",
            params![self.repo_id, seq as i64, now_ms() as i64],
        )?;
        let others = self.others(&self.recipients(&s.roster)?);
        self.queue(&others, &self.envelope(Body::ResendRequest(ResendRequest { seq })))
    }

    /// Was this device away longer than the relay keeps mail? Then what was
    /// sent meanwhile has expired: say so, ask for history at once, and don't
    /// read the silence as a freeze attack.
    async fn detect_absence(&mut self, report: &mut SyncReport) {
        let repo = hex::encode(&self.repo_id);
        let Ok(Some(prev)) = self.dev.db.meta_u64(&format!("last-sync:{repo}")) else { return };
        let away = now_ms().saturating_sub(prev);
        // Only ask the relay once it could matter (its lifetime is days).
        if away < 2 * 24 * 3600 * 1000 {
            return;
        }
        let ttl_key = format!("relay-ttl:{}", self.relay_url);
        let ttl_ms = match self.relay.info().await {
            Ok(i) if i.mail_ttl_secs > 0 => {
                let _ = self.dev.db.meta_set_u64(&ttl_key, i.mail_ttl_secs * 1000);
                i.mail_ttl_secs * 1000
            }
            _ => self.dev.db.meta_u64(&ttl_key).ok().flatten().unwrap_or(14 * 24 * 3600 * 1000),
        };
        // The relay says how long it keeps mail; don't let a tiny figure make
        // every short gap look like a long absence (which would mute the
        // freeze check). Never less than the staleness limit.
        let ttl_ms = ttl_ms.max(env_secs("E2EE_MAX_STALENESS_SECS", 7 * 24 * 3600) * 1000);
        if away <= ttl_ms {
            return;
        }
        self.long_absence = true;
        let _ = self.dev.db.meta_set_u64(&format!("online-since:{repo}"), now_ms());
        report.notes.push(format!(
            "this device last synced this repo {} ago, longer than the relay keeps mail ({}), so what was \
             sent meanwhile has expired",
            fmt_age(away),
            fmt_age(ttl_ms)
        ));
    }

    /// We got past where we were stuck (by any route): forget the markers.
    fn clear_stuck(&self) -> Result<()> {
        let repo = hex::encode(&self.repo_id);
        self.dev.db.conn().execute("DELETE FROM meta WHERE k LIKE ?1", [format!("stuck-since:{repo}:%")])?;
        self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [format!("history-requested:{repo}")])?;
        Ok(())
    }

    fn history_requested(&self) -> Result<bool> {
        Ok(self.dev.db.meta_u64(&format!("history-requested:{}", hex::encode(&self.repo_id)))?.is_some())
    }

    /// What to tell the user when stuck at `seq`.
    fn behind_note(&self, seq: u64) -> Result<Option<String>> {
        if self.token_lost {
            return Ok(Some(
                "can't read this repo's log: the relay no longer accepts its access secret. A member changed \
                 the membership and this device missed the message with the new secret, so it asked the other \
                 members for the current state. Ask another member to run `git e2ee sync` in this repo, then \
                 run `git pull` again. (If you were removed from the repo, nobody will answer.)"
                    .into(),
            ));
        }
        if !self.history_requested()? {
            return Ok(None);
        }
        Ok(Some(format!(
            "behind at log entry {seq}: its message is no longer available, so this device asked the other \
             members for the current state. Ask another member to run `git e2ee sync` in this repo, then run \
             `git pull` again"
        )))
    }

    /// For `git e2ee status`: how far behind we are and what's being done.
    pub fn behind_status(&self) -> Result<Option<String>> {
        let repo = hex::encode(&self.repo_id);
        let now = now_ms();
        let stuck: Option<(String, Vec<u8>)> = self
            .dev
            .db
            .conn()
            .query_row(
                "SELECT k, v FROM meta WHERE k LIKE ?1 ORDER BY k LIMIT 1",
                [format!("stuck-since:{repo}:%")],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((k, v)) = stuck else { return Ok(None) };
        let seq = k.rsplit(':').next().unwrap_or("?").to_string();
        let since = u64::from_be_bytes(v.try_into().unwrap_or([0; 8]));
        let asked = self.dev.db.meta_u64(&format!("history-requested:{repo}"))?;
        Ok(Some(match asked {
            Some(t) => format!(
                "stuck at entry {seq} for {}; asked the other members for the current state {} ago. Ask another \
                 member to run `git e2ee sync` in this repo, then run `git pull` again",
                fmt_age(now.saturating_sub(since)),
                fmt_age(now.saturating_sub(t))
            ),
            None => format!(
                "waiting {} for entry {seq}'s message; if it doesn't come, this device asks the other members \
                 for the current state",
                fmt_age(now.saturating_sub(since))
            ),
        }))
    }

    /// Stuck at an entry for a long time (its message and pack have likely
    /// expired, e.g. after we were offline for weeks): ask two random member
    /// devices for a history bundle, again every interval until one comes.
    fn maybe_request_history(&self, seq: u64, s: &RepoState) -> Result<()> {
        let repo = hex::encode(&self.repo_id);
        let since_key = format!("stuck-since:{repo}:{seq}");
        let now = now_ms();
        let since = match self.dev.db.meta_u64(&since_key)? {
            Some(t) => t,
            None => {
                self.dev.db.meta_set_u64(&since_key, now)?;
                now
            }
        };
        let interval = env_secs("E2EE_HISTORY_AFTER_SECS", 3600) * 1000;
        // How long we wait before asking, and between asks.
        let (wait, repeat) = if self.long_absence || self.token_lost {
            // We know why we're stuck (what was sent meanwhile has expired, or
            // we can't even read the log): ask at once, but not on every
            // sync, so a device syncing in a loop (or a removed one, which
            // never gets an answer) can't flood members' mailboxes.
            (0, env_secs("E2EE_HISTORY_REPEAT_SECS", 300) * 1000)
        } else {
            (interval, interval)
        };
        let asked_key = format!("history-requested:{repo}");
        let asked = self.dev.db.meta_u64(&asked_key)?;
        if now.saturating_sub(since) < wait || asked.is_some_and(|t| now.saturating_sub(t) < repeat) {
            return Ok(());
        }
        // Ask every member device: claims in the log make sure only one
        // answers. Claimants who claimed for us but never delivered are
        // excluded from claiming again.
        let others = self.others(&self.recipients(&s.roster)?);
        let claim_secs = env_secs("E2EE_CLAIM_SECS", 3600) * 1000;
        let exclude: Vec<DeviceRef> = {
            let mut st = self.db().prepare(
                "SELECT claimant_user, claimant_dev FROM claims_for_me WHERE repo_id = ?1 AND received_ms <= ?2",
            )?;
            st.query_map(params![self.repo_id, now.saturating_sub(claim_secs) as i64], |r| {
                Ok(DeviceRef { user: r.get(0)?, device: r.get::<_, i64>(1)? as u32 })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        self.dev.db.meta_set_u64(&asked_key, now)?;
        self.queue(&others, &self.envelope(Body::HistoryRequest(HistoryRequest { seq: s.seq, exclude })))
    }

    /// Store a push-log entry. `ttl_secs`: the repo's disappearing-log timer
    /// when it happened, which fixes when it disappears (later changes don't
    /// move that). `timer_change`: it's the notice of a new timer instead,
    /// kept until the next change replaces it.
    fn record_log_entry(&self, mut entry: PushLogEntry, ttl_secs: u64, timer_change: bool) -> Result<()> {
        if timer_change {
            self.db().execute("DELETE FROM push_log WHERE repo_id = ?1 AND timer = 1", [&self.repo_id])?;
            entry.timer = true;
            entry.expires_ms = 0;
        } else {
            entry.expires_ms = if ttl_secs == 0 { 0 } else { entry.at_ms.saturating_add(ttl_secs.saturating_mul(1000)) };
        }
        self.store_log_row(&entry, None)
    }

    /// Insert a push-log row as is (`source`: the member whose account it
    /// is, for inherited ones).
    fn store_log_row(&self, entry: &PushLogEntry, source: Option<&[u8]>) -> Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO push_log (repo_id, seq, entry, inherited, source, expires_ms, timer) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.repo_id, entry.seq as i64, entry.encode_to_vec(), source.is_some(), source, entry.expires_ms as i64, entry.timer],
        )?;
        Ok(())
    }

    /// Delete push-log entries whose time is up. Deleted rows are
    /// overwritten (`secure_delete`), and the write-ahead log is emptied so
    /// no copy lingers there.
    pub fn prune_push_log(&self) -> Result<()> {
        let n = self.db().execute(
            "DELETE FROM push_log WHERE repo_id = ?1 AND expires_ms > 0 AND expires_ms <= ?2",
            params![self.repo_id, now_ms() as i64],
        )?;
        if n > 0 {
            let _ = self.db().query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        }
        Ok(())
    }

    fn record_claim(&self, seq: u64, claimant: (&[u8], u32), target: (&[u8], u32)) -> Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO history_claims (repo_id, seq, claimant_user, claimant_dev, target_user, target_dev, at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.repo_id, seq as i64, claimant.0, claimant.1 as i64, target.0, target.1 as i64, now_ms() as i64],
        )?;
        if self.push_log {
            let entry = PushLogEntry {
                seq,
                at_ms: now_ms(),
                user_id: claimant.0.to_vec(),
                device_id: claimant.1,
                changes: vec![],
                note: format!("sent history to {}.{}", short(target.0), target.1),
                ..Default::default()
            };
            let ttl = self.state()?.map(|s| s.roster.log_ttl_secs).unwrap_or(0);
            self.record_log_entry(entry, ttl, false)?;
        }
        Ok(())
    }

    /// The highest entry a device has acknowledged to us.
    fn acked_seq(&self, user: &[u8], device: u32) -> Result<u64> {
        Ok(self
            .db()
            .query_row(
                "SELECT MAX(seq) FROM acks WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                params![self.repo_id, user, device as i64],
                |r| r.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(0) as u64)
    }

    /// A claim whose interval passed while its target still hadn't caught up.
    fn failed_claim(&self, claimant: (&[u8], u32), target: (&[u8], u32), interval: u64) -> Result<bool> {
        let acked = self.acked_seq(target.0, target.1)?;
        let cutoff = now_ms().saturating_sub(interval) as i64;
        Ok(self
            .db()
            .query_row(
                "SELECT 1 FROM history_claims WHERE repo_id = ?1 AND claimant_user = ?2 AND claimant_dev = ?3
                 AND target_user = ?4 AND target_dev = ?5 AND at_ms <= ?6 AND seq > ?7",
                params![self.repo_id, claimant.0, claimant.1 as i64, target.0, target.1 as i64, cutoff, acked as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Answer stuck devices' history requests, coordinated through the log:
    /// claim with a log entry first (compare-and-swap makes it a lock, so
    /// one member uploads, not all), then send the bundle. Others stand down
    /// while a claim is fresh, unless its claimant already failed this
    /// device once. Claims only coordinate: the stuck device accepts any
    /// valid bundle.
    async fn answer_history_requests(&mut self, report: &mut SyncReport) -> Result<()> {
        // How long a claim holds other members off.
        let interval = env_secs("E2EE_CLAIM_SECS", 3600) * 1000;
        type Request = (Vec<u8>, u32, u64, Vec<u8>);
        let requests: Vec<Request> = {
            let mut st = self.db().prepare("SELECT user, device_id, from_seq, exclude FROM history_requests WHERE repo_id = ?1")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u32, r.get::<_, i64>(2)? as u64, r.get(3)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let me = (self.dev.user.clone(), self.dev.device_id);
        for (user, dev, from_seq, exclude) in requests {
            let s = self.require_state()?;
            let db = self.dev.db.clone();
            let repo_id = self.repo_id.clone();
            let done = || {
                db.conn().execute(
                    "DELETE FROM history_requests WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                    params![repo_id, user, dev as i64],
                )
            };
            let member = s.roster.members.iter().any(|m| m.user_id == user);
            if !member || self.dev.db.device_key(&user, dev)?.is_none() || self.acked_seq(&user, dev)? > from_seq {
                done()?; // gone, or caught up already
                continue;
            }
            let ex = RecipientList::decode(exclude.as_slice()).unwrap_or_default();
            let excluded = ex.users.iter().zip(&ex.devices).any(|(u, d)| *u == me.0 && *d == me.1);
            if excluded || from_seq >= s.seq || s.conflict.is_some() {
                continue;
            }
            // A fresh claim by someone who hasn't failed this device: stand down.
            let cutoff = now_ms().saturating_sub(interval) as i64;
            let fresh: Vec<(Vec<u8>, u32)> = {
                let mut st = self.db().prepare(
                    "SELECT claimant_user, claimant_dev FROM history_claims WHERE repo_id = ?1 AND target_user = ?2 AND target_dev = ?3 AND at_ms > ?4",
                )?;
                st.query_map(params![self.repo_id, user, dev as i64, cutoff], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u32)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut someone_on_it = false;
            for (cu, cd) in &fresh {
                if !self.failed_claim((cu, *cd), (&user, dev), interval)? {
                    someone_on_it = true;
                }
            }
            if someone_on_it || self.failed_claim((&me.0, me.1), (&user, dev), interval)? {
                continue;
            }
            // Claim: a log entry committing to the unchanged view.
            let seq = next_seq(s.seq)?;
            let salt = random_bytes::<16>().to_vec();
            let nonce = e2ee_proto::claim_nonce(&self.repo_id, seq, (&me.0, me.1), (&user, dev), &salt);
            let entry = LogEntry {
                seq,
                prev_head: s.head.clone(),
                commitment: log_commitment(&self.repo_id, seq, log_kind::CLAIM, &s.view, &nonce, s.roster.protocol).to_vec(),
                version: s.roster.protocol,
                nonce: nonce.clone(),
            };
            let bytes = entry.encode_to_vec();
            let access = self.take_tokens(api::cost::LOG_APPEND).await?;
            match self.relay.append(&self.rid, &self.token()?, &access, &bytes, None).await? {
                Append::Conflict => continue, // someone appended first; look again next sync
                Append::Ok => {}
            }
            let mut s2 = s.clone();
            s2.seq = seq;
            s2.head = log_head(&bytes).to_vec();
            s2.last_log_at_ms = now_ms();
            self.save_state(&s2)?;
            self.db().execute(
                "INSERT OR REPLACE INTO claim_entries (repo_id, seq, nonce) VALUES (?1, ?2, ?3)",
                params![self.repo_id, seq as i64, nonce],
            )?;
            self.record_claim(seq, (&me.0, me.1), (&user, dev))?;
            let announce = HistoryClaim { seq, target: Some(DeviceRef { user: user.clone(), device: dev }), salt };
            let others = self.others(&self.recipients(&s2.roster)?);
            self.queue(&others, &self.envelope(Body::HistoryClaim(announce)))?;
            if cfg!(debug_assertions) && std::env::var("E2EE_TEST_CLAIM_WITHOUT_SENDING").is_ok() {
                // Test hook: a member that claims but never delivers.
                done()?;
                continue;
            }
            self.send_history(&[(user.clone(), dev)]).await?;
            report.notes.push(format!("sent history to {}.{dev}, which had fallen behind", short(&user)));
            done()?;
        }
        Ok(())
    }

    /// If we asked for history: take a bundle from a current member that is
    /// ahead of us *on our chain*. The relay log must show our own last
    /// verified head at our position and an unbroken hash chain from there to
    /// the bundle's position. For the entries in between we take the sender's
    /// word for the refs, as a newcomer takes its inviter's.
    async fn catch_up(&mut self, report: &mut SyncReport) -> Result<()> {
        let asked_key = format!("history-requested:{}", hex::encode(&self.repo_id));
        if self.dev.db.meta_u64(&asked_key)?.is_none() {
            return Ok(());
        }
        let s = self.require_state()?;
        // A conflict stops the repo until the user clears it: a bundle must
        // not quietly replace the state it is about.
        if s.conflict.is_some() {
            return Ok(());
        }
        for (msg_id, sender, sender_dev, env) in self.inbox()? {
            let Some(Body::HistoryBundle(hb)) = env.body else { continue };
            let Some(roster) = hb.roster.clone() else { continue };
            if hb.seq <= s.seq || !s.roster.members.iter().any(|m| m.user_id == sender) {
                continue;
            }
            let ok: Result<()> = async {
                if !roster.members.iter().any(|m| m.user_id == self.dev.user) {
                    bail!("it doesn't include us");
                }
                if roster.genesis_secret != s.roster.genesis_secret || !e2ee_proto::roster_is_for(&roster, &self.repo_id) {
                    bail!("its roster isn't this repo's");
                }
                if roster.object_format != s.roster.object_format
                    || roster.protocol < s.roster.protocol
                    || roster.version < s.roster.version
                {
                    bail!("its roster changes the format, downgrades the protocol or rolls back");
                }
                let token = e2ee_proto::delivery_token(&roster.repo_secret).to_vec();
                let entries = self
                    .relay
                    .log_since(&self.rid, &token, s.seq.saturating_sub(1))
                    .await?
                    .ok_or_else(|| anyhow!("the relay rejects the bundle's repo token"))?;
                let mut prev: Option<(u64, Vec<u8>)> = None;
                for bytes in &entries {
                    let e = LogEntry::decode(bytes.as_slice())?;
                    let head = log_head(bytes).to_vec();
                    match &prev {
                        None if s.seq > 0 => {
                            if e.seq != s.seq || head != s.head {
                                bail!("the relay log no longer contains our verified head (fork?)");
                            }
                        }
                        None => {}
                        Some((pseq, phead)) if pseq.checked_add(1) != Some(e.seq) || &e.prev_head != phead => {
                            bail!("the relay log is not one chain");
                        }
                        Some(_) => {}
                    }
                    prev = Some((e.seq, head));
                    if e.seq == hb.seq {
                        break;
                    }
                }
                if prev.as_ref().is_none_or(|(seq, head)| *seq != hb.seq || *head != hb.log_head) {
                    bail!("it isn't on our chain of the relay log");
                }
                Ok(())
            }
            .await;
            if let Err(e) = ok {
                report.warnings.push(format!("ignored a history bundle from {}.{sender_dev}: {e:#}", short(&sender)));
                self.delete_inbox(&msg_id)?;
                continue;
            }
            match self.apply_bundle(hb, roster, &sender, report).await {
                Ok(()) => {
                    // What changed in the entries we skipped is announced as
                    // if we had applied them one by one.
                    let after = self.require_state()?;
                    self.roster_transition(&s.roster, &after.roster)?;
                    // Someone may have been removed and re-added in the
                    // entries we skipped (the rosters alone can't show it):
                    // any membership change means moving our mailboxes.
                    if after.roster.version > s.roster.version {
                        self.dev.db.meta_set(&format!("mailbox-rotate:{}", hex::encode(&self.repo_id)), b"1")?;
                    }
                    self.announce_new_members(&s.roster, &after.roster, None, report)?;
                    self.delete_inbox(&msg_id)?;
                    self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [&asked_key])?;
                    self.clear_stuck()?;
                    self.db().execute("DELETE FROM claims_for_me WHERE repo_id = ?1", [&self.repo_id])?;
                    // Tell members we're current (claims count as delivered).
                    self.pending_ack = true;
                    report.notes.push(format!(
                        "caught up: {}.{sender_dev} sent the current state. Who pushed what while this device \
                         was away is their account (`git e2ee log` marks it as inherited)",
                        short(&sender)
                    ));
                    return Ok(());
                }
                Err(e) if e.downcast_ref::<BadBundle>().is_some() => {
                    report.warnings.push(format!("discarded a history bundle from {}.{sender_dev}: {e:#}", short(&sender)));
                    self.delete_inbox(&msg_id)?;
                }
                // Not this bundle's fault (needs a newer build, network
                // trouble): keep it for later, and try the others.
                Err(e) => report.warnings.push(format!("could not use a history bundle from {}.{sender_dev} yet: {e:#}", short(&sender))),
            }
        }
        Ok(())
    }

    /// Mark ref moves that aren't fast-forwards (the new value doesn't
    /// contain the old one), counting the commits that became unreachable
    /// from the ref. Both values are in the mirror: the old one was part of
    /// the view, the new one was just imported. A deleted ref's last value is
    /// remembered, so deleting a branch and creating it again elsewhere in a
    /// later push counts as the force push it is.
    fn mark_forced(&self, git: &Git, changes: &mut [e2ee_proto::RefChange]) -> Result<()> {
        let key = |name: &str| format!("deleted-ref:{}:{name}", hex::encode(&self.repo_id));
        for c in changes.iter_mut() {
            if c.new_oid.is_empty() {
                // Remembering deleted refs is part of the local push log:
                // with `e2ee.pushLog` off, nothing about refs is kept (and a
                // delete then recreate isn't recognised).
                if !c.old_oid.is_empty() && self.push_log {
                    self.dev.db.meta_set(&key(&c.name), c.old_oid.as_bytes())?;
                }
                continue;
            }
            let old = if c.old_oid.is_empty() {
                let Some(prev) = self.dev.db.meta_get(&key(&c.name))? else { continue };
                self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [key(&c.name)])?;
                String::from_utf8(prev).unwrap_or_default()
            } else {
                c.old_oid.clone()
            };
            if !old.is_empty() && !git.is_ancestor(&old, &c.new_oid).unwrap_or(false) {
                c.forced = true;
                c.dropped = git.count_commits(&old, &c.new_oid).unwrap_or(0);
            }
        }
        Ok(())
    }

    /// The signed device lists of everyone in `roster` we know of.
    fn signed_lists(&self, roster: &Roster) -> Vec<SignedDeviceList> {
        roster
            .members
            .iter()
            .filter_map(|m| self.dev.db.signed_device_list(&m.user_id).ok().flatten())
            .filter_map(|b| SignedDeviceList::decode(b.as_slice()).ok())
            .collect()
    }

    /// Adopt newer device lists carried in an envelope (members only; each
    /// list is verified against that member's pinned master key).
    fn adopt_lists(&self, roster: &Roster, lists: &[SignedDeviceList]) {
        for signed in lists {
            let Ok(body) = e2ee_proto::DeviceListBody::decode(signed.body.as_slice()) else { continue };
            if roster.members.iter().any(|m| m.user_id == body.user_id) {
                // Older or identical lists are ignored; a fork surfaces later
                // as a recipient-set mismatch.
                let _ = self.dev.accept_device_list(&body.user_id, signed);
            }
        }
    }

    fn check_recipients(&self, roster: &Roster, claimed: &[u8]) -> Result<()> {
        let ours = recipients_hash(&self.recipients(roster)?);
        if ours.as_slice() != claimed {
            bail!("sender's recipient device set differs from our verified device lists (extra or missing devices)");
        }
        Ok(())
    }

    async fn apply_push(&mut self, git: &Git, s: &mut RepoState, e: &Resolved, p: &Push, own: bool) -> Result<()> {
        if !own {
            check_refs(&p.refs, &p.head_ref, &s.roster.object_format, Some(&s.refs))?;
        }
        if p.seq != e.seq || push_view(&self.repo_id, p).as_slice() != p.view || p.view != e.view {
            bail!("push envelope does not match the log entry's view (equivocation?)");
        }
        if sha256(&p.pack_key).as_slice() != p.pack_key_hash {
            bail!("push carries a different pack key than its view commits to");
        }
        if p.prev_view != s.view {
            bail!("push does not build on our current view");
        }
        if p.roster_hash != roster_hash(&s.roster) {
            bail!("pusher has a different member roster");
        }
        if !own {
            self.adopt_lists(&s.roster, &p.device_lists);
            self.check_recipients(&s.roster, &p.recipients_hash)?;
            self.download_pack(git, &p.pack_key, &p.blob_ids, &p.chunk_hashes, &p.pack_hash).await?;
            for r in &p.refs {
                if !git.has_object(&r.oid) {
                    bail!("push references missing object {}", r.oid);
                }
            }
        }
        s.refs = p.refs.clone();
        s.head_ref = p.head_ref.clone();
        Ok(())
    }

    async fn apply_roster(&mut self, s: &mut RepoState, e: &Resolved, rc: &RosterChange, own: bool, report: &mut SyncReport) -> Result<()> {
        let roster = rc.roster.clone().ok_or_else(|| anyhow!("roster change without roster"))?;
        if roster.protocol < s.roster.protocol {
            bail!("roster change would downgrade the repo's protocol version");
        }
        if roster.object_format != s.roster.object_format {
            bail!("roster change would change the repo's object format");
        }
        if roster.genesis_secret != s.roster.genesis_secret {
            bail!("roster change would change the repo's genesis secret");
        }
        if rc.seq != e.seq || roster_view(&self.repo_id, rc).as_slice() != rc.view || rc.view != e.view {
            bail!("roster envelope does not match the log entry's view (equivocation?)");
        }
        if rc.prev_view != s.view {
            bail!("roster change does not build on our current view");
        }
        if roster.version <= s.roster.version {
            bail!("roster version did not increase");
        }
        // A protocol switch is valid only once every member device says it
        // supports the new version (in its signed device list). Ours says
        // ours, so a version newer than this build can't pass: that's a bad
        // change, not a reason to stall on "upgrade".
        if roster.protocol > s.roster.protocol {
            for m in &roster.members {
                let max = self.max_protocol_of(&m.user_id)?;
                if max < roster.protocol {
                    bail!(
                        "roster change raises the protocol to {}, which a device of user {} doesn't support (max {max})",
                        roster.protocol,
                        short(&m.user_id)
                    );
                }
            }
        }
        // Pin new members (needed to check their device lists), but undo
        // that if the change turns out to be bad.
        let mut new_pins = vec![];
        for m in &roster.members {
            if self.dev.db.pinned(&m.user_id)?.is_none() {
                new_pins.push(m.user_id.clone());
            }
            self.dev.db.pin(&m.user_id, &m.master_key, false).context("pinning new member")?;
        }
        self.adopt_lists(&roster, &rc.device_lists);
        if own {
            // We computed the recipient set ourselves.
        } else if roster.members.iter().any(|m| m.user_id == self.dev.user) {
            if let Err(e) = self.check_recipients(&roster, &rc.recipients_hash) {
                for u in &new_pins {
                    self.dev.db.unpin_unverified(u)?;
                }
                return Err(e);
            }
        } else {
            report.warnings.push("this user was removed from the repo".into());
        }
        self.roster_transition(&s.roster, &roster)?;
        s.roster = roster;
        Ok(())
    }

    /// Side effects of moving from roster `old` to `new` (one change, or
    /// several skipped over by a history bundle).
    fn roster_transition(&self, old: &Roster, new: &Roster) -> Result<()> {
        // A member left (or was removed) without the secret being rotated:
        // they still hold it, so a remaining member must rotate it.
        let removed = old.members.iter().any(|m| !new.members.iter().any(|n| n.user_id == m.user_id));
        if removed {
            // The removed member knows our mailbox address: move.
            self.dev.db.meta_set(&format!("mailbox-rotate:{}", hex::encode(&self.repo_id)), b"1")?;
        }
        let key = self.rotation_key();
        if new.repo_secret != old.repo_secret {
            self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [&key])?;
        } else if removed {
            self.dev.db.meta_set(&key, b"1")?;
        }
        self.add_secret(&new.repo_secret)?;
        Ok(())
    }

    /// Warn about members in `new` who weren't in `old`: they receive
    /// everything pushed from now on. `by`: who added them, if known.
    fn announce_new_members(&self, old: &Roster, new: &Roster, by: Option<&[u8]>, report: &mut SyncReport) -> Result<()> {
        for m in new.members.iter().filter(|m| !old.members.iter().any(|b| b.user_id == m.user_id)) {
            if m.user_id == self.dev.user {
                continue;
            }
            let verified = self.dev.db.pinned(&m.user_id)?.is_some_and(|p| p.1);
            let who = match by {
                Some(u) => format!("user {}", short(u)),
                None => "while this device was away, a member".into(),
            };
            report.warnings.push(format!(
                "{who} added user {} to this repo; they receive everything pushed from now on{}",
                short(&m.user_id),
                if verified { "" } else { ". You haven't verified them: if you don't know who they are, ask, or verify them (`git e2ee verify`)" }
            ));
        }
        Ok(())
    }

    /// A member's device that was revoked still knows this repo's token and
    /// our mailbox addresses: if one disappeared since last time, rotate the
    /// repo secret and our mailboxes, as after a member leaving.
    fn note_revoked_devices(&self) -> Result<()> {
        let Some(s) = self.state()? else { return Ok(()) };
        let now: Vec<(Vec<u8>, u32)> = self.recipients(&s.roster)?.into_iter().map(|(u, d, _)| (u, d)).collect();
        let key = format!("member-devices:{}", hex::encode(&self.repo_id));
        let before = self.dev.db.meta_get(&key)?.and_then(|b| RecipientList::decode(b.as_slice()).ok());
        if let Some(before) = before {
            let gone = before.users.iter().zip(&before.devices).any(|(u, d)| {
                s.roster.members.iter().any(|m| &m.user_id == u) && !now.iter().any(|(nu, nd)| nu == u && nd == d)
            });
            if gone {
                self.dev.db.meta_set(&self.rotation_key(), b"1")?;
                self.dev.db.meta_set(&format!("mailbox-rotate:{}", hex::encode(&self.repo_id)), b"1")?;
            }
        }
        let list = RecipientList { users: now.iter().map(|(u, _)| u.clone()).collect(), devices: now.iter().map(|(_, d)| *d).collect() };
        self.dev.db.meta_set(&key, &list.encode_to_vec())?;
        Ok(())
    }

    /// A member device whose signed list says it can't speak the repo's
    /// protocol (added after an upgrade, running an old build) can't take
    /// part until it's upgraded: say so, once per device and version.
    fn warn_outdated_devices(&self, report: &mut SyncReport) -> Result<()> {
        let Some(s) = self.state()? else { return Ok(()) };
        for m in &s.roster.members {
            let Some(signed) = self.dev.db.signed_device_list(&m.user_id)? else { continue };
            let body = e2ee_proto::DeviceListBody::decode(SignedDeviceList::decode(signed.as_slice())?.body.as_slice())?;
            for d in body.devices.iter().filter(|d| d.max_protocol != 0 && d.max_protocol < s.roster.protocol) {
                let key = format!("outdated-device:{}:{}.{}:{}", hex::encode(&self.repo_id), hex::encode(&m.user_id), d.device_id, s.roster.protocol);
                if self.dev.db.meta_get(&key)?.is_none() {
                    self.dev.db.meta_set(&key, b"1")?;
                    report.warnings.push(format!(
                        "device {} of user {} only speaks protocol {}, but this repo uses {}: it can't take part until \
                         it runs a newer git-e2ee",
                        d.device_id,
                        short(&m.user_id),
                        d.max_protocol,
                        s.roster.protocol
                    ));
                }
            }
        }
        Ok(())
    }

    /// The lowest "newest supported protocol" among a user's devices (0 if
    /// we have no list for them).
    fn max_protocol_of(&self, user: &[u8]) -> Result<u32> {
        if user == self.dev.user.as_slice() {
            return Ok(e2ee_proto::PROTOCOL_VERSION);
        }
        let Some(signed) = self.dev.db.signed_device_list(user)? else { return Ok(0) };
        let body = e2ee_proto::DeviceListBody::decode(SignedDeviceList::decode(signed.as_slice())?.body.as_slice())?;
        Ok(body.devices.iter().map(|d| d.max_protocol).min().unwrap_or(0))
    }

    fn rotation_key(&self) -> String {
        format!("rotate-pending:{}", hex::encode(&self.repo_id))
    }

    /// After someone left: rotate the repo secret so they're cut off from
    /// everything pushed from now on. Any remaining member's device does it
    /// on its next sync; if several race, the log takes one and the others'
    /// attempts fail and are dropped.
    async fn rotate_if_pending(&mut self, report: &mut SyncReport) {
        let Ok(Some(_)) = self.dev.db.meta_get(&self.rotation_key()) else { return };
        let Ok(Some(s)) = self.state() else { return };
        if s.conflict.is_some() || !s.roster.members.iter().any(|m| m.user_id == self.dev.user) {
            return;
        }
        match self.change_roster_inner(None, None, true).await {
            Ok(()) => report.notes.push("rotated the repo secret after a member or device left".into()),
            Err(e) if format!("{e:#}").contains("concurrently") => {}
            Err(e) => report.warnings.push(format!("could not rotate the repo secret after a member left: {e:#}")),
        }
    }

    /// Leave the repo. The change removes us but keeps the current secret (we
    /// hold it anyway); the next remaining member to sync rotates it, which
    /// is what cuts us off. Then this device forgets the repo. Returns false
    /// if we were the only member (nothing to announce; just forgotten).
    pub async fn leave(&mut self) -> Result<bool> {
        let s = self.require_state()?;
        if s.roster.members.iter().all(|m| m.user_id == self.dev.user) {
            self.forget().await?;
            return Ok(false);
        }
        self.change_roster_inner(None, Some(self.dev.user.clone()), false).await?;
        self.forget().await?;
        self.dev.db.conn().execute("DELETE FROM meta WHERE k = ?1", [self.rotation_key()])?;
        Ok(true)
    }

    /// Acks, heartbeats, resend requests: compare peers' views with ours.
    /// Returns devices whose sessions must be reset before resending.
    fn process_misc(&mut self, report: &mut SyncReport) -> Result<Vec<DeviceAddr>> {
        let mut reset = Vec::new();
        let Some(s) = self.state()? else { return Ok(reset) };
        let member = |u: &[u8]| s.roster.members.iter().any(|m| m.user_id == u);
        for (id, user, dev, env) in self.inbox()? {
            let who = format!("{}.{dev}", short(&user));
            // Only current members may ack, gossip or ask for resends. (Push
            // and roster envelopes may come from members added later in the
            // log; envelope_for checks their author against the roster.)
            let control = matches!(
                env.body,
                Some(Body::Ack(_) | Body::Heartbeat(_) | Body::ResendRequest(_) | Body::HistoryRequest(_) | Body::HistoryClaim(_))
            );
            if control && !member(&user) {
                self.delete_inbox(&id)?;
                continue;
            }
            match env.body {
                Some(Body::Ack(Ack { seq, view, log_head })) => {
                    if seq > s.seq {
                        report.warnings.push(format!(
                            "member {who} reports log seq {seq} but the relay shows us only {}: the relay may be withholding \
                             updates. Retry later; if it persists, compare `git e2ee status` with that member",
                            s.seq
                        ));
                        continue;
                    }
                    self.compare_peer(seq, &view, &log_head, &who)?;
                    self.db().execute(
                        "INSERT OR REPLACE INTO acks (repo_id, seq, user, device_id, view, head) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![self.repo_id, seq as i64, user, dev as i64, view, log_head],
                    )?;
                    self.delete_inbox(&id)?;
                }
                Some(Body::Heartbeat(Heartbeat { seq, log_head, at_ms })) => {
                    if seq > s.seq {
                        report.warnings.push(format!(
                            "member {who} reports log seq {seq} but the relay shows us only {}: the relay may be withholding \
                             updates. Retry later; if it persists, compare `git e2ee status` with that member",
                            s.seq
                        ));
                        continue;
                    }
                    if let Some((_, head)) = self.history_at(seq)?
                        && head != log_head
                    {
                        self.set_conflict(format!(
                            "member {who} saw a different log head at seq {seq}: the relay is showing members different logs"
                        ))?;
                    }
                    self.db().execute(
                        "INSERT OR REPLACE INTO peer_heartbeats (repo_id, user, device_id, at_ms, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![self.repo_id, user, dev as i64, at_ms as i64, seq as i64],
                    )?;
                    self.delete_inbox(&id)?;
                }
                Some(Body::HistoryRequest(HistoryRequest { seq, exclude })) => {
                    // A member device that can't catch up from the log;
                    // answered (or not) in answer_history_requests.
                    if self.dev.db.device_key(&user, dev)?.is_some() {
                        let ex = RecipientList {
                            users: exclude.iter().map(|d| d.user.clone()).collect(),
                            devices: exclude.iter().map(|d| d.device).collect(),
                        };
                        self.db().execute(
                            "INSERT OR REPLACE INTO history_requests (repo_id, user, device_id, from_seq, exclude, received_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![self.repo_id, user, dev as i64, seq as i64, ex.encode_to_vec(), now_ms() as i64],
                        )?;
                    }
                    self.delete_inbox(&id)?;
                }
                Some(Body::HistoryClaim(c)) => {
                    let Some(t) = c.target.clone() else {
                        self.delete_inbox(&id)?;
                        continue;
                    };
                    if t.user == self.dev.user && t.device == self.dev.device_id {
                        // Someone is sending us history: remember who, so a
                        // claimant that never delivers can be excluded.
                        self.db().execute(
                            "INSERT OR IGNORE INTO claims_for_me (repo_id, claimant_user, claimant_dev, received_ms) VALUES (?1, ?2, ?3, ?4)",
                            params![self.repo_id, user, dev as i64, now_ms() as i64],
                        )?;
                        self.delete_inbox(&id)?;
                        continue;
                    }
                    if c.seq > s.seq {
                        continue; // its log entry isn't applied yet
                    }
                    let nonce: Option<Vec<u8>> = self
                        .db()
                        .query_row(
                            "SELECT nonce FROM claim_entries WHERE repo_id = ?1 AND seq = ?2",
                            params![self.repo_id, c.seq as i64],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let expected = e2ee_proto::claim_nonce(&self.repo_id, c.seq, (&user, dev), (&t.user, t.device), &c.salt);
                    if nonce.as_deref() == Some(expected.as_slice()) {
                        self.record_claim(c.seq, (&user, dev), (&t.user, t.device))?;
                    }
                    self.delete_inbox(&id)?;
                }
                Some(Body::ResendRequest(ResendRequest { seq })) => {
                    let own: Option<(Vec<u8>, Vec<u8>)> = self
                        .db()
                        .query_row(
                            "SELECT envelope, recipients FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                            params![self.repo_id, seq as i64],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    // The envelope holds the pack key: resend it only to a
                    // device that was one of its original recipients and is
                    // still a verified device of a current member.
                    let entitled = |recips: &[u8]| -> Result<bool> {
                        let list = RecipientList::decode(recips)?;
                        let was_recipient = list.users.iter().zip(&list.devices).any(|(u, d)| *u == user && *d == dev);
                        Ok(was_recipient && member(&user) && self.dev.db.device_key(&user, dev)?.is_some())
                    };
                    if let Some((b, recips)) = own
                        && entitled(&recips)?
                    {
                        // The requester could not decrypt our message. If our
                        // session with it names prekeys it has since deleted,
                        // resending on it fails forever (and libsignal's
                        // tiebreak may keep it active), so start a fresh one.
                        let key = format!("session-reset:{}.{dev}", hex::encode(&user));
                        let interval = env_secs("E2EE_SESSION_RESET_SECS", 3600) * 1000;
                        let now = now_ms();
                        if self.dev.db.meta_u64(&key)?.is_none_or(|t| now.saturating_sub(t) >= interval) {
                            reset.push((user.clone(), dev));
                            self.dev.db.meta_set_u64(&key, now)?;
                        }
                        self.queue(&[(user.clone(), dev)], &Envelope::decode(b.as_slice())?)?;
                    }
                    self.delete_inbox(&id)?;
                }
                Some(Body::Push(_)) | Some(Body::RosterChange(_)) => {
                    let Some((seq, view)) = envelope_seq_view(&env) else { continue };
                    if seq <= s.seq {
                        // A member's copy of an entry we already applied must
                        // match it. (Non-members' claims prove nothing.)
                        if member(&user)
                            && let Some((ours, _)) = self.history_at(seq)?
                            && ours != view
                        {
                            self.set_conflict(format!(
                                "member {who} sent entry {seq} with a different view than our log: \
                                 the relay is showing members different logs, or the member equivocated"
                            ))?;
                        }
                        self.delete_inbox(&id)?;
                    } else if report.waiting_for.is_none() && member(&user) {
                        // Senders append before fanning out, so the log must
                        // already contain this entry.
                        report.warnings.push(format!(
                            "member {who} sent entry {seq} but the relay shows us only up to {}: the relay may be withholding \
                             updates. Retry later; if it persists, compare `git e2ee status` with that member",
                            s.seq
                        ));
                    }
                }
                Some(Body::HistoryBundle(_)) => self.delete_inbox(&id)?,
                // Nothing we know what to do with (a body from a newer build,
                // or none): don't let it sit and take room.
                None => self.delete_inbox(&id)?,
            }
        }
        Ok(reset)
    }

    fn compare_peer(&self, seq: u64, view: &[u8], head: &[u8], who: &str) -> Result<()> {
        if let Some((our_view, our_head)) = self.history_at(seq)? {
            if our_head != head {
                self.set_conflict(format!(
                    "member {who} saw a different log head at seq {seq}: the relay is showing members different logs"
                ))?;
            } else if our_view != view {
                self.set_conflict(format!("member {who} computed a different view at seq {seq} (equivocation)"))?;
            }
        }
        Ok(())
    }

    /// Staleness warnings, then our own heartbeat if due.
    async fn freshness(&mut self, report: &mut SyncReport) -> Result<()> {
        let Some(mut s) = self.state()? else { return Ok(()) };
        if s.conflict.is_some() || !s.roster.members.iter().any(|m| m.user_id == self.dev.user) {
            return Ok(());
        }
        let max_stale = env_secs("E2EE_MAX_STALENESS_SECS", 7 * 24 * 3600) * 1000;
        let now = now_ms();
        // Freeze detection: when did any *other* member device last reach us
        // with authenticated mail? Log entries don't count (the relay can
        // fabricate heartbeat entries or accept ours on a fork), and neither
        // does anything we did ourselves. Active members gossip hourly.
        let others = self.others(&self.recipients(&s.roster)?);
        if !others.is_empty() {
            // Silence only counts while we were syncing: from when we
            // joined, or came back from a long absence, whichever is later.
            if self.long_absence {
                return Ok(());
            }
            let back = self.dev.db.meta_u64(&format!("online-since:{}", hex::encode(&self.repo_id)))?.unwrap_or(0);
            let mut last = self.joined_ms()?.max(back);
            for (u, d) in &others {
                let t: Option<i64> = self
                    .db()
                    .query_row(
                        "SELECT last_ms FROM peer_contact WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                        params![self.repo_id, u, *d as i64],
                        |r| r.get(0),
                    )
                    .optional()?;
                last = last.max(t.unwrap_or(0) as u64);
            }
            if now.saturating_sub(last) > max_stale {
                report.warnings.push(format!(
                    "no other member device has been heard from in {}: the relay may be hiding updates \
                     from you (freeze attack), or everyone has been offline. Ask a collaborator whether they've \
                     pushed recently, and compare `git e2ee status` with them",
                    fmt_age(now.saturating_sub(last))
                ));
            }
        }
        let interval = env_secs("E2EE_HEARTBEAT_SECS", 24 * 3600) * 1000;
        if now.saturating_sub(s.last_heartbeat_ms) < interval || report.waiting_for.is_some() {
            return Ok(());
        }
        let nonce = random_bytes::<16>().to_vec();
        let entry = LogEntry {
            seq: next_seq(s.seq)?,
            prev_head: s.head.clone(),
            commitment: log_commitment(&self.repo_id, next_seq(s.seq)?, log_kind::HEARTBEAT, &s.view, &nonce, s.roster.protocol).to_vec(),
            version: s.roster.protocol,
            nonce,
        };
        let bytes = entry.encode_to_vec();
        // Only the first append (which creates the log) costs tokens.
        let access = self.take_tokens(if s.seq == 0 { api::cost::LOG_CREATE } else { api::cost::LOG_APPEND }).await?;
        match self.relay.append(&self.rid, &self.token()?, &access, &bytes, None).await? {
            Append::Ok => {
                s.seq = entry.seq;
                s.head = log_head(&bytes).to_vec();
                s.last_heartbeat_ms = now;
                s.last_log_at_ms = now;
                self.save_state(&s)?;
                let hb = self.envelope(Body::Heartbeat(Heartbeat { seq: s.seq, log_head: s.head.clone(), at_ms: now }));
                self.queue(&others, &hb)?;
            }
            Append::Conflict => {
                // Someone appended first: fine if the relay now shows us that
                // entry. If it shows nothing newer, the log we see is not the
                // log the relay appends to.
                if self.fetch_log(s.seq).await?.is_some_and(|e| e.is_empty()) {
                    report.warnings.push(
                        "the relay refused our heartbeat but shows no newer log entries: it may be \
                         showing us a frozen or forked log"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }

    /// When this device joined the repo (created it or received its history),
    /// the baseline for "not heard from anyone since".
    fn joined_ms(&self) -> Result<u64> {
        let key = format!("joined:{}", self.rid);
        if let Some(t) = self.dev.db.meta_u64(&key)? {
            return Ok(t);
        }
        let now = now_ms();
        self.dev.db.meta_set_u64(&key, now)?;
        Ok(now)
    }

    /// Debug-build fault injection: act like a misbehaving (e.g. removed)
    /// member, before the rest of the sync can fail.
    async fn test_inject(&mut self, report: &mut SyncReport) -> Result<()> {
        if !cfg!(debug_assertions) {
            return Ok(());
        }
        let Some(s) = self.state()? else { return Ok(()) };
        let others = self.others(&self.recipients(&s.roster)?);
        if let Some(seq) = std::env::var("E2EE_TEST_REQUEST_RESEND").ok().and_then(|v| v.parse().ok()) {
            self.queue(&others, &self.envelope(Body::ResendRequest(ResendRequest { seq })))?;
        }
        if let Some(n) = std::env::var("E2EE_TEST_JUNK_REPOS").ok().and_then(|v| v.parse::<usize>().ok()) {
            for _ in 0..n {
                let junk = Envelope {
                    repo_id: random_bytes::<16>().to_vec(),
                    body: Some(Body::Ack(Ack { seq: 1, view: vec![0; 32], log_head: vec![0; 32] })),
                    ..Default::default()
                };
                self.queue(&others, &junk)?;
            }
        }
        if std::env::var("E2EE_TEST_FORWARD_PUSHES").is_ok() {
            // A member forwarding others' pushes, hoping to be credited.
            for (_, author, _, env) in self.inbox()? {
                if author != self.dev.user && matches!(env.body, Some(Body::Push(_))) {
                    self.queue(&others, &env)?;
                }
            }
        }
        if std::env::var("E2EE_TEST_BOGUS_ACK").is_ok() {
            let ack = Ack { seq: s.seq, view: random_bytes::<32>().to_vec(), log_head: s.head.clone() };
            self.queue(&others, &self.envelope(Body::Ack(ack)))?;
        }
        self.flush_outbox(&mut report.warnings).await
    }

    /// Surface every device-list change since the last run. Added devices are
    /// trusted automatically (their owner's master key signed them), so a
    /// device the owner didn't add means their master device is compromised;
    /// the user should hear about each one.
    fn report_device_changes(&self, report: &mut SyncReport) -> Result<()> {
        for (user, device, added, version) in self.dev.db.take_device_events()? {
            let whose = if user == self.dev.user { "your own user".to_string() } else { format!("user {}", short(&user)) };
            let what = if added { "added" } else { "removed" };
            let mut msg = format!("{whose} {what} device {device} (device list v{version})");
            if added {
                if user == self.dev.user {
                    msg.push_str(&format!(
                        "; if you did not approve this, your master device is compromised: revoke it with \
                         `git e2ee device revoke {device}` on your master device"
                    ));
                } else {
                    msg.push_str(
                        "; if they did not do this, their master device is compromised: ask them over a trusted \
                         channel, and they should revoke it",
                    );
                }
            }
            report.warnings.push(msg);
        }
        Ok(())
    }

    /// Tell every other device our log position, at most every
    /// `E2EE_GOSSIP_SECS` (default 1 hour). Mail only, no log entry, so quiet
    /// members on a forked or frozen log notice within the hour instead of at
    /// the next daily heartbeat.
    /// Make the next sync message every other device, regardless of the
    /// gossip interval or recent traffic (used after a device revocation or
    /// delivery-token rotation, so the news goes out at once).
    pub fn force_gossip(&self) -> Result<()> {
        self.db().execute("DELETE FROM meta WHERE k = ?1", [format!("gossip:{}", self.rid)])?;
        self.db().execute("DELETE FROM peer_sent WHERE repo_id = ?1", [&self.repo_id])?;
        Ok(())
    }

    /// One cumulative ack for everything applied since the last one.
    fn send_pending_ack(&mut self) -> Result<()> {
        if !std::mem::take(&mut self.pending_ack) {
            return Ok(());
        }
        let Some(s) = self.state()? else { return Ok(()) };
        if s.conflict.is_some() {
            return Ok(());
        }
        let others = self.others(&self.recipients(&s.roster)?);
        let ack = self.envelope(Body::Ack(Ack { seq: s.seq, view: s.view.clone(), log_head: s.head.clone() }));
        self.queue(&others, &ack)
    }

    fn gossip(&self) -> Result<()> {
        let Some(s) = self.state()? else { return Ok(()) };
        if s.conflict.is_some() || !s.roster.members.iter().any(|m| m.user_id == self.dev.user) {
            return Ok(());
        }
        let key = format!("gossip:{}", self.rid);
        let now = now_ms();
        let interval = env_secs("E2EE_GOSSIP_SECS", 4 * 3600) * 1000;
        if self.dev.db.meta_u64(&key)?.is_some_and(|t| now.saturating_sub(t) < interval) {
            return Ok(());
        }
        // Devices we already messaged in this interval (acks, pushes) know
        // our log position; gossip only to the rest.
        let mut others = Vec::new();
        for (u, d) in self.others(&self.recipients(&s.roster)?) {
            let sent: Option<i64> = self
                .db()
                .query_row(
                    "SELECT last_ms FROM peer_sent WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                    params![self.repo_id, u, d as i64],
                    |r| r.get(0),
                )
                .optional()?;
            if sent.is_none_or(|t| now.saturating_sub(t as u64) >= interval) {
                others.push((u, d));
            }
        }
        let hb = self.envelope(Body::Heartbeat(Heartbeat { seq: s.seq, log_head: s.head.clone(), at_ms: now }));
        if !others.is_empty() {
            self.queue(&others, &hb)?;
        }
        self.dev.db.meta_set_u64(&key, now)
    }

    /// Delete our blobs once every recipient acked the matching view.
    async fn gc_blobs(&mut self) -> Result<()> {
        // (seq, blob id, recipients, envelope, created)
        type OwnEntry = (i64, String, Vec<u8>, Vec<u8>, i64);
        let rows: Vec<OwnEntry> = {
            let mut st = self
                .db()
                .prepare("SELECT seq, blob_id, recipients, envelope, created_ms FROM own_entries WHERE repo_id = ?1")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (seq, blob_id, recips, env, created) in rows {
            if self.history_at(seq as u64)?.is_none() {
                continue; // not applied yet
            }
            let list = RecipientList::decode(recips.as_slice())?;
            // Past the relay's mail lifetime, a device that never acked will
            // never get this envelope anyway: stop waiting, so one dead device
            // can't keep our pack keys forever.
            let expired = now_ms().saturating_sub(created as u64) >= outbox_ttl_ms();
            let mut all = true;
            for (u, d) in list.users.iter().zip(&list.devices).filter(|_| !expired) {
                if self.dev.db.device_key(u, *d)?.is_none() {
                    continue; // revoked since
                }
                // Acks are cumulative: the device's newest ack covers this
                // entry if it is at or after it and matches our view there.
                let newest: Option<(i64, Vec<u8>)> = self
                    .db()
                    .query_row(
                        "SELECT seq, view FROM acks WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3 ORDER BY seq DESC LIMIT 1",
                        params![self.repo_id, u, *d as i64],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let covers = match newest {
                    Some((aseq, aview)) if aseq >= seq => {
                        self.history_at(aseq as u64)?.is_some_and(|(v, _)| v == aview)
                    }
                    _ => false,
                };
                if !covers {
                    all = false;
                    break;
                }
            }
            if all {
                if !blob_id.is_empty()
                    && let Ok(Envelope { body: Some(Body::Push(p)), .. }) = Envelope::decode(env.as_slice())
                {
                    self.delete_blobs(&p.blob_ids, &p.pack_key).await;
                }
                // Dropping the envelope deletes our copy of the pack key.
                self.db().execute(
                    "DELETE FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                    params![self.repo_id, seq],
                )?;
            }
        }
        Ok(())
    }

    // -- writing -----------------------------------------------------------------

    /// Append our own entry to the log (CAS), then apply and fan it out.
    /// Returns false if someone else appended first.
    /// `replace_token`: this append rotates the repo token to that one.
    #[allow(clippy::too_many_arguments)]
    async fn commit_own(
        &mut self,
        s: &RepoState,
        kind: u32,
        view: Vec<u8>,
        env: Envelope,
        blob_id: &str,
        recipients: &[e2ee_proto::Recipient],
        replace_token: Option<&[u8]>,
    ) -> Result<bool> {
        let env_copy = env.clone();
        let seq = next_seq(s.seq)?;
        let others = self.others(recipients);
        let list = RecipientList {
            users: others.iter().map(|o| o.0.clone()).collect(),
            devices: others.iter().map(|o| o.1).collect(),
        };
        // Persist before appending so a crash after the append can recover.
        self.db().execute(
            "INSERT OR REPLACE INTO own_entries (repo_id, seq, envelope, blob_id, recipients, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![self.repo_id, seq as i64, env.encode_to_vec(), blob_id, list.encode_to_vec(), now_ms() as i64],
        )?;
        let nonce = random_bytes::<16>().to_vec();
        let entry = LogEntry {
            seq,
            prev_head: s.head.clone(),
            // At the repo's protocol (the one before this entry, if it's the
            // roster change raising it), never this build's own: a member
            // running a newer build writes what everyone can read.
            commitment: log_commitment(&self.repo_id, seq, kind, &view, &nonce, s.roster.protocol).to_vec(),
            version: s.roster.protocol,
            nonce,
        };
        let bytes = entry.encode_to_vec();
        let access = self.take_tokens(if s.seq == 0 { api::cost::LOG_CREATE } else { api::cost::LOG_APPEND }).await?;
        match self.relay.append(&self.rid, &self.token()?, &access, &bytes, replace_token).await? {
            Append::Conflict => {
                self.db().execute(
                    "DELETE FROM own_entries WHERE repo_id = ?1 AND seq = ?2",
                    params![self.repo_id, seq as i64],
                )?;
                Ok(false)
            }
            Append::Ok => {
                failpoint("after_log_append");
                let mut report = SyncReport::default();
                let git = self.mirror()?;
                // Apply the bytes we appended rather than re-reading them, so a
                // relay hiding the log cannot stall our own fan-out.
                self.apply_entries(&git, vec![bytes], &mut report).await?;
                self.send_pending_ack()?;
                if let Some(c) = self.require_state()?.conflict {
                    if cfg!(debug_assertions) && std::env::var("E2EE_TEST_FAN_OUT_ANYWAY").is_ok() {
                        // Test hook: a modified client sending a bad entry anyway.
                        let others = self.others(recipients);
                        self.queue(&others, &env_copy)?;
                        self.flush_outbox(&mut report.warnings).await?;
                    }
                    bail!("conflict after our own append: {c}");
                }
                self.flush_outbox(&mut report.warnings).await?;
                for w in report.warnings {
                    eprintln!("e2ee: warning: {}", crate::printable(&w));
                }
                Ok(true)
            }
        }
    }

    /// Push ref updates `(src oid or None for delete, dst, force)`.
    pub async fn push(&mut self, git: &Git, updates: &[(Option<String>, String, bool)]) -> Result<Vec<(String, Result<(), String>)>> {
        let s = self.require_state()?;
        if let Some(c) = &s.conflict {
            bail!("refusing to push: {c}\nrun `git e2ee status` for details");
        }
        let mut refs = s.refs.clone();
        let mut results = Vec::new();
        let mut include = Vec::new();
        for (src, dst, force) in updates {
            // The same check every receiver applies: a name they'd reject
            // would stop the repo for all of them. (Deleting is always fine.)
            if src.is_some()
                && let Err(e) = check_ref_name(dst)
            {
                results.push((dst.clone(), Err(format!("{e:#}"))));
                continue;
            }
            let old = refs.iter().find(|r| &r.name == dst).map(|r| r.oid.clone());
            match src {
                None => {
                    refs.retain(|r| &r.name != dst);
                    results.push((dst.clone(), Ok(())));
                }
                Some(oid) => {
                    if let Some(old) = &old
                        && !force
                        && old != oid
                    {
                        let ff = git.has_object(old)
                            && git.object_type(oid)? == "commit"
                            && git.is_ancestor(old, oid)?;
                        if !ff {
                            results.push((dst.clone(), Err("non-fast-forward".into())));
                            continue;
                        }
                    }
                    refs.retain(|r| &r.name != dst);
                    refs.push(RefEntry { name: dst.clone(), oid: oid.clone() });
                    include.push(oid.clone());
                    results.push((dst.clone(), Ok(())));
                }
            }
        }
        refs.sort();
        if refs == s.refs || results.iter().all(|r| r.1.is_err()) {
            return Ok(results);
        }
        let exclude: Vec<String> = s.refs.iter().map(|r| r.oid.clone()).collect();
        self.check_policy(git, &include, &exclude)?;

        // Streams the pack in chunks to the relay, and into our mirror (which
        // must hold every object in the view).
        let up = self.upload_pack(git, &include, &exclude, true, true).await?;
        let head_ref = pick_head(&s.head_ref, &refs);
        if cfg!(debug_assertions)
            && std::env::var("E2EE_TEST_BAD_REF").is_ok()
            && let Some(r) = refs.first().cloned()
        {
            refs.push(RefEntry { name: "refs/heads/x\n0000 refs/heads/injected".into(), oid: r.oid });
        }
        let recipients = self.recipients(&s.roster)?;
        let mut p = Push {
            seq: next_seq(s.seq)?,
            blob_ids: up.blob_ids.clone(),
            pack_key: up.key.clone(),
            pack_key_hash: sha256(&up.key).to_vec(),
            pack_hash: up.pack_hash.clone(),
            chunk_hashes: up.chunk_hashes.clone(),
            refs,
            prev_view: s.view.clone(),
            roster_hash: roster_hash(&s.roster).to_vec(),
            recipients_hash: test_hooks::recipients(recipients_hash(&recipients)),
            nonce: random_bytes::<16>().to_vec(),
            view: vec![],
            log_head: s.head.clone(),
            head_ref,
            device_lists: self.signed_lists(&s.roster),
            author_user: self.dev.user.clone(),
            author_device: self.dev.device_id,
        };
        p.view = push_view(&self.repo_id, &p).to_vec();
        let env = self.envelope(Body::Push(p.clone()));
        if !self.commit_own(&s, log_kind::PUSH, p.view.clone(), env, &up.blob_ids.join(","), &recipients, None).await? {
            self.delete_blobs(&up.blob_ids, &up.key).await;
            return Ok(results
                .into_iter()
                .map(|(d, r)| (d, r.and(Err("fetch first".to_string()))))
                .collect());
        }
        Ok(results)
    }

    /// Deniable mode: no signed commits or tags; optional pseudonym check.
    fn check_policy(&self, git: &Git, include: &[String], exclude: &[String]) -> Result<()> {
        let allow_signed = git.config_bool("e2ee.allowSigned")?;
        let pseudonym = git.config("e2ee.pseudonym")?;
        let require = git.config_bool("e2ee.requirePseudonym")?;
        if require && pseudonym.is_none() {
            bail!(
                "e2ee.requirePseudonym is set but e2ee.pseudonym isn't: set it to the `Name <email>` your commits \
                 must use (git config e2ee.pseudonym \"Name <email>\")"
            );
        }
        // Every new tag, including tags nested inside other tags (a signed
        // tag wrapped in an unsigned one is still a signature).
        for t in git.new_tags(include, exclude)? {
            let body = git.cat("tag", &t)?;
            if !allow_signed && git::object_is_signed("tag", &body) {
                bail!("refusing to push signed tag {t}: signatures are non-repudiable (set e2ee.allowSigned=true to override)");
            }
            if let Some(p) = &pseudonym {
                for id in git::commit_identities(&body) {
                    if &id != p {
                        if require {
                            bail!("tag {t} has tagger {id:?}, expected pseudonym {p:?}");
                        }
                        eprintln!("e2ee: warning: tag {} has tagger {:?}, not pseudonym {p:?}", &t[..12], crate::printable(&id));
                    }
                }
            }
        }
        for c in git.new_commits(include, exclude)? {
            let body = git.cat("commit", &c)?;
            if !allow_signed && git::object_is_signed("commit", &body) {
                bail!("refusing to push signed commit {c}: signatures are non-repudiable (set e2ee.allowSigned=true to override)");
            }
            if let Some(p) = &pseudonym {
                for id in git::commit_identities(&body) {
                    if &id != p {
                        if require {
                            bail!("commit {c} has identity {id:?}, expected pseudonym {p:?}");
                        }
                        eprintln!("e2ee: warning: commit {} has identity {:?}, not pseudonym {p:?}", &c[..12], crate::printable(&id));
                    }
                }
            }
        }
        Ok(())
    }

    // -- repo and membership management ------------------------------------------

    /// Create a new repo on the relay with this user as the only member.
    /// `object_format` is `sha256`, or `sha1` for a repo whose members have
    /// opted in to SHA-1 (see the README).
    pub async fn init_repo(dev: Device, relay_url: &str, object_format: &str) -> Result<Self> {
        if e2ee_proto::object_format::oid_len(object_format).is_none() {
            bail!("unknown object format {object_format:?}");
        }
        let secret = random_bytes::<32>();
        // The id is bound to the first token, so only holders of the repo
        // secret can create the log (see `repo_id_for_token`).
        let rid = e2ee_proto::repo_id_for_token(&e2ee_proto::delivery_token(&secret));
        let url = format!("{}/{}", relay_url.trim_end_matches('/'), hex::encode(rid));
        let mut eng = Self::new(dev, &url)?;
        // Nothing is sent to the relay yet: the repo's log comes into existence
        // with its first append, which reveals no creator.
        eng.ensure_registered().await?;
        let roster = Roster {
            version: 1,
            members: vec![Member { user_id: eng.dev.user.clone(), master_key: eng.dev.master_pub.clone() }],
            repo_secret: secret.to_vec(),
            protocol: e2ee_proto::PROTOCOL_VERSION,
            object_format: object_format.to_string(),
            genesis_secret: secret.to_vec(),
            log_ttl_secs: 0,
        };
        eng.add_secret(&secret)?;
        eng.save_state(&RepoState {
            relay_url: eng.relay_url.clone(),
            roster,
            seq: 0,
            head: ZERO_HASH.to_vec(),
            view: ZERO_HASH.to_vec(),
            refs: vec![],
            head_ref: String::new(),
            conflict: None,
            last_heartbeat_ms: now_ms(),
            last_log_at_ms: 0,
        })?;
        Ok(eng)
    }

    /// Change the roster through the log. Adds get a history bundle; removals
    /// rotate the repo secret and delivery token.
    pub async fn change_roster(&mut self, add: Option<Member>, remove: Option<Vec<u8>>) -> Result<()> {
        if remove.as_ref().is_some_and(|u| *u == self.dev.user) {
            bail!("to remove yourself, use `git e2ee repo leave`");
        }
        let rotate = remove.is_some();
        self.change_roster_inner(add, remove, rotate).await
    }

    /// `rotate`: give the roster a new secret (and the relay a new token),
    /// cutting off everyone not in the new roster.
    async fn change_roster_inner(&mut self, add: Option<Member>, remove: Option<Vec<u8>>, rotate: bool) -> Result<()> {
        self.change_roster_full(add, remove, rotate, None).await
    }

    /// Set the repo's disappearing-log timer (`git e2ee log-timer`), for
    /// every member: entries recorded from now on disappear after `secs`
    /// (0: kept). Entries already recorded keep their own expiry.
    pub async fn set_log_timer(&mut self, secs: u64) -> Result<()> {
        if self.require_state()?.roster.log_ttl_secs == secs {
            bail!("the disappearing-log timer is already {}", fmt_ttl(secs));
        }
        self.change_roster_full(None, None, false, Some(secs)).await
    }

    async fn change_roster_full(&mut self, add: Option<Member>, remove: Option<Vec<u8>>, rotate: bool, log_ttl: Option<u64>) -> Result<()> {
        let s = self.require_state()?;
        if let Some(c) = &s.conflict {
            bail!("refusing to change the repo: {c}");
        }
        let mut roster = s.roster.clone();
        roster.version += 1;
        if let Some(t) = log_ttl {
            roster.log_ttl_secs = t;
        }
        let mut new_devices = vec![];
        let mut warnings = vec![];
        if let Some(m) = &add {
            if roster.members.iter().any(|x| x.user_id == m.user_id) {
                bail!("already a member");
            }
            self.refresh_device_lists(std::slice::from_ref(&m.user_id), &mut warnings).await?;
            new_devices = self.dev.db.devices_of(&m.user_id)?;
            if new_devices.is_empty() {
                bail!("no verified devices for that user on this relay; they must run `git e2ee register {}` first", self.relay_url);
            }
            roster.members.push(m.clone());
        }
        let leaving = remove.as_ref().is_some_and(|u| *u == self.dev.user);
        if let Some(u) = &remove {
            let before = roster.members.len();
            roster.members.retain(|m| &m.user_id != u);
            if roster.members.len() == before {
                bail!("not a member");
            }
        }
        if rotate {
            roster.repo_secret = random_bytes::<32>().to_vec();
        }
        if cfg!(debug_assertions) && let Some(v) = std::env::var("E2EE_TEST_ROSTER_PROTOCOL").ok().and_then(|v| v.parse().ok()) {
            roster.protocol = v; // a member claiming an upgrade nobody supports
        }
        let recipients = self.recipients(&roster)?;
        let mut rc = RosterChange {
            seq: next_seq(s.seq)?,
            roster: Some(roster.clone()),
            prev_view: s.view.clone(),
            nonce: random_bytes::<16>().to_vec(),
            view: vec![],
            recipients_hash: test_hooks::recipients(recipients_hash(&recipients)),
            log_head: s.head.clone(),
            device_lists: self.signed_lists(&roster),
            author_user: self.dev.user.clone(),
            author_device: self.dev.device_id,
        };
        rc.view = roster_view(&self.repo_id, &rc).to_vec();
        // Only existing members get the roster change; new members get a bundle.
        let mut existing: Vec<e2ee_proto::Recipient> = recipients
            .iter()
            .filter(|(u, _, _)| add.as_ref().is_none_or(|m| &m.user_id != u))
            .cloned()
            .collect();
        if leaving {
            // Our other devices learn we left too (they're outside the new
            // roster, so outside the recipient hash members check).
            for (d, k) in self.dev.db.devices_of(&self.dev.user)? {
                existing.push((self.dev.user.clone(), d, k));
            }
        }
        let new_token = e2ee_proto::delivery_token(&roster.repo_secret).to_vec();
        if rotate {
            // Save the new secret first: if we crash after the relay took
            // the rotation, we can still read the log and finish applying it.
            self.add_secret(&roster.repo_secret)?;
        }
        let env = self.envelope(Body::RosterChange(rc.clone()));
        // A rotation replaces the relay's token in the same step as the
        // append, so it happens exactly if the append wins: concurrent
        // rotations can't both take effect, and none is left half done. The
        // append itself authenticates with the token of the roster we have
        // applied (the one the relay knows), not the new one.
        if !self.commit_own(&s, log_kind::ROSTER, rc.view.clone(), env, "", &existing, rotate.then_some(new_token.as_slice())).await? {
            bail!("another member changed the repo concurrently; fetch and retry");
        }
        if let Some(m) = add {
            let devs: Vec<(Vec<u8>, u32)> = new_devices.iter().map(|(d, _)| (m.user_id.clone(), *d)).collect();
            let sent = self.send_history(&devs).await?;
            // Re-sent until they clone (see `resend_invites`).
            self.note_invites(&devs, &sent)?;
        }
        self.flush_outbox(&mut warnings).await?;
        for w in warnings {
            eprintln!("e2ee: warning: {}", crate::printable(&w));
        }
        Ok(())
    }

    /// Send our current state as a full pack to the given devices.
    /// Returns the uploaded pack's blob ids and key (to delete this copy
    /// once it's replaced).
    pub async fn send_history(&mut self, to: &[(Vec<u8>, u32)]) -> Result<(Vec<String>, Vec<u8>)> {
        let s = self.require_state()?;
        if let Some(c) = &s.conflict {
            bail!("not sending history while this repo has a conflict ({c}); resolve it first");
        }
        let git = self.mirror()?;
        let tips: Vec<String> = s.refs.iter().map(|r| r.oid.clone()).collect();
        let up = if tips.is_empty() { Uploaded::default() } else { self.upload_pack(&git, &tips, &[], false, false).await? };
        let uploaded = (up.blob_ids.clone(), up.key.clone());
        let mut hb = HistoryBundle {
            seq: s.seq,
            view: s.view.clone(),
            log_head: s.head.clone(),
            refs: s.refs.clone(),
            roster: Some(s.roster.clone()),
            blob_ids: up.blob_ids,
            pack_key: up.key,
            pack_hash: up.pack_hash,
            chunk_hashes: up.chunk_hashes,
            push_log: vec![],
            mailboxes: self.known_mailboxes()?,
            proof_push: None,
            proof_rosters: vec![],
            head_ref: s.head_ref.clone(),
            relay_url: self.relay_url.clone(),
            device_lists: self.signed_lists(&s.roster),
            delivery_tokens: s
                .roster
                .members
                .iter()
                .filter_map(|m| {
                    let t = if m.user_id == self.dev.user {
                        self.dev.delivery_token().ok()
                    } else {
                        self.dev.db.delivery_token(&m.user_id).ok().flatten()
                    };
                    t.map(|token| e2ee_proto::UserToken { user_id: m.user_id.clone(), token })
                })
                .collect(),
        };
        (hb.proof_push, hb.proof_rosters) = self.view_proof()?;
        hb.push_log = self.push_log_entries(1000)?.into_iter().map(|(e, _)| e).collect();
        if cfg!(debug_assertions)
            && let Ok(oid) = std::env::var("E2EE_TEST_FORGE_BUNDLE_REFS")
            && let Some(r) = hb.refs.first_mut()
        {
            // A sender pairing the real view with refs of its own choosing.
            r.oid = oid;
        }
        if cfg!(debug_assertions) && std::env::var("E2EE_TEST_BAD_BUNDLE").is_ok() {
            hb.refs.push(RefEntry { name: "refs/heads/bad name".into(), oid: "0".repeat(64) });
        }
        self.queue(to, &self.envelope(Body::HistoryBundle(hb)))?;
        let mut w = vec![];
        self.flush_outbox(&mut w).await?;
        for w in w {
            eprintln!("e2ee: warning: {}", crate::printable(&w));
        }
        Ok(uploaded)
    }

    /// Has this member device ever acknowledged anything or otherwise been
    /// heard from in this repo? (It has, once it has cloned.)
    fn device_joined(&self, user: &[u8], device: u32) -> Result<bool> {
        let seen = |table: &str| -> Result<bool> {
            Ok(self
                .db()
                .query_row(
                    &format!("SELECT 1 FROM {table} WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3"),
                    params![self.repo_id, user, device as i64],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        };
        Ok(seen("acks")? || seen("peer_contact")?)
    }

    /// Remember invitations just sent (or re-sent), to re-send them until
    /// taken up. `sent`: the copy's blob ids and key.
    fn note_invites(&self, devs: &[(Vec<u8>, u32)], sent: &(Vec<String>, Vec<u8>)) -> Result<()> {
        let now = now_ms() as i64;
        for (u, d) in devs {
            self.db().execute(
                "INSERT INTO pending_invites (repo_id, user, device_id, first_ms, sent_ms, sends, blob_ids, pack_key) VALUES (?1, ?2, ?3, ?4, ?4, 1, ?5, ?6)
                 ON CONFLICT (repo_id, user, device_id) DO UPDATE SET sent_ms = ?4, sends = sends + 1, blob_ids = ?5, pack_key = ?6",
                params![self.repo_id, u, *d as i64, now, sent.0.join(","), sent.1],
            )?;
        }
        Ok(())
    }

    /// Invitations waiting to be taken up, one per user.
    pub fn pending_invites(&self) -> Result<Vec<PendingInvite>> {
        let mut st = self.db().prepare(
            "SELECT user, device_id, sends, sent_ms FROM pending_invites WHERE repo_id = ?1 ORDER BY user, device_id",
        )?;
        let rows: Vec<(Vec<u8>, u32, u64, u64)> = st
            .query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u32, r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out: Vec<PendingInvite> = Vec::new();
        for (u, d, n, t) in rows {
            match out.last_mut() {
                Some(last) if last.0 == u => {
                    last.1.push(d);
                    last.2 = last.2.max(n);
                    last.3 = last.3.max(t);
                }
                _ => out.push((u, vec![d], n, t)),
            }
        }
        Ok(out)
    }

    /// `git e2ee member add` for someone already in the roster: if none of
    /// their devices has cloned yet, re-send the invitation to all of them
    /// now. Returns how many devices it went to (0: they've already joined).
    pub async fn reinvite(&mut self, user: &[u8]) -> Result<usize> {
        let s = self.require_state()?;
        if !s.roster.members.iter().any(|m| m.user_id == user) {
            bail!("not a member");
        }
        let mut w = vec![];
        self.refresh_device_lists(&[user.to_vec()], &mut w).await?;
        let devs: Vec<(Vec<u8>, u32)> = self.dev.db.devices_of(user)?.into_iter().map(|(d, _)| (user.to_vec(), d)).collect();
        for (u, d) in &devs {
            if self.device_joined(u, *d)? {
                return Ok(0);
            }
        }
        if devs.is_empty() {
            bail!("no registered devices for that user");
        }
        self.resend_to(&devs).await?;
        Ok(devs.len())
    }

    /// Send a fresh copy of the history to these devices, and replace (and
    /// delete) the copy they were sent before.
    async fn resend_to(&mut self, devs: &[(Vec<u8>, u32)]) -> Result<()> {
        let mut old: Vec<(String, Vec<u8>)> = Vec::new();
        for (u, d) in devs {
            let row: Option<(String, Vec<u8>)> = self
                .db()
                .query_row(
                    "SELECT blob_ids, pack_key FROM pending_invites WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                    params![self.repo_id, u, *d as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some(r) = row
                && !old.contains(&r)
            {
                old.push(r);
            }
        }
        // The first copy may have expired with our half of the handshake:
        // send that again too, or start a new one.
        for (u, d) in devs {
            if !self.dev.pq_requeue_handshake(u, *d, &self.relay_url)? && !self.dev.pq_ready(u, *d)? {
                let _ = self.send_pq_init(u, *d).await;
            }
        }
        let sent = self.send_history(devs).await?;
        self.note_invites(devs, &sent)?;
        for (ids, key) in old {
            let ids: Vec<String> = ids.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
            self.delete_blobs(&ids, &key).await;
        }
        Ok(())
    }

    /// Invitations this device sent that nobody has taken up: re-send them
    /// before the relay can expire the previous copy (after 6 days,
    /// `E2EE_INVITE_RESEND_SECS`), until the device clones (then it
    /// acknowledges the log) or 60 days pass (`E2EE_INVITE_GIVE_UP_SECS`).
    /// A newcomer who never cloned can't ask for history itself: it has no
    /// roster, repo token or mailbox addresses yet.
    async fn resend_invites(&mut self, report: &mut SyncReport) -> Result<()> {
        let Some(s) = self.state()? else { return Ok(()) };
        if s.conflict.is_some() {
            return Ok(());
        }
        let rows: Vec<(Vec<u8>, u32, u64, u64)> = {
            let mut st = self.db().prepare("SELECT user, device_id, first_ms, sent_ms FROM pending_invites WHERE repo_id = ?1")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u32, r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let (now, resend, give_up) =
            (now_ms(), env_secs("E2EE_INVITE_RESEND_SECS", 6 * 86_400) * 1000, env_secs("E2EE_INVITE_GIVE_UP_SECS", 60 * 86_400) * 1000);
        let mut due: Vec<(Vec<u8>, u32)> = Vec::new();
        for (u, d, first, sent) in rows {
            let forget = |e: &Self| {
                e.db().execute(
                    "DELETE FROM pending_invites WHERE repo_id = ?1 AND user = ?2 AND device_id = ?3",
                    params![e.repo_id, u, d as i64],
                )
            };
            let member = s.roster.members.iter().any(|m| m.user_id == u);
            let listed = self.dev.db.devices_of(&u)?.iter().any(|(x, _)| *x == d);
            if !member || !listed || self.device_joined(&u, d)? {
                forget(self)?;
            } else if now.saturating_sub(first) >= give_up {
                forget(self)?;
                report.notes.push(format!(
                    "{}'s device {d} never cloned this repo; stopped re-sending the invitation. If they still \
                     want access, run `git e2ee member add <their user code>` again",
                    short(&u)
                ));
            } else if now.saturating_sub(sent) >= resend {
                due.push((u.clone(), d));
            }
        }
        if !due.is_empty() {
            self.resend_to(&due).await?;
            report.notes.push(format!("re-sent the invitation to {} device(s) that haven't cloned yet", due.len()));
        }
        Ok(())
    }

    /// The bare mirror holding every object of the view, in the repo's
    /// object format (created on first use).
    pub fn mirror(&self) -> Result<Git> {
        Git::init_mirror(self.mirror.path(), &self.require_state()?.roster.object_format)
    }

    /// The repo's git object format (`sha256`, or `sha1` if opted in).
    pub fn object_format(&self) -> Result<String> {
        Ok(self.require_state()?.roster.object_format)
    }

    /// Copy the objects needed for `wants` from the mirror into `dest`.
    pub fn export_objects(&self, dest: &Git, wants: &[String]) -> Result<()> {
        let wants: Vec<String> = wants.iter().filter(|w| !dest.has_object(w)).cloned().collect();
        if wants.is_empty() {
            return Ok(());
        }
        // Anything reachable from dest's refs is already there.
        let have: Vec<String> = dest.ref_oids()?.into_iter().filter(|o| self.mirror.has_object(o)).collect();
        let mut src = self.mirror.pack_stream(&wants, &have, false)?;
        let mut sink = dest.index_pack_stream()?;
        loop {
            let piece = src.read_chunk(pack::chunk_bytes())?;
            if piece.is_empty() {
                break;
            }
            if let Err(e) = sink.write(&piece) {
                return Err(sink.finish().err().unwrap_or(e));
            }
        }
        src.finish()?;
        sink.finish()
    }

    /// Stream a pack from `src` into encrypted chunks on the relay (and into
    /// our mirror if `to_mirror`), holding about one chunk in memory.
    async fn upload_pack(&mut self, src: &Git, include: &[String], exclude: &[String], thin: bool, to_mirror: bool) -> Result<Uploaded> {
        let mut stream = src.pack_stream(include, exclude, thin)?;
        let mut current = stream.read_chunk(pack::chunk_bytes())?;
        if git::pack_object_count(&current)? == 0 {
            while !stream.read_chunk(pack::chunk_bytes())?.is_empty() {}
            stream.finish()?;
            return Ok(Uploaded::default());
        }
        let key = pack::random_key();
        let delete = e2ee_proto::blob_delete_token(&key);
        let mut mirror = if to_mirror { Some(self.mirror()?.index_pack_stream()?) } else { None };
        let mut up = Uploaded { key: key.to_vec(), ..Default::default() };
        let mut total = 0u64;
        let result: Result<()> = async {
            for index in 0u32.. {
                let next = stream.read_chunk(pack::chunk_bytes())?;
                let last = next.is_empty();
                total += current.len() as u64;
                if total > pack::max_pack_bytes() {
                    bail!("pack is larger than E2EE_MAX_PACK_BYTES ({} bytes)", pack::max_pack_bytes());
                }
                if let Some(m) = mirror.as_mut() {
                    m.write(&current)?;
                }
                // Receivers refuse pushes of more chunks than this (each
                // costs them a token); say so here instead.
                let max_chunks = env_secs("E2EE_MAX_CHUNKS", 1024);
                if u64::from(index) >= max_chunks {
                    bail!(
                        "pack needs more than {max_chunks} chunks (E2EE_MAX_CHUNKS); raise E2EE_CHUNK_BYTES (at most {} MiB)",
                        pack::MAX_CHUNK_BYTES >> 20
                    );
                }
                let blob = pack::seal_chunk(&key, index, last, &current)?;
                let id = hex::encode(random_bytes::<16>());
                up.chunk_hashes.push(sha256(&blob).to_vec());
                let access = self.take_tokens(api::cost::blob_put(blob.len())).await?;
                self.relay.put_blob(&access, &id, blob, &delete).await?;
                up.blob_ids.push(id);
                if last {
                    break;
                }
                current = next;
            }
            stream.finish()?;
            if let Some(m) = mirror.take() {
                m.finish()?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.delete_blobs(&up.blob_ids, &up.key).await;
            return Err(e);
        }
        up.pack_hash = e2ee_proto::chunks_hash(&up.chunk_hashes).to_vec();
        Ok(up)
    }

    /// Fetch, verify and decrypt a chunked pack, streaming it into
    /// `index-pack`. Problems with the data itself are `BadBundle`.
    async fn download_pack(&mut self, git: &Git, key: &[u8], ids: &[String], hashes: &[Vec<u8>], pack_hash: &[u8]) -> Result<()> {
        let bad = |m: String| anyhow::Error::new(BadBundle(m));
        if ids.is_empty() {
            return if hashes.is_empty() { Ok(()) } else { Err(bad("chunk list mismatch".into())) };
        }
        // The view commits to pack_hash, which commits to every chunk hash.
        if ids.len() != hashes.len() || e2ee_proto::chunks_hash(hashes).as_slice() != pack_hash {
            return Err(bad("chunk list does not match the pack hash".into()));
        }
        // Chunks are at least 1 KiB, so this bounds requests; the real limit
        // is on the decrypted bytes below (senders may pick any chunk size).
        if ids.len() as u64 > pack::max_pack_bytes().div_ceil(1024) {
            return Err(bad(format!("pack of {} chunks exceeds E2EE_MAX_PACK_BYTES", ids.len())));
        }
        // Each chunk costs us an access token to fetch: a member splitting a
        // push into many tiny chunks must not drain everyone's budget.
        let max_chunks = env_secs("E2EE_MAX_CHUNKS", 1024);
        if ids.len() as u64 > max_chunks {
            return Err(bad(format!("pack of {} chunks exceeds E2EE_MAX_CHUNKS ({max_chunks})", ids.len())));
        }
        let mut sink = git.index_pack_stream()?;
        let mut total = 0u64;
        for (i, (id, hash)) in ids.iter().zip(hashes).enumerate() {
            let access = self.take_tokens(api::cost::BLOB_GET).await?;
            // No chunk bigger than what's left of the pack budget (plus the
            // encryption overhead), nor than any relay serves.
            let cap = pack::sealed_len((pack::max_pack_bytes() - total).min(64 << 20) as usize);
            let blob = self.relay.get_blob(&access, id, cap).await.map_err(|e| {
                if e.downcast_ref::<crate::client::TooLarge>().is_some() {
                    bad(format!("pack exceeds E2EE_MAX_PACK_BYTES ({} bytes): chunk {i} is too large", pack::max_pack_bytes()))
                } else {
                    e
                }
            })?;
            if sha256(&blob).as_slice() != hash.as_slice() {
                return Err(bad(format!("chunk {i} does not match its hash")));
            }
            let piece = pack::open_chunk(key, i as u32, i + 1 == ids.len(), &blob).map_err(|e| bad(format!("{e:#}")))?;
            total += piece.len() as u64;
            if total > pack::max_pack_bytes() {
                return Err(bad(format!("pack exceeds E2EE_MAX_PACK_BYTES ({} bytes)", pack::max_pack_bytes())));
            }
            if let Err(e) = sink.write(&piece) {
                let e = sink.finish().err().unwrap_or(e);
                return Err(bad(format!("pack rejected: {e:#}")));
            }
        }
        sink.finish().map_err(|e| bad(format!("pack rejected: {e:#}")))
    }

    async fn delete_blobs(&self, ids: &[String], key: &[u8]) {
        let token = e2ee_proto::blob_delete_token(key);
        for id in ids {
            let _ = self.relay.delete_blob(id, &token).await;
        }
    }

    /// Delete all of this device's local state for the repo, including the
    /// mirror. Membership is unchanged; later mail for the repo is ignored
    /// (only history bundles are kept for unknown repos).
    /// Forget the repo on this device, first retiring its pseudonymous
    /// mailboxes on the relay (best effort): senders then fall back to our
    /// user mailbox, where mail for a repo we're not in is dropped, instead
    /// of it piling up unread.
    pub async fn forget(&self) -> Result<()> {
        let own: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut st = self.db().prepare("SELECT mailbox, key FROM own_mailboxes WHERE repo_id = ?1")?;
            st.query_map([&self.repo_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        for (mb, key) in own {
            let _ = self.relay.retire_pmail(&hex::encode(&mb), &key).await;
        }
        self.forget_local()
    }

    pub fn forget_local(&self) -> Result<()> {
        let c = self.db();
        for table in [
            "repos", "repo_secrets", "history", "inbox", "outbox", "own_entries", "acks", "resend_requests",
            "peer_heartbeats", "peer_contact", "peer_sent", "own_mailboxes", "peer_mailboxes",
            "claim_entries", "history_claims", "history_requests", "claims_for_me",
        ] {
            c.execute(&format!("DELETE FROM {table} WHERE repo_id = ?1"), [&self.repo_id])?;
        }
        c.execute("DELETE FROM meta WHERE k LIKE '%' || ?1 || '%'", [&self.rid])?;
        if self.mirror.path().exists() {
            std::fs::remove_dir_all(self.mirror.path())?;
        }
        Ok(())
    }

    /// The newest `limit` push-log entries, oldest first, with whether each
    /// was inherited from an inviter (its word only).
    /// The push log, oldest first. The second field is, for an entry this
    /// device didn't see itself, the member whose log it came from.
    pub fn push_log_entries(&self, limit: usize) -> Result<Vec<(PushLogEntry, Option<Vec<u8>>)>> {
        self.prune_push_log()?;
        let mut st = self.db().prepare(
            "SELECT entry, inherited, source FROM (SELECT seq, entry, inherited, source FROM push_log WHERE repo_id = ?1 ORDER BY seq DESC LIMIT ?2) ORDER BY seq",
        )?;
        let rows = st.query_map(params![self.repo_id, limit as i64], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, Option<Vec<u8>>>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (b, inherited, source) = row?;
            out.push((PushLogEntry::decode(b.as_slice())?, inherited.then(|| source.unwrap_or_default())));
        }
        Ok(out)
    }

    pub fn pending_outbox(&self) -> Result<u64> {
        Ok(self
            .db()
            .query_row("SELECT COUNT(*) FROM outbox WHERE repo_id = ?1", [&self.repo_id], |r| r.get::<_, i64>(0))?
            as u64)
    }

    pub fn unacked_own_entries(&self) -> Result<u64> {
        Ok(self
            .db()
            .query_row("SELECT COUNT(*) FROM own_entries WHERE repo_id = ?1", [&self.repo_id], |r| r.get::<_, i64>(0))?
            as u64)
    }
}

/// Shuffle deliveries while keeping each recipient's messages in order: draw
/// random keys, then hand each recipient's sorted keys to its rows in order.
/// An outbox delivery: (what it is, recipient user, recipient device, payload).
type Delivery<I, T> = (I, Vec<u8>, u32, T);

fn shuffle_per_recipient<I, T>(rows: Vec<Delivery<I, T>>) -> Vec<Delivery<I, T>> {
    let mut keys: std::collections::HashMap<(Vec<u8>, u32), Vec<u64>> = Default::default();
    for (_, u, d, _) in &rows {
        keys.entry((u.clone(), *d)).or_default().push(rand::random());
    }
    for k in keys.values_mut() {
        k.sort_unstable_by(|a, b| b.cmp(a)); // popped from the back = ascending
    }
    let mut keyed: Vec<(u64, Delivery<I, T>)> = rows
        .into_iter()
        .map(|r| {
            let k = keys.get_mut(&(r.1.clone(), r.2)).and_then(Vec::pop).unwrap_or(0);
            (k, r)
        })
        .collect();
    keyed.sort_by_key(|(k, _)| *k);
    keyed.into_iter().map(|(_, r)| r).collect()
}

/// An invitation waiting to be taken up: (user, their devices, times sent,
/// when last sent, ms).
pub type PendingInvite = (Vec<u8>, Vec<u32>, u64, u64);

/// A disappearing-log timer, as people say it ("1 week", "90 seconds").
pub fn fmt_ttl(secs: u64) -> String {
    let unit = |n: u64, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
    match secs {
        0 => "off".into(),
        s if s % 604_800 == 0 => unit(s / 604_800, "week"),
        s if s % 86_400 == 0 => unit(s / 86_400, "day"),
        s if s % 3600 == 0 => unit(s / 3600, "hour"),
        s if s % 60 == 0 => unit(s / 60, "minute"),
        s => unit(s, "second"),
    }
}

/// "30s", "10m", "12h", "7d", "2w", or "off".
pub fn parse_ttl(s: &str) -> Result<u64> {
    let s = s.trim();
    if s == "off" || s == "0" {
        return Ok(0);
    }
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().map_err(|_| anyhow!("expected a duration like 30s, 10m, 12h, 7d, 2w, or off"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => bail!("unknown unit {unit:?}: use s, m, h, d or w"),
    };
    n.checked_mul(mult).filter(|t| *t > 0).ok_or_else(|| anyhow!("duration out of range"))
}

pub fn fmt_age(ms: u64) -> String {
    match ms / 1000 {
        s if s < 120 => format!("{s} seconds"),
        s if s < 7200 => format!("{} minutes", s / 60),
        s if s < 172_800 => format!("{} hours", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

/// Access tokens obtained per refill (always this many, never "what's needed").
const TOKEN_BATCH: usize = 100;
/// Tokens kept on hand, topped up at the start of each sync.
const TOKEN_RESERVE: usize = 300;

/// Most envelopes one known repo may have waiting locally.
const MAX_INBOX_PER_REPO: i64 = 10_000;
/// Waiting envelopes one sender can have for one repo.
const MAX_INBOX_PER_SENDER: i64 = 1_000;
/// Most history bundles waiting for repos this device has not cloned.
const MAX_PENDING_BUNDLES: i64 = 50;

enum InboxDrop {
    UnknownRepo,
    Full,
}

/// File a decrypted, authenticated envelope into the inbox. Returns why it
/// was dropped, if it was, and how long ago it was sent.
fn admit(dev: &Device, relay_url: &str, current: &[u8], id: &str, u: &[u8], d: u32, pt: &[u8]) -> Result<(Option<InboxDrop>, u64)> {
    let env = Envelope::decode(pt)?;
    // Where this device wants mail for that repo from now on.
    if env.reply_mailbox.len() == 16 && env.repo_id.len() == 16 && !(u == dev.user.as_slice() && d == dev.device_id) {
        dev.db.conn().execute(
            "INSERT OR REPLACE INTO peer_mailboxes (repo_id, user, device_id, mailbox) VALUES (?1, ?2, ?3, ?4)",
            params![env.repo_id, u, d as i64, env.reply_mailbox],
        )?;
    }
    // Token keys this member was given by the relay this mail came through.
    for k in env.token_keys.iter().take(8) {
        dev.db.conn().execute(
            "INSERT OR IGNORE INTO peer_token_keys (relay_url, epoch, generation, key_hash, user, device_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![relay_url, k.epoch as i64, k.generation as i64, k.key_hash, u, d as i64],
        )?;
    }
    if env.repo_id.len() != 16 {
        bail!("envelope without a valid repo id");
    }
    // Contacts' delivery tokens arrive with their own mail;
    // our own other devices tell us about rotations.
    if !env.sender_delivery_token.is_empty() {
        if u == dev.user {
            dev.db.meta_set("delivery_token", &env.sender_delivery_token)?;
        } else {
            dev.db.set_delivery_token(u, &env.sender_delivery_token)?;
        }
    }
    if let Some(why) = inbox_admission(&dev.db, current, &env, u)? {
        return Ok((Some(why), 0));
    }
    dev.db.conn().execute(
        "INSERT INTO inbox (repo_id, msg_id, sender_user, sender_device, envelope, received_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![env.repo_id, id, u, d as i64, pt, now_ms() as i64],
    )?;
    // Freshness counts when the peer *sent* this (capped at our
    // clock), so mail the relay held back doesn't look recent.
    let sent = env.sent_ms.min(now_ms());
    dev.db.conn().execute(
        "INSERT INTO peer_contact (repo_id, user, device_id, last_ms) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(repo_id, user, device_id) DO UPDATE SET last_ms = MAX(last_ms, excluded.last_ms)",
        params![env.repo_id, u, d as i64, sent as i64],
    )?;
    Ok((None, now_ms().saturating_sub(sent)))
}

/// The sequence number after `seq` (checked: release builds don't check
/// overflow, and a relay plus a member could push the log to the end).
fn next_seq(seq: u64) -> Result<u64> {
    seq.checked_add(1).ok_or_else(|| anyhow!("this repo's log has reached its last sequence number"))
}

fn check_protocol_or_upgrade(what: &str, version: u32) -> Result<()> {
    e2ee_proto::check_protocol(what, version).map_err(|e| anyhow!(e))
}

/// Where a fetched message came from: the user-id mailbox (`None`) or one of
/// our pseudonymous mailboxes (address, key).
type MailSource = Option<(Vec<u8>, Vec<u8>)>;

/// Check that a history bundle's refs, default branch and roster are the
/// ones its view commits to: its proof is the last push (if any) and the
/// roster changes after it, and their recomputed views must chain from the
/// push (or from the zero view of a new repo) to `hb.view`.
fn verify_bundle_proof(repo_id: &[u8], hb: &HistoryBundle, roster: &Roster) -> Result<()> {
    let mut view = ZERO_HASH.to_vec();
    let mut roster_at = None;
    match &hb.proof_push {
        Some(p) => {
            if push_view(repo_id, p).as_slice() != p.view {
                bail!("its proof push doesn't match its own view");
            }
            let mut a = p.refs.clone();
            let mut b = hb.refs.clone();
            a.sort_by(|x, y| x.name.cmp(&y.name));
            b.sort_by(|x, y| x.name.cmp(&y.name));
            if a != b || p.head_ref != hb.head_ref {
                bail!("its refs aren't the ones the repo's view commits to");
            }
            view = p.view.clone();
            roster_at = Some(p.roster_hash.clone());
        }
        None => {
            if !hb.refs.is_empty() || !hb.head_ref.is_empty() {
                bail!("it claims refs but has no push to prove them");
            }
        }
    }
    for rc in &hb.proof_rosters {
        let Some(r) = &rc.roster else { bail!("its proof has a roster change without a roster") };
        if roster_view(repo_id, rc).as_slice() != rc.view || rc.prev_view != view {
            bail!("its proof's roster changes don't chain");
        }
        view = rc.view.clone();
        roster_at = Some(roster_hash(r).to_vec());
    }
    if view != hb.view {
        bail!("its proof doesn't lead to the view it claims");
    }
    match roster_at {
        Some(h) if h == roster_hash(roster).as_slice() => Ok(()),
        Some(_) => bail!("its roster isn't the one the repo's view commits to"),
        // A brand-new repo can't have a bundle without a roster change.
        None => bail!("it proves no roster"),
    }
}

/// What an outbox delivery was, for bookkeeping once it is posted.
enum Sent {
    Outbox(i64),
    PqInit,
    PqResponse(i64),
}

/// Whether to keep an incoming envelope. Repos this device has no state for
/// (and isn't cloning right now) only get history bundles, which are what
/// starts a clone; anything else for them is noise or a disk-filling attempt.
fn inbox_admission(db: &crate::store::Db, current: &[u8], env: &Envelope, sender: &[u8]) -> Result<Option<InboxDrop>> {
    let c = db.conn();
    let known = env.repo_id == current
        || c.query_row("SELECT 1 FROM repos WHERE repo_id = ?1", [&env.repo_id], |_| Ok(())).optional()?.is_some();
    if known {
        // Per sender too: one contact (say, a removed member who still has
        // our address) can't fill the repo's share and crowd members out.
        let mine: i64 = c.query_row(
            "SELECT COUNT(*) FROM inbox WHERE repo_id = ?1 AND sender_user = ?2",
            params![env.repo_id, sender],
            |r| r.get(0),
        )?;
        if mine >= MAX_INBOX_PER_SENDER {
            return Ok(Some(InboxDrop::Full));
        }
        let n: i64 = c.query_row("SELECT COUNT(*) FROM inbox WHERE repo_id = ?1", [&env.repo_id], |r| r.get(0))?;
        return Ok((n >= MAX_INBOX_PER_REPO).then_some(InboxDrop::Full));
    }
    if !matches!(env.body, Some(Body::HistoryBundle(_))) {
        return Ok(Some(InboxDrop::UnknownRepo));
    }
    let pending: i64 = c.query_row(
        "SELECT COUNT(*) FROM inbox WHERE repo_id NOT IN (SELECT repo_id FROM repos)",
        [],
        |r| r.get(0),
    )?;
    Ok((pending >= MAX_PENDING_BUNDLES).then_some(InboxDrop::Full))
}

/// Is this ref shown to git? Refs our policy refuses (inherited from older
/// builds through a history bundle) are kept but hidden.
pub fn ref_visible(name: &str) -> bool {
    check_ref_name(name).is_ok()
}

/// A ref name members may push. `refs/replace/` is refused: a replace ref
/// makes `git log` show other content for an existing commit (for anyone who
/// fetches it, e.g. with a mirror refspec).
fn check_ref_name(name: &str) -> Result<()> {
    if !git::valid_ref_name(name) {
        bail!("invalid ref name {name:?}");
    }
    if name.starts_with("refs/replace/") {
        bail!("{name}: replace refs can't be pushed to an e2ee remote (they change what existing commits show)");
    }
    Ok(())
}

/// Refs received from other members must be well-formed before they reach
/// git or the remote-helper protocol.
/// `known`: refs we already accepted. An unchanged one isn't re-checked
/// by name, so a ref accepted under older rules can't block every later push
/// (it can still be deleted). `None` (a history bundle, which a newcomer
/// can't compare with anything): names are checked for syntax only; refs
/// our policy refuses are kept in the state, so members' later pushes still
/// match it, but never shown to git (`ref_visible`).
fn check_refs(refs: &[RefEntry], head_ref: &str, format: &str, known: Option<&[RefEntry]>) -> Result<()> {
    for r in refs {
        match known {
            None if !git::valid_ref_name(&r.name) => bail!("invalid ref name {:?}", r.name),
            None => {}
            Some(k) if !k.iter().any(|k| k.name == r.name && k.oid == r.oid) => check_ref_name(&r.name)?,
            Some(_) => {}
        }
        if !git::valid_oid(&r.oid, format) {
            bail!("invalid object id {:?} for {}", r.oid, r.name);
        }
    }
    let mut names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    if names.windows(2).any(|w| w[0] == w[1]) {
        bail!("duplicate ref names");
    }
    if !head_ref.is_empty() && !refs.iter().any(|r| r.name == head_ref) {
        bail!("HEAD points to a ref that is not in the push: {head_ref:?}");
    }
    Ok(())
}

/// The envelope for a log entry, and who sent it to us.
struct EntryEnvelope {
    msg_id: Option<String>,
    own: bool,
    author: (Vec<u8>, u32),
    env: Envelope,
}

/// Ref updates between two ref sets, by name.
fn ref_changes(before: &[RefEntry], after: &[RefEntry]) -> Vec<e2ee_proto::RefChange> {
    let mut names: Vec<&str> = before.iter().chain(after).map(|r| r.name.as_str()).collect();
    names.sort();
    names.dedup();
    let find = |set: &[RefEntry], n: &str| set.iter().find(|r| r.name == n).map(|r| r.oid.clone()).unwrap_or_default();
    names
        .into_iter()
        .filter_map(|n| {
            let (old_oid, new_oid) = (find(before, n), find(after, n));
            (old_oid != new_oid).then(|| e2ee_proto::RefChange { name: n.to_string(), old_oid, new_oid, ..Default::default() })
        })
        .collect()
}

/// "added …, removed …" for a roster change (empty if none).
fn roster_note(before: &Roster, after: &Roster) -> String {
    let has = |r: &Roster, u: &[u8]| r.members.iter().any(|m| m.user_id == u);
    let mut parts = Vec::new();
    for m in &after.members {
        if !has(before, &m.user_id) {
            parts.push(format!("added {}", short(&m.user_id)));
        }
    }
    for m in &before.members {
        if !has(after, &m.user_id) {
            parts.push(format!("removed {}", short(&m.user_id)));
        }
    }
    if before.log_ttl_secs != after.log_ttl_secs {
        parts.push(match after.log_ttl_secs {
            0 => "turned disappearing log entries off".to_string(),
            t => format!("set log entries to disappear after {}", fmt_ttl(t)),
        });
    }
    parts.join(", ")
}

/// A pack uploaded as encrypted chunks.
#[derive(Default)]
struct Uploaded {
    key: Vec<u8>,
    blob_ids: Vec<String>,
    chunk_hashes: Vec<Vec<u8>>,
    pack_hash: Vec<u8>,
}

/// A history bundle that is itself invalid (as opposed to a transient error).
#[derive(Debug)]
struct BadBundle(String);

impl std::fmt::Display for BadBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadBundle {}

/// How long undelivered mail and unacknowledged pushes are kept: the relay's
/// default mail lifetime, after which nothing could be delivered anyway.
fn outbox_ttl_ms() -> u64 {
    env_secs("E2EE_OUTBOX_TTL_SECS", 14 * 24 * 3600) * 1000
}

/// A log entry once a member has worked out what it commits to.
struct Resolved {
    seq: u64,
    /// The committed view (empty if the envelope at hand doesn't match).
    view: Vec<u8>,
}

/// The device a push or roster change names as its author.
fn envelope_author(env: &Envelope) -> Option<(Vec<u8>, u32)> {
    match &env.body {
        Some(Body::Push(p)) => Some((p.author_user.clone(), p.author_device)),
        Some(Body::RosterChange(r)) => Some((r.author_user.clone(), r.author_device)),
        _ => None,
    }
}

/// The log kind and view an envelope describes.
fn envelope_kind_view(env: &Envelope) -> Option<(u32, Vec<u8>)> {
    match &env.body {
        Some(Body::Push(p)) => Some((log_kind::PUSH, p.view.clone())),
        Some(Body::RosterChange(r)) => Some((log_kind::ROSTER, r.view.clone())),
        _ => None,
    }
}

fn envelope_seq_view(env: &Envelope) -> Option<(u64, Vec<u8>)> {
    match &env.body {
        Some(Body::Push(p)) => Some((p.seq, p.view.clone())),
        Some(Body::RosterChange(r)) => Some((r.seq, r.view.clone())),
        _ => None,
    }
}

/// Fault injection for tests, compiled only into debug builds.
mod test_hooks {
    use super::*;

    /// `E2EE_TEST_EQUIVOCATE_TO=<user hex>`: recipients of that user get a
    /// different (but internally consistent) push than everyone else.
    pub fn split_equivocation(to: &[DeviceAddr]) -> (Vec<DeviceAddr>, Vec<DeviceAddr>) {
        let target = if cfg!(debug_assertions) { std::env::var("E2EE_TEST_EQUIVOCATE_TO").ok() } else { None };
        to.iter().cloned().partition(|(u, _)| target.as_deref() != Some(hex::encode(u).as_str()))
    }

    /// `E2EE_TEST_BAD_RECIPIENTS=1`: claim a recipient set that differs from
    /// the verified device lists (as a member hiding an extra device would).
    pub fn recipients(h: e2ee_proto::Hash) -> Vec<u8> {
        let mut h = h.to_vec();
        if cfg!(debug_assertions) && std::env::var("E2EE_TEST_BAD_RECIPIENTS").is_ok() {
            h[0] ^= 1;
        }
        h
    }

    pub fn equivocate(repo_id: &[u8], env: &Envelope) -> Envelope {
        let mut env = env.clone();
        if let Some(Body::Push(p)) = &mut env.body {
            if let Some(r) = p.refs.first().cloned() {
                p.refs.push(RefEntry { name: "refs/heads/equivocated".into(), oid: r.oid });
            }
            p.view = push_view(repo_id, p).to_vec();
        }
        env
    }
}

pub fn pick_head(current: &str, refs: &[RefEntry]) -> String {
    if refs.iter().any(|r| r.name == current) {
        return current.to_string();
    }
    for pref in ["refs/heads/main", "refs/heads/master"] {
        if refs.iter().any(|r| r.name == pref) {
            return pref.to_string();
        }
    }
    refs.iter()
        .find(|r| r.name.starts_with("refs/heads/"))
        .map(|r| r.name.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {

    #[test]
    fn log_timer_durations_parse_and_print() {
        assert_eq!(parse_ttl("30s").unwrap(), 30);
        assert_eq!(parse_ttl("10m").unwrap(), 600);
        assert_eq!(parse_ttl("12h").unwrap(), 43_200);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert_eq!(parse_ttl("2w").unwrap(), 1_209_600);
        assert_eq!(parse_ttl("off").unwrap(), 0);
        assert_eq!(parse_ttl("45").unwrap(), 45);
        for bad in ["", "1y", "w", "-1s", "99999999999999999999s"] {
            assert!(parse_ttl(bad).is_err(), "{bad:?}");
        }
        assert_eq!(fmt_ttl(604_800), "1 week");
        assert_eq!(fmt_ttl(3 * 86_400), "3 days");
        assert_eq!(fmt_ttl(90), "90 seconds");
        assert_eq!(fmt_ttl(3600), "1 hour");
    }

    /// A ref accepted under older rules doesn't block later pushes; a new
    /// one with the same problem is still refused.
    #[test]
    fn unchanged_refs_are_not_rechecked_by_name() {
        let oid = "a".repeat(64);
        let main = RefEntry { name: "refs/heads/main".into(), oid: oid.clone() };
        let old = RefEntry { name: format!("refs/replace/{oid}"), oid: oid.clone() };
        let refs = vec![main.clone(), old.clone()];
        assert!(check_refs(&refs, "", "sha256", Some(&[])).is_err());
        assert!(check_refs(&refs, "", "sha256", Some(std::slice::from_ref(&old))).is_ok());
        // A bundle: kept (syntax is fine), hidden from git.
        assert!(check_refs(&refs, "", "sha256", None).is_ok());
        assert!(!ref_visible(&old.name) && ref_visible(&main.name));
        let moved = RefEntry { oid: "b".repeat(64), ..old };
        assert!(check_refs(&[main, moved.clone()], "", "sha256", Some(&[RefEntry { oid, ..moved }])).is_err());
    }

    use super::*;

    #[test]
    fn shuffle_keeps_per_recipient_order() {
        let rows: Vec<(i64, Vec<u8>, u32, ())> =
            (0..60).map(|i| (i, vec![(i % 3) as u8], 1, ())).collect();
        let mut interleavings = std::collections::HashSet::new();
        for _ in 0..20 {
            let out = shuffle_per_recipient(rows.clone());
            assert_eq!(out.len(), rows.len());
            for r in 0..3u8 {
                let ids: Vec<i64> = out.iter().filter(|x| x.1 == vec![r]).map(|x| x.0).collect();
                assert!(ids.windows(2).all(|w| w[0] < w[1]), "order kept per recipient");
            }
            interleavings.insert(out.iter().map(|x| x.0).collect::<Vec<_>>());
        }
        assert!(interleavings.len() > 1, "interleaving is randomized");
    }
}
