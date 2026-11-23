//! Post-quantum authentication of device-to-device messages.
//!
//! libsignal authenticates sessions with Curve25519 identity keys only, so a
//! quantum attacker who recovers one could open a new session posing as that
//! device. On top of libsignal, every pair of devices runs a KEM handshake
//! against their long-term ML-KEM (Kyber1024) authentication keys, which the
//! hybrid-signed device lists name by hash:
//!
//! ```text
//! A -> B  INIT  hs_id, A's KEM key, ct_B = Encaps(B's KEM key)
//! B -> A  RESP  hs_id, ct_A = Encaps(A's KEM key), MAC(K, resp)
//! K = KDF(ss_B, ss_A, both devices, both KEM keys, both ciphertexts, hs_id)
//! ```
//!
//! Every later message between the two is encrypted and authenticated under
//! K (XChaCha20-Poly1305, a key per direction), inside the libsignal message.
//! Only the real B can decapsulate `ct_B` and only the real A `ct_A`, so
//! someone posing as either can't compute K: it can neither forge messages
//! nor read them, even if it takes over the libsignal session (as a quantum
//! attacker holding a device's Curve25519 key could). B trusts A's messages because
//! they decrypt under a key that needs ss_A, which only A could recover; A
//! trusts B's after the response MAC. Symmetric keys (not signatures) keep messages
//! deniable: both ends hold K and could have produced any of them.
//!
//! The handshake runs once per device pair. Messages to a device without an
//! established key wait in the outbox; messages that arrive under a handshake
//! we started, before its response, are held until it arrives.

use anyhow::{Result, anyhow, bail};
use e2ee_proto::{DeviceListBody, Message, PqFrame, SignedDeviceList, domain, hash_fields, kem_key_hash, pq_kind};
use hmac::{KeyInit, Mac};
use libsignal_protocol::kem;
use rusqlite::{OptionalExtension, params};

use crate::device::Device;

/// Resend an unanswered handshake after this long.
const INIT_RETRY_MS: u64 = 3600 * 1000;
/// Handshake frames are padded to this size, like a small envelope.
const HANDSHAKE_PAD: usize = 4096;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// (row or message id, peer user, peer device, frame or payload bytes).
pub type PeerItem<I> = (I, Vec<u8>, u32, Vec<u8>);

/// What an incoming frame turned out to be.
pub enum PqIn {
    /// An authenticated message for the application.
    Payload(Vec<u8>),
    /// A handshake message, handled here.
    Handled,
    /// A handshake init: the peer has no working state with us, so the
    /// caller should also retire our libsignal session with it (it may name
    /// prekeys the peer has deleted; the next send starts a fresh one).
    HandledInit,
    /// A message under a handshake we started that isn't answered yet.
    Held,
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn mac_ok(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.verify_slice(tag).is_ok()
}

/// The key for one direction of traffic under pairwise key `k`.
fn data_key(k: &[u8], from: (&[u8], u32), to: (&[u8], u32)) -> [u8; 32] {
    hash_fields(domain::PQ_DATA_KEY, &[k, from.0, &from.1.to_be_bytes(), to.0, &to.1.to_be_bytes()])
}

/// What a data frame's AEAD binds besides the payload: direction and handshake.
/// `purpose` keeps what's sealed for one use (a data frame, a handshake's
/// delivery token) from being accepted as another.
/// `version` is the frame's own protocol version, bound so it can't be
/// rewritten in transit (by whoever controls the libsignal session).
fn data_aad(purpose: &[u8], from: (&[u8], u32), to: (&[u8], u32), hs_id: &[u8], version: u32) -> Vec<u8> {
    hash_fields(purpose, &[from.0, &from.1.to_be_bytes(), to.0, &to.1.to_be_bytes(), hs_id, &version.to_be_bytes()]).to_vec()
}

/// What a handshake response's MAC covers: its purpose and its version.
fn resp_mac_input(version: u32) -> Vec<u8> {
    [domain::PQ_AUTH_RESP, &version.to_be_bytes()].concat()
}

fn seal_data(purpose: &[u8], k: &[u8], from: (&[u8], u32), to: (&[u8], u32), hs_id: &[u8], version: u32, payload: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let nonce: [u8; 24] = rand::random();
    let cipher = XChaCha20Poly1305::new((&data_key(k, from, to)).into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: payload, aad: &data_aad(purpose, from, to, hs_id, version) })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

fn open_data(purpose: &[u8], k: &[u8], from: (&[u8], u32), to: (&[u8], u32), hs_id: &[u8], version: u32, sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    if sealed.len() < 24 + 16 {
        return None;
    }
    let nonce: [u8; 24] = sealed[..24].try_into().ok()?;
    let cipher = XChaCha20Poly1305::new((&data_key(k, from, to)).into());
    cipher.decrypt(&XNonce::from(nonce), Payload { msg: &sealed[24..], aad: &data_aad(purpose, from, to, hs_id, version) }).ok()
}

/// The pairwise key, from both shared secrets and the whole transcript.
#[allow(clippy::too_many_arguments)]
fn derive_key(
    init: (&[u8], u32),
    resp: (&[u8], u32),
    init_kem: &[u8],
    resp_kem: &[u8],
    ct_resp: &[u8],
    ct_init: &[u8],
    ss_resp: &[u8],
    ss_init: &[u8],
    hs_id: &[u8],
    version: u32,
) -> Vec<u8> {
    // The init's protocol version is bound into the key.
    let info = hash_fields(
        domain::PQ_AUTH,
        &[init.0, &init.1.to_be_bytes(), resp.0, &resp.1.to_be_bytes(), init_kem, resp_kem, ct_resp, ct_init, &version.to_be_bytes()],
    );
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(hs_id), &[ss_resp, ss_init].concat());
    let mut k = [0u8; 32];
    hk.expand(&info, &mut k).expect("32 bytes is a valid HKDF length");
    k.to_vec()
}

/// Set when a device sends under a key we don't have: we owe it a
/// handshake. It never stops us sending (see `pq_needs_handshake`).
/// A handshake we started: (ss, ct, the peer's KEM key, our init's version).
type PendingRow = (Vec<u8>, Vec<u8>, Vec<u8>, u32);

fn stale_key(user: &[u8], device_id: u32) -> String {
    format!("pq-stale:{}.{device_id}", hex::encode(user))
}

/// The handshake id of the last handshake we started with a device and
/// completed, until the device is first seen using it. Until then its
/// messages under older keys are expected, not a sign it lacks ours.
fn awaiting_key(user: &[u8], device_id: u32) -> String {
    format!("pq-awaiting:{}.{device_id}", hex::encode(user))
}

fn padded(mut f: PqFrame, version: u32) -> Vec<u8> {
    f.version = version;
    // The padding field's own tag and length prefix vary by a byte or two.
    let mut n = HANDSHAKE_PAD.saturating_sub(f.encoded_len() + 4);
    loop {
        f.padding = vec![0; n];
        // Start below the target and grow: always terminates.
        if f.encoded_len() >= HANDSHAKE_PAD {
            break;
        }
        n += 1;
    }
    f.encode_to_vec()
}

impl Device {
    /// This device's long-term ML-KEM authentication key pair.
    pub(crate) fn kem_auth(&self) -> Result<kem::KeyPair> {
        let (pk, sk) = (self.db.meta_get("device_kem_pk")?, self.db.meta_get("device_kem_sk")?);
        let (Some(pk), Some(sk)) = (pk, sk) else { bail!("device has no KEM authentication key") };
        Ok(kem::KeyPair::from_public_and_private(&pk, &sk)?)
    }

    pub fn kem_auth_public(&self) -> Result<Vec<u8>> {
        Ok(self.kem_auth()?.public_key.serialize().to_vec())
    }

    /// The KEM key hash a device's verified list names for it.
    fn listed_kem_hash(&self, user: &[u8], device_id: u32) -> Result<Vec<u8>> {
        let signed = self.db.signed_device_list(user)?.ok_or_else(|| anyhow!("no device list for this user"))?;
        let body = DeviceListBody::decode(SignedDeviceList::decode(signed.as_slice())?.body.as_slice())?;
        body.devices
            .iter()
            .find(|d| d.device_id == device_id)
            .map(|d| d.kem_key_hash.clone())
            .ok_or_else(|| anyhow!("device is not in its user's list"))
    }

    /// Remember a peer device's KEM key if it matches its verified list.
    pub fn store_peer_kem(&self, user: &[u8], device_id: u32, key: &[u8]) -> Result<()> {
        if kem_key_hash(key).as_slice() != self.listed_kem_hash(user, device_id)? {
            bail!("KEM key of {}.{device_id} does not match its device list", crate::device::short(user));
        }
        kem::PublicKey::deserialize(key)?;
        self.db.conn().execute(
            "INSERT OR REPLACE INTO pq_peer_kem (user, device_id, kem_key) VALUES (?1, ?2, ?3)",
            params![user, device_id as i64, key],
        )?;
        Ok(())
    }

    pub fn has_peer_kem(&self, user: &[u8], device_id: u32) -> Result<bool> {
        Ok(self.peer_kem(user, device_id)?.is_some())
    }

    fn peer_kem(&self, user: &[u8], device_id: u32) -> Result<Option<Vec<u8>>> {
        let k: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row(
                "SELECT kem_key FROM pq_peer_kem WHERE user = ?1 AND device_id = ?2",
                params![user, device_id as i64],
                |r| r.get(0),
            )
            .optional()?;
        // Re-check against the current list (it could have been replaced).
        Ok(k.filter(|k| self.listed_kem_hash(user, device_id).is_ok_and(|h| h == kem_key_hash(k))))
    }

    /// The key to send to a device with: the newest confirmed one, else the
    /// newest unconfirmed one (a first contact still waiting for a MAC).
    fn pq_key(&self, user: &[u8], device_id: u32) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT hs_id, key FROM pq_keys WHERE user = ?1 AND device_id = ?2 ORDER BY confirmed DESC, created_ms DESC LIMIT 1",
                params![user, device_id as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// The version for frames to a device: the newest both it and this
    /// build speak (its signed device entry says what it supports). So a
    /// device running a newer build still writes frames older ones read,
    /// until both support the new version. Unknown: the oldest we speak.
    fn frame_version(&self, user: &[u8], device_id: u32) -> Result<u32> {
        let theirs = self
            .db
            .signed_device_list(user)?
            .and_then(|s| e2ee_proto::SignedDeviceList::decode(s.as_slice()).ok())
            .and_then(|s| e2ee_proto::DeviceListBody::decode(s.body.as_slice()).ok())
            .and_then(|b| b.devices.into_iter().find(|d| d.device_id == device_id))
            .map(|d| d.max_protocol)
            .unwrap_or(0);
        if theirs != 0 && theirs < e2ee_proto::MIN_PROTOCOL_VERSION {
            bail!("this device only speaks protocol {theirs}, older than this build supports; it needs upgrading");
        }
        Ok(theirs.clamp(e2ee_proto::MIN_PROTOCOL_VERSION, e2ee_proto::PROTOCOL_VERSION))
    }

    /// Do we have a key to send to this device under?
    pub fn pq_ready(&self, user: &[u8], device_id: u32) -> Result<bool> {
        Ok(self.pq_key(user, device_id)?.is_some())
    }

    /// Does this device need a new handshake from us (it sent under a key
    /// we don't have; see the DATA case of `pq_receive`)?
    pub fn pq_needs_handshake(&self, user: &[u8], device_id: u32) -> Result<bool> {
        Ok(self.db.meta_get(&stale_key(user, device_id))?.is_some())
    }

    /// Wrap a payload for a device we share a key with.
    pub fn pq_wrap(&self, user: &[u8], device_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let (hs_id, key) = self.pq_key(user, device_id)?.ok_or_else(|| anyhow!("no post-quantum key with this device yet"))?;
        let v = self.frame_version(user, device_id)?;
        let sealed = seal_data(domain::PQ_AUTH_DATA, &key, (&self.user, self.device_id), (user, device_id), &hs_id, v, payload)?;
        Ok(PqFrame { kind: pq_kind::DATA, hs_id, payload: sealed, version: v, ..Default::default() }.encode_to_vec())
    }

    /// A handshake init for a device, unless one is already in flight
    /// (sent within the retry interval). Needs the peer's KEM key.
    pub fn pq_init(&self, user: &[u8], device_id: u32) -> Result<Option<Vec<u8>>> {
        let recent: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT MAX(created_ms) FROM pq_pending WHERE user = ?1 AND device_id = ?2",
                params![user, device_id as i64],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if recent.is_some_and(|t| crate::now_ms().saturating_sub(t as u64) < INIT_RETRY_MS) {
            return Ok(None);
        }
        let peer = self.peer_kem(user, device_id)?.ok_or_else(|| anyhow!("no KEM key for this device"))?;
        let (ss, ct) = kem::PublicKey::deserialize(&peer)?.encapsulate(&mut rand::rng())?;
        let hs_id = rand::random::<[u8; 16]>().to_vec();
        let v = self.frame_version(user, device_id)?;
        self.db.conn().execute(
            "INSERT INTO pq_pending (user, device_id, hs_id, ss, ct, peer_kem, created_ms, version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![user, device_id as i64, hs_id, ss.as_ref(), ct.as_ref(), peer, crate::now_ms() as i64, v],
        )?;
        // Keep only the two newest attempts (a late response to the previous
        // one still completes); older secrets are deleted.
        self.db.conn().execute(
            "DELETE FROM pq_pending WHERE user = ?1 AND device_id = ?2 AND hs_id NOT IN
             (SELECT hs_id FROM pq_pending WHERE user = ?1 AND device_id = ?2 ORDER BY created_ms DESC LIMIT 2)",
            params![user, device_id as i64],
        )?;
        // Our delivery token, readable only by the real responder (under the
        // secret we just encapsulated to its key), so its reply can use the
        // normal lane.
        let token = seal_data(domain::PQ_INIT_TOKEN, &ss, (&self.user, self.device_id), (user, device_id), &hs_id, v, &self.delivery_token()?)?;
        Ok(Some(padded(PqFrame {
            kind: pq_kind::INIT,
            hs_id,
            kem_key: self.kem_auth_public()?,
            ct: ct.to_vec(),
            sender_delivery_token: token,
            ..Default::default()
        }, v)))
    }

    /// Process a frame from a device (already decrypted by libsignal).
    /// `relay_url` is where a handshake response must go; `msg_id` names the
    /// message if it has to be held.
    pub fn pq_receive(&self, user: &[u8], device_id: u32, frame: &[u8], relay_url: &str, msg_id: &str) -> Result<PqIn> {
        let f = PqFrame::decode(frame).map_err(|_| anyhow!("malformed post-quantum frame"))?;
        e2ee_proto::check_protocol("a message from this device", f.version).map_err(|e| anyhow!(e))?;
        match f.kind {
            pq_kind::DATA => {
                let key: Option<(Vec<u8>, bool)> = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT key, confirmed FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                        params![user, device_id as i64, f.hs_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match key {
                    Some((key, confirmed)) => {
                        let Some(plain) = open_data(domain::PQ_AUTH_DATA, &key, (user, device_id), (&self.user, self.device_id), &f.hs_id, f.version, &f.payload) else {
                            bail!("message fails post-quantum authentication");
                        };
                        if !confirmed {
                            // The initiator proved it holds its KEM key.
                            self.db.conn().execute(
                                "UPDATE pq_keys SET confirmed = 1, resp = NULL WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                                params![user, device_id as i64, f.hs_id],
                            )?;
                        }
                        // Something from it decrypts: it has a key we have, so
                        // there's nothing more to wait for (whichever key it is:
                        // after simultaneous handshakes it may keep another).
                        self.db.conn().execute("DELETE FROM meta WHERE k = ?1", [awaiting_key(user, device_id)])?;
                        Ok(PqIn::Payload(plain))
                    }
                    None if self.pending(user, device_id, &f.hs_id)? => {
                        self.db.conn().execute(
                            "INSERT OR IGNORE INTO pq_held (msg_id, user, device_id, frame, received_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![msg_id, user, device_id as i64, frame, crate::now_ms() as i64],
                        )?;
                        Ok(PqIn::Held)
                    }
                    None => {
                        // A key the sender has and we don't (we never got
                        // its handshake, or an impostor's inits pushed it
                        // out): start a handshake of our own, which only the
                        // real device can answer. Once it's confirmed both
                        // ends switch to it, so the pair heals.
                        // (Not an error: this runs in the mailbox transaction,
                        // which must keep the mark. The message is dropped;
                        // the engine's resend requests recover what it held.)
                        // If we just completed a handshake of our own, the
                        // device hasn't heard from us under it yet: its
                        // older messages are expected, and it switches once
                        // ours arrive. Only otherwise does it lack a key.
                        if self.db.meta_get(&awaiting_key(user, device_id))?.is_none() {
                            self.db.meta_set(&stale_key(user, device_id), b"1")?;
                        }
                        Ok(PqIn::Handled)
                    }
                }
            }
            pq_kind::INIT => {
                // We respond: decapsulate ours, encapsulate to theirs. The
                // init is only classically authenticated (anyone able to pose
                // as the sender to libsignal could send it), so the key stays
                // unconfirmed: it never displaces a confirmed key for sending
                // until a message that decrypts under it shows the sender
                // holds its KEM key.
                // A handshake id is 16 random bytes and names one handshake:
                // an init can't reuse one (that would overwrite its key).
                let taken: bool = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT 1 FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                        params![user, device_id as i64, f.hs_id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                let pending = self.pending(user, device_id, &f.hs_id)?;
                if f.hs_id.len() != 16 || taken || pending {
                    bail!("handshake init with a malformed or already used handshake id");
                }
                // One init per device per half retry interval (an honest
                // initiator retries hourly): a flood of inits must not make
                // us store keys, pay to answer, or reset our session for each.
                let recent: Option<i64> = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT MAX(created_ms) FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 0",
                        params![user, device_id as i64],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                if recent.is_some_and(|t| crate::now_ms().saturating_sub(t as u64) < INIT_RETRY_MS / 2) {
                    return Ok(PqIn::Handled);
                }
                self.store_peer_kem(user, device_id, &f.kem_key)?;
                let had_confirmed = self.has_confirmed_key(user, device_id)?;
                let me = self.kem_auth()?;
                let ss_resp = me.secret_key.decapsulate(&f.ct.clone().into_boxed_slice())?;
                // Its delivery token, on first contact only (so our first
                // replies, e.g. history for a new member, don't all go over
                // the limited stranger lane). Anyone can make an init, so it
                // never replaces a token we know, and the authenticated token
                // in the sender's first message replaces it.
                if let Some(t) = open_data(domain::PQ_INIT_TOKEN, &ss_resp, (user, device_id), (&self.user, self.device_id), &f.hs_id, f.version, &f.sender_delivery_token)
                    && user != self.user.as_slice()
                    && self.db.delivery_token(user)?.is_none()
                {
                    self.db.set_delivery_token(user, &t)?;
                }
                let (ss_init, ct_init) = kem::PublicKey::deserialize(&f.kem_key)?.encapsulate(&mut rand::rng())?;
                let key = derive_key(
                    (user, device_id),
                    (&self.user, self.device_id),
                    &f.kem_key,
                    &me.public_key.serialize(),
                    &f.ct,
                    &ct_init,
                    &ss_resp,
                    &ss_init,
                    &f.hs_id,
                    f.version,
                );
                self.db.conn().execute(
                    "INSERT OR REPLACE INTO pq_keys (user, device_id, hs_id, key, created_ms, confirmed) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    params![user, device_id as i64, f.hs_id, key, crate::now_ms() as i64],
                )?;
                // The init's version (already checked as one we speak).
                let v = f.version;
                let token = seal_data(domain::PQ_RESP_TOKEN, &key, (&self.user, self.device_id), (user, device_id), &f.hs_id, v, &self.delivery_token()?)?;
                let resp = padded(PqFrame {
                    kind: pq_kind::RESP,
                    hs_id: f.hs_id.clone(),
                    ct: ct_init.to_vec(),
                    mac: mac(&key, &resp_mac_input(v)),
                    // Encrypted under the new key: only the real initiator
                    // can read it, not whoever controls the libsignal session.
                    sender_delivery_token: token,
                    ..Default::default()
                }, v);
                // At most one answer waiting per device, and eight unconfirmed
                // keys kept. An impostor's inits can push out a real one;
                // the DATA case heals that.
                // (Per relay: an init through one relay mustn't drop an
                // answer still owed through another.)
                self.db.conn().execute(
                    "DELETE FROM pq_outbox WHERE user = ?1 AND device_id = ?2 AND relay_url = ?3",
                    params![user, device_id as i64, relay_url],
                )?;
                self.db.conn().execute(
                    "INSERT INTO pq_outbox (relay_url, user, device_id, frame) VALUES (?1, ?2, ?3, ?4)",
                    params![relay_url, user, device_id as i64, resp],
                )?;
                // Kept until the key is confirmed, in case it's lost.
                self.db.conn().execute(
                    "UPDATE pq_keys SET resp = ?4 WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                    params![user, device_id as i64, f.hs_id, resp],
                )?;
                self.db.conn().execute(
                    "DELETE FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 0 AND hs_id NOT IN
                     (SELECT hs_id FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 0 ORDER BY created_ms DESC LIMIT 8)",
                    params![user, device_id as i64],
                )?;
                // Retire our libsignal session only if we had nothing
                // confirmed with this device (see `HandledInit`); otherwise a
                // forged init could keep resetting it.
                Ok(if had_confirmed { PqIn::Handled } else { PqIn::HandledInit })
            }
            pq_kind::RESP => {
                let row: Option<PendingRow> = self
                    .db
                    .conn()
                    .query_row(
                        "SELECT ss, ct, peer_kem, version FROM pq_pending WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                        params![user, device_id as i64, f.hs_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                let Some((ss_resp, ct_resp, peer_kem, init_version)) = row else {
                    bail!("handshake response for a handshake we did not start");
                };
                let me = self.kem_auth()?;
                let ss_init = me.secret_key.decapsulate(&f.ct.clone().into_boxed_slice())?;
                let key = derive_key(
                    (&self.user, self.device_id),
                    (user, device_id),
                    &me.public_key.serialize(),
                    &peer_kem,
                    &ct_resp,
                    &f.ct,
                    &ss_resp,
                    &ss_init,
                    &f.hs_id,
                    init_version, // what our init said
                );
                if !mac_ok(&key, &resp_mac_input(f.version), &f.mac) {
                    bail!("handshake response fails post-quantum authentication");
                }
                self.store_key(user, device_id, &f.hs_id, &key)?;
                // Owed handshake done; we send under this key (the newest
                // confirmed one) from now on, and wait to see the device use it.
                self.db.conn().execute("DELETE FROM meta WHERE k = ?1", [stale_key(user, device_id)])?;
                self.db.meta_set(&awaiting_key(user, device_id), &f.hs_id)?;
                if let Some(t) = open_data(domain::PQ_RESP_TOKEN, &key, (user, device_id), (&self.user, self.device_id), &f.hs_id, f.version, &f.sender_delivery_token) {
                    self.adopt_delivery_token(user, &t)?;
                }
                self.db.conn().execute(
                    "DELETE FROM pq_pending WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                    params![user, device_id as i64, f.hs_id],
                )?;
                Ok(PqIn::Handled)
            }
            k => bail!("unknown post-quantum frame kind {k}"),
        }
    }

    fn pending(&self, user: &[u8], device_id: u32, hs_id: &[u8]) -> Result<bool> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT 1 FROM pq_pending WHERE user = ?1 AND device_id = ?2 AND hs_id = ?3",
                params![user, device_id as i64, hs_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn has_confirmed_key(&self, user: &[u8], device_id: u32) -> Result<bool> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT 1 FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 1",
                params![user, device_id as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// A delivery token from a post-quantum authenticated frame of `user`'s
    /// (our own devices tell us about rotations of ours).
    fn adopt_delivery_token(&self, user: &[u8], token: &[u8]) -> Result<()> {
        if user == self.user.as_slice() {
            self.db.meta_set("delivery_token", token)
        } else {
            self.db.set_delivery_token(user, token)
        }
    }

    fn store_key(&self, user: &[u8], device_id: u32, hs_id: &[u8], key: &[u8]) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR REPLACE INTO pq_keys (user, device_id, hs_id, key, created_ms, confirmed) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![user, device_id as i64, hs_id, key, crate::now_ms() as i64],
        )?;
        Ok(())
    }

    /// Handshake responses to send through `relay_url`: (row id, user, device, frame).
    pub fn pq_outbox(&self, relay_url: &str) -> Result<Vec<PeerItem<i64>>> {
        let mut st = self
            .db
            .conn()
            .prepare("SELECT id, user, device_id, frame FROM pq_outbox WHERE relay_url = ?1 ORDER BY id")?;
        let rows = st.query_map([relay_url], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32, r.get(3)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Drop the newest handshake we started with a device: its init never
    /// went out, so the next flush may start another right away.
    /// Before re-sending something a device may never have received: if
    /// our newest key with it is one it hasn't confirmed, queue our reply to
    /// its handshake again (the first may have expired on the relay, and its
    /// messages under that key wait for it). With no key at all, forget our
    /// own unanswered inits, so the next one goes out at once. Returns
    /// whether a reply was queued.
    pub fn pq_requeue_handshake(&self, user: &[u8], device_id: u32, relay_url: &str) -> Result<bool> {
        let resp: Option<Vec<u8>> = self
            .db
            .conn()
            .query_row(
                "SELECT resp FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 0 AND resp IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM pq_keys WHERE user = ?1 AND device_id = ?2 AND confirmed = 1)
                 ORDER BY created_ms DESC LIMIT 1",
                params![user, device_id as i64],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(frame) = resp {
            self.db.conn().execute(
                "DELETE FROM pq_outbox WHERE user = ?1 AND device_id = ?2 AND relay_url = ?3",
                params![user, device_id as i64, relay_url],
            )?;
            self.db.conn().execute(
                "INSERT INTO pq_outbox (relay_url, user, device_id, frame) VALUES (?1, ?2, ?3, ?4)",
                params![relay_url, user, device_id as i64, frame],
            )?;
            return Ok(true);
        }
        if self.pq_key(user, device_id)?.is_none() {
            self.db.conn().execute("DELETE FROM pq_pending WHERE user = ?1 AND device_id = ?2", params![user, device_id as i64])?;
        }
        Ok(false)
    }

    pub fn pq_forget_pending(&self, user: &[u8], device_id: u32) -> Result<()> {
        self.db.conn().execute(
            "DELETE FROM pq_pending WHERE user = ?1 AND device_id = ?2
             AND created_ms = (SELECT MAX(created_ms) FROM pq_pending WHERE user = ?1 AND device_id = ?2)",
            params![user, device_id as i64],
        )?;
        Ok(())
    }

    pub fn pq_outbox_done(&self, id: i64) -> Result<()> {
        self.db.conn().execute("DELETE FROM pq_outbox WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Held messages whose handshake has completed since, verified and
    /// removed: (msg id, user, device, payload). Bad ones are dropped, and
    /// ones held longer than `max_age_ms` expire.
    pub fn pq_release_held(&self, max_age_ms: u64) -> Result<Vec<PeerItem<String>>> {
        let cutoff = crate::now_ms().saturating_sub(max_age_ms) as i64;
        self.db.conn().execute("DELETE FROM pq_held WHERE received_ms < ?1", [cutoff])?;
        let rows: Vec<(String, Vec<u8>, u32, Vec<u8>)> = {
            let mut st = self.db.conn().prepare("SELECT msg_id, user, device_id, frame FROM pq_held ORDER BY received_ms")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32, r.get(3)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut out = Vec::new();
        for (id, user, dev, frame) in rows {
            let hs_id = PqFrame::decode(frame.as_slice()).map(|f| f.hs_id).unwrap_or_default();
            if self.pending(&user, dev, &hs_id)? {
                continue; // still waiting for the response
            }
            self.db.conn().execute("DELETE FROM pq_held WHERE msg_id = ?1", [&id])?;
            if let Ok(PqIn::Payload(p)) = self.pq_receive(&user, dev, &frame, "", &id) {
                out.push((id, user, dev, p));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    fn user() -> Device {
        Device::create_user(&Db::open_in_memory().unwrap()).unwrap()
    }

    fn introduce(a: &Device, b: &Device) {
        a.db.pin(&b.user, &b.master_pub, true).unwrap();
        let signed = SignedDeviceList::decode(b.db.signed_device_list(&b.user).unwrap().unwrap().as_slice()).unwrap();
        a.accept_device_list(&b.user, &signed).unwrap();
    }

    fn pair() -> (Device, Device) {
        let (a, b) = (user(), user());
        introduce(&a, &b);
        introduce(&b, &a);
        a.store_peer_kem(&b.user, 1, &b.kem_auth_public().unwrap()).unwrap();
        (a, b)
    }

    fn payload(r: Result<PqIn>) -> Vec<u8> {
        match r.unwrap() {
            PqIn::Payload(p) => p,
            _ => panic!("expected a payload"),
        }
    }

    #[test]
    fn handshake_then_authenticated_messages_both_ways() {
        let (a, b) = pair();
        assert!(!a.pq_ready(&b.user, 1).unwrap());
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        assert_eq!(init.len(), HANDSHAKE_PAD);
        assert!(a.pq_init(&b.user, 1).unwrap().is_none(), "one handshake in flight at a time");
        assert!(matches!(b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap(), PqIn::HandledInit));
        // B is ready at once; its first message reaches A before the response.
        assert!(b.pq_ready(&a.user, 1).unwrap());
        let early = b.pq_wrap(&a.user, 1, b"early").unwrap();
        assert!(matches!(a.pq_receive(&b.user, 1, &early, "r", "m2").unwrap(), PqIn::Held));
        assert!(a.pq_release_held(u64::MAX).unwrap().is_empty(), "held until the response");
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        assert!(b.pq_outbox("other relay").unwrap().is_empty());
        assert!(matches!(a.pq_receive(&b.user, 1, &resp, "r", "m3").unwrap(), PqIn::Handled));
        let released = a.pq_release_held(u64::MAX).unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!((released[0].0.as_str(), released[0].3.as_slice()), ("m2", &b"early"[..]));
        let m = a.pq_wrap(&b.user, 1, b"hello").unwrap();
        assert_eq!(payload(b.pq_receive(&a.user, 1, &m, "r", "m4")), b"hello");
    }

    #[test]
    fn tampering_reflection_and_missing_handshakes_are_rejected() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &resp, "r", "m2").unwrap();

        let m = a.pq_wrap(&b.user, 1, b"hello").unwrap();
        let mut f = PqFrame::decode(m.as_slice()).unwrap();
        f.payload = b"jello".to_vec();
        assert!(b.pq_receive(&a.user, 1, &f.encode_to_vec(), "r", "m3").is_err(), "tampered payload");
        // A's own message fed back to A as if from B: the MAC binds direction.
        assert!(a.pq_receive(&b.user, 1, &m, "r", "m4").is_err(), "reflected message");
        // A device we never shook hands with.
        let c = user();
        introduce(&b, &c);
        let raw = PqFrame { kind: pq_kind::DATA, hs_id: vec![0; 16], mac: vec![0; 32], payload: b"x".to_vec(), version: e2ee_proto::PROTOCOL_VERSION, ..Default::default() };
        // Dropped (nothing gets through), and B will start a handshake.
        assert!(matches!(b.pq_receive(&c.user, 1, &raw.encode_to_vec(), "r", "m5").unwrap(), PqIn::Handled));
    }

    /// Someone able to pose as A to libsignal sends B a fresh init after A
    /// and B already share a confirmed key. B must keep sending under the
    /// confirmed key (A can still read B), must not reset its session, and
    /// must not adopt the init's delivery token.
    #[test]
    fn forged_init_does_not_displace_a_confirmed_key() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &resp, "r", "m2").unwrap();
        let hello = a.pq_wrap(&b.user, 1, b"hello").unwrap();
        payload(b.pq_receive(&a.user, 1, &hello, "r", "m3")); // confirms B's key

        let b_kem = kem::PublicKey::deserialize(&b.kem_auth_public().unwrap()).unwrap();
        let (_, ct) = b_kem.encapsulate(&mut rand::rng()).unwrap();
        let forged = PqFrame {
            kind: pq_kind::INIT,
            hs_id: vec![7; 16],
            kem_key: a.kem_auth_public().unwrap(),
            ct: ct.to_vec(),
            sender_delivery_token: b"attacker token".to_vec(),
            version: e2ee_proto::PROTOCOL_VERSION,
            ..Default::default()
        };
        assert!(matches!(b.pq_receive(&a.user, 1, &forged.encode_to_vec(), "r", "m4").unwrap(), PqIn::Handled));
        let reply = b.pq_wrap(&a.user, 1, b"still readable").unwrap();
        assert_eq!(payload(a.pq_receive(&b.user, 1, &reply, "r", "m5")), b"still readable");
        assert_ne!(b.db.delivery_token(&a.user).unwrap().as_deref(), Some(&b"attacker token"[..]));
    }

    /// Data frames are encrypted under the pairwise key, not just MACed: a
    /// party that controls the libsignal session sees only ciphertext.
    #[test]
    fn data_frames_hide_their_payload() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &resp, "r", "m2").unwrap();
        let m = a.pq_wrap(&b.user, 1, b"the secret plans").unwrap();
        assert!(!m.windows(16).any(|w| w == b"the secret plans"), "plaintext visible in the frame");
        assert_eq!(payload(b.pq_receive(&a.user, 1, &m, "r", "m3")), b"the secret plans");
    }

    /// B loses the key A sends under (an impostor's inits pushed it out).
    /// B starts a handshake of its own, and once it completes both
    /// directions work again.
    #[test]
    fn a_lost_key_heals() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &resp, "r", "m2").unwrap();
        b.db.conn().execute("DELETE FROM pq_keys", []).unwrap(); // evicted
        b.db.conn().execute("DELETE FROM pq_outbox", []).unwrap();
        let lost = a.pq_wrap(&b.user, 1, b"lost").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &lost, "r", "m3").unwrap(), PqIn::Handled));
        assert!(b.pq_needs_handshake(&a.user, 1).unwrap(), "B doesn't know it needs a new handshake");
        let init = b.pq_init(&a.user, 1).unwrap().unwrap();
        a.pq_receive(&b.user, 1, &init, "r", "m4").unwrap();
        let resp = a.pq_outbox("r").unwrap().remove(0).3;
        b.pq_receive(&a.user, 1, &resp, "r", "m5").unwrap();
        assert!(!b.pq_needs_handshake(&a.user, 1).unwrap());
        // The bad order: another message from A under the old key arrives
        // after the handshake completed (same mailbox pull). It's expected,
        // not a reason to start over.
        let straggler = a.pq_wrap(&b.user, 1, b"late").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &straggler, "r", "m5b").unwrap(), PqIn::Handled));
        assert!(!b.pq_needs_handshake(&a.user, 1).unwrap(), "a straggler restarted the handshake");
        let hello = b.pq_wrap(&a.user, 1, b"hello").unwrap();
        assert!(matches!(a.pq_receive(&b.user, 1, &hello, "r", "m6").unwrap(), PqIn::Payload(_)));
        let back = a.pq_wrap(&b.user, 1, b"back").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &back, "r", "m7").unwrap(), PqIn::Payload(p) if p == b"back"));
    }

    /// Eviction for real: after A's genuine handshake, inits B can't tell
    /// from A's (made here by A forgetting each one, so they never complete)
    /// push A's key out of B's eight unconfirmed slots. A keeps sending under
    /// it; B heals with a handshake of its own.
    #[test]
    fn evicted_keys_heal_without_touching_the_database_by_hand() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m0").unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &resp, "r", "m1").unwrap();
        for i in 0..8 {
            a.db.conn().execute("DELETE FROM pq_pending", []).unwrap();
            // Past B's half-hour limit on answered inits.
            b.db.conn().execute("UPDATE pq_keys SET created_ms = created_ms - 3600000", []).unwrap();
            let forged = a.pq_init(&b.user, 1).unwrap().unwrap();
            b.pq_receive(&a.user, 1, &forged, "r", &format!("f{i}")).unwrap();
        }
        let n: i64 = b.db.conn().query_row("SELECT COUNT(*) FROM pq_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 8);
        let lost = a.pq_wrap(&b.user, 1, b"lost").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &lost, "r", "m2").unwrap(), PqIn::Handled));
        assert!(b.pq_needs_handshake(&a.user, 1).unwrap());
        b.db.conn().execute("DELETE FROM pq_outbox", []).unwrap();
        let init = b.pq_init(&a.user, 1).unwrap().unwrap();
        a.pq_receive(&b.user, 1, &init, "r", "m3").unwrap();
        let resp = a.pq_outbox("r").unwrap().remove(0).3;
        b.pq_receive(&a.user, 1, &resp, "r", "m4").unwrap();
        let hello = b.pq_wrap(&a.user, 1, b"hello").unwrap();
        assert!(matches!(a.pq_receive(&b.user, 1, &hello, "r", "m5").unwrap(), PqIn::Payload(_)));
        let back = a.pq_wrap(&b.user, 1, b"back").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &back, "r", "m6").unwrap(), PqIn::Payload(p) if p == b"back"));
    }

    /// Both start a handshake at once. Each answers the other's; traffic
    /// works both ways, nothing is left waiting, and a later loss still
    /// heals (the "awaiting" mark doesn't stick).
    #[test]
    fn simultaneous_handshakes_settle_and_later_losses_still_heal() {
        let (a, b) = pair();
        b.store_peer_kem(&a.user, 1, &a.kem_auth_public().unwrap()).unwrap();
        let ia = a.pq_init(&b.user, 1).unwrap().unwrap();
        let ib = b.pq_init(&a.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &ia, "r", "a1").unwrap();
        a.pq_receive(&b.user, 1, &ib, "r", "b1").unwrap();
        let ra = a.pq_outbox("r").unwrap().remove(0).3;
        let rb = b.pq_outbox("r").unwrap().remove(0).3;
        a.pq_receive(&b.user, 1, &rb, "r", "b2").unwrap();
        b.pq_receive(&a.user, 1, &ra, "r", "a2").unwrap();
        for (from, to, id) in [(&a, &b, "x1"), (&b, &a, "x2"), (&a, &b, "x3"), (&b, &a, "x4")] {
            let m = from.pq_wrap(&to.user, 1, b"hi").unwrap();
            assert!(matches!(to.pq_receive(&from.user, 1, &m, "r", id).unwrap(), PqIn::Payload(_)), "{id}");
        }
        let awaiting = |d: &Device, peer: &Device| d.db.meta_get(&awaiting_key(&peer.user, 1)).unwrap();
        assert!(awaiting(&a, &b).is_none() && awaiting(&b, &a).is_none(), "an awaiting mark stuck");
        // Later B loses every key; A's next message marks A as owed a handshake.
        b.db.conn().execute("DELETE FROM pq_keys", []).unwrap();
        let m = a.pq_wrap(&b.user, 1, b"later").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &m, "r", "x5").unwrap(), PqIn::Handled));
        assert!(b.pq_needs_handshake(&a.user, 1).unwrap(), "a later loss no longer heals");
    }

    /// A flood of inits from one device gets one answer: no key, outbox
    /// entry or session reset per init.
    #[test]
    fn init_floods_get_one_answer() {
        let (a, b) = pair();
        let first = a.pq_init(&b.user, 1).unwrap().unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &first, "r", "m1").unwrap(), PqIn::HandledInit));
        for i in 0..5 {
            a.db.conn().execute("DELETE FROM pq_pending", []).unwrap(); // let A init again at once
            let again = a.pq_init(&b.user, 1).unwrap().unwrap();
            assert!(matches!(b.pq_receive(&a.user, 1, &again, "r", &format!("m{}", i + 2)).unwrap(), PqIn::Handled));
        }
        let n = |t: &str| b.db.conn().query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!((n("pq_keys"), n("pq_outbox")), (1, 1));
    }

    /// Delivery tokens in handshakes are encrypted (to the responder's KEM
    /// key in an init, under the new key in a response), and a pending
    /// handshake's id can't be taken by the peer's init either.
    #[test]
    fn handshake_tokens_are_encrypted_and_pending_ids_are_taken() {
        let (a, b) = pair();
        let a_token = a.delivery_token().unwrap();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        assert!(!init.windows(a_token.len()).any(|w| w == a_token.as_slice()), "init carries the token in the clear");
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        assert_eq!(b.db.delivery_token(&a.user).unwrap(), Some(a_token.clone()));
        let b_token = b.delivery_token().unwrap();
        let resp = b.pq_outbox("r").unwrap().remove(0).3;
        assert!(!resp.windows(b_token.len()).any(|w| w == b_token.as_slice()), "response carries the token in the clear");
        a.pq_receive(&b.user, 1, &resp, "r", "m2").unwrap();
        assert_eq!(a.db.delivery_token(&b.user).unwrap(), Some(b_token));
        let data = a.pq_wrap(&b.user, 1, b"hi").unwrap();
        assert!(matches!(b.pq_receive(&a.user, 1, &data, "r", "m3").unwrap(), PqIn::Payload(_)));
        assert_eq!(b.db.delivery_token(&a.user).unwrap(), Some(a_token));
        // B's init reusing A's pending handshake id is refused by A.
        let (a2, b2) = pair();
        b2.store_peer_kem(&a2.user, 1, &a2.kem_auth_public().unwrap()).unwrap();
        let mine = PqFrame::decode(a2.pq_init(&b2.user, 1).unwrap().unwrap().as_slice()).unwrap();
        let mut theirs = PqFrame::decode(b2.pq_init(&a2.user, 1).unwrap().unwrap().as_slice()).unwrap();
        theirs.hs_id = mine.hs_id;
        assert!(a2.pq_receive(&b2.user, 1, &theirs.encode_to_vec(), "r", "m2").is_err());
    }

    /// An init can't reuse a handshake id (which would overwrite that key).
    #[test]
    fn handshake_ids_cant_be_reused() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        b.pq_receive(&a.user, 1, &init, "r", "m1").unwrap();
        assert!(b.pq_receive(&a.user, 1, &init, "r", "m2").is_err());
        let mut f = PqFrame::decode(init.as_slice()).unwrap();
        f.hs_id = vec![1; 3];
        assert!(b.pq_receive(&a.user, 1, &f.encode_to_vec(), "r", "m3").is_err());
    }

    #[test]
    fn frames_from_a_newer_protocol_are_refused() {
        let (a, b) = pair();
        let init = a.pq_init(&b.user, 1).unwrap().unwrap();
        let mut f = PqFrame::decode(init.as_slice()).unwrap();
        f.version = e2ee_proto::PROTOCOL_VERSION + 1;
        let err = b.pq_receive(&a.user, 1, &f.encode_to_vec(), "r", "m").err().unwrap().to_string();
        assert!(err.contains("upgrade"), "{err}");
    }

    /// Someone who can pose as A at the libsignal layer (e.g. a quantum
    /// attacker holding A's Curve25519 key) but lacks A's ML-KEM secret key.
    #[test]
    fn impostor_without_the_kem_secret_cannot_authenticate() {
        let (a, b) = pair();
        let a_kem = a.kem_auth_public().unwrap();
        let b_kem = kem::PublicKey::deserialize(&b.kem_auth_public().unwrap()).unwrap();

        // Its own KEM key isn't the one A's device list names.
        let own = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rand::rng());
        let (_, ct) = b_kem.encapsulate(&mut rand::rng()).unwrap();
        let fake = PqFrame { kind: pq_kind::INIT, hs_id: vec![1; 16], kem_key: own.public_key.serialize().to_vec(), ct: ct.to_vec(), version: e2ee_proto::PROTOCOL_VERSION, ..Default::default() };
        assert!(b.pq_receive(&a.user, 1, &fake.encode_to_vec(), "r", "m1").is_err());

        // With A's real (public) KEM key B answers, but encapsulates to A:
        // the impostor knows ss_B, not ss_A, so it can't produce valid MACs.
        let (ss_b, ct) = b_kem.encapsulate(&mut rand::rng()).unwrap();
        let hs_id = vec![2; 16];
        let fake = PqFrame { kind: pq_kind::INIT, hs_id: hs_id.clone(), kem_key: a_kem.clone(), ct: ct.to_vec(), version: e2ee_proto::PROTOCOL_VERSION, ..Default::default() };
        assert!(matches!(b.pq_receive(&a.user, 1, &fake.encode_to_vec(), "r", "m2").unwrap(), PqIn::HandledInit));
        let resp = PqFrame::decode(b.pq_outbox("r").unwrap().remove(0).3.as_slice()).unwrap();
        let guess = derive_key(
            (&a.user, 1),
            (&b.user, 1),
            &a_kem,
            &b.kem_auth_public().unwrap(),
            &ct,
            &resp.ct,
            &ss_b,
            &[0u8; 32], // ss_A: unknown without A's KEM secret
            &hs_id,
            e2ee_proto::PROTOCOL_VERSION,
        );
        let forged = PqFrame {
            kind: pq_kind::DATA,
            payload: seal_data(domain::PQ_AUTH_DATA, &guess, (&a.user, 1), (&b.user, 1), &hs_id, e2ee_proto::PROTOCOL_VERSION, b"evil").unwrap(),
            hs_id,
            version: e2ee_proto::PROTOCOL_VERSION,
            ..Default::default()
        };
        assert!(b.pq_receive(&a.user, 1, &forged.encode_to_vec(), "r", "m3").is_err());

        // Posing as B toward A: A's init is encapsulated to B's key, so a
        // forged response can't confirm the key.
        let init = PqFrame::decode(a.pq_init(&b.user, 1).unwrap().unwrap().as_slice()).unwrap();
        let (ss_a, ct_a) = kem::PublicKey::deserialize(&a_kem).unwrap().encapsulate(&mut rand::rng()).unwrap();
        let guess = derive_key(
            (&a.user, 1),
            (&b.user, 1),
            &a_kem,
            &b.kem_auth_public().unwrap(),
            &init.ct,
            &ct_a,
            &[0u8; 32], // ss_B: unknown without B's KEM secret
            &ss_a,
            &init.hs_id,
            e2ee_proto::PROTOCOL_VERSION,
        );
        let forged = PqFrame { kind: pq_kind::RESP, hs_id: init.hs_id, ct: ct_a.to_vec(), mac: mac(&guess, &resp_mac_input(e2ee_proto::PROTOCOL_VERSION)), version: e2ee_proto::PROTOCOL_VERSION, ..Default::default() };
        assert!(a.pq_receive(&b.user, 1, &forged.encode_to_vec(), "r", "m4").is_err());
        assert!(!a.pq_ready(&b.user, 1).unwrap());
    }
}
