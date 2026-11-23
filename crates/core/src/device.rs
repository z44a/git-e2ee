//! This device's identity, prekeys, and pairwise sealed-sender sessions.

use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use e2ee_proto::api::{Bundle, KeyUpload, OneTimeKey, SignedKey};
use e2ee_proto::{DeviceEntry, Message, SignedDeviceList, user_id_of};
use libsignal_protocol::{
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage,
    ProtocolAddress, PublicKey, SenderCertificate, ServerCertificate, SessionUsabilityRequirements,
    SignalMessage, SignedPreKeyId, SignedPreKeyRecord, Timestamp, kem, message_decrypt_prekey,
    message_decrypt_signal, process_prekey_bundle, sealed_sender_decrypt_to_usmc,
    message_encrypt, sealed_sender_encrypt_from_usmc, ContentHint, UnidentifiedSenderMessageContent, IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SessionStore,
    SignedPreKeyStore,
};
use rand::Rng;

use crate::identity::{self, Approval, MasterKeyPair, VerifiedDeviceList};
use crate::store::{Db, Stores};

pub const ONE_TIME_BATCH: u32 = 50;
pub const KYBER_ONE_TIME_BATCH: u32 = 20;
pub const ONE_TIME_LOW_WATER: u64 = 10;
/// Rough sealed-sender overhead around the inner message (first guess only).
const DUMMY_OVERHEAD_GUESS: usize = 400;

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

pub struct Device {
    pub db: Db,
    pub stores: Stores,
    pub user: Vec<u8>,
    pub device_id: u32,
    pub identity: IdentityKeyPair,
    /// This device's ML-DSA seed (signs relay requests next to `identity`).
    pub pq_seed: [u8; 32],
    /// The user's master id (see `e2ee_proto::master_id`).
    pub master_pub: Vec<u8>,
    /// Present only on the device holding the master key.
    pub master: Option<MasterKeyPair>,
    sender_cert: SenderCertificate,
}

fn sender_certificate(user_hex: &str, device_id: u32, identity: &IdentityKeyPair) -> Result<SenderCertificate> {
    // Recipients authenticate senders through the inner pairwise session and
    // the cross-signed device gate, not through this certificate, so it is
    // signed by a throwaway key that proves nothing to anyone.
    let rng = &mut rand::rng();
    let trust_root = KeyPair::generate(rng);
    let server = KeyPair::generate(rng);
    let server_cert = ServerCertificate::new(1, server.public_key, &trust_root.private_key, rng)?;
    let expires = Timestamp::from_epoch_millis(crate::now_ms() + 7 * 24 * 3600 * 1000);
    Ok(SenderCertificate::new(
        user_hex.to_string(),
        None,
        *identity.public_key(),
        DeviceId::new(device_id as u8)?,
        expires,
        server_cert,
        &server.private_key,
        rng,
    )?)
}

impl Device {
    /// Load the fully set-up device, if any.
    pub fn load(db: &Db) -> Result<Option<Self>> {
        let (Some(id), Some(dev), Some(master_pub)) = (
            db.meta_get("device_identity")?,
            db.meta_u64("device_id")?,
            db.meta_get("master_pub")?,
        ) else {
            return Ok(None);
        };
        let identity = IdentityKeyPair::try_from(id.as_slice())?;
        let master = match (db.meta_get("master_pair")?, db.meta_get("master_pq_seed")?) {
            (Some(m), Some(seed)) => Some(MasterKeyPair {
                classical: IdentityKeyPair::try_from(m.as_slice())?,
                pq_seed: seed.as_slice().try_into().map_err(|_| anyhow!("bad master pq seed"))?,
            }),
            _ => None,
        };
        let pq_seed: [u8; 32] = db
            .meta_get("device_pq_seed")?
            .ok_or_else(|| anyhow!("device has no post-quantum key"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("bad device pq seed"))?;
        let reg = db.meta_u64("registration_id")?.unwrap_or(1) as u32;
        let user = user_id_of(&master_pub).to_vec();
        let sender_cert = sender_certificate(&hex::encode(&user), dev as u32, &identity)?;
        Ok(Some(Self {
            stores: Stores::new(db, identity, reg),
            db: db.clone(),
            user,
            device_id: dev as u32,
            identity,
            pq_seed,
            master_pub,
            master,
            sender_cert,
        }))
    }

    pub fn require(db: &Db) -> Result<Self> {
        Self::load(db)?.ok_or_else(|| {
            anyhow!("this device is not set up; run `git e2ee init-user` or `git e2ee device link`")
        })
    }

    fn device_identity_or_create(db: &Db) -> Result<IdentityKeyPair> {
        if let Some(id) = db.meta_get("device_identity")? {
            return Ok(IdentityKeyPair::try_from(id.as_slice())?);
        }
        let id = IdentityKeyPair::generate(&mut rand::rng());
        db.meta_set("device_pq_seed", &rand::random::<[u8; 32]>())?;
        let kem_auth = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rand::rng());
        db.meta_set("device_kem_pk", &kem_auth.public_key.serialize())?;
        db.meta_set("device_kem_sk", &kem_auth.secret_key.serialize())?;
        db.meta_set("device_identity", &id.serialize())?;
        db.meta_set_u64("registration_id", rand::rng().random_range(1..16380))?;
        Ok(id)
    }

    /// Create a new user: a master key plus this device as device 1.
    pub fn create_user(db: &Db) -> Result<Self> {
        if db.meta_get("master_pub")?.is_some() {
            bail!("this device already belongs to a user");
        }
        let identity = Self::device_identity_or_create(db)?;
        let master = MasterKeyPair::generate();
        let master_pub = master.id();
        let body = identity::next_device_list(
            &master,
            None,
            vec![DeviceEntry {
                device_id: 1,
                identity_key: identity.identity_key().serialize().to_vec(),
                added_at_ms: crate::now_ms(),
                pq_key_hash: Self::device_pq_hash(db)?.to_vec(),
                kem_key_hash: Self::device_kem_hash(db)?.to_vec(),
                max_protocol: e2ee_proto::PROTOCOL_VERSION,
                added_in: 0,
            }],
        );
        let signed = identity::sign_device_list(&master, &body)?;
        db.meta_set("master_pair", &master.classical.serialize())?;
        db.meta_set("master_pq_seed", &master.pq_seed)?;
        db.meta_set("master_pub", &master_pub)?;
        db.meta_set_u64("device_id", 1)?;
        let user = user_id_of(&master_pub);
        db.pin(&user, &master_pub, true)?;
        let dev = Self::require(db)?;
        dev.accept_device_list(&dev.user.clone(), &signed)?;
        Ok(dev)
    }

    fn device_pq_hash(db: &Db) -> Result<e2ee_proto::Hash> {
        let seed = db.meta_get("device_pq_seed")?.ok_or_else(|| anyhow!("device has no post-quantum key"))?;
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| anyhow!("bad device pq seed"))?;
        Ok(e2ee_proto::pq::key_hash(&e2ee_proto::pq::public_key(&seed)))
    }

    fn device_kem_hash(db: &Db) -> Result<e2ee_proto::Hash> {
        let pk = db.meta_get("device_kem_pk")?.ok_or_else(|| anyhow!("device has no KEM authentication key"))?;
        Ok(e2ee_proto::kem_key_hash(&pk))
    }

    /// This device's ML-DSA public key.
    pub fn pq_public(&self) -> Vec<u8> {
        e2ee_proto::pq::public_key(&self.pq_seed)
    }

    /// Start linking: create (or reuse) this device's identity and return the
    /// code to paste on the master device.
    pub fn begin_link(db: &Db) -> Result<String> {
        if db.meta_get("master_pub")?.is_some() {
            bail!("this device is already linked");
        }
        let id = Self::device_identity_or_create(db)?;
        Ok(identity::encode_link_code(&id.identity_key().serialize(), &Self::device_pq_hash(db)?, &Self::device_kem_hash(db)?))
    }

    /// Finish linking with the approval code from the master device.
    /// `signed`: the user's device list, fetched from the approval's relay.
    pub fn finish_link(db: &Db, approval: &Approval, signed: &SignedDeviceList) -> Result<Self> {
        let identity = Self::device_identity_or_create(db)?;
        // The master key comes with the list; it must be the one the user
        // id names (the relay served the list, and can't forge that).
        let body = e2ee_proto::DeviceListBody::decode(signed.body.as_slice()).context("malformed device list")?;
        if user_id_of(&body.master_key).as_slice() != approval.user_id {
            bail!("the relay served a device list for another user: refusing it");
        }
        let master_key = body.master_key.clone();
        let (list, _) = identity::verify_device_list(signed, &master_key, None)?;
        let mine = identity.identity_key().serialize().to_vec();
        if !list
            .body
            .devices
            .iter()
            .any(|d| {
                d.device_id == approval.device_id
                    && d.identity_key == mine
                    && d.pq_key_hash == Self::device_pq_hash(db).unwrap_or_default()
                    && d.kem_key_hash == Self::device_kem_hash(db).unwrap_or_default()
            })
        {
            bail!(
                "the device list on the relay doesn't include this device yet: run `git e2ee device approve` \
                 on the master device again (it publishes the list), then finish again"
            );
        }
        db.meta_set("master_pub", &master_key)?;
        db.meta_set_u64("device_id", approval.device_id as u64)?;
        if !approval.delivery_token.is_empty() {
            db.meta_set("delivery_token", &approval.delivery_token)?;
        }
        let user = user_id_of(&master_key);
        db.pin(&user, &master_key, true)?;
        let dev = Self::require(db)?;
        dev.accept_device_list(&dev.user.clone(), signed)?;
        Ok(dev)
    }

    /// Master device: approve a link code, producing the new signed list and
    /// the approval code to paste on the new device.
    /// `relay_url`: this account's relay, where the new device fetches the
    /// list and registers.
    pub fn approve_link(&self, link_code: &str, relay_url: &str) -> Result<(SignedDeviceList, String, u32)> {
        let master = self.master.as_ref().ok_or_else(|| anyhow!("only the master device can approve devices"))?;
        let (new_key, pq_key_hash, kem_key_hash) = identity::decode_link_code(link_code)?;
        let current = self.own_device_list()?;
        let mut devices = current.body.devices.clone();
        if devices.iter().any(|d| d.identity_key == new_key) {
            bail!("that device is already linked");
        }
        let used: Vec<u32> = devices.iter().map(|d| d.device_id).collect();
        let next_meta = self.db.meta_u64("max_device_id")?.unwrap_or(0) as u32;
        let id = (1..=127u32)
            .find(|i| *i > next_meta.max(*used.iter().max().unwrap_or(&0)))
            .ok_or_else(|| anyhow!("device id space exhausted"))?;
        devices.push(DeviceEntry { device_id: id, identity_key: new_key, added_at_ms: crate::now_ms(), pq_key_hash, kem_key_hash, max_protocol: e2ee_proto::PROTOCOL_VERSION, added_in: 0 });
        let signed = identity::sign_device_list(master, &identity::next_device_list(master, Some(&current), devices))?;
        self.accept_own_signed(&signed)?;
        self.db.meta_set_u64("max_device_id", id as u64)?;
        let code = identity::encode_approval(&Approval {
            user_id: self.user.clone(),
            device_id: id,
            delivery_token: self.delivery_token()?,
            relay_url: relay_url.to_string(),
        });
        Ok((signed, code, id))
    }

    /// Master device: revoke a device by publishing a list without it.
    pub fn revoke(&self, device_id: u32) -> Result<SignedDeviceList> {
        let master = self.master.as_ref().ok_or_else(|| anyhow!("only the master device can revoke devices"))?;
        if device_id == self.device_id {
            bail!("cannot revoke the master device itself");
        }
        let current = self.own_device_list()?;
        let devices: Vec<DeviceEntry> =
            current.body.devices.iter().filter(|d| d.device_id != device_id).cloned().collect();
        if devices.len() == current.body.devices.len() {
            bail!("device {device_id} is not in the device list");
        }
        let signed = identity::sign_device_list(master, &identity::next_device_list(master, Some(&current), devices))?;
        self.accept_own_signed(&signed)?;
        Ok(signed)
    }

    pub fn own_device_list(&self) -> Result<VerifiedDeviceList> {
        let signed = self
            .db
            .signed_device_list(&self.user)?
            .ok_or_else(|| anyhow!("no device list stored for this user"))?;
        let signed = SignedDeviceList::decode(signed.as_slice())?;
        Ok(identity::verify_device_list(&signed, &self.master_pub, None)?.0)
    }

    /// Verify a signed list against the pinned master key and our last seen
    /// version, and adopt it if newer. Returns the devices now trusted.
    pub fn accept_device_list(&self, user: &[u8], signed: &SignedDeviceList) -> Result<Vec<(u32, Vec<u8>)>> {
        self.accept_list(user, signed, true)
    }

    /// Adopt a list this device just signed itself (no change notice).
    fn accept_own_signed(&self, signed: &SignedDeviceList) -> Result<Vec<(u32, Vec<u8>)>> {
        self.accept_list(&self.user.clone(), signed, false)
    }

    fn accept_list(&self, user: &[u8], signed: &SignedDeviceList, notify: bool) -> Result<Vec<(u32, Vec<u8>)>> {
        let (master, _) = self
            .db
            .pinned(user)?
            .ok_or_else(|| anyhow!("no pinned master key for user {}", hex::encode(user)))?;
        let last = self.db.device_list_state(user)?;
        let (list, update) =
            identity::verify_device_list(signed, &master, last.as_ref().map(|(v, h)| (*v, h.as_slice())))
                .with_context(|| format!("device list of user {}", short(user)))?;
        if list.body.user_id != user {
            bail!("device list is for user {}, not {}", short(&list.body.user_id), short(user));
        }
        let devices = list.devices();
        if update == identity::ListUpdate::Newer {
            // Devices that came and went in versions we never saw: report
            // both, so a skipped version can't hide a short-lived device.
            if notify && let Some((old_version, _)) = last {
                let known = self.db.devices_of(user)?;
                for r in &list.body.revoked {
                    if r.revoked_in > old_version && r.added_in > old_version && !known.iter().any(|(d, _)| *d == r.device_id) {
                        self.db.add_device_event(user, r.device_id, true, r.added_in)?;
                        self.db.add_device_event(user, r.device_id, false, r.revoked_in)?;
                    }
                }
            }
            self.db.store_device_list(user, list.body.version, &list.body_hash, &signed.encode_to_vec(), &devices, notify)?;
            let keep: Vec<u32> = devices.iter().map(|d| d.0).collect();
            self.db.drop_sessions_except(&hex::encode(user), &keep)?;
        }
        Ok(devices)
    }

    /// Our user's delivery token (created on first use; shared by all of our
    /// devices through the approval code and in-band rotation).
    pub fn delivery_token(&self) -> Result<Vec<u8>> {
        if let Some(t) = self.db.meta_get("delivery_token")? {
            return Ok(t);
        }
        let mut t = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut t);
        self.db.meta_set("delivery_token", &t)?;
        Ok(t)
    }

    /// Replace our delivery token (cuts off anyone who obtained the old one).
    pub fn rotate_delivery_token(&self) -> Result<Vec<u8>> {
        let mut t = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut t);
        self.db.meta_set("delivery_token", &t)?;
        Ok(t)
    }

    pub fn address(&self) -> Result<ProtocolAddress> {
        address(&self.user, self.device_id)
    }

    // -- prekeys -------------------------------------------------------------

    /// Current signed prekey id (0 if none yet).
    pub fn signed_prekey_id(&self) -> Result<u32> {
        Ok(self.db.meta_u64("signed_prekey_id")?.unwrap_or(0) as u32)
    }

    /// Rotate the signed EC prekey and the last-resort Kyber prekey if they
    /// are older than `E2EE_PREKEY_ROTATE_SECS` (default 7 days), and delete
    /// superseded ones older than `E2EE_PREKEY_GRACE_SECS` (default 14 days),
    /// which bounds how long a stolen prekey can decrypt delayed first messages.
    /// Returns whether a rotation happened.
    pub async fn rotate_prekeys_if_due(&mut self) -> Result<bool> {
        let rotate_ms = env_secs("E2EE_PREKEY_ROTATE_SECS", 7 * 24 * 3600) * 1000;
        let grace_ms = env_secs("E2EE_PREKEY_GRACE_SECS", 14 * 24 * 3600) * 1000;
        self.rotate_prekeys(rotate_ms, grace_ms).await
    }

    pub async fn rotate_prekeys(&mut self, rotate_ms: u64, grace_ms: u64) -> Result<bool> {
        let now = crate::now_ms();
        let last = self.db.meta_u64("prekeys_rotated_ms")?.unwrap_or(0);
        let due = self.signed_prekey_id()? == 0 || now.saturating_sub(last) >= rotate_ms;
        if due {
            // The grace period runs from when a key stops being current.
            self.db.conn().execute("UPDATE signed_prekeys SET superseded_ms = ?1 WHERE superseded_ms IS NULL", [now as i64])?;
            self.db
                .conn()
                .execute("UPDATE kyber_prekeys SET superseded_ms = ?1 WHERE one_time = 0 AND superseded_ms IS NULL", [now as i64])?;
            let rng = &mut rand::rng();
            let id = self.db.next_ids("signed_prekey", 1)? as u32;
            let kp = KeyPair::generate(rng);
            let sig = self.identity.private_key().calculate_signature(&kp.public_key.serialize(), rng)?;
            let rec = SignedPreKeyRecord::new(id.into(), Timestamp::from_epoch_millis(now), &kp, &sig);
            self.stores.signed_prekeys.save_signed_pre_key(id.into(), &rec).await?;
            let kid = self.db.next_ids("kyber_prekey", 1)? as u32;
            let krec = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kid.into(), self.identity.private_key())?;
            self.stores.kyber.save_kyber_pre_key(kid.into(), &krec).await?;
            self.db.meta_set_u64("signed_prekey_id", id as u64)?;
            self.db.meta_set_u64("kyber_prekey_id", kid as u64)?;
            self.db.meta_set_u64("prekeys_rotated_ms", now)?;
        }
        let cutoff = now.saturating_sub(grace_ms) as i64;
        let (spk, kpk) = (self.signed_prekey_id()?, self.db.meta_u64("kyber_prekey_id")?.unwrap_or(0) as u32);
        self.db
            .conn()
            .execute("DELETE FROM signed_prekeys WHERE id != ?1 AND superseded_ms < ?2", rusqlite::params![spk, cutoff])?;
        self.db.conn().execute(
            "DELETE FROM kyber_prekeys WHERE one_time = 0 AND id != ?1 AND superseded_ms < ?2",
            rusqlite::params![kpk, cutoff],
        )?;
        Ok(due)
    }

    /// Keys to upload to a relay: optionally the current signed and
    /// last-resort Kyber prekeys, plus fresh one-time EC and Kyber prekeys.
    pub async fn key_upload(&mut self, one_time: u32, kyber_one_time: u32, include_signed: bool) -> Result<KeyUpload> {
        self.rotate_prekeys_if_due().await?;
        let rng = &mut rand::rng();
        let mut upload = KeyUpload {
            identity_key: self.identity.identity_key().serialize().to_vec(),
            pq_key: self.pq_public(),
            kem_auth_key: self.kem_auth_public()?,
            registration_id: self.stores.identity.get_local_registration_id().await?,
            signed_prekey: None,
            kyber_prekey: None,
            one_time: vec![],
            kyber_one_time: vec![],
        };
        if include_signed {
            let rec = self.stores.signed_prekeys.get_signed_pre_key(SignedPreKeyId::from(self.signed_prekey_id()?)).await?;
            upload.signed_prekey = Some(SignedKey {
                id: self.signed_prekey_id()?,
                public: rec.public_key()?.serialize().to_vec(),
                signature: rec.signature()?.to_vec(),
            });
            let kid = self.db.meta_u64("kyber_prekey_id")?.unwrap_or(0) as u32;
            let rec = self.stores.kyber.get_kyber_pre_key(KyberPreKeyId::from(kid)).await?;
            upload.kyber_prekey = Some(SignedKey {
                id: kid,
                public: rec.public_key()?.serialize().to_vec(),
                signature: rec.signature()?.to_vec(),
            });
        }
        if one_time > 0 {
            let start = self.db.next_ids("prekey", one_time as u64)? as u32;
            for id in start..start + one_time {
                let kp = KeyPair::generate(rng);
                self.stores.prekeys.save_pre_key(PreKeyId::from(id), &PreKeyRecord::new(id.into(), &kp)).await?;
                upload.one_time.push(OneTimeKey { id, public: kp.public_key.serialize().to_vec() });
            }
        }
        if kyber_one_time > 0 {
            let start = self.db.next_ids("kyber_prekey", kyber_one_time as u64)? as u32;
            for id in start..start + kyber_one_time {
                let rec = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id.into(), self.identity.private_key())?;
                self.stores.kyber.save_kyber_pre_key(id.into(), &rec).await?;
                self.db.conn().execute("UPDATE kyber_prekeys SET one_time = 1 WHERE id = ?1", [id])?;
                upload.kyber_one_time.push(SignedKey {
                    id,
                    public: rec.public_key()?.serialize().to_vec(),
                    signature: rec.signature()?.to_vec(),
                });
            }
        }
        Ok(upload)
    }

    // -- sessions ------------------------------------------------------------

    /// Whether we have a usable PQXDH session with this device.
    pub async fn has_session(&self, user: &[u8], device_id: u32) -> Result<bool> {
        let addr = address(user, device_id)?;
        let Some(rec) = self.stores.sessions.load_session(&addr).await? else {
            return Ok(false);
        };
        Ok(rec
            .has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::all())
            .unwrap_or(false))
    }

    /// Establish a session from a prekey bundle fetched from the relay.
    pub async fn start_session(&mut self, user: &[u8], device_id: u32, b: &Bundle) -> Result<()> {
        let addr = address(user, device_id)?;
        let bundle = PreKeyBundle::new(
            b.registration_id,
            DeviceId::new(device_id as u8)?,
            b.one_time
                .as_ref()
                .map(|k| Ok::<_, anyhow::Error>((PreKeyId::from(k.id), PublicKey::deserialize(&k.public)?)))
                .transpose()?,
            SignedPreKeyId::from(b.signed_prekey.id),
            PublicKey::deserialize(&b.signed_prekey.public)?,
            b.signed_prekey.signature.clone(),
            KyberPreKeyId::from(b.kyber_prekey.id),
            kem::PublicKey::deserialize(&b.kyber_prekey.public)?,
            b.kyber_prekey.signature.clone(),
            IdentityKey::try_from(b.identity_key.as_slice())?,
        )?;
        // process_prekey_bundle consults is_trusted_identity: the bundle's
        // identity key must be in the user's cross-signed device list.
        process_prekey_bundle(
            &addr,
            &self.address()?,
            &mut self.stores.sessions,
            &mut self.stores.identity,
            &bundle,
            SystemTime::now(),
            &mut rand::rng(),
        )
        .await
        .with_context(|| format!("starting session with {}.{device_id}", short(user)))?;
        self.store_peer_kem(user, device_id, &b.kem_auth_key)?;
        Ok(())
    }

    /// Retire the active session with a device so the next send starts a
    /// fresh one from a new prekey bundle. Old sessions stay archived and can
    /// still decrypt messages already sent on them.
    pub async fn reset_session(&mut self, user: &[u8], device_id: u32) -> Result<()> {
        let addr = address(user, device_id)?;
        if let Some(mut rec) = self.stores.sessions.load_session(&addr).await? {
            rec.archive_current_state()?;
            self.stores.sessions.store_session(&addr, &rec).await?;
        }
        Ok(())
    }

    /// Encrypt to one device with the pairwise session, wrapped in sealed sender.
    ///
    /// Our current signed device list rides along in the sealed-sender layer
    /// (the otherwise unused `group_id` field), readable by the recipient
    /// before the inner message. So a revocation reaches every peer with our
    /// next message, and a new device introduces itself, whatever device list
    /// the relay chooses to serve.
    pub async fn seal_to(&mut self, user: &[u8], device_id: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let addr = address(user, device_id)?;
        let rng = &mut rand::rng();
        let inner = message_encrypt(
            plaintext,
            &addr,
            &self.address()?,
            &mut self.stores.sessions,
            &mut self.stores.identity,
            SystemTime::now(),
            rng,
        )
        .await?;
        let usmc = UnidentifiedSenderMessageContent::new(
            inner.message_type(),
            self.sender_cert.clone(),
            inner.serialize().to_vec(),
            ContentHint::Default,
            self.db.signed_device_list(&self.user)?,
        )?;
        Ok(sealed_sender_encrypt_from_usmc(&addr, &usmc, &self.stores.identity, rng).await?)
    }

    /// A sealed-sender message to our own mailbox that the relay cannot tell
    /// apart from real mail: a genuine sealed-sender envelope (fresh ephemeral
    /// key, our certificate inside) around random bytes, sized to
    /// `target_len`. No session with ourselves is involved.
    pub async fn dummy_to_self(&self, target_len: usize) -> Result<Vec<u8>> {
        let addr = self.address()?;
        let rng = &mut rand::rng();
        let mut inner = target_len.saturating_sub(DUMMY_OVERHEAD_GUESS);
        let mut out = Vec::new();
        // The outer length is the inner length plus a near-constant overhead
        // (protobuf varints can shift it by a byte), so this converges fast.
        for _ in 0..6 {
            let mut contents = vec![0u8; inner];
            rand::RngCore::fill_bytes(rng, &mut contents);
            let usmc = UnidentifiedSenderMessageContent::new(
                CiphertextMessageType::Whisper,
                self.sender_cert.clone(),
                contents,
                ContentHint::Default,
                self.db.signed_device_list(&self.user)?,
            )?;
            out = sealed_sender_encrypt_from_usmc(&addr, &usmc, &self.stores.identity, rng).await?;
            if out.len() == target_len {
                break;
            }
            inner = (inner as isize + target_len as isize - out.len() as isize).max(0) as usize;
        }
        Ok(out)
    }

    /// Identify the sender of a sealed message without decrypting its body.
    /// libsignal checks the certificate key equals the sender's static key.
    pub async fn peek_sender(&self, sealed: &[u8]) -> Result<(Vec<u8>, u32)> {
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &self.stores.identity).await?;
        let cert = usmc.sender()?;
        Ok((hex::decode(cert.sender_uuid()?)?, u32::from(cert.sender_device_id()?)))
    }

    /// Decrypt a sealed message. Fails unless the sender device is in a
    /// verified device list and its key matches the certificate.
    pub async fn open_sealed(&mut self, sealed: &[u8]) -> Result<(Vec<u8>, u32, Vec<u8>)> {
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &self.stores.identity).await?;
        let cert = usmc.sender()?;
        let user = hex::decode(cert.sender_uuid()?)?;
        let dev = u32::from(cert.sender_device_id()?);
        // Adopt the sender's device list if it is newer than ours. It is
        // self-authenticating (master-signed); an older or invalid one is
        // simply ignored, and a fork is reported by accept_device_list.
        if let Some(list) = usmc.group_id()?
            && let Ok(signed) = SignedDeviceList::decode(list)
            && let Err(e) = self.accept_device_list(&user, &signed)
            && format!("{e:#}").contains("fork")
        {
            return Err(e);
        }
        let known = self
            .db
            .device_key(&user, dev)?
            .ok_or_else(|| anyhow!("message from unknown device {}.{dev}", short(&user)))?;
        if known != IdentityKey::new(cert.key()?).serialize().as_ref() {
            bail!("sender certificate key does not match the verified device key");
        }
        let remote = address(&user, dev)?;
        let local = self.address()?;
        let rng = &mut rand::rng();
        let pt = match usmc.msg_type()? {
            CiphertextMessageType::Whisper => {
                let m = SignalMessage::try_from(usmc.contents()?)?;
                message_decrypt_signal(&m, &remote, &local, &mut self.stores.sessions, &mut self.stores.identity, rng).await?
            }
            CiphertextMessageType::PreKey => {
                let m = PreKeySignalMessage::try_from(usmc.contents()?)?;
                let r = message_decrypt_prekey(
                    &m,
                    &remote,
                    &local,
                    &mut self.stores.sessions,
                    &mut self.stores.identity,
                    &mut self.stores.prekeys,
                    &self.stores.signed_prekeys,
                    &mut self.stores.kyber,
                    rng,
                )
                .await?;
                r.plaintext
            }
            t => bail!("unexpected inner message type {t:?}"),
        };
        Ok((user, dev, pt))
    }
}


pub fn address(user: &[u8], device_id: u32) -> Result<ProtocolAddress> {
    Ok(ProtocolAddress::new(hex::encode(user), DeviceId::new(device_id as u8)?))
}

pub fn short(user: &[u8]) -> String {
    hex::encode(&user[..user.len().min(6)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2ee_proto::api::Bundle;

    fn bundle_from(up: &KeyUpload) -> Bundle {
        Bundle {
            identity_key: up.identity_key.clone(),
            registration_id: up.registration_id,
            signed_prekey: up.signed_prekey.clone().unwrap(),
            kyber_prekey: up.kyber_prekey.clone().unwrap(),
            one_time: up.one_time.first().cloned(),
            kem_auth_key: up.kem_auth_key.clone(),
        }
    }

    fn introduce(a: &Device, b: &Device) {
        a.db.pin(&b.user, &b.master_pub, true).unwrap();
        let signed = SignedDeviceList::decode(b.db.signed_device_list(&b.user).unwrap().unwrap().as_slice()).unwrap();
        a.accept_device_list(&b.user, &signed).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pqxdh_session_roundtrip_with_sealed_sender() {
        let mut alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        introduce(&alice, &bob);
        introduce(&bob, &alice);

        let up = bob.key_upload(5, 0, true).await.unwrap();
        alice.start_session(&bob.user, 1, &bundle_from(&up)).await.unwrap();
        assert!(alice.has_session(&bob.user, 1).await.unwrap());

        let ct = alice.seal_to(&bob.user.clone(), 1, b"hello bob").await.unwrap();
        assert_eq!(bob.peek_sender(&ct).await.unwrap(), (alice.user.clone(), 1));
        let (u, d, pt) = bob.open_sealed(&ct).await.unwrap();
        assert_eq!((u, d, pt.as_slice()), (alice.user.clone(), 1, &b"hello bob"[..]));
        // Replaying the same message must fail.
        assert!(bob.open_sealed(&ct).await.is_err());

        let reply = bob.seal_to(&alice.user.clone(), 1, b"hi alice").await.unwrap();
        let (_, _, pt) = alice.open_sealed(&reply).await.unwrap();
        assert_eq!(pt, b"hi alice");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn session_gate_rejects_unlisted_device() {
        let mut alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        introduce(&alice, &bob);
        // A "ghost" device injected by the relay: valid prekeys, but its
        // identity is not in Bob's signed device list.
        let mut ghost_db_dev = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut up = ghost_db_dev.key_upload(1, 0, true).await.unwrap();
        assert!(alice.start_session(&bob.user, 2, &bundle_from(&up)).await.is_err());
        // Even claiming to be Bob's device 1 with the ghost key fails.
        up.registration_id = 7;
        assert!(alice.start_session(&bob.user, 1, &bundle_from(&up)).await.is_err());
        // Bob's real bundle works.
        let real = bob.key_upload(1, 0, true).await.unwrap();
        alice.start_session(&bob.user, 1, &bundle_from(&real)).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn linking_and_revocation() {
        let master_db = Db::open_in_memory().unwrap();
        let master = Device::create_user(&master_db).unwrap();
        let new_db = Db::open_in_memory().unwrap();
        let link = Device::begin_link(&new_db).unwrap();
        let (signed, code, id) = master.approve_link(&link, "https://relay.test").unwrap();
        assert_eq!(id, 2);
        // Short: the device list (with its ML-DSA signature) isn't in it.
        assert!(code.len() < 200, "approval code is {} characters", code.len());
        let approval = identity::decode_approval(&code).unwrap();
        assert_eq!(approval.relay_url, "https://relay.test");
        // A list for another user (what a relay could serve instead) is refused.
        let other = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let other_list = other.own_device_list().unwrap();
        let other_signed = SignedDeviceList::decode(other.db.signed_device_list(&other.user).unwrap().unwrap().as_slice()).unwrap();
        let _ = other_list;
        assert!(Device::finish_link(&new_db, &approval, &other_signed).is_err());
        let laptop = Device::finish_link(&new_db, &approval, &signed).unwrap();
        assert_eq!(laptop.user, master.user);
        assert!(laptop.master.is_none());
        assert_eq!(laptop.own_device_list().unwrap().devices().len(), 2);

        let revoked = master.revoke(2).unwrap();
        assert_eq!(master.own_device_list().unwrap().devices().len(), 1);
        laptop.accept_device_list(&laptop.user.clone(), &revoked).unwrap();
        assert!(laptop.db.device_key(&laptop.user, 2).unwrap().is_none());
        // Re-linking the revoked key gets a fresh id, never reusing 2.
        let link2 = Device::begin_link(&Db::open_in_memory().unwrap()).unwrap();
        let (_, _, id2) = master.approve_link(&link2, "https://relay.test").unwrap();
        assert_eq!(id2, 3);
    }

    fn bundle_with_kyber(up: &KeyUpload, kyber: &SignedKey) -> Bundle {
        Bundle { kyber_prekey: kyber.clone(), ..bundle_from(up) }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotation_keeps_old_prekeys_for_in_flight_messages() {
        let mut alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        introduce(&alice, &bob);
        introduce(&bob, &alice);
        let old = bob.key_upload(1, 0, true).await.unwrap();
        // Alice fetched the old bundle and sends; meanwhile Bob rotates.
        alice.start_session(&bob.user, 1, &bundle_from(&old)).await.unwrap();
        let ct = alice.seal_to(&bob.user.clone(), 1, b"in flight").await.unwrap();
        let week = 7 * 24 * 3600 * 1000;
        assert!(bob.rotate_prekeys(0, week).await.unwrap());
        let new = bob.key_upload(0, 0, true).await.unwrap();
        assert_ne!(new.signed_prekey.as_ref().unwrap().id, old.signed_prekey.as_ref().unwrap().id);
        assert_ne!(new.kyber_prekey.as_ref().unwrap().id, old.kyber_prekey.as_ref().unwrap().id);
        // Within the grace period the old prekeys still decrypt.
        assert_eq!(bob.open_sealed(&ct).await.unwrap().2, b"in flight");
        // After the grace period they are gone.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!bob.rotate_prekeys(week, 0).await.unwrap());
        let old_id = old.signed_prekey.as_ref().unwrap().id;
        assert!(bob.stores.signed_prekeys.get_signed_pre_key(old_id.into()).await.is_err());
        assert!(bob.stores.signed_prekeys.get_signed_pre_key(bob.signed_prekey_id().unwrap().into()).await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_time_kyber_prekeys_are_single_use() {
        let mut alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mut carol = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        for x in [&alice, &carol] {
            introduce(x, &bob);
            introduce(&bob, x);
        }
        let up = bob.key_upload(2, 1, true).await.unwrap();
        let otk = up.kyber_one_time[0].clone();
        let mut b1 = bundle_with_kyber(&up, &otk);
        alice.start_session(&bob.user, 1, &b1).await.unwrap();
        let ct = alice.seal_to(&bob.user.clone(), 1, b"one").await.unwrap();
        bob.open_sealed(&ct).await.unwrap();
        // A second session (a misbehaving relay re-serving the key) fails.
        b1.one_time = up.one_time.get(1).cloned();
        carol.start_session(&bob.user, 1, &b1).await.unwrap();
        let ct2 = carol.seal_to(&bob.user.clone(), 1, b"two").await.unwrap();
        assert!(bob.open_sealed(&ct2).await.is_err());
    }

    #[test]
    fn user_ids_are_bound_to_master_keys() {
        let alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let mallory = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        // A roster claiming "Bob's id has Mallory's key" cannot be pinned.
        assert!(alice.db.pin(&bob.user, &mallory.master_pub, false).is_err());
        // Nor can a list signed by Mallory be stored as Bob's even if a
        // pin for Bob's id somehow pointed at Mallory's key.
        alice.db.pin(&mallory.user, &mallory.master_pub, false).unwrap();
        let mlist = SignedDeviceList::decode(mallory.db.signed_device_list(&mallory.user).unwrap().unwrap().as_slice()).unwrap();
        alice.db.conn().execute("INSERT INTO pinned (user, master_key, verified) VALUES (?1, ?2, 0)", rusqlite::params![bob.user, mallory.master_pub]).unwrap();
        assert!(alice.accept_device_list(&bob.user, &mlist).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn grace_period_runs_from_supersession_not_creation() {
        let mut bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let old = bob.key_upload(0, 0, true).await.unwrap().signed_prekey.unwrap().id;
        // Pretend the current key was created 40 days ago.
        bob.db.conn().execute("UPDATE signed_prekeys SET created_ms = 0", []).unwrap();
        let day = 24 * 3600 * 1000;
        assert!(bob.rotate_prekeys(0, 30 * day).await.unwrap());
        // Superseded just now: still within its 14-day grace period.
        assert!(bob.stores.signed_prekeys.get_signed_pre_key(old.into()).await.is_ok());
    }

    /// The relay hides v2 (which added a device) and serves v3 (which revoked
    /// it). The peer that last saw v1 is still told the device came and went.
    #[test]
    fn skipped_versions_cant_hide_a_short_lived_device() {
        let alice = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        let bob = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
        introduce(&bob, &alice);
        let master = alice.master.as_ref().unwrap();
        let v1 = alice.own_device_list().unwrap();
        let k = IdentityKeyPair::generate(&mut rand::rng());
        let mut devs = v1.body.devices.clone();
        devs.push(DeviceEntry {
            device_id: 2,
            identity_key: k.identity_key().serialize().to_vec(),
            pq_key_hash: vec![1; 32],
            kem_key_hash: vec![2; 32],
            max_protocol: e2ee_proto::PROTOCOL_VERSION,
            ..Default::default()
        });
        let s2 = identity::sign_device_list(master, &identity::next_device_list(master, Some(&v1), devs)).unwrap();
        let (v2, _) = identity::verify_device_list(&s2, &alice.master_pub, Some((1, &v1.body_hash))).unwrap();
        let s3 = identity::sign_device_list(master, &identity::next_device_list(master, Some(&v2), v1.body.devices.clone())).unwrap();
        bob.db.take_device_events().unwrap();
        bob.accept_device_list(&alice.user, &s3).unwrap(); // v2 never seen
        let events: Vec<(u32, bool)> = bob.db.take_device_events().unwrap().into_iter().map(|(_, d, a, _)| (d, a)).collect();
        assert_eq!(events, vec![(2, true), (2, false)]);
        // And the id can never be reused.
        let mut reuse = v1.body.devices.clone();
        reuse.push(DeviceEntry { device_id: 2, ..v2.body.devices[1].clone() });
        let (v3, _) = identity::verify_device_list(&s3, &alice.master_pub, Some((2, &v2.body_hash))).unwrap();
        let s4 = identity::sign_device_list(master, &identity::next_device_list(master, Some(&v3), reuse)).unwrap();
        assert!(identity::verify_device_list(&s4, &alice.master_pub, Some((3, &v3.body_hash))).is_err());
    }
}