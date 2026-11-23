//! Wire types and hashing rules shared by the helper and the relay.
//!
//! Everything that is signed or hashed is serialized exactly once and the
//! resulting bytes are transmitted alongside the signature. Verifiers work on
//! those bytes and never re-serialize.

pub mod api;
pub mod tokens;

pub use prost::Message;
use sha2::{Digest, Sha256};

/// Context strings prefixed to every hash and signature input, so a value
/// produced for one purpose can never be accepted for another.
pub mod migrate;

/// The wire protocol version this build speaks. Every versioned message
/// (`PqFrame`, `LogEntry`, `DeviceListBody`, `Roster`) and every relay
/// request carries it. Bump it for incompatible changes; a build accepts
/// versions `MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION`.
///
/// Upgrades: devices advertise the newest version they support in their
/// device entry (`max_protocol`), and a repo's roster records the version
/// its members use. A future version is switched on for a repo with a
/// roster change, once every member device advertises it.
///
/// History: 1 was the prototype. 2 changed what a push's view commits to
/// (the pack key's hash) and moved repo-token rotation into log appends;
/// version 1 repos can't be carried over and must be recreated.
pub const PROTOCOL_VERSION: u32 = 2;
pub const MIN_PROTOCOL_VERSION: u32 = 2;

/// Check a received protocol version; the error says what to do.
pub fn check_protocol(what: &str, version: u32) -> Result<(), String> {
    if version > PROTOCOL_VERSION {
        Err(format!(
            "{what} uses protocol version {version}, newer than this build's {PROTOCOL_VERSION}: upgrade git-e2ee"
        ))
    } else if version < MIN_PROTOCOL_VERSION {
        Err(format!(
            "{what} uses protocol version {version}, which this build no longer supports (oldest: {MIN_PROTOCOL_VERSION})"
        ))
    } else {
        Ok(())
    }
}

pub mod domain {
    pub const DEVICE_LIST: &[u8] = b"git-e2ee/v1/device-list";
    pub const VIEW: &[u8] = b"git-e2ee/v1/view";
    pub const LOG_COMMIT: &[u8] = b"git-e2ee/v1/log-commit";
    pub const LOG_ENTRY: &[u8] = b"git-e2ee/v1/log-entry";
    pub const ROSTER: &[u8] = b"git-e2ee/v1/roster";
    pub const RECIPIENTS: &[u8] = b"git-e2ee/v1/recipients";
    pub const PACK: &[u8] = b"git-e2ee/v1/pack";
    pub const PACK_CHUNKS: &[u8] = b"git-e2ee/v1/pack-chunks";
    pub const RELAY_AUTH: &[u8] = b"git-e2ee/v1/relay-auth";
    pub const DELIVERY_TOKEN: &[u8] = b"git-e2ee/v1/delivery-token";
    pub const USER_ID: &[u8] = b"git-e2ee/v1/user-id";
    pub const BLOB_DELETE: &[u8] = b"git-e2ee/v1/blob-delete";
    pub const REPO_ID: &[u8] = b"git-e2ee/v1/repo-id";
    pub const PQ_KEY: &[u8] = b"git-e2ee/v1/pq-key";
    pub const KEM_AUTH_KEY: &[u8] = b"git-e2ee/v1/kem-auth-key";
    pub const PQ_AUTH: &[u8] = b"git-e2ee/v1/pq-auth";
    pub const PQ_AUTH_RESP: &[u8] = b"git-e2ee/v1/pq-auth-resp";
    pub const PQ_AUTH_DATA: &[u8] = b"git-e2ee/v1/pq-auth-data";
    pub const PQ_DATA_KEY: &[u8] = b"git-e2ee/v1/pq-data-key";
    pub const PQ_INIT_TOKEN: &[u8] = b"git-e2ee/v1/pq-init-token";
    pub const PQ_RESP_TOKEN: &[u8] = b"git-e2ee/v1/pq-resp-token";
    pub const TOKEN_KEY: &[u8] = b"git-e2ee/v1/token-key";
    pub const CLAIM_NONCE: &[u8] = b"git-e2ee/v1/claim-nonce";
}

/// ML-DSA-87 (FIPS 204, NIST level 5), used next to every classical
/// signature of ours so that forging one needs both Curve25519 and ML-DSA
/// broken. Secret keys are kept as a 32-byte seed and re-derived on use.
pub mod pq {
    use libcrux_ml_dsa::ml_dsa_87 as dsa;

    pub const PUBLIC_KEY_LEN: usize = 2592;
    pub const SIGNATURE_LEN: usize = 4627;

    pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
        dsa::generate_key_pair(*seed).verification_key.as_slice().to_vec()
    }

    /// Hash of a public key, which is what device lists and user ids commit to.
    pub fn key_hash(public_key: &[u8]) -> super::Hash {
        super::hash_fields(super::domain::PQ_KEY, &[public_key])
    }

    /// Sign `msg`; `context` is the domain string (FIPS 204 context, max 255 bytes).
    pub fn sign(seed: &[u8; 32], context: &[u8], msg: &[u8]) -> Vec<u8> {
        let kp = dsa::generate_key_pair(*seed);
        let mut r = [0u8; 32];
        rand_core06::RngCore::fill_bytes(&mut rand_core06::OsRng, &mut r);
        dsa::sign(&kp.signing_key, msg, context, r)
            .expect("ML-DSA signing with a short context cannot fail")
            .as_slice()
            .to_vec()
    }

    pub fn verify(public_key: &[u8], context: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let (Ok(pk), Ok(sig)) = (<[u8; PUBLIC_KEY_LEN]>::try_from(public_key), <[u8; SIGNATURE_LEN]>::try_from(sig)) else {
            return false;
        };
        dsa::verify(&dsa::MLDSA87VerificationKey::new(pk), msg, context, &dsa::MLDSA87Signature::new(sig)).is_ok()
    }
}

/// A user's master identity: the classical master key (serialized libsignal
/// `IdentityKey`, 33 bytes) followed by the hash of the ML-DSA master key.
/// This is what is pinned, shown in user codes and hashed into the user id.
pub const MASTER_ID_LEN: usize = 33 + 32;

pub fn master_id(classical: &[u8], pq_public: &[u8]) -> Vec<u8> {
    [classical, &pq::key_hash(pq_public)].concat()
}

/// Split a master id into (classical key, ML-DSA key hash).
pub fn split_master_id(id: &[u8]) -> Option<(&[u8], &[u8])> {
    (id.len() == MASTER_ID_LEN).then(|| id.split_at(33))
}

pub type Hash = [u8; 32];
pub const ZERO_HASH: Hash = [0u8; 32];

/// SHA-256 over a domain string followed by length-prefixed fields.
/// Length prefixes make the encoding injective.
pub fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    for f in fields {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f);
    }
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

/// Bytes to sign for a payload under a domain (domain || payload).
pub fn signing_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 1 + payload.len());
    v.extend_from_slice(domain);
    v.push(0);
    v.extend_from_slice(payload);
    v
}

// ---------------------------------------------------------------------------
// Identity / cross-signing

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeviceEntry {
    #[prost(uint32, tag = "1")]
    pub device_id: u32,
    /// Serialized libsignal `IdentityKey` of the device.
    #[prost(bytes = "vec", tag = "2")]
    pub identity_key: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub added_at_ms: u64,
    /// `pq::key_hash` of the device's ML-DSA key (signs relay requests).
    #[prost(bytes = "vec", tag = "4")]
    pub pq_key_hash: Vec<u8>,
    /// `kem_key_hash` of the device's long-term ML-KEM authentication key
    /// (post-quantum authentication of its messages; see `PqFrame`).
    #[prost(bytes = "vec", tag = "5")]
    pub kem_key_hash: Vec<u8>,
    /// Newest protocol version this device supports (for upgrades).
    #[prost(uint32, tag = "6")]
    pub max_protocol: u32,
    /// The list version that added this device.
    #[prost(uint64, tag = "7")]
    pub added_in: u64,
}

/// A device that was in the list and has been revoked. Lists keep these, so
/// a peer that misses versions (or is served a later one by the relay)
/// still learns a short-lived device existed.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RevokedDevice {
    #[prost(uint32, tag = "1")]
    pub device_id: u32,
    #[prost(uint64, tag = "2")]
    pub added_in: u64,
    #[prost(uint64, tag = "3")]
    pub revoked_in: u64,
}

pub fn kem_key_hash(public_key: &[u8]) -> Hash {
    hash_fields(domain::KEM_AUTH_KEY, &[public_key])
}

/// What travels inside every libsignal message between two devices.
///
/// libsignal authenticates sessions with Curve25519 identity keys only. On
/// top, each pair of devices runs a KEM handshake against their long-term
/// ML-KEM keys (named in the hybrid-signed device lists) and encrypts every
/// message again under the resulting key (XChaCha20-Poly1305), so
/// impersonating a device, or reading its messages after taking over a
/// session, needs ML-KEM broken too. No signatures: both ends hold the key,
/// so it stays deniable.
///
/// - `INIT` (initiator to responder): `hs_id`, the initiator's KEM key,
///   `ct` = encapsulation to the responder's key.
/// - `RESP`: `hs_id`, `ct` = encapsulation to the initiator's key, `mac`
///   (key confirmation), and the responder's delivery token encrypted under
///   the new key.
/// - `DATA`: `hs_id` of an established handshake, `payload` = the message
///   encrypted under it.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PqFrame {
    #[prost(uint32, tag = "1")]
    pub kind: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub hs_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub mac: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub kem_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub ct: Vec<u8>,
    /// The sender's delivery token (as in `Envelope`), encrypted, so replies
    /// don't need the stranger lane: on `INIT` to the responder's KEM key
    /// (used on first contact only), on `RESP` under the new key.
    #[prost(bytes = "vec", tag = "7")]
    pub sender_delivery_token: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub padding: Vec<u8>,
    /// Protocol version of this frame and of the envelope inside it.
    #[prost(uint32, tag = "10")]
    pub version: u32,
}

pub mod pq_kind {
    pub const DATA: u32 = 1;
    pub const INIT: u32 = 2;
    pub const RESP: u32 = 3;
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeviceListBody {
    #[prost(bytes = "vec", tag = "1")]
    pub user_id: Vec<u8>,
    /// The master id (see `master_id`); `user_id` must equal `user_id_of(master_key)`.
    #[prost(bytes = "vec", tag = "2")]
    pub master_key: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub version: u64,
    /// Hash of the previous version's body bytes (zero for version 1).
    #[prost(bytes = "vec", tag = "4")]
    pub prev_hash: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub devices: Vec<DeviceEntry>,
    /// Protocol version of this list's format.
    #[prost(uint32, tag = "6")]
    pub protocol: u32,
    /// Every device ever revoked from this list (ids are never reused).
    #[prost(message, repeated, tag = "7")]
    pub revoked: Vec<RevokedDevice>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedDeviceList {
    /// Serialized `DeviceListBody`.
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    /// Classical master-key signature over `signing_input(DEVICE_LIST, body)`.
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    /// ML-DSA master-key signature over the same input. Both must verify.
    #[prost(bytes = "vec", tag = "3")]
    pub pq_signature: Vec<u8>,
    /// The ML-DSA master public key (its hash is part of the master id).
    #[prost(bytes = "vec", tag = "4")]
    pub master_pq_key: Vec<u8>,
}

impl SignedDeviceList {
    /// Check the ML-DSA half: the key matches the master id the body names
    /// and its signature verifies. Returns the decoded body. Callers also
    /// check the classical signature, and compare the master id with the one
    /// they pinned.
    pub fn verify_pq(&self) -> Option<DeviceListBody> {
        use prost::Message;
        let body = DeviceListBody::decode(self.body.as_slice()).ok()?;
        let (_, pq_hash) = split_master_id(&body.master_key)?;
        if pq::key_hash(&self.master_pq_key).as_slice() != pq_hash {
            return None;
        }
        let input = signing_input(domain::DEVICE_LIST, &self.body);
        pq::verify(&self.master_pq_key, domain::DEVICE_LIST, &input, &self.pq_signature).then_some(body)
    }
}

pub fn user_id_of(master_key: &[u8]) -> Hash {
    hash_fields(domain::USER_ID, &[master_key])
}

// ---------------------------------------------------------------------------
// Repo state

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, prost::Message)]
pub struct RefEntry {
    #[prost(string, tag = "1")]
    pub name: String,
    /// Hex SHA-256 object id.
    #[prost(string, tag = "2")]
    pub oid: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Member {
    #[prost(bytes = "vec", tag = "1")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub master_key: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Roster {
    #[prost(uint64, tag = "1")]
    pub version: u64,
    #[prost(message, repeated, tag = "2")]
    pub members: Vec<Member>,
    /// Shared repo secret; the relay delivery token is derived from it.
    #[prost(bytes = "vec", tag = "3")]
    pub repo_secret: Vec<u8>,
    /// The protocol version this repo's members use (see `PROTOCOL_VERSION`).
    #[prost(uint32, tag = "4")]
    pub protocol: u32,
    /// The repo's git object format: `object_format::SHA256`, or `SHA1` if
    /// its creator opted in. Fixed for the repo's lifetime.
    #[prost(string, tag = "5")]
    pub object_format: String,
    /// The repo's first secret. The repo id is derived from it (through its
    /// relay token, `repo_id_for_token(delivery_token(genesis_secret))`), so a
    /// newcomer can check a history bundle really is for this repo: only
    /// someone who has been a member knows it (the relay saw only the token).
    #[prost(bytes = "vec", tag = "6")]
    pub genesis_secret: Vec<u8>,
    /// Disappearing push-log entries: each entry of `git e2ee log` recorded
    /// while this is set is deleted this many seconds after it happened
    /// (0: kept). Any member can change it; it goes through the log like
    /// membership, so every member applies the same value at the same point.
    #[prost(uint64, tag = "7")]
    pub log_ttl_secs: u64,
}

pub mod object_format {
    pub const SHA256: &str = "sha256";
    pub const SHA1: &str = "sha1";

    /// Hex length of an object id in a known format.
    pub fn oid_len(format: &str) -> Option<usize> {
        match format {
            SHA256 => Some(64),
            SHA1 => Some(40),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Envelopes (plaintext inside libsignal + sealed sender)

#[derive(Clone, PartialEq, prost::Message)]
pub struct Push {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    /// The pack's encrypted chunks, in order (empty: no new objects).
    #[prost(string, repeated, tag = "2")]
    pub blob_ids: Vec<String>,
    #[prost(bytes = "vec", tag = "3")]
    pub pack_key: Vec<u8>,
    /// `chunks_hash(chunk_hashes)`: commits to every chunk, in order.
    #[prost(bytes = "vec", tag = "4")]
    pub pack_hash: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub refs: Vec<RefEntry>,
    #[prost(bytes = "vec", tag = "6")]
    pub prev_view: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub roster_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub recipients_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub view: Vec<u8>,
    /// Log head before this push's entry was appended.
    #[prost(bytes = "vec", tag = "11")]
    pub log_head: Vec<u8>,
    #[prost(string, tag = "12")]
    pub head_ref: String,
    /// The signed device lists the author computed `recipients_hash` from,
    /// so receivers can catch up without asking the relay (which would reveal
    /// the roster). Self-authenticating; not part of the view.
    #[prost(message, repeated, tag = "13")]
    pub device_lists: Vec<SignedDeviceList>,
    /// SHA-256 of each encrypted chunk as uploaded.
    #[prost(bytes = "vec", repeated, tag = "14")]
    pub chunk_hashes: Vec<Vec<u8>>,
    /// The device that made this push. Part of the view, and must be the
    /// authenticated sender of the envelope: nobody can forward someone
    /// else's push as their own.
    #[prost(bytes = "vec", tag = "15")]
    pub author_user: Vec<u8>,
    #[prost(uint32, tag = "16")]
    pub author_device: u32,
    /// SHA-256 of `pack_key`. The view commits to this (not the key), so a
    /// proof of the view can be passed on without the key.
    #[prost(bytes = "vec", tag = "17")]
    pub pack_key_hash: Vec<u8>,
}

/// An access-token key a device was given (see `Envelope::token_keys`).
#[derive(Clone, PartialEq, prost::Message)]
pub struct TokenKeySeen {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(uint32, tag = "2")]
    pub generation: u32,
    /// `token_key_hash(epoch, generation, key)`.
    #[prost(bytes = "vec", tag = "3")]
    pub key_hash: Vec<u8>,
}

pub fn token_key_hash(epoch: u64, generation: u32, key: &[u8]) -> Hash {
    hash_fields(domain::TOKEN_KEY, &[&epoch.to_be_bytes(), &generation.to_be_bytes(), key])
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Ack {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub view: Vec<u8>,
    /// Log head after entry `seq`.
    #[prost(bytes = "vec", tag = "3")]
    pub log_head: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Heartbeat {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub log_head: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub at_ms: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HistoryBundle {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub view: Vec<u8>,
    /// Log head after entry `seq`.
    #[prost(bytes = "vec", tag = "3")]
    pub log_head: Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    pub refs: Vec<RefEntry>,
    #[prost(message, optional, tag = "5")]
    pub roster: Option<Roster>,
    #[prost(string, repeated, tag = "6")]
    pub blob_ids: Vec<String>,
    #[prost(bytes = "vec", tag = "7")]
    pub pack_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub pack_hash: Vec<u8>,
    #[prost(string, tag = "9")]
    pub head_ref: String,
    #[prost(string, tag = "10")]
    pub relay_url: String,
    /// Every member's current signed device list, so a newcomer never takes
    /// its first view of anyone's devices from the relay.
    #[prost(message, repeated, tag = "11")]
    pub device_lists: Vec<SignedDeviceList>,
    /// Delivery tokens of the members the inviter knows, so the newcomer can
    /// reach them through the normal lane from the start.
    #[prost(message, repeated, tag = "12")]
    pub delivery_tokens: Vec<UserToken>,
    #[prost(bytes = "vec", repeated, tag = "13")]
    pub chunk_hashes: Vec<Vec<u8>>,
    /// The inviter's push log (its word only: the newcomer wasn't there).
    #[prost(message, repeated, tag = "14")]
    pub push_log: Vec<PushLogEntry>,
    /// Members' pseudonymous mailboxes for this repo that the inviter knows,
    /// so the newcomer can use them from the start.
    #[prost(message, repeated, tag = "15")]
    pub mailboxes: Vec<PeerMailbox>,
    /// Proof of `refs`, `head_ref` and `roster`: the last push (if any) and
    /// every roster change after it, whose views chain to `view`. Without
    /// it a sender could pair the real view with refs of its own making.
    #[prost(message, optional, tag = "16")]
    pub proof_push: Option<Push>,
    #[prost(message, repeated, tag = "17")]
    pub proof_rosters: Vec<RosterChange>,
}

/// A device's pseudonymous mailbox for one repo (see `Envelope::reply_mailbox`).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PeerMailbox {
    #[prost(bytes = "vec", tag = "1")]
    pub user: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub device: u32,
    /// 16 random bytes; the relay address is its hex.
    #[prost(bytes = "vec", tag = "3")]
    pub mailbox: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RosterChange {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(message, optional, tag = "2")]
    pub roster: Option<Roster>,
    #[prost(bytes = "vec", tag = "3")]
    pub prev_view: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub view: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub recipients_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub log_head: Vec<u8>,
    /// Signed device lists of every member of the new roster (see Push).
    #[prost(message, repeated, tag = "8")]
    pub device_lists: Vec<SignedDeviceList>,
    /// The device that made this change (see `Push::author_user`).
    #[prost(bytes = "vec", tag = "9")]
    pub author_user: Vec<u8>,
    #[prost(uint32, tag = "10")]
    pub author_device: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ResendRequest {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    #[prost(bytes = "vec", tag = "1")]
    pub repo_id: Vec<u8>,
    #[prost(oneof = "envelope::Body", tags = "2, 3, 4, 5, 6, 7, 8, 14")]
    pub body: Option<envelope::Body>,
    /// Zeros filling the encoding up to a size bucket (see `pad_envelope`).
    #[prost(bytes = "vec", tag = "9")]
    pub padding: Vec<u8>,
    /// The sender user's current delivery token, so contacts can reach it
    /// through the relay's normal lane (and learn rotations).
    #[prost(bytes = "vec", tag = "10")]
    pub sender_delivery_token: Vec<u8>,
    /// When the sender encrypted this (its clock). Authenticated, so a relay
    /// that holds mail back cannot make it look fresh on arrival.
    #[prost(uint64, tag = "11")]
    pub sent_ms: u64,
    /// The access-token keys the sender was given by this relay for the
    /// current and previous day. Members compare them: a relay that gives
    /// one device a key of its own (to recognize that device's "anonymous"
    /// tokens) is caught when that device's key reaches anyone else.
    #[prost(message, repeated, tag = "12")]
    pub token_keys: Vec<TokenKeySeen>,
    /// The sender device's current pseudonymous mailbox for `repo_id`: reply
    /// there, not to the mailbox named by its user id. Mail to it reveals no
    /// user to the relay, and isn't linkable to the device's other repos.
    #[prost(bytes = "vec", tag = "13")]
    pub reply_mailbox: Vec<u8>,
}

/// One ref update in a push: `old`/`new` empty for creation/deletion.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RefChange {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub old_oid: String,
    #[prost(string, tag = "3")]
    pub new_oid: String,
    /// The ref moved to something that doesn't contain its old value.
    #[prost(bool, tag = "4")]
    pub forced: bool,
    /// Commits reachable from the old value but not the new one.
    #[prost(uint32, tag = "5")]
    pub dropped: u32,
}

/// A member's local record of who made a log entry and what it changed.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PushLogEntry {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(uint64, tag = "2")]
    pub at_ms: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub user_id: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub device_id: u32,
    #[prost(message, repeated, tag = "5")]
    pub changes: Vec<RefChange>,
    /// Membership changes ("added …", "removed …").
    #[prost(string, tag = "6")]
    pub note: String,
    /// When this entry disappears (ms since the epoch; 0: never). Set from the
    /// repo's timer when the entry was recorded; later timer changes don't
    /// touch it.
    #[prost(uint64, tag = "7")]
    pub expires_ms: u64,
    /// This entry is the notice of the latest timer change: it stays until
    /// the next one replaces it.
    #[prost(bool, tag = "8")]
    pub timer: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserToken {
    #[prost(bytes = "vec", tag = "1")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub token: Vec<u8>,
}

/// Smallest padded envelope size.
pub const MIN_ENVELOPE: usize = 1024;

/// Size bucket for an envelope: powers of two from 1 KiB up to 64 KiB,
/// then multiples of 64 KiB. Acks, heartbeats and pushes of up to ~20 refs all
/// look alike, and the number of refs or the length of their names is hidden
/// within a bucket.
pub fn envelope_bucket(len: usize) -> usize {
    if len <= 64 << 10 {
        len.max(MIN_ENVELOPE).next_power_of_two()
    } else {
        len.div_ceil(64 << 10) * (64 << 10)
    }
}

/// Encode an envelope padded to its size bucket.
pub fn pad_envelope(env: &Envelope) -> Vec<u8> {
    let mut e = env.clone();
    e.padding.clear();
    let target = envelope_bucket(e.encoded_len() + 4);
    // The padding field's own tag and length prefix shift the size by a few
    // bytes, so converge in a couple of steps.
    for _ in 0..4 {
        let len = e.encoded_len();
        if len == target {
            break;
        }
        let want = (e.padding.len() as isize + target as isize - len as isize).max(0) as usize;
        e.padding = vec![0; want];
    }
    e.encode_to_vec()
}

pub mod envelope {
    // A history bundle (with its proof) is much bigger than the rest; these
    // are decoded messages, so boxing would only complicate every use.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "2")]
        Push(super::Push),
        #[prost(message, tag = "3")]
        Ack(super::Ack),
        #[prost(message, tag = "4")]
        Heartbeat(super::Heartbeat),
        #[prost(message, tag = "5")]
        HistoryBundle(super::HistoryBundle),
        #[prost(message, tag = "6")]
        RosterChange(super::RosterChange),
        #[prost(message, tag = "7")]
        ResendRequest(super::ResendRequest),
        #[prost(message, tag = "8")]
        HistoryRequest(super::HistoryRequest),
        // (Tags 9-13 are Envelope's own fields.)
        #[prost(message, tag = "14")]
        HistoryClaim(super::HistoryClaim),
    }
}

/// "I'm stuck at `seq` (the entries after it can no longer be fetched, e.g.
/// after a long time offline): send me a history bundle."
#[derive(Clone, PartialEq, prost::Message)]
pub struct HistoryRequest {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    /// Devices whose earlier claim to answer never delivered: they mustn't
    /// claim again for this request.
    #[prost(message, repeated, tag = "2")]
    pub exclude: Vec<DeviceRef>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeviceRef {
    #[prost(bytes = "vec", tag = "1")]
    pub user: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub device: u32,
}

/// The claim entry at `seq` is the sender's: it is sending history to
/// `target` (see `log_kind::CLAIM`, `claim_nonce`).
#[derive(Clone, PartialEq, prost::Message)]
pub struct HistoryClaim {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(message, optional, tag = "2")]
    pub target: Option<DeviceRef>,
    #[prost(bytes = "vec", tag = "3")]
    pub salt: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Relay commitment log

pub mod log_kind {
    pub const PUSH: u32 = 1;
    pub const ROSTER: u32 = 2;
    pub const HEARTBEAT: u32 = 3;
    /// "I'm sending history to a stuck device": like a heartbeat it commits
    /// to the unchanged view, so anyone can apply it from the log alone.
    pub const CLAIM: u32 = 4;
}

/// The nonce of a claim entry, binding it to its claimant and target (told
/// to members in a `HistoryClaim`, with the salt). Nobody can attach a false
/// announcement to someone else's entry.
pub fn claim_nonce(repo_id: &[u8], seq: u64, claimant: (&[u8], u32), target: (&[u8], u32), salt: &[u8]) -> Vec<u8> {
    hash_fields(
        domain::CLAIM_NONCE,
        &[repo_id, &seq.to_be_bytes(), claimant.0, &claimant.1.to_be_bytes(), target.0, &target.1.to_be_bytes(), salt],
    )[..16]
        .to_vec()
}

/// A log entry as the relay stores it. It reveals nothing about what the
/// entry is (push, membership change or heartbeat) or what it commits to:
/// members check `commitment` against what they know, the relay only orders
/// entries by `seq` and chains them through `prev_head`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LogEntry {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub prev_head: Vec<u8>,
    /// Random; makes every commitment fresh (even a heartbeat over an
    /// unchanged view).
    #[prost(bytes = "vec", tag = "6")]
    pub nonce: Vec<u8>,
    /// `log_commitment(repo_id, seq, kind, view, nonce, version)`.
    #[prost(bytes = "vec", tag = "7")]
    pub commitment: Vec<u8>,
    /// Protocol version the entry was written with.
    #[prost(uint32, tag = "8")]
    pub version: u32,
}

/// What a log entry commits to, hidden from the relay.
/// Covers the entry's protocol version too, so the relay can't change it (to
/// make a member stall on a fake "upgrade" instead of seeing a fork).
pub fn log_commitment(repo_id: &[u8], seq: u64, kind: u32, view: &[u8], nonce: &[u8], version: u32) -> Hash {
    hash_fields(domain::LOG_COMMIT, &[repo_id, &seq.to_be_bytes(), &kind.to_be_bytes(), view, nonce, &version.to_be_bytes()])
}

/// Commitment to a chunked pack: the hashes of its encrypted chunks, in order.
pub fn chunks_hash(chunk_hashes: &[Vec<u8>]) -> Hash {
    let fields: Vec<&[u8]> = chunk_hashes.iter().map(|h| h.as_slice()).collect();
    hash_fields(domain::PACK_CHUNKS, &fields)
}

/// Head of the hash chain after appending the entry with these serialized bytes.
pub fn log_head(entry_bytes: &[u8]) -> Hash {
    hash_fields(domain::LOG_ENTRY, &[entry_bytes])
}

// ---------------------------------------------------------------------------
// View hashing

/// Canonical encoding of a ref set: sorted by name, each field length-prefixed.
pub fn canonical_refs(refs: &[RefEntry]) -> Vec<u8> {
    let mut sorted: Vec<&RefEntry> = refs.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    for r in sorted {
        for f in [r.name.as_bytes(), r.oid.as_bytes()] {
            out.extend_from_slice(&(f.len() as u64).to_be_bytes());
            out.extend_from_slice(f);
        }
    }
    out
}

pub fn roster_hash(roster: &Roster) -> Hash {
    let mut members: Vec<(&[u8], &[u8])> = roster
        .members
        .iter()
        .map(|m| (m.user_id.as_slice(), m.master_key.as_slice()))
        .collect();
    members.sort();
    let mut enc = Vec::new();
    for (u, k) in members {
        for f in [u, k] {
            enc.extend_from_slice(&(f.len() as u64).to_be_bytes());
            enc.extend_from_slice(f);
        }
    }
    let secret_hash = sha256(&roster.repo_secret);
    let genesis = sha256(&roster.genesis_secret);
    let (ttl, version, protocol) = (roster.log_ttl_secs.to_be_bytes(), roster.version.to_be_bytes(), roster.protocol.to_be_bytes());
    let mut fields: Vec<&[u8]> = vec![&version, &enc, &secret_hash, &protocol, roster.object_format.as_bytes(), &genesis];
    // Only when set, so rosters without a timer keep the hash they had.
    if roster.log_ttl_secs != 0 {
        fields.push(&ttl);
    }
    hash_fields(domain::ROSTER, &fields)
}

/// A recipient device as (user id, device id, serialized identity key).
pub type Recipient = (Vec<u8>, u32, Vec<u8>);

/// Hash of the full device set a sender believes the repo has (including itself).
pub fn recipients_hash(recipients: &[Recipient]) -> Hash {
    let mut sorted = recipients.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut enc = Vec::new();
    for (u, d, k) in &sorted {
        for f in [u.as_slice(), &d.to_be_bytes(), k.as_slice()] {
            enc.extend_from_slice(&(f.len() as u64).to_be_bytes());
            enc.extend_from_slice(f);
        }
    }
    hash_fields(domain::RECIPIENTS, &[&enc])
}

pub fn push_view(repo_id: &[u8], p: &Push) -> Hash {
    hash_fields(
        domain::VIEW,
        &[
            repo_id,
            &p.seq.to_be_bytes(),
            b"push",
            &p.pack_hash,
            &canonical_refs(&p.refs),
            p.head_ref.as_bytes(),
            &p.roster_hash,
            &p.recipients_hash,
            &p.prev_view,
            &p.nonce,
            &p.author_user,
            &p.author_device.to_be_bytes(),
            // The key too (by hash): everyone must get the same one
            // (XChaCha20-Poly1305 isn't key-committing, so one ciphertext
            // could open under two); recipients check the hash.
            &p.pack_key_hash,
        ],
    )
}

pub fn roster_view(repo_id: &[u8], r: &RosterChange) -> Hash {
    let rh = r.roster.as_ref().map(roster_hash).unwrap_or(ZERO_HASH);
    hash_fields(
        domain::VIEW,
        &[
            repo_id,
            &r.seq.to_be_bytes(),
            b"roster",
            &rh,
            &r.recipients_hash,
            &r.prev_view,
            &r.nonce,
            &r.author_user,
            &r.author_device.to_be_bytes(),
        ],
    )
}

/// Token that deletes a blob from the relay, derived from the pack key so
/// exactly the members who can read the blob can delete it.
pub fn blob_delete_token(pack_key: &[u8]) -> Hash {
    hash_fields(domain::BLOB_DELETE, &[pack_key])
}

/// A repo's id, derived from its first repo token. The relay only lets the
/// first append create a log whose id matches the token presented, so knowing
/// a repo's URL is not enough to squat it before its first push.
/// Does `roster` belong to the repo with this id (see `Roster::genesis_secret`)?
pub fn roster_is_for(roster: &Roster, repo_id: &[u8]) -> bool {
    repo_id_for_token(&delivery_token(&roster.genesis_secret)).as_slice() == repo_id
}

pub fn repo_id_for_token(token: &[u8]) -> [u8; 16] {
    hash_fields(domain::REPO_ID, &[token])[..16].try_into().unwrap()
}

/// Repo token for the log, derived from the shared repo secret.
pub fn delivery_token(repo_secret: &[u8]) -> Hash {
    hash_fields(domain::DELIVERY_TOKEN, &[repo_secret])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push() -> Push {
        Push {
            seq: 3,
            blob_ids: vec!["b".into()],
            pack_key: vec![1; 32],
            pack_hash: vec![2; 32],
            refs: vec![
                RefEntry { name: "refs/heads/main".into(), oid: "aa".into() },
                RefEntry { name: "refs/heads/dev".into(), oid: "bb".into() },
            ],
            prev_view: vec![3; 32],
            roster_hash: vec![4; 32],
            recipients_hash: vec![5; 32],
            nonce: vec![6; 16],
            view: vec![],
            log_head: vec![],
            head_ref: "refs/heads/main".into(),
            device_lists: vec![],
            chunk_hashes: vec![],
            author_user: vec![7; 32],
            author_device: 1,
            pack_key_hash: sha256(&[1; 32]).to_vec(),
        }
    }

    #[test]
    fn hash_fields_is_injective_over_boundaries() {
        assert_ne!(hash_fields(b"d", &[b"ab", b"c"]), hash_fields(b"d", &[b"a", b"bc"]));
        assert_ne!(hash_fields(b"d1", &[b"x"]), hash_fields(b"d2", &[b"x"]));
    }

    #[test]
    fn view_is_independent_of_ref_order_but_not_content() {
        let p = push();
        let mut q = push();
        q.refs.reverse();
        assert_eq!(push_view(b"repo", &p), push_view(b"repo", &q));
        q.refs[0].oid = "cc".into();
        assert_ne!(push_view(b"repo", &p), push_view(b"repo", &q));
    }

    #[test]
    fn view_binds_every_field() {
        let base = push_view(b"repo", &push());
        assert_ne!(base, push_view(b"other", &push()));
        let muts: Vec<fn(&mut Push)> = vec![
            |p| p.seq += 1,
            |p| p.pack_hash[0] ^= 1,
            |p| p.prev_view[0] ^= 1,
            |p| p.roster_hash[0] ^= 1,
            |p| p.recipients_hash[0] ^= 1,
            |p| p.nonce[0] ^= 1,
            |p| p.head_ref = "refs/heads/dev".into(),
        ];
        for m in muts {
            let mut p = push();
            m(&mut p);
            assert_ne!(base, push_view(b"repo", &p));
        }
    }

    #[test]
    fn push_and_roster_views_never_collide() {
        let p = push();
        let r = RosterChange {
            seq: p.seq,
            roster: None,
            prev_view: p.prev_view.clone(),
            nonce: p.nonce.clone(),
            view: vec![],
            recipients_hash: p.recipients_hash.clone(),
            log_head: vec![],
            device_lists: vec![],
            author_user: p.author_user.clone(),
            author_device: p.author_device,
        };
        assert_ne!(push_view(b"repo", &p), roster_view(b"repo", &r));
    }

    #[test]
    fn views_bind_the_pack_key_and_rosters_their_protocol_and_format() {
        let p = push();
        let mut other = p.clone();
        other.pack_key_hash = sha256(&[9; 32]).to_vec();
        assert_ne!(push_view(b"repo", &p), push_view(b"repo", &other));
        let r = Roster { version: 1, members: vec![], repo_secret: vec![7], protocol: 1, object_format: "sha256".into(), genesis_secret: vec![7], log_ttl_secs: 0 };
        assert_ne!(roster_hash(&r), roster_hash(&Roster { protocol: 2, ..r.clone() }));
        assert_ne!(roster_hash(&r), roster_hash(&Roster { object_format: "sha1".into(), ..r.clone() }));
        assert_ne!(roster_hash(&r), roster_hash(&Roster { genesis_secret: vec![8], ..r.clone() }));
        assert_ne!(roster_hash(&r), roster_hash(&Roster { log_ttl_secs: 60, ..r.clone() }));
    }

    #[test]
    fn views_bind_the_author() {
        let p = push();
        let mut other = p.clone();
        other.author_device = 2;
        assert_ne!(push_view(b"repo", &p), push_view(b"repo", &other));
        let mut other = p.clone();
        other.author_user = vec![8; 32];
        assert_ne!(push_view(b"repo", &p), push_view(b"repo", &other));
    }

    /// Only the genesis secret the repo id came from proves a roster is for
    /// that repo; the token (which the relay sees) doesn't help forge one.
    #[test]
    fn rosters_prove_their_repo() {
        let g = [5u8; 32];
        let rid = repo_id_for_token(&delivery_token(&g));
        let r = Roster { genesis_secret: g.to_vec(), ..Default::default() };
        assert!(roster_is_for(&r, &rid));
        assert!(!roster_is_for(&Roster { genesis_secret: vec![6; 32], ..r.clone() }, &rid));
        assert!(!roster_is_for(&Roster { genesis_secret: delivery_token(&g).to_vec(), ..r }, &rid));
    }

    #[test]
    fn roster_hash_covers_secret_and_is_order_independent() {
        let m1 = Member { user_id: vec![1], master_key: vec![9] };
        let m2 = Member { user_id: vec![2], master_key: vec![8] };
        let a = Roster { version: 1, members: vec![m1.clone(), m2.clone()], repo_secret: vec![7], protocol: PROTOCOL_VERSION, object_format: object_format::SHA256.into(), genesis_secret: vec![7], log_ttl_secs: 0 };
        let b = Roster { version: 1, members: vec![m2, m1], repo_secret: vec![7], protocol: PROTOCOL_VERSION, object_format: object_format::SHA256.into(), genesis_secret: vec![7], log_ttl_secs: 0 };
        assert_eq!(roster_hash(&a), roster_hash(&b));
        let c = Roster { repo_secret: vec![6], ..a.clone() };
        assert_ne!(roster_hash(&a), roster_hash(&c));
    }

    #[test]
    fn recipients_hash_is_set_semantics() {
        let a = vec![(vec![1], 1, vec![5]), (vec![2], 1, vec![6])];
        let mut b = a.clone();
        b.reverse();
        b.push(a[0].clone());
        assert_eq!(recipients_hash(&a), recipients_hash(&b));
        let c = vec![(vec![1], 1, vec![5]), (vec![2], 2, vec![6])];
        assert_ne!(recipients_hash(&a), recipients_hash(&c));
    }

    #[test]
    fn envelopes_pad_to_buckets_regardless_of_kind() {
        let ack = Envelope {
            repo_id: vec![1; 16],
            body: Some(envelope::Body::Ack(Ack { seq: 9, view: vec![2; 32], log_head: vec![3; 32] })),
            ..Default::default()
        };
        let mut p = push();
        p.view = vec![4; 32];
        p.log_head = vec![5; 32];
        let push_env = Envelope { repo_id: vec![1; 16], body: Some(envelope::Body::Push(p)), ..Default::default() };
        let a = pad_envelope(&ack);
        let b = pad_envelope(&push_env);
        assert_eq!(a.len(), b.len(), "an ack and a small push look the same");
        assert!(a.len().is_power_of_two() && a.len() >= MIN_ENVELOPE);
        // Decoding ignores the padding.
        assert_eq!(Envelope::decode(a.as_slice()).unwrap().body, ack.body);
        // Many refs only move a push to the next bucket.
        let mut big = push();
        big.refs = (0..40).map(|i| RefEntry { name: format!("refs/heads/branch-{i}"), oid: "a".repeat(64) }).collect();
        let n = pad_envelope(&Envelope { repo_id: vec![1; 16], body: Some(envelope::Body::Push(big)), ..Default::default() }).len();
        assert!(n.is_power_of_two(), "{n}");
    }

    #[test]
    fn log_entry_roundtrip_and_head() {
        let e = LogEntry { seq: 1, prev_head: ZERO_HASH.to_vec(), nonce: vec![1; 16], commitment: vec![2; 32], version: PROTOCOL_VERSION };
        let bytes = e.encode_to_vec();
        assert_eq!(LogEntry::decode(bytes.as_slice()).unwrap(), e);
        assert_ne!(log_head(&bytes), ZERO_HASH);
    }

    #[test]
    fn pq_signatures() {
        let seed = [7u8; 32];
        let pk = pq::public_key(&seed);
        assert_eq!(pk.len(), pq::PUBLIC_KEY_LEN);
        let sig = pq::sign(&seed, b"ctx", b"msg");
        assert!(pq::verify(&pk, b"ctx", b"msg", &sig));
        assert!(!pq::verify(&pk, b"ctx", b"msh", &sig));
        assert!(!pq::verify(&pk, b"other", b"msg", &sig), "context is bound");
        assert!(!pq::verify(&pq::public_key(&[8; 32]), b"ctx", b"msg", &sig));
        assert!(!pq::verify(&pk, b"ctx", b"msg", &sig[1..]));
    }

    #[test]
    fn log_commitments_hide_kind_and_repetition() {
        let v = [5u8; 32];
        // Same view, different kinds or nonces: unrelated commitments.
        let a = log_commitment(b"r", 3, log_kind::HEARTBEAT, &v, &[1; 16], 1);
        let b = log_commitment(b"r", 3, log_kind::HEARTBEAT, &v, &[2; 16], 1);
        let c = log_commitment(b"r", 3, log_kind::PUSH, &v, &[1; 16], 1);
        assert!(a != b && a != c && b != c);
    }}
