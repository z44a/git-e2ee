//! JSON bodies of the relay HTTP API. Binary fields are base64.

use serde::{Deserialize, Serialize};

pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Auth headers for device-authenticated requests.
/// Error body of a request whose repo token the relay doesn't accept (on an
/// append: someone rotated it since our last sync, or we were removed).
pub const BAD_REPO_TOKEN: &str = "bad repo token";

pub mod headers {
    pub const USER: &str = "x-e2ee-user";
    pub const DEVICE: &str = "x-e2ee-device";
    pub const TIME: &str = "x-e2ee-time";
    pub const SIGNATURE: &str = "x-e2ee-sig";
    /// ML-DSA signature over the same payload (base64); both must verify.
    pub const PQ_SIGNATURE: &str = "x-e2ee-pq-sig";
    /// Protocol version of the sender, on every request and response.
    pub const PROTOCOL: &str = "x-e2ee-protocol";
    /// Secret that authorizes reading and deleting a pseudonymous mailbox.
    pub const MAILBOX_KEY: &str = "x-e2ee-mailbox-key";
    /// On a log append: hash of the token that replaces the repo's token,
    /// in the same step as the append (a rotation).
    pub const REPLACE_TOKEN: &str = "x-e2ee-replace-token";
    /// Random per-request value; the relay refuses repeats within the window.
    pub const NONCE: &str = "x-e2ee-nonce";
    pub const TOKEN: &str = "x-e2ee-token";
    /// Operator-issued token for a user's first registration (invite-only relays).
    pub const REGISTRATION_TOKEN: &str = "x-e2ee-registration-token";
    /// Hash of a blob's delete token, set at upload.
    pub const BLOB_DELETE_HASH: &str = "x-e2ee-blob-delete-hash";
    /// A blob's delete token.
    pub const BLOB_DELETE_TOKEN: &str = "x-e2ee-blob-delete-token";
    /// Anonymous rate-limited access tokens being spent (comma-separated
    /// `epoch:nonce:output`).
    pub const ACCESS: &str = "x-e2ee-access";
    /// The recipient user's delivery token (normal mailbox lane).
    pub const DELIVERY: &str = "x-e2ee-delivery";
}

pub fn now_ms_for_tokens() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_canonical() {
        assert_eq!(origin_of("https://Relay.Example:443/x/y").as_deref(), Some("https://relay.example"));
        assert_eq!(origin_of("http://127.0.0.1:8470").as_deref(), Some("http://127.0.0.1:8470"));
        assert_ne!(origin_of("https://a.example"), origin_of("https://b.example"));
        assert_ne!(origin_of("https://a.example"), origin_of("https://a.example:8443"));
    }
}

/// Allowed clock skew for signed requests.
pub const AUTH_WINDOW_MS: u64 = 5 * 60 * 1000;

/// Bytes a device signs to authenticate a relay request. `origin` is the
/// relay's origin as the *client* chose it and TLS authenticated it (see
/// `origin_of`); each relay checks it against its own configured public URL.
/// So a request signed for one relay cannot be replayed to another, whatever
/// the first relay claims about itself.
pub fn auth_payload(origin: &str, method: &str, path: &str, time_ms: u64, nonce: &str, body: &[u8]) -> Vec<u8> {
    let body_hash = hex::encode(crate::sha256(body));
    crate::signing_input(
        crate::domain::RELAY_AUTH,
        format!("{origin}\n{method}\n{path}\n{time_ms}\n{nonce}\n{body_hash}").as_bytes(),
    )
}

/// Canonical origin of a URL: `scheme://host[:port]`, lowercase, default
/// port omitted (e.g. `https://relay.example`, `http://127.0.0.1:8470`).
pub fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    match u.origin() {
        o @ url::Origin::Tuple(..) => Some(o.ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedKey {
    pub id: u32,
    #[serde(with = "b64")]
    pub public: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeKey {
    pub id: u32,
    #[serde(with = "b64")]
    pub public: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUpload {
    #[serde(with = "b64")]
    pub identity_key: Vec<u8>,
    /// The device's ML-DSA public key; its hash must be in the device list.
    #[serde(with = "b64")]
    pub pq_key: Vec<u8>,
    /// The device's long-term ML-KEM authentication key.
    #[serde(with = "b64")]
    pub kem_auth_key: Vec<u8>,
    pub registration_id: u32,
    /// Current signed EC prekey; replaces the relay's copy (rotation).
    pub signed_prekey: Option<SignedKey>,
    /// Current last-resort Kyber prekey; replaces the relay's copy.
    pub kyber_prekey: Option<SignedKey>,
    pub one_time: Vec<OneTimeKey>,
    /// One-time Kyber prekeys, each handed out at most once.
    #[serde(default)]
    pub kyber_one_time: Vec<SignedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    #[serde(with = "b64")]
    pub identity_key: Vec<u8>,
    pub registration_id: u32,
    pub signed_prekey: SignedKey,
    /// A one-time Kyber prekey if any are left, else the last-resort one.
    pub kyber_prekey: SignedKey,
    pub one_time: Option<OneTimeKey>,
    /// The device's long-term ML-KEM authentication key (hash in its list).
    #[serde(with = "b64")]
    pub kem_auth_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCount {
    pub one_time: u64,
    #[serde(default)]
    pub kyber_one_time: u64,
}

/// Body of `POST /tokens/{user}/{device}` (device-authenticated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub epoch: u64,
    #[serde(with = "vec_b64")]
    pub blinded: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    #[serde(with = "vec_b64")]
    pub evaluations: Vec<Vec<u8>>,
    #[serde(with = "b64")]
    pub proof: Vec<u8>,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    /// Key generation (see `TokenKey`).
    pub generation: u32,
}

/// Response of `GET /token-key/{epoch}` (anonymous).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenKey {
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    /// Generation of this key. A relay rotates its key (a new generation,
    /// public and the same for everyone) when it bans someone.
    pub generation: u32,
    /// The relay's current generation.
    pub current: u32,
}

/// Body of `PUT /users/{user}/{device}/delivery-token` (device-authenticated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryTokenHash {
    /// Hex SHA-256 of the user's delivery token.
    pub token_hash: String,
}

/// Token costs of anonymous actions.
pub mod cost {
    /// Creating a pseudonymous mailbox.
    pub const MAIL: usize = 1;
    /// Delivering mail: one token per started 64 KiB (most messages are
    /// one), so filling the relay's mail storage takes many users' budgets.
    pub fn mail(len: usize) -> usize {
        len.div_ceil(64 << 10).max(1)
    }
    pub const BUNDLE: usize = 1;
    pub const BLOB_GET: usize = 1;
    /// The append that creates a repo's log.
    pub const LOG_CREATE: usize = 5;
    /// Every later append: the repo token shows you're a member, the access
    /// token that the relay currently lets you act (so a ban stops it too).
    pub const LOG_APPEND: usize = 1;
    /// Blob uploads: one token plus one per started MiB.
    pub fn blob_put(len: usize) -> usize {
        1 + len.div_ceil(1 << 20)
    }
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntries {
    /// Serialized `LogEntry` messages in seq order.
    #[serde(with = "vec_b64")]
    pub entries: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResult {
    pub seq: u64,
    pub head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: String,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub messages: Vec<MailboxMessage>,
    /// More messages wait: fetch again with `?after=<next>`. Pages are
    /// bounded (`MAIL_PAGE_BYTES`), so a full mailbox is read in steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<u64>,
}

/// Most mail bytes one mailbox fetch returns (at least one message).
pub const MAIL_PAGE_BYTES: usize = 4 << 20;

pub mod vec_b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&STANDARD.encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// `GET /info`: what a relay speaks, for clients deciding whether to upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub software: String,
    /// How long the relay keeps undelivered mail and packs.
    #[serde(default)]
    pub mail_ttl_secs: u64,
}
