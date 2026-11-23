//! Cross-signing: a per-user master key signs a versioned list of device
//! identity keys. Peers pin the master key (after comparing safety numbers)
//! and only open sessions with devices in a list it signed.
//!
//! The master key is hybrid: a Curve25519 key and an ML-DSA-87 key, and
//! device lists carry both signatures. Forging a list needs both broken, so a
//! quantum computer alone can't add a device to someone's account.

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use e2ee_proto::{
    DeviceEntry, DeviceListBody, Hash, MASTER_ID_LEN, Message, SignedDeviceList, ZERO_HASH, domain, master_id, pq,
    sha256, signing_input, split_master_id, user_id_of,
};
use libsignal_protocol::{Fingerprint, IdentityKey, IdentityKeyPair};

/// A user's hybrid master key pair (only on the master device).
#[derive(Clone)]
pub struct MasterKeyPair {
    pub classical: IdentityKeyPair,
    /// Seed of the ML-DSA-87 key.
    pub pq_seed: [u8; 32],
}

impl MasterKeyPair {
    pub fn generate() -> Self {
        Self { classical: IdentityKeyPair::generate(&mut rand::rng()), pq_seed: rand::random() }
    }

    pub fn pq_public(&self) -> Vec<u8> {
        pq::public_key(&self.pq_seed)
    }

    /// The master id: what peers pin and what the user id is a hash of.
    pub fn id(&self) -> Vec<u8> {
        master_id(&self.classical.identity_key().serialize(), &self.pq_public())
    }
}

pub fn sign_device_list(master: &MasterKeyPair, body: &DeviceListBody) -> Result<SignedDeviceList> {
    let body = body.encode_to_vec();
    let input = signing_input(domain::DEVICE_LIST, &body);
    let signature = master.classical.private_key().calculate_signature(&input, &mut rand::rng())?.to_vec();
    Ok(SignedDeviceList {
        pq_signature: pq::sign(&master.pq_seed, domain::DEVICE_LIST, &input),
        master_pq_key: master.pq_public(),
        body,
        signature,
    })
}

/// A device list that passed verification.
#[derive(Debug, Clone)]
pub struct VerifiedDeviceList {
    pub body: DeviceListBody,
    pub body_hash: Hash,
}

impl VerifiedDeviceList {
    pub fn devices(&self) -> Vec<(u32, Vec<u8>)> {
        self.body
            .devices
            .iter()
            .map(|d| (d.device_id, d.identity_key.clone()))
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListUpdate {
    /// Newer than what we had; adopt it.
    Newer,
    /// Exactly the list we already have.
    Same,
}

/// Verify a signed device list against a pinned master key and the last
/// version we accepted (`last` = (version, body hash)). Rejects bad
/// signatures, wrong users, rollbacks, and forks of an already-seen version.
pub fn verify_device_list(
    signed: &SignedDeviceList,
    pinned_master: &[u8],
    last: Option<(u64, &[u8])>,
) -> Result<(VerifiedDeviceList, ListUpdate)> {
    let (classical, _) = split_master_id(pinned_master).ok_or_else(|| anyhow!("malformed master id"))?;
    let master = IdentityKey::try_from(classical)?;
    if !master
        .public_key()
        .verify_signature(&signing_input(domain::DEVICE_LIST, &signed.body), &signed.signature)
    {
        bail!("device list signature is invalid");
    }
    let Some(body) = signed.verify_pq() else {
        bail!("device list post-quantum signature is invalid");
    };
    if body.master_key != pinned_master {
        bail!("device list is for a different master key");
    }
    e2ee_proto::check_protocol("device list", body.protocol).map_err(|e| anyhow!(e))?;
    if body.user_id != user_id_of(&body.master_key) {
        bail!("device list user id does not match its master key");
    }
    let body_hash = sha256(&signed.body);
    // Device ids are unique, and never reused after a revocation.
    let mut ids: Vec<u32> = body.devices.iter().map(|d| d.device_id).chain(body.revoked.iter().map(|r| r.device_id)).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    if ids.len() != n {
        bail!("device list contains duplicate or reused device ids");
    }
    for r in &body.revoked {
        if !(1..=127).contains(&r.device_id) || r.added_in == 0 || r.added_in >= r.revoked_in || r.revoked_in > body.version {
            bail!("device list has a malformed revocation for device {}", r.device_id);
        }
    }
    for d in &body.devices {
        IdentityKey::try_from(d.identity_key.as_slice())?;
        if d.max_protocol < e2ee_proto::MIN_PROTOCOL_VERSION {
            bail!("device {} supports no protocol version this build speaks", d.device_id);
        }
        if d.pq_key_hash.len() != 32 || d.kem_key_hash.len() != 32 {
            bail!("device {} has no post-quantum keys", d.device_id);
        }
        if !(1..=127).contains(&d.device_id) {
            bail!("device id {} out of range", d.device_id);
        }
    }
    let update = match last {
        None => {
            if body.version == 1 && body.prev_hash != ZERO_HASH {
                bail!("version 1 device list must have a zero prev_hash");
            }
            ListUpdate::Newer
        }
        Some((v, h)) if body.version == v => {
            if body_hash != h {
                bail!("device list fork: two different lists claim version {v}");
            }
            ListUpdate::Same
        }
        Some((v, _)) if body.version < v => {
            bail!("device list rollback: got version {} but already saw {v}", body.version)
        }
        Some((v, h)) => {
            if body.version == v + 1 && body.prev_hash != h {
                bail!("device list version {} does not chain to version {v}", body.version);
            }
            ListUpdate::Newer
        }
    };
    let verified = VerifiedDeviceList { body, body_hash };
    Ok((verified, update))
}

/// Build the successor of `prev` (or version 1) with the given device set.
pub fn next_device_list(
    master: &MasterKeyPair,
    prev: Option<&VerifiedDeviceList>,
    mut devices: Vec<DeviceEntry>,
) -> DeviceListBody {
    let master_key = master.id();
    let version = prev.map_or(1, |p| p.body.version + 1);
    // Devices leaving the list become tombstones; new ones record when.
    let mut revoked = prev.map(|p| p.body.revoked.clone()).unwrap_or_default();
    if let Some(p) = prev {
        for d in &p.body.devices {
            if !devices.iter().any(|n| n.device_id == d.device_id) {
                // (Entries from before versions were recorded count from v1.)
                revoked.push(e2ee_proto::RevokedDevice { device_id: d.device_id, added_in: d.added_in.max(1), revoked_in: version });
            }
        }
    }
    for d in &mut devices {
        if d.added_in == 0 {
            d.added_in = version;
        }
    }
    DeviceListBody {
        user_id: user_id_of(&master_key).to_vec(),
        master_key,
        version,
        prev_hash: prev.map_or(ZERO_HASH.to_vec(), |p| p.body_hash.to_vec()),
        devices,
        protocol: e2ee_proto::PROTOCOL_VERSION,
        revoked,
    }
}

/// Safety number between two users, computed over their master keys. The
/// libsignal fingerprint takes the classical key, and the user id (its
/// "stable identifier") is a hash of the whole master id, so the number also
/// commits to the ML-DSA key.
pub struct SafetyNumber {
    /// 60 digits: about 99.7 bits per person, as in Signal.
    pub display: String,
    /// Protobuf with 256 bits per person, for the QR code.
    pub scannable: Vec<u8>,
    /// `WORDS_PER_PERSON` BIP39 words per person (110 bits each).
    pub local_words: Vec<&'static str>,
    pub remote_words: Vec<&'static str>,
}

/// 10 words x 11 bits = 110 bits per person, at least the ~99.7 bits of
/// Signal's 30 digits per person.
pub const WORDS_PER_PERSON: usize = 10;

static BIP39_ENGLISH: &str = include_str!("bip39_english.txt");

fn bip39_words() -> Vec<&'static str> {
    BIP39_ENGLISH.lines().collect()
}

/// Encode the leading `WORDS_PER_PERSON * 11` bits of a fingerprint as words,
/// using the BIP39 list as a plain base-2048 alphabet (no BIP39 checksum).
pub fn fingerprint_words(fp: &[u8]) -> Vec<&'static str> {
    let list = bip39_words();
    (0..WORDS_PER_PERSON)
        .map(|i| {
            let mut idx = 0usize;
            for bit in i * 11..(i + 1) * 11 {
                idx = (idx << 1) | ((fp[bit / 8] >> (7 - bit % 8)) & 1) as usize;
            }
            list[idx]
        })
        .collect()
}

/// libsignal's scannable fingerprint layout (`CombinedFingerprints`).
#[derive(Clone, PartialEq, prost::Message)]
struct CombinedFingerprints {
    #[prost(uint32, optional, tag = "1")]
    version: Option<u32>,
    #[prost(message, optional, tag = "2")]
    local: Option<LogicalFingerprint>,
    #[prost(message, optional, tag = "3")]
    remote: Option<LogicalFingerprint>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LogicalFingerprint {
    #[prost(bytes = "vec", optional, tag = "1")]
    content: Option<Vec<u8>>,
}

impl SafetyNumber {
    /// Both word groups in a canonical order (smaller fingerprint first),
    /// so both people see the same sequence; the bool marks the local group.
    pub fn word_groups(&self) -> [(bool, &[&'static str]); 2] {
        let l = (true, self.local_words.as_slice());
        let r = (false, self.remote_words.as_slice());
        if self.local_words <= self.remote_words { [l, r] } else { [r, l] }
    }
}

pub fn safety_number(
    local_user: &[u8],
    local_master: &[u8],
    remote_user: &[u8],
    remote_master: &[u8],
) -> Result<SafetyNumber> {
    let fp = Fingerprint::new(
        2,
        5200,
        local_user,
        &classical_part(local_master)?,
        remote_user,
        &classical_part(remote_master)?,
    )
    .map_err(|e| anyhow!("fingerprint: {e:?}"))?;
    let scannable = fp.scannable.serialize().map_err(|e| anyhow!("fingerprint: {e:?}"))?;
    let combined = CombinedFingerprints::decode(scannable.as_slice())?;
    let half = |f: Option<LogicalFingerprint>| -> Result<Vec<u8>> {
        f.and_then(|f| f.content)
            .filter(|c| c.len() * 8 >= WORDS_PER_PERSON * 11)
            .ok_or_else(|| anyhow!("unexpected fingerprint layout"))
    };
    Ok(SafetyNumber {
        display: fp.display_string().map_err(|e| anyhow!("fingerprint: {e:?}"))?,
        local_words: fingerprint_words(&half(combined.local)?),
        remote_words: fingerprint_words(&half(combined.remote)?),
        scannable,
    })
}

fn classical_part(master_id: &[u8]) -> Result<IdentityKey> {
    let (c, _) = split_master_id(master_id).ok_or_else(|| anyhow!("malformed master id"))?;
    Ok(IdentityKey::try_from(c)?)
}

/// Group a 60-digit safety number into blocks of five for display.
pub fn format_safety_number(s: &str) -> String {
    s.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|row| row.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Copy-paste codes exchanged out of band

const USER_CODE: &str = "e2eeu1:";
const LINK_CODE: &str = "e2eed1:";
const APPROVAL_CODE: &str = "e2eea1:";

pub fn encode_user_code(master_key: &[u8]) -> String {
    format!("{USER_CODE}{}", B64.encode(master_key))
}

pub fn decode_user_code(code: &str) -> Result<Vec<u8>> {
    let raw = code
        .trim()
        .strip_prefix(USER_CODE)
        .ok_or_else(|| anyhow!("not a user code (expected {USER_CODE}...)"))?;
    let key = B64.decode(raw)?;
    if key.len() != MASTER_ID_LEN {
        bail!("user code has the wrong length");
    }
    classical_part(&key)?;
    Ok(key)
}

/// A new device's identity key and the hashes of its ML-DSA and ML-KEM keys.
pub fn encode_link_code(device_identity: &[u8], pq_key_hash: &[u8], kem_key_hash: &[u8]) -> String {
    format!("{LINK_CODE}{}", B64.encode([device_identity, pq_key_hash, kem_key_hash].concat()))
}

pub fn decode_link_code(code: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let raw = code
        .trim()
        .strip_prefix(LINK_CODE)
        .ok_or_else(|| anyhow!("not a device link code (expected {LINK_CODE}...)"))?;
    let key = B64.decode(raw)?;
    if key.len() != 33 + 32 + 32 {
        bail!("device link code has the wrong length");
    }
    let (id, rest) = key.split_at(33);
    let (pq, kem) = rest.split_at(32);
    IdentityKey::try_from(id)?;
    Ok((id.to_vec(), pq.to_vec(), kem.to_vec()))
}

/// Handed from the master device to a newly linked device.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Approval {
    #[prost(bytes = "vec", tag = "1")]
    pub master_key: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub device_id: u32,
    #[prost(message, optional, tag = "3")]
    pub device_list: Option<SignedDeviceList>,
    /// The user's delivery token, shared by all its devices.
    #[prost(bytes = "vec", tag = "4")]
    pub delivery_token: Vec<u8>,
}

pub fn encode_approval(a: &Approval) -> String {
    format!("{APPROVAL_CODE}{}", B64.encode(a.encode_to_vec()))
}

pub fn decode_approval(code: &str) -> Result<Approval> {
    let raw = code
        .trim()
        .strip_prefix(APPROVAL_CODE)
        .ok_or_else(|| anyhow!("not an approval code (expected {APPROVAL_CODE}...)"))?;
    Ok(Approval::decode(B64.decode(raw)?.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32) -> DeviceEntry {
        let k = IdentityKeyPair::generate(&mut rand::rng());
        DeviceEntry {
            device_id: id,
            identity_key: k.identity_key().serialize().to_vec(),
            added_at_ms: 0,
            pq_key_hash: vec![1; 32],
            kem_key_hash: vec![2; 32],
            max_protocol: e2ee_proto::PROTOCOL_VERSION,
            added_in: 0,
        }
    }

    fn master_bytes(m: &MasterKeyPair) -> Vec<u8> {
        m.id()
    }

    #[test]
    fn accepts_valid_chain() {
        let m = MasterKeyPair::generate();
        let v1 = sign_device_list(&m, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        let (l1, u) = verify_device_list(&v1, &master_bytes(&m), None).unwrap();
        assert_eq!(u, ListUpdate::Newer);
        let v2 = sign_device_list(&m, &next_device_list(&m, Some(&l1), vec![entry(1), entry(2)]))
            .unwrap();
        let (l2, u) =
            verify_device_list(&v2, &master_bytes(&m), Some((1, &l1.body_hash))).unwrap();
        assert_eq!(u, ListUpdate::Newer);
        assert_eq!(l2.devices().len(), 2);
        let (_, u) = verify_device_list(&v2, &master_bytes(&m), Some((2, &l2.body_hash))).unwrap();
        assert_eq!(u, ListUpdate::Same);
    }

    #[test]
    fn rejects_wrong_master_and_tampering() {
        let m = MasterKeyPair::generate();
        let other = MasterKeyPair::generate();
        let v1 = sign_device_list(&m, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        assert!(verify_device_list(&v1, &master_bytes(&other), None).is_err());

        // A list signed by another key but claiming m's master key.
        let forged = sign_device_list(&other, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        assert!(verify_device_list(&forged, &master_bytes(&m), None).is_err());

        let mut tampered = v1.clone();
        let mut body = DeviceListBody::decode(tampered.body.as_slice()).unwrap();
        body.devices.push(entry(9));
        tampered.body = body.encode_to_vec();
        assert!(verify_device_list(&tampered, &master_bytes(&m), None).is_err());
    }

    #[test]
    fn rejects_rollback_and_fork() {
        let m = MasterKeyPair::generate();
        let v1 = sign_device_list(&m, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        let (l1, _) = verify_device_list(&v1, &master_bytes(&m), None).unwrap();
        let v2 = sign_device_list(&m, &next_device_list(&m, Some(&l1), vec![entry(1), entry(2)]))
            .unwrap();
        let (l2, _) =
            verify_device_list(&v2, &master_bytes(&m), Some((1, &l1.body_hash))).unwrap();
        // Relay serves the old list again.
        assert!(verify_device_list(&v1, &master_bytes(&m), Some((2, &l2.body_hash))).is_err());
        // A different list with the same version.
        let v2b = sign_device_list(&m, &next_device_list(&m, Some(&l1), vec![entry(3)])).unwrap();
        assert!(verify_device_list(&v2b, &master_bytes(&m), Some((2, &l2.body_hash))).is_err());
        // A successor that does not chain.
        let mut bad = next_device_list(&m, Some(&l2), vec![entry(1)]);
        bad.prev_hash = vec![7; 32];
        let bad = sign_device_list(&m, &bad).unwrap();
        assert!(verify_device_list(&bad, &master_bytes(&m), Some((2, &l2.body_hash))).is_err());
    }

    #[test]
    fn domain_separation_blocks_cross_protocol_signatures() {
        // A signature the master key made over the raw body (as if for another
        // purpose) must not verify as a device list.
        let m = MasterKeyPair::generate();
        let good = sign_device_list(&m, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        let sig = m.classical.private_key().calculate_signature(&good.body, &mut rand::rng()).unwrap().to_vec();
        let s = SignedDeviceList { signature: sig, ..good.clone() };
        assert!(verify_device_list(&s, &master_bytes(&m), None).is_err());
        let input = signing_input(domain::DEVICE_LIST, &good.body);
        let s = SignedDeviceList { pq_signature: pq::sign(&m.pq_seed, b"other", &input), ..good };
        assert!(verify_device_list(&s, &master_bytes(&m), None).is_err());
    }

    #[test]
    fn device_lists_from_a_newer_protocol_are_refused() {
        let m = MasterKeyPair::generate();
        let mut body = next_device_list(&m, None, vec![entry(1)]);
        body.protocol = e2ee_proto::PROTOCOL_VERSION + 1;
        let err = verify_device_list(&sign_device_list(&m, &body).unwrap(), &master_bytes(&m), None).unwrap_err();
        assert!(format!("{err:#}").contains("upgrade"), "{err:#}");
    }

    /// A quantum attacker who recovers the classical master key still can't
    /// forge a list: the ML-DSA signature is required too.
    #[test]
    fn classical_signature_alone_is_not_enough() {
        let m = MasterKeyPair::generate();
        let attacker_pq = MasterKeyPair::generate();
        // The attacker has m's classical key but not its ML-DSA key.
        let stolen = MasterKeyPair { classical: m.classical, pq_seed: attacker_pq.pq_seed };
        let body = next_device_list(&m, None, vec![entry(1), entry(2)]);
        // Signing with its own ML-DSA key and shipping that key: hash mismatch.
        let forged = sign_device_list(&stolen, &body).unwrap();
        assert!(verify_device_list(&forged, &master_bytes(&m), None).is_err());
        // Keeping m's ML-DSA public key but a signature that isn't m's.
        let real = sign_device_list(&m, &next_device_list(&m, None, vec![entry(1)])).unwrap();
        let forged = SignedDeviceList { master_pq_key: real.master_pq_key.clone(), ..forged };
        assert!(verify_device_list(&forged, &master_bytes(&m), None).is_err());
        // And dropping the ML-DSA part entirely.
        let stripped = SignedDeviceList { pq_signature: vec![], master_pq_key: vec![], ..real.clone() };
        assert!(verify_device_list(&stripped, &master_bytes(&m), None).is_err());
        assert!(verify_device_list(&real, &master_bytes(&m), None).is_ok());
    }

    /// The safety number changes if only the ML-DSA half of the master id does.
    #[test]
    fn safety_number_commits_to_pq_key() {
        let a = MasterKeyPair::generate();
        let b = MasterKeyPair::generate();
        let b2 = MasterKeyPair { classical: b.classical, pq_seed: [9; 32] };
        let (ak, bk, b2k) = (a.id(), b.id(), b2.id());
        let s1 = safety_number(&user_id_of(&ak), &ak, &user_id_of(&bk), &bk).unwrap();
        let s2 = safety_number(&user_id_of(&ak), &ak, &user_id_of(&b2k), &b2k).unwrap();
        assert_ne!(s1.display, s2.display);
        assert_ne!(s1.remote_words, s2.remote_words);
    }

    #[test]
    fn safety_numbers_match_on_both_sides() {
        let a = MasterKeyPair::generate();
        let b = MasterKeyPair::generate();
        let (ak, bk) = (master_bytes(&a), master_bytes(&b));
        let (au, bu) = (user_id_of(&ak), user_id_of(&bk));
        let s1 = safety_number(&au, &ak, &bu, &bk).unwrap();
        let s2 = safety_number(&bu, &bk, &au, &ak).unwrap();
        assert_eq!(s1.display, s2.display);
        assert_eq!(s1.display.len(), 60);
    }

    #[test]
    fn bip39_list_is_the_canonical_one() {
        assert_eq!(bip39_words().len(), 2048);
        assert_eq!(
            hex::encode(sha256(BIP39_ENGLISH.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn fingerprint_words_encode_11_bit_chunks() {
        let zeros = [0u8; 32];
        assert_eq!(fingerprint_words(&zeros), vec!["abandon"; WORDS_PER_PERSON]);
        let ones = [0xffu8; 32];
        assert_eq!(fingerprint_words(&ones), vec!["zoo"; WORDS_PER_PERSON]);
        // First 11 bits = 0b00000000_001 -> index 1 ("ability").
        let mut fp = [0u8; 32];
        fp[1] = 0b0010_0000;
        assert_eq!(fingerprint_words(&fp)[0], "ability");
    }

    #[test]
    fn safety_words_match_on_both_sides_and_differ_per_key() {
        let a = MasterKeyPair::generate();
        let b = MasterKeyPair::generate();
        let c = MasterKeyPair::generate();
        let (ak, bk, ck) = (master_bytes(&a), master_bytes(&b), master_bytes(&c));
        let (au, bu, cu) = (user_id_of(&ak), user_id_of(&bk), user_id_of(&ck));
        let ab = safety_number(&au, &ak, &bu, &bk).unwrap();
        let ba = safety_number(&bu, &bk, &au, &ak).unwrap();
        assert_eq!(ab.local_words.len(), WORDS_PER_PERSON);
        assert_eq!(ab.local_words, ba.remote_words);
        assert_eq!(ab.remote_words, ba.local_words);
        let groups = |s: &SafetyNumber| s.word_groups().map(|g| g.1.to_vec());
        assert_eq!(groups(&ab), groups(&ba));
        // A different remote key changes the remote words.
        let ac = safety_number(&au, &ak, &cu, &ck).unwrap();
        assert_eq!(ab.local_words, ac.local_words);
        assert_ne!(ab.remote_words, ac.remote_words);
    }

    #[test]
    fn codes_roundtrip() {
        let m = MasterKeyPair::generate();
        let k = master_bytes(&m);
        assert_eq!(decode_user_code(&encode_user_code(&k)).unwrap(), k);
        let id = m.classical.identity_key().serialize().to_vec();
        assert_eq!(decode_link_code(&encode_link_code(&id, &[3; 32], &[4; 32])).unwrap(), (id, vec![3; 32], vec![4; 32]));
        assert!(decode_link_code(&encode_user_code(&k)).is_err());
    }
}
