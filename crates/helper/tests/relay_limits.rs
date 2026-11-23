//! Relay hardening: registration gating, quotas, rate limits, token rules.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::sync::Arc;

use e2ee_core::client::{DeviceAuth, RelayClient};
use e2ee_core::device::Device;
use e2ee_core::store::Db;
use e2ee_proto::api::TokenRequest;
use e2ee_proto::tokens::{self, Token};
use e2ee_relay::{Limits, Relay};

async fn start(limits: Limits) -> (Arc<Relay>, String) {
    let relay = Relay::open_in_memory_with(limits).unwrap();
    relay.enable_test_instrumentation();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(e2ee_relay::serve(l, relay.clone(), 0));
    (relay, url)
}

fn auth(d: &Device) -> DeviceAuth<'_> {
    DeviceAuth { user_hex: hex::encode(&d.user), device_id: d.device_id, identity: &d.identity, pq_seed: &d.pq_seed }
}

/// A user with one device whose list and keys are on the relay.
async fn registered(c: &RelayClient) -> Device {
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    c.put_device_list(&hex::encode(&d.user), &list).await.unwrap();
    let up = d.key_upload(2, 1, true).await.unwrap();
    c.upload_keys(&auth(&d), &up, None).await.unwrap();
    d
}

/// Anonymous access tokens obtained for a device (a test wallet).
struct Wallet(std::cell::RefCell<Vec<Token>>);

impl Wallet {
    fn take(&self, n: usize) -> Vec<Token> {
        self.0.borrow_mut().drain(..n).collect()
    }
}

async fn issue(c: &RelayClient, d: &Device, n: usize) -> anyhow::Result<Vec<Token>> {
    let epoch = tokens::epoch_now();
    let (pending, blinded) = tokens::blind(n, epoch);
    let r = c.issue_tokens(&auth(d), &TokenRequest { epoch, blinded }).await?;
    Ok(tokens::finalize(pending, &r.evaluations, &r.proof, &r.public_key).expect("valid proof"))
}

async fn wallet(c: &RelayClient, d: &Device, n: usize) -> Wallet {
    Wallet(std::cell::RefCell::new(issue(c, d, n).await.unwrap()))
}

fn err_contains<T: std::fmt::Debug>(r: anyhow::Result<T>, needle: &str) {
    let e = format!("{:#}", r.expect_err("expected an error"));
    assert!(e.contains(needle), "{e}");
}

#[tokio::test(flavor = "current_thread")]
async fn registration_requires_a_signed_device_list() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let up = d.key_upload(1, 0, true).await.unwrap();
    // No device list published yet.
    err_contains(c.upload_keys(&auth(&d), &up, None).await, "signed device list");
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    c.put_device_list(&hex::encode(&d.user), &list).await.unwrap();
    c.upload_keys(&auth(&d), &up, None).await.unwrap();

    // Someone else's key cannot squat device 2 of this user.
    let mut squatter = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let sup = squatter.key_upload(1, 0, true).await.unwrap();
    let fake = DeviceAuth { user_hex: hex::encode(&d.user), device_id: 2, identity: &squatter.identity, pq_seed: &squatter.pq_seed };
    err_contains(c.upload_keys(&fake, &sup, None).await, "signed device list");
}



#[tokio::test(flavor = "current_thread")]
async fn requests_are_rate_limited_per_ip() {
    let (_r, url) = start(Limits { rate_per_sec: 0.5, rate_burst: 2.0, ..Default::default() }).await;
    let http = reqwest::Client::new();
    let get = || {
        http.get(format!("{url}/users/{}/device-list", "0".repeat(64)))
            .header(e2ee_proto::api::headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.to_string())
            .send()
    };
    assert_eq!(get().await.unwrap().status(), 404);
    assert_eq!(get().await.unwrap().status(), 404);
    assert_eq!(get().await.unwrap().status(), 429);
}


#[tokio::test(flavor = "current_thread")]
async fn bundles_hand_out_one_time_kyber_keys_once() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    c.put_device_list(&hex::encode(&d.user), &list).await.unwrap();
    let up = d.key_upload(0, 1, true).await.unwrap();
    c.upload_keys(&auth(&d), &up, None).await.unwrap();
    let u = hex::encode(&d.user);
    let w = wallet(&c, &d, 2).await;
    let first = c.bundle(&w.take(1), &u, 1).await.unwrap();
    let second = c.bundle(&w.take(1), &u, 1).await.unwrap();
    assert_eq!(first.kyber_prekey.id, up.kyber_one_time[0].id);
    assert_eq!(second.kyber_prekey.id, up.kyber_prekey.as_ref().unwrap().id);
    let counts = c.key_count(&auth(&d)).await.unwrap();
    assert_eq!((counts.one_time, counts.kyber_one_time), (0, 0));
}



/// A user's first device, with its device list published, ready to upload keys.
/// A new user whose device list is on the relay (published with `token`,
/// as an invite-only relay requires) but whose device isn't registered yet.
async fn unregistered(c: &RelayClient, token: Option<&str>) -> (Device, e2ee_proto::api::KeyUpload) {
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    c.put_device_list_with_token(&hex::encode(&d.user), &list, token).await.unwrap();
    let up = d.key_upload(1, 0, true).await.unwrap();
    (d, up)
}

#[tokio::test(flavor = "current_thread")]
async fn invite_only_relays_need_a_single_use_unexpired_token() {
    let (relay, url) = start(Limits { invite_only: true, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();

    // Without an invite the relay won't even store a new user's device list.
    let stranger = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = stranger.db.signed_device_list(&stranger.user).unwrap().unwrap();
    err_contains(c.put_device_list(&hex::encode(&stranger.user), &list).await, "invite-only");
    err_contains(c.put_device_list_with_token(&hex::encode(&stranger.user), &list, Some("bogus")).await, "invite-only");
    // Storing the list with an invite redeems it: keys need no token after.
    let token = relay.issue_registration_token(std::time::Duration::from_secs(3600)).unwrap();
    let (a, up) = unregistered(&c, Some(&token)).await;
    c.upload_keys(&auth(&a), &up, None).await.unwrap();
    issue(&c, &a, 1).await.unwrap();
    // Later uploads by a registered user need no token.
    let up2 = {
        let mut a = a;
        a.key_upload(1, 0, false).await.unwrap()
    };
    let _ = up2;

    // Single use: a second user cannot reuse it, nor an expired one.
    let b = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let blist = b.db.signed_device_list(&b.user).unwrap().unwrap();
    err_contains(c.put_device_list_with_token(&hex::encode(&b.user), &blist, Some(&token)).await, "invite-only");
    let expired = relay.issue_registration_token(std::time::Duration::ZERO).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    err_contains(c.put_device_list_with_token(&hex::encode(&b.user), &blist, Some(&expired)).await, "invite-only");
    // Unregistered users get no posting token and cannot create repos.
    err_contains(issue(&c, &b, 1).await, "unknown device");
}

#[tokio::test(flavor = "current_thread")]
async fn linked_devices_of_a_registered_user_need_no_token() {
    let (relay, url) = start(Limits { invite_only: true, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let token = relay.issue_registration_token(std::time::Duration::from_secs(3600)).unwrap();
    let (mut master, up) = unregistered(&c, Some(&token)).await;
    c.upload_keys(&auth(&master), &up, Some(&token)).await.unwrap();

    let new_db = Db::open_in_memory().unwrap();
    let link = Device::begin_link(&new_db).unwrap();
    let (signed, approval, _) = master.approve_link(&link).unwrap();
    c.put_device_list(&hex::encode(&master.user), &e2ee_proto::Message::encode_to_vec(&signed)).await.unwrap();
    let mut laptop = Device::finish_link(&new_db, &approval).unwrap();
    let lup = laptop.key_upload(1, 0, true).await.unwrap();
    c.upload_keys(&auth(&laptop), &lup, None).await.unwrap();
    let _ = master.key_upload(0, 0, false).await.unwrap();
}


fn rid_for(token: &[u8]) -> String {
    hex::encode(e2ee_proto::repo_id_for_token(token))
}

fn first_entry() -> Vec<u8> {
    use e2ee_proto::Message;
    e2ee_proto::LogEntry {
        seq: 1,
        prev_head: e2ee_proto::ZERO_HASH.to_vec(),
        nonce: vec![],
        commitment: vec![0; 32],
        version: e2ee_proto::PROTOCOL_VERSION,
    }
    .encode_to_vec()
}

#[tokio::test(flavor = "current_thread")]
async fn first_append_creates_a_log_anonymously_and_is_capped() {
    let (_relay, url) = start(Limits { max_new_logs_per_hour: 1, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 20).await;
    let rid = rid_for(b"tok");
    // Before the first append the log just reads as empty.
    assert_eq!(c.log_since(&rid, b"tok", 0).await.unwrap(), Some(vec![]));
    // Without a valid posting token nobody can create a log.
    err_contains(c.append(&rid, b"tok", &[], &first_entry(), None).await.map(|_| ()), "access token");
    err_contains(c.append(&rid, b"tok", &w.take(2), &first_entry(), None).await.map(|_| ()), "needs 5");
    assert!(matches!(c.append(&rid, b"tok", &w.take(5), &first_entry(), None).await.unwrap(), e2ee_core::client::Append::Ok));
    // Now the repo token is required to read, and the relay stored no creator.
    assert!(c.log_since(&rid, b"other", 0).await.unwrap().is_none());
    assert_eq!(c.log_since(&rid, b"tok", 0).await.unwrap().unwrap().len(), 1);
    // Relay-wide creation cap.
    let r = c.append(&rid_for(b"tok2"), b"tok2", &w.take(5), &first_entry(), None).await;
    err_contains(r.map(|_| ()), "too many new repos");
}

#[tokio::test(flavor = "current_thread")]
async fn mail_and_blob_quotas() {
    let limits = Limits {
        max_mail_bytes: 100,
        max_mailbox_messages: 2,
        max_blob_bytes: 1000,
        max_total_blob_bytes: 1500,
        ..Default::default()
    };
    let (_r, url) = start(limits).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let (u, dev) = (hex::encode(&d.user), d.device_id);
    let w = wallet(&c, &d, 20).await;

    err_contains(c.send_mail(&w.take(1), None, &u, dev, vec![0; 101]).await, "413");
    c.send_mail(&w.take(1), None, &u, dev, vec![0; 100]).await.unwrap();
    c.send_mail(&w.take(1), None, &u, dev, vec![0; 100]).await.unwrap();
    err_contains(c.send_mail(&w.take(1), None, &u, dev, vec![0; 10]).await, "mailbox full");

    err_contains(c.put_blob(&w.take(2), &"a".repeat(32), vec![0; 1001], b"k").await, "413");
    c.put_blob(&w.take(2), &"a".repeat(32), vec![0; 1000], b"k").await.unwrap();
    err_contains(c.put_blob(&w.take(2), &"b".repeat(32), vec![0; 1000], b"k").await, "storage is full");
    // Replacing a blob does not count it twice.
    c.put_blob(&w.take(2), &"a".repeat(32), vec![0; 900], b"k").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn blobs_are_global_and_deletable_only_with_the_pack_derived_token() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 20).await;
    let id = "c".repeat(32);
    c.put_blob(&w.take(2), &id, b"ciphertext".to_vec(), b"right").await.unwrap();
    // Without access tokens nobody can download; with them you need the id.
    err_contains(c.get_blob(&[], &id, 1 << 30).await, "access token");
    assert_eq!(c.get_blob(&w.take(1), &id, 1 << 30).await.unwrap(), b"ciphertext");
    // Someone else cannot overwrite it.
    err_contains(c.put_blob(&w.take(2), &id, b"evil".to_vec(), b"other").await, "in use");
    // A wrong delete token does nothing; the right one deletes.
    c.delete_blob(&id, b"wrong").await.unwrap();
    assert!(c.get_blob(&w.take(1), &id, 1 << 30).await.is_ok());
    c.delete_blob(&id, b"right").await.unwrap();
    assert!(c.get_blob(&w.take(1), &id, 1 << 30).await.is_err());
}

fn entry_after(prev: &[u8], seq: u64) -> Vec<u8> {
    use e2ee_proto::Message;
    e2ee_proto::LogEntry {
        seq,
        prev_head: e2ee_proto::log_head(prev).to_vec(),
        nonce: vec![seq as u8; 16],
        commitment: vec![0; 32],
        version: e2ee_proto::PROTOCOL_VERSION,
    }
    .encode_to_vec()
}

/// A rotation is an append that replaces the repo's one token, in the same
/// step. Two members rotating at once: only the append that wins changes the
/// token, so the repo never ends up with a token nobody holds.
#[tokio::test(flavor = "current_thread")]
async fn rotations_happen_exactly_when_their_append_wins() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 10).await;
    let rid = rid_for(b"t1");
    let first = first_entry();
    c.append(&rid, b"t1", &w.take(5), &first, None).await.unwrap();
    let second = entry_after(&first, 2);
    let rival = {
        use e2ee_proto::Message;
        let mut e = e2ee_proto::LogEntry::decode(second.as_slice()).unwrap();
        e.nonce = vec![9; 16];
        e.encode_to_vec()
    };
    use e2ee_core::client::Append;
    assert!(matches!(c.append(&rid, b"t1", &w.take(1), &second, Some(b"alice-new")).await.unwrap(), Append::Ok));
    // The rival rotation was built on the same head: it loses, and changes nothing.
    assert!(matches!(c.append(&rid, b"alice-new", &w.take(1), &rival, Some(b"bob-new")).await.unwrap(), Append::Conflict));
    assert!(c.log_since(&rid, b"t1", 0).await.unwrap().is_none(), "old token still valid");
    assert!(c.log_since(&rid, b"bob-new", 0).await.unwrap().is_none(), "the losing rotation took effect");
    assert_eq!(c.log_since(&rid, b"alice-new", 0).await.unwrap().unwrap().len(), 2);
}

/// There is no way to add a token besides rotating, and a rotation leaves
/// exactly one: a member can't plant a token that outlives its removal.
#[tokio::test(flavor = "current_thread")]
async fn no_token_can_be_planted() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 10).await;
    let rid = rid_for(b"shared");
    let first = first_entry();
    c.append(&rid, b"shared", &w.take(5), &first, None).await.unwrap();
    // The old endpoint for adding tokens is gone.
    let r = reqwest::Client::new()
        .post(format!("{url}/repos/{rid}/tokens"))
        .header(e2ee_proto::api::headers::TOKEN, hex::encode(b"shared"))
        .header(e2ee_proto::api::headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.to_string())
        .header("content-type", "application/json")
        .body(format!("{{\"add\":\"{}\"}}", hex::encode(e2ee_proto::sha256(b"planted"))))
        .send()
        .await
        .unwrap();
    assert!(r.status() == 404 || r.status() == 405, "{}", r.status());
    // A member's rogue rotation is itself the one token; the next rotation
    // replaces it.
    let second = entry_after(&first, 2);
    c.append(&rid, b"shared", &w.take(1), &second, Some(b"planted")).await.unwrap();
    let third = entry_after(&second, 3);
    c.append(&rid, b"planted", &w.take(1), &third, Some(b"rotated")).await.unwrap();
    assert!(c.log_since(&rid, b"planted", 0).await.unwrap().is_none());
    assert!(c.log_since(&rid, b"shared", 0).await.unwrap().is_none());
    assert!(c.log_since(&rid, b"rotated", 0).await.unwrap().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn knowing_a_repo_id_is_not_enough_to_create_it() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 10).await;
    // The squatter saw the URL (the id) but has no repo secret, so no token
    // that hashes to it.
    let rid = rid_for(b"real token");
    err_contains(c.append(&rid, b"squatter token", &w.take(5), &first_entry(), None).await.map(|_| ()), "not derived");
    assert!(matches!(c.append(&rid, b"real token", &w.take(5), &first_entry(), None).await.unwrap(), e2ee_core::client::Append::Ok));
}

#[tokio::test(flavor = "current_thread")]
async fn one_time_prekeys_cannot_be_drained() {
    let (_r, url) = start(Limits { max_one_time_handouts_per_hour: 2, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let mut victim = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = victim.db.signed_device_list(&victim.user).unwrap().unwrap();
    c.put_device_list(&hex::encode(&victim.user), &list).await.unwrap();
    let up = victim.key_upload(10, 10, true).await.unwrap();
    c.upload_keys(&auth(&victim), &up, None).await.unwrap();
    let v = hex::encode(&victim.user);
    // Anonymous callers get nothing at all.
    assert!(c.bundle(&[], &v, 1).await.is_err());
    // A registered caller gets one-time keys only up to the hourly cap...
    let attacker = registered(&c).await;
    let w = wallet(&c, &attacker, 7).await;
    for _ in 0..2 {
        assert!(c.bundle(&w.take(1), &v, 1).await.unwrap().one_time.is_some());
    }
    for _ in 0..5 {
        let b = c.bundle(&w.take(1), &v, 1).await.unwrap();
        assert!(b.one_time.is_none(), "cap exceeded");
        assert_eq!(b.kyber_prekey.id, up.kyber_prekey.as_ref().unwrap().id, "last-resort Kyber key");
    }
    // ...so most of the supply survives.
    let left = c.key_count(&auth(&victim)).await.unwrap();
    assert_eq!((left.one_time, left.kyber_one_time), (8, 8));
}

#[tokio::test(flavor = "current_thread")]
async fn signed_requests_cannot_be_replayed_to_another_relay() {
    let (_a, url_a) = start(Limits::default()).await;
    let (_b, url_b) = start(Limits::default()).await;
    let a = RelayClient::new(&url_a).unwrap();
    let b = RelayClient::new(&url_b).unwrap();
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    for c in [&a, &b] {
        c.put_device_list(&hex::encode(&d.user), &list).await.unwrap();
        let up = d.key_upload(1, 0, true).await.unwrap();
        c.upload_keys(&auth(&d), &up, None).await.unwrap();
    }
    issue(&a, &d, 1).await.unwrap();
    // Relay A replays to relay B what the device signed for A. The client
    // signs the origin it connected to (A's, authenticated by TLS), not
    // anything A tells it, so A cannot make it sign for B. A client aimed at
    // B but signing with A's origin produces exactly the replayed requests.
    let mut replayer = RelayClient::new(&url_b).unwrap();
    replayer.set_origin_for_tests(&url_a);
    err_contains(issue(&replayer, &d, 1).await, "bad request signature");
    err_contains(replayer.mailbox(&auth(&d)).await, "bad request signature");
    // Nor does lying in the Host header help: B checks its own public URL.
    let resp = reqwest::Client::new()
        .get(format!("{url_b}/mailbox/{}/1", hex::encode(&d.user)))
        .header("host", url_a.trim_start_matches("http://"))
        .header(e2ee_proto::api::headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    // Signed for B itself, it works.
    issue(&b, &d, 1).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn access_tokens_are_budgeted_and_single_use() {
    let (_r, url) = start(Limits { access_tokens_per_day: 10, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let u = hex::encode(&d.user);
    let w = wallet(&c, &d, 8).await;
    // The daily budget holds no matter how many requests (or IPs) are used.
    err_contains(issue(&c, &d, 3).await, "budget");
    issue(&c, &d, 2).await.unwrap();
    // No tokens, no anonymous action.
    err_contains(c.send_mail(&[], None, &u, 1, vec![1]).await, "access token");
    // Each token works exactly once.
    let t = w.take(1);
    c.send_mail(&t, None, &u, 1, vec![1]).await.unwrap();
    err_contains(c.send_mail(&t, None, &u, 1, vec![1]).await, "already spent");
    // A made-up token is rejected.
    let mut fake = w.take(1);
    fake[0].output[0] ^= 1;
    err_contains(c.send_mail(&fake, None, &u, 1, vec![1]).await, "invalid access token");
    // Blob uploads cost per MiB.
    let id = "e".repeat(32);
    err_contains(c.put_blob(&w.take(2), &id, vec![0; (1 << 20) + 1], b"k").await, "needs 3");
}

#[tokio::test(flavor = "current_thread")]
async fn tokens_from_another_relay_are_worthless() {
    let (_a, url_a) = start(Limits::default()).await;
    let (_b, url_b) = start(Limits::default()).await;
    let a = RelayClient::new(&url_a).unwrap();
    let b = RelayClient::new(&url_b).unwrap();
    let da = registered(&a).await;
    let db_ = registered(&b).await;
    let from_a = wallet(&a, &da, 1).await;
    err_contains(b.send_mail(&from_a.take(1), None, &hex::encode(&db_.user), 1, vec![1]).await, "invalid access token");
}

#[tokio::test(flavor = "current_thread")]
async fn banning_voids_every_outstanding_token() {
    let (relay, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let mallory = registered(&c).await;
    let victim = registered(&c).await;
    let v = hex::encode(&victim.user);
    let stockpile = wallet(&c, &mallory, 5).await;
    c.send_mail(&stockpile.take(1), None, &v, 1, vec![1]).await.unwrap();
    relay.ban(&hex::encode(&mallory.user)).unwrap();
    // Her stockpiled tokens are dead, and she can't get new ones.
    err_contains(c.send_mail(&stockpile.take(1), None, &v, 1, vec![1]).await, "invalid access token");
    err_contains(issue(&c, &mallory, 1).await, "unknown device");
    let list = mallory.db.signed_device_list(&mallory.user).unwrap().unwrap();
    err_contains(c.put_device_list(&hex::encode(&mallory.user), &list).await, "banned");
    // Everyone else simply obtains fresh tokens.
    let fresh = wallet(&c, &victim, 1).await;
    c.send_mail(&fresh.take(1), None, &v, 1, vec![1]).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn without_the_delivery_token_only_the_request_lane_is_open() {
    let (_r, url) = start(Limits { request_lane_per_day: 3, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let mut victim = registered(&c).await;
    let token = victim.delivery_token().unwrap();
    c.put_delivery_token(&auth(&victim), &token).await.unwrap();
    let _ = victim.key_upload(0, 0, false).await.unwrap();
    let v = hex::encode(&victim.user);
    let stranger = registered(&c).await;
    let w = wallet(&c, &stranger, 20).await;
    // A stranger (no delivery token) gets the small request lane only...
    for _ in 0..3 {
        c.send_mail(&w.take(1), None, &v, 1, vec![1]).await.unwrap();
    }
    err_contains(c.send_mail(&w.take(1), None, &v, 1, vec![1]).await, "request lane full");
    err_contains(c.send_mail(&w.take(1), Some(b"guessed"), &v, 1, vec![1]).await, "request lane full");
    // ...while contacts holding the token are unaffected.
    for _ in 0..5 {
        c.send_mail(&w.take(1), Some(&token), &v, 1, vec![1]).await.unwrap();
    }
}

/// A request the relay rejects must not cost the sender its tokens.
#[tokio::test(flavor = "current_thread")]
async fn rejected_requests_do_not_burn_tokens() {
    let limits = Limits {
        max_mailbox_messages: 1,
        request_lane_per_day: 1,
        max_total_blob_bytes: 10,
        max_new_logs_per_hour: 0,
        ..Default::default()
    };
    let (_r, url) = start(limits).await;
    let c = RelayClient::new(&url).unwrap();
    let a = registered(&c).await;
    let b = registered(&c).await;
    let (ua, ub) = (hex::encode(&a.user), hex::encode(&b.user));
    let w = wallet(&c, &a, 5).await;
    let t = w.take(1);
    c.send_mail(&w.take(1), None, &ub, 1, vec![1]).await.unwrap(); // fills b's lane and mailbox
    // Each of these fails, and the same token is still good afterwards.
    err_contains(c.send_mail(&t, None, &ub, 1, vec![1]).await, "request lane full");
    err_contains(c.bundle(&t, &ub, 9).await, "404");
    err_contains(c.get_blob(&t, &"f".repeat(32), 1 << 30).await, "404");
    err_contains(c.put_blob(&[t[0].clone(), w.take(1)[0].clone()], &"f".repeat(32), vec![0; 100], b"k").await, "storage is full");
    err_contains(c.append(&rid_for(b"x"), b"x", &[], &first_entry(), None).await.map(|_| ()), "too many new repos");
    // A full mailbox (with the right delivery token) doesn't charge either.
    let tok_b = b.delivery_token().unwrap();
    c.put_delivery_token(&auth(&b), &tok_b).await.unwrap();
    err_contains(c.send_mail(&t, Some(&tok_b), &ub, 1, vec![1]).await, "mailbox full");
    // After all those rejections the same token still pays for a delivery.
    let tok_a = a.delivery_token().unwrap();
    c.put_delivery_token(&auth(&a), &tok_a).await.unwrap();
    c.send_mail(&t, Some(&tok_a), &ua, 1, vec![1]).await.unwrap();
}

/// A captured signed request (e.g. at a TLS-terminating proxy) can't be
/// replayed to the same relay within the signature's time window.
#[tokio::test(flavor = "current_thread")]
async fn signed_requests_cannot_be_replayed_to_the_same_relay() {
    use e2ee_proto::api::{self, headers};
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let path = format!("/mailbox/{}/1", hex::encode(&d.user));
    let time = e2ee_proto::api::now_ms_for_tokens();
    let nonce = hex::encode([7u8; 16]);
    let payload = api::auth_payload(&api::origin_of(&url).unwrap(), "GET", &path, time, &nonce, b"");
    let sig = d.identity.private_key().calculate_signature(&payload, &mut rand::rng()).unwrap();
    let good_pq = e2ee_proto::pq::sign(&d.pq_seed, e2ee_proto::domain::RELAY_AUTH, &payload);
    let send = |pq: Option<Vec<u8>>| {
        let r = reqwest::Client::new()
            .get(format!("{url}{path}"))
            .header(headers::USER, hex::encode(&d.user))
            .header(headers::DEVICE, "1")
            .header(headers::TIME, time.to_string())
            .header(headers::NONCE, &nonce)
            .header(headers::SIGNATURE, hex::encode(&sig))
            .header(headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.to_string());
        match pq {
            Some(pq) => r.header(headers::PQ_SIGNATURE, B64.encode(pq)),
            None => r,
        }
        .send()
    };
    // A valid classical signature alone is not enough: a quantum attacker
    // who recovered the device's Curve25519 key still can't authenticate.
    let resp = send(None).await.unwrap();
    assert_eq!(resp.status(), 401);
    let wrong = e2ee_proto::pq::sign(&[1; 32], e2ee_proto::domain::RELAY_AUTH, &payload);
    let resp = send(Some(wrong)).await.unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.text().await.unwrap().contains("post-quantum"));
    assert_eq!(send(Some(good_pq.clone())).await.unwrap().status(), 200);
    let replay = send(Some(good_pq)).await.unwrap();
    assert_eq!(replay.status(), 401);
    assert!(replay.text().await.unwrap().contains("replayed"));
}

/// A device can only register with the ML-DSA key its master-signed list
/// names: swapping in another key (keeping the identity key) is refused.
#[tokio::test(flavor = "current_thread")]
async fn registration_requires_the_listed_pq_key() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let mut d = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
    c.put_device_list(&hex::encode(&d.user), &list).await.unwrap();
    d.pq_seed = [5; 32];
    let up = d.key_upload(2, 1, true).await.unwrap();
    let err = c.upload_keys(&auth(&d), &up, None).await.unwrap_err().to_string();
    assert!(err.contains("not in the user's signed device list"), "{err}");
}

/// Undelivered mail and blobs expire by generation (no stored arrival time):
/// they survive one generation change and are gone after the second.
#[tokio::test(flavor = "current_thread")]
async fn expiry_works_without_stored_times() {
    let (relay, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 5).await;
    let u = hex::encode(&d.user);
    c.send_mail(&w.take(1), None, &u, 1, vec![1]).await.unwrap();
    c.put_blob(&w.take(2), &"9".repeat(32), vec![0; 10], b"k").await.unwrap();
    relay.advance_generation_for_tests().unwrap();
    relay.gc().unwrap();
    assert_eq!(c.mailbox(&auth(&d)).await.unwrap().len(), 1);
    assert!(c.get_blob(&w.take(1), &"9".repeat(32), 1 << 30).await.is_ok());
    relay.advance_generation_for_tests().unwrap();
    relay.gc().unwrap();
    assert!(c.mailbox(&auth(&d)).await.unwrap().is_empty());
    assert!(c.get_blob(&w.take(1), &"9".repeat(32), 1 << 30).await.is_err());
}

/// Requests must name a protocol version the relay speaks; responses name the
/// relay's, and `/info` says what it supports.
#[tokio::test(flavor = "current_thread")]
async fn relay_checks_and_announces_protocol_versions() {
    use e2ee_proto::api::headers;
    let (_r, url) = start(Limits::default()).await;
    let http = reqwest::Client::new();
    let get = |v: Option<&str>| {
        let r = http.get(format!("{url}/token-key/1"));
        match v {
            Some(v) => r.header(headers::PROTOCOL, v),
            None => r,
        }
        .send()
    };
    let missing = get(None).await.unwrap();
    assert_eq!(missing.status(), 400);
    let newer = get(Some(&(e2ee_proto::PROTOCOL_VERSION + 1).to_string())).await.unwrap();
    assert_eq!(newer.status(), 400);
    assert_eq!(newer.headers()[headers::PROTOCOL], e2ee_proto::PROTOCOL_VERSION.to_string().as_str());
    assert!(newer.text().await.unwrap().contains("upgrade"));
    assert_ne!(get(Some(&e2ee_proto::PROTOCOL_VERSION.to_string())).await.unwrap().status(), 400);
    let info = RelayClient::new(&url).unwrap().info().await.unwrap();
    assert_eq!((info.protocol_min, info.protocol_max), (e2ee_proto::MIN_PROTOCOL_VERSION, e2ee_proto::PROTOCOL_VERSION));
}

/// A relay database written by a newer build is refused, not misread.
#[test]
fn relay_refuses_a_newer_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    drop(e2ee_relay::Relay::open(&path, std::time::Duration::from_secs(60), Limits::default()).unwrap());
    rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
    let err = e2ee_relay::Relay::open(&path, std::time::Duration::from_secs(60), Limits::default()).err().unwrap().to_string();
    assert!(err.contains("newer version"), "{err}");
}

/// Seen nonces are kept in memory only. A request captured just before a
/// restart must not be replayable afterwards: requests signed before the
/// relay started are refused, while fresh ones work.
#[tokio::test(flavor = "current_thread")]
async fn requests_signed_before_a_restart_are_refused() {
    use e2ee_proto::api::{self, headers};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let public = "http://relay.test";
    let serve = |relay: Arc<Relay>| async move {
        relay.set_public_url(public).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(e2ee_relay::serve(l, relay, 0));
        url
    };
    let ttl = std::time::Duration::from_secs(3600);
    let url = serve(Relay::open(&path, ttl, Limits::default()).unwrap()).await;
    let mut c = RelayClient::new(&url).unwrap();
    c.set_origin_for_tests(public);
    let d = registered(&c).await;
    // Capture a valid mailbox fetch.
    let path_q = format!("/mailbox/{}/1", hex::encode(&d.user));
    let time = e2ee_proto::api::now_ms_for_tokens();
    let nonce = hex::encode([3u8; 16]);
    let payload = api::auth_payload(public, "GET", &path_q, time, &nonce, b"");
    let sig = d.identity.private_key().calculate_signature(&payload, &mut rand::rng()).unwrap();
    let pq = e2ee_proto::pq::sign(&d.pq_seed, e2ee_proto::domain::RELAY_AUTH, &payload);
    let send = |base: String| {
        reqwest::Client::new()
            .get(format!("{base}{path_q}"))
            .header(headers::USER, hex::encode(&d.user))
            .header(headers::DEVICE, "1")
            .header(headers::TIME, time.to_string())
            .header(headers::NONCE, &nonce)
            .header(headers::SIGNATURE, hex::encode(&sig))
            .header(headers::PQ_SIGNATURE, B64.encode(&pq))
            .header(headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.to_string())
            .send()
    };
    assert_eq!(send(url.clone()).await.unwrap().status(), 200);
    // "Restart": a new relay process on the same database.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let url2 = serve(Relay::open(&path, ttl, Limits::default()).unwrap()).await;
    let replay = send(url2.clone()).await.unwrap();
    assert_eq!(replay.status(), 401);
    assert!(replay.text().await.unwrap().contains("before the relay restarted"));
    let mut c2 = RelayClient::new(&url2).unwrap();
    c2.set_origin_for_tests(public);
    c2.mailbox(&auth(&d)).await.unwrap();
}

/// Fetching a prekey bundle is a GET but writes (spends a token, deletes a
/// one-time prekey). The write-ahead log, which would keep arrival order,
/// must be empty afterwards anyway.
#[tokio::test(flavor = "current_thread")]
async fn writes_from_get_requests_leave_the_wal_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let relay = Relay::open(&path, std::time::Duration::from_secs(3600), Limits::default()).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(e2ee_relay::serve(l, relay.clone(), 0));
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 2).await;
    let wal = dir.path().join("relay.sqlite-wal");
    let wal_len = || std::fs::metadata(&wal).map_or(0, |m| m.len());
    c.bundle(&w.take(1), &hex::encode(&d.user), 1).await.unwrap();
    assert_eq!(wal_len(), 0, "the bundle fetch's writes are still in the WAL");
}

/// Pseudonymous mailboxes: created anonymously, written by anyone with the
/// address (and a token), read and deleted only with the key.
#[tokio::test(flavor = "current_thread")]
async fn pseudonymous_mailboxes_need_their_key() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 5).await;
    let id = "7".repeat(32);
    let key = [4u8; 32];
    c.create_pmail(&w.take(1), &id, &key).await.unwrap();
    err_contains(c.create_pmail(&w.take(1), &id, &[5u8; 32]).await, "exists");
    err_contains(c.send_pmail(&w.take(1), &"8".repeat(32), vec![1]).await, "404");
    c.send_pmail(&w.take(1), &id, vec![1, 2, 3]).await.unwrap();
    err_contains(c.pmail(&id, &[5u8; 32]).await, "wrong mailbox key");
    let msgs = c.pmail(&id, &key).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].data, vec![1, 2, 3]);
    err_contains(c.delete_pmail(&id, &[5u8; 32], &msgs[0].id).await, "wrong mailbox key");
    c.delete_pmail(&id, &key, &msgs[0].id).await.unwrap();
    assert!(c.pmail(&id, &key).await.unwrap().is_empty());
    c.retire_pmail(&id, &key).await.unwrap();
    err_contains(c.pmail(&id, &key).await, "404");
}

/// The relay serves its operator's policy; by default a repeat-infringer
/// policy with the configured contact address.
#[tokio::test(flavor = "current_thread")]
async fn relay_serves_its_policy() {
    let (_r, url) = start(Limits::default()).await;
    let p = RelayClient::new(&url).unwrap().policy().await.unwrap();
    assert!(p.contains("Repeat infringers") && p.contains("has not published a contact"), "{p}");

    let relay = Relay::open_in_memory().unwrap();
    relay.set_policy(e2ee_relay::default_policy(Some("abuse@relay.example"))).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url2 = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(e2ee_relay::serve(l, relay.clone(), 0));
    let p = RelayClient::new(&url2).unwrap().policy().await.unwrap();
    assert!(p.contains("Contact: abuse@relay.example"), "{p}");

    let custom = Relay::open_in_memory().unwrap();
    custom.set_policy("Be nice.\n".into()).unwrap();
    assert!(custom.set_policy("x".repeat(e2ee_relay::MAX_POLICY_BYTES + 1)).is_err());
    assert_eq!(custom.policy_text(), "Be nice.\n");
}

/// Every append costs an access token, not just the creating one: holding a
/// repo token isn't enough, so a banned member (whose tokens die with the
/// ban) can't keep writing to repos it was in. A lost race isn't charged.
#[tokio::test(flavor = "current_thread")]
async fn every_append_needs_an_access_token() {
    use e2ee_proto::Message;
    let (relay, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 10).await;
    let rid = rid_for(b"tok");
    let first = first_entry();
    c.append(&rid, b"tok", &w.take(5), &first, None).await.unwrap();
    let next = |seq: u64, prev: &[u8]| {
        e2ee_proto::LogEntry {
            seq,
            prev_head: prev.to_vec(),
            nonce: vec![seq as u8; 16],
            commitment: vec![0; 32],
            version: e2ee_proto::PROTOCOL_VERSION,
        }
        .encode_to_vec()
    };
    let second = next(2, &e2ee_proto::log_head(&first));
    err_contains(c.append(&rid, b"tok", &[], &second, None).await.map(|_| ()), "access token");
    // A stale append loses the race without spending the token it carried.
    let stale = next(1, e2ee_proto::ZERO_HASH.as_slice());
    let t = w.take(1);
    assert!(matches!(c.append(&rid, b"tok", &t, &stale, None).await.unwrap(), e2ee_core::client::Append::Conflict));
    assert!(matches!(c.append(&rid, b"tok", &t, &second, None).await.unwrap(), e2ee_core::client::Append::Ok));
    // After a ban the member's remaining tokens are void, so even with the
    // repo token it can't append.
    relay.ban(&hex::encode(&d.user)).unwrap();
    let third = next(3, &e2ee_proto::log_head(&second));
    err_contains(c.append(&rid, b"tok", &w.take(1), &third, None).await.map(|_| ()), "invalid access token");
}

/// Storage-abuse limits: oversized bodies are refused while being read, log
/// entries must have their fixed shape, and device lists can't list device
/// ids outside 1..=127. No table records arrival order in rowids, and the
/// test-only counters are off unless a test turns them on.
#[tokio::test(flavor = "current_thread")]
async fn relay_refuses_storage_abuse() {
    let (relay, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 10).await;
    // A mail far over the mail limit: refused before it's stored.
    err_contains(c.send_mail(&w.take(1), None, &hex::encode(&d.user), 1, vec![0; 2 << 20]).await, "413");
    // A log entry carrying data.
    let rid = rid_for(b"tok");
    c.append(&rid, b"tok", &w.take(5), &first_entry(), None).await.unwrap();
    use e2ee_proto::Message;
    let fat = e2ee_proto::LogEntry {
        seq: 2,
        prev_head: e2ee_proto::log_head(&first_entry()).to_vec(),
        nonce: vec![0; 200],
        commitment: vec![0; 32],
        version: e2ee_proto::PROTOCOL_VERSION,
    }
    .encode_to_vec();
    err_contains(c.append(&rid, b"tok", &w.take(1), &fat, None).await.map(|_| ()), "malformed log entry");
    // A device list with an out-of-range device id.
    let master = d.master.as_ref().unwrap();
    let cur = d.own_device_list().unwrap();
    let mut devs = cur.body.devices.clone();
    devs.push(e2ee_proto::DeviceEntry { device_id: 200, ..devs[0].clone() });
    let body = e2ee_core::identity::next_device_list(master, Some(&cur), devs);
    let signed = e2ee_core::identity::sign_device_list(master, &body).unwrap();
    err_contains(c.put_device_list(&hex::encode(&d.user), &signed.encode_to_vec()).await, "1..=127");
    assert!(relay.rowid_tables().is_empty(), "tables with rowids: {:?}", relay.rowid_tables());
    let plain = Relay::open_in_memory().unwrap();
    assert!(plain.connection_kinds.lock().unwrap().is_empty() && plain.issuance_sizes.lock().unwrap().is_empty());
}

/// The daily token budget is per user, not per device; and a ban (a new key
/// generation) gives honest users a fresh budget even if it was done from
/// the CLI rather than by the running relay.
#[tokio::test(flavor = "current_thread")]
async fn token_budget_is_per_user_and_resets_on_a_ban() {
    let (relay, url) = start(Limits { access_tokens_per_day: 3, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let master = registered(&c).await;
    let new_db = Db::open_in_memory().unwrap();
    let link = Device::begin_link(&new_db).unwrap();
    let (signed, approval, _) = master.approve_link(&link).unwrap();
    c.put_device_list(&hex::encode(&master.user), &e2ee_proto::Message::encode_to_vec(&signed)).await.unwrap();
    let mut laptop = Device::finish_link(&new_db, &approval).unwrap();
    let lup = laptop.key_upload(1, 0, true).await.unwrap();
    c.upload_keys(&auth(&laptop), &lup, None).await.unwrap();
    issue(&c, &master, 3).await.unwrap();
    err_contains(issue(&c, &laptop, 1).await, "budget");
    relay.ban(&"ab".repeat(32)).unwrap();
    issue(&c, &laptop, 3).await.unwrap();
}

/// More limits: blob uploads are charged before their body is read, an
/// invite serves one user, prekeys have fixed sizes, and mail costs a token
/// per started 64 KiB.
#[tokio::test(flavor = "current_thread")]
async fn uploads_invites_keys_and_mail_are_bounded() {
    let (relay, url) = start(Limits { invite_only: true, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let token = relay.issue_registration_token(std::time::Duration::from_secs(3600)).unwrap();
    let (mut d, up) = unregistered(&c, Some(&token)).await;
    // The same invite can't publish a second identity.
    let other = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let list = other.db.signed_device_list(&other.user).unwrap().unwrap();
    err_contains(c.put_device_list_with_token(&hex::encode(&other.user), &list, Some(&token)).await, "invite-only");
    // Oversized prekeys are refused.
    let mut fat = up.clone();
    fat.one_time.push(e2ee_proto::api::OneTimeKey { id: 999, public: vec![0; 4096] });
    err_contains(c.upload_keys(&auth(&d), &fat, Some(&token)).await, "oversized prekey");
    c.upload_keys(&auth(&d), &up, Some(&token)).await.unwrap();
    let _ = d.key_upload(0, 0, false).await.unwrap();
    let w = wallet(&c, &d, 10).await;
    // A blob upload without tokens is refused (before its body is stored).
    err_contains(c.put_blob(&[], &"5".repeat(32), vec![0; 1 << 20], b"k").await, "access token");
    // 100 KiB of mail costs two tokens.
    err_contains(c.send_mail(&w.take(1), None, &hex::encode(&d.user), 1, vec![0; 100 << 10]).await, "needs 2");
    c.send_mail(&w.take(2), None, &hex::encode(&d.user), 1, vec![0; 100 << 10]).await.unwrap();
}

/// The relay speaks only HTTP/1.1: a client starting HTTP/2 (prior
/// knowledge, ignoring ALPN) gets no HTTP/2 connection.
#[tokio::test(flavor = "current_thread")]
async fn http2_is_not_served() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_r, url) = start(Limits::default()).await;
    let addr = url.trim_start_matches("http://").trim_end_matches('/');
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").await.unwrap();
    let mut buf = vec![0; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap_or(0);
    // An HTTP/2 server would answer with a SETTINGS frame (type 4 at byte 3).
    assert!(n == 0 || buf.starts_with(b"HTTP/1.1"), "{:?}", &buf[..n]);
}

/// Blobs are streamed out in pieces and come back whole; a download needs
/// an access token; a deleted blob is gone.
#[tokio::test(flavor = "current_thread")]
async fn blobs_stream_back_whole() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 20).await;
    let data: Vec<u8> = (0..(300u32 << 10) + 17).map(|i| (i * 7 + i / 251) as u8).collect();
    let id = "c".repeat(32);
    c.put_blob(&w.take(2), &id, data.clone(), b"k").await.unwrap();
    err_contains(c.get_blob(&[], &id, 1 << 30).await.map(|_| ()), "access token");
    assert!(c.get_blob(&w.take(1), &id, 1 << 30).await.unwrap() == data, "blob came back different");
    c.delete_blob(&id, b"k").await.unwrap();
    assert!(c.get_blob(&w.take(1), &id, 1 << 30).await.is_err());
}

/// A mailbox is served in bounded pages; the client reads them all.
#[tokio::test(flavor = "current_thread")]
async fn mailboxes_are_read_in_pages() {
    let (_r, url) = start(Limits::default()).await;
    let c = RelayClient::new(&url).unwrap();
    let d = registered(&c).await;
    let w = wallet(&c, &d, 100).await;
    let u = hex::encode(&d.user);
    for i in 0..18u8 {
        c.send_mail(&w.take(4), None, &u, d.device_id, vec![i; 250 << 10]).await.unwrap();
    }
    // One raw page stops at the byte bound and says where to go on.
    let page = c.mailbox_page(&auth(&d), 0).await.unwrap();
    assert!(page.messages.len() < 18 && page.next.is_some(), "{} messages, next {:?}", page.messages.len(), page.next);
    let all = c.mailbox(&auth(&d)).await.unwrap();
    assert_eq!(all.iter().map(|m| m.data[0]).collect::<Vec<_>>(), (0..18).collect::<Vec<_>>());
}

/// An invite for N uses registers N different users, then no more. A user
/// registering again (another device) doesn't use one up.
#[tokio::test(flavor = "current_thread")]
async fn multi_use_invites_serve_that_many_users() {
    let (relay, url) = start(Limits { invite_only: true, ..Default::default() }).await;
    let c = RelayClient::new(&url).unwrap();
    let token = relay.issue_invite(std::time::Duration::from_secs(3600), 2).unwrap();
    let put = |d: &Device| {
        let list = d.db.signed_device_list(&d.user).unwrap().unwrap();
        (hex::encode(&d.user), list)
    };
    let a = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let (u, l) = put(&a);
    c.put_device_list_with_token(&u, &l, Some(&token)).await.unwrap();
    // The same user again: already registered, no use taken.
    c.put_device_list_with_token(&u, &l, Some(&token)).await.unwrap();
    let b = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let (u, l) = put(&b);
    c.put_device_list_with_token(&u, &l, Some(&token)).await.unwrap();
    let third = Device::create_user(&Db::open_in_memory().unwrap()).unwrap();
    let (u, l) = put(&third);
    err_contains(c.put_device_list_with_token(&u, &l, Some(&token)).await, "invite-only");
}

