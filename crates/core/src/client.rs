//! HTTP client for the relay.

use anyhow::{Context, Result, anyhow};
use e2ee_proto::api::{self, headers};
use e2ee_proto::tokens::Token;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use libsignal_protocol::IdentityKeyPair;
use reqwest::{Method, StatusCode};

pub struct RelayClient {
    base: String,
    http: reqwest::Client,
    /// Everything not signed by the device (token-paid, repo-token and
    /// public requests): a fresh connection per request (no pooling, no TLS
    /// session reuse), so the relay can't tie a spent access token to the
    /// device that just signed in on the same connection. The IP address is
    /// still the same; that needs Tor.
    anon: reqwest::Client,
    /// The origin we connect to (TLS-authenticated), bound into signatures.
    origin: String,
}

/// Device credentials for signed requests.
pub struct DeviceAuth<'a> {
    pub user_hex: String,
    pub device_id: u32,
    pub identity: &'a IdentityKeyPair,
    pub pq_seed: &'a [u8; 32],
}

/// The relay refused or failed a request. Distinguishes "the relay (or the
/// network) let us down, try again later" from "the data is bad".
#[derive(Debug)]
pub struct RelayError(pub String);

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RelayError {}

/// Whether an error came from the relay or the network (transient).
pub fn is_transient(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<RelayError>() || c.is::<reqwest::Error>())
}

pub enum Append {
    Ok,
    Conflict,
}

/// Retry requests the relay rate-limited (HTTP 429) with backoff.
trait SendRetry {
    async fn send_retry(self) -> reqwest::Result<reqwest::Response>;
}

impl SendRetry for reqwest::RequestBuilder {
    async fn send_retry(self) -> reqwest::Result<reqwest::Response> {
        let mut delay = std::time::Duration::from_millis(200);
        for _ in 0..6 {
            let Some(attempt) = self.try_clone() else { break };
            let resp = attempt.send().await?;
            if resp.status() != StatusCode::TOO_MANY_REQUESTS {
                return Ok(resp);
            }
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
        self.send().await
    }
}

fn versioned_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(headers::PROTOCOL, e2ee_proto::PROTOCOL_VERSION.into());
    h
}

/// A relay response over its size limit (`read_capped`).
#[derive(Debug)]
pub struct TooLarge(pub String);

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TooLarge {}

/// Most mail one mailbox read collects in one sync.
const MAIL_FETCH_BYTES: usize = 64 << 20;

/// A response body of at most `cap` bytes (a relay is untrusted: an endless
/// body must not exhaust memory).
pub(crate) async fn read_capped(mut resp: reqwest::Response, cap: usize, what: &str) -> Result<Vec<u8>> {
    let too_large = || TooLarge(format!("the relay's {what} is larger than the {cap} bytes allowed"));
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(too_large().into());
    }
    let mut buf = Vec::new();
    while let Some(c) = resp.chunk().await? {
        if buf.len() + c.len() > cap {
            return Err(too_large().into());
        }
        buf.extend_from_slice(&c);
    }
    Ok(buf)
}

async fn read_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response, cap: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read_capped(resp, cap, "response").await?)?)
}

/// A relay's error text, as we show it: printable and short (the relay is
/// untrusted, and its text ends up on the user's terminal).
async fn relay_text(mut resp: reqwest::Response) -> String {
    // Read no more than we'd show.
    let mut buf = Vec::new();
    while buf.len() < 4096 {
        match resp.chunk().await {
            Ok(Some(c)) => buf.extend_from_slice(&c),
            _ => break,
        }
    }
    buf.truncate(4096);
    let t = crate::printable(&String::from_utf8_lossy(&buf));
    match t.char_indices().nth(300) {
        Some((i, _)) => format!("{}…", &t[..i]),
        None => t,
    }
}

impl RelayClient {
    /// A client following the transport policy from the environment.
    pub fn new(base: &str) -> Result<Self> {
        Self::with_policy(base, &crate::tls::TlsPolicy::from_env())
    }

    pub fn with_policy(base: &str, policy: &crate::tls::TlsPolicy) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        let url: reqwest::Url = base.parse().with_context(|| format!("bad relay url {base:?}"))?;
        policy.check_url(&url)?;
        let http = reqwest::Client::builder()
            .default_headers(versioned_headers())
            .tls_backend_preconfigured(policy.client_config()?)
            // Never follow redirects: one could point us at a plaintext URL.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        // No TLS session resumption either: a resumption ticket the relay
        // issued on one anonymous connection would link it to the next.
        let mut anon_tls = policy.client_config()?;
        anon_tls.resumption = rustls::client::Resumption::disabled();
        let anon = reqwest::Client::builder()
            .default_headers(versioned_headers())
            .tls_backend_preconfigured(anon_tls)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .build()?;
        let origin = api::origin_of(&base).ok_or_else(|| anyhow!("relay url has no origin"))?;
        Ok(Self { base, http, anon, origin })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn base_path(&self) -> String {
        // The path prefix of the base URL, for signing.
        let after_scheme = self.base.split_once("://").map(|x| x.1).unwrap_or("");
        after_scheme.find('/').map(|i| after_scheme[i..].to_string()).unwrap_or_default()
    }

    /// Sign as if talking to another relay (tests of cross-relay replay).
    #[doc(hidden)]
    pub fn set_origin_for_tests(&mut self, origin: &str) {
        self.origin = origin.to_string();
    }

    async fn signed(&self, method: Method, path: &str, body: Vec<u8>, auth: &DeviceAuth<'_>) -> Result<reqwest::RequestBuilder> {
        let time = crate::now_ms();
        let full_path = format!("{}{path}", self.base_path());
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let payload = api::auth_payload(&self.origin, method.as_str(), &full_path, time, &nonce, &body);
        let sig = auth.identity.private_key().calculate_signature(&payload, &mut rand::rng())?;
        let pq_sig = e2ee_proto::pq::sign(auth.pq_seed, e2ee_proto::domain::RELAY_AUTH, &payload);
        Ok(self
            .http
            .request(method, format!("{}{path}", self.base))
            .header(headers::USER, &auth.user_hex)
            .header(headers::DEVICE, auth.device_id.to_string())
            .header(headers::TIME, time.to_string())
            .header(headers::NONCE, &nonce)
            .header(headers::SIGNATURE, hex::encode(sig))
            .header(headers::PQ_SIGNATURE, B64.encode(pq_sig))
            .body(body))
    }

    fn tokened(&self, method: Method, path: &str, token: &[u8]) -> reqwest::RequestBuilder {
        self.anon
            .request(method, format!("{}{path}", self.base))
            .header(headers::TOKEN, hex::encode(token))
    }

    async fn check(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let theirs = resp.headers().get(headers::PROTOCOL).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u32>().ok());
        if let Some(v) = theirs
            && v > e2ee_proto::PROTOCOL_VERSION
        {
            let text = relay_text(resp).await;
            return Err(RelayError(format!(
                "relay {what} failed: {status} {text} (the relay speaks protocol {v}, this build {}: consider upgrading)",
                e2ee_proto::PROTOCOL_VERSION
            ))
            .into());
        }
        let text = relay_text(resp).await;
        Err(RelayError(format!("relay {what} failed: {status} {text}")).into())
    }

    // -- devices -------------------------------------------------------------

    pub async fn put_device_list(&self, user_hex: &str, signed: &[u8]) -> Result<()> {
        self.put_device_list_with_token(user_hex, signed, None).await.map(|_| ())
    }

    /// `registration_token`: needed on invite-only relays until the user's
    /// first device has registered.
    /// Ok(true): the relay already has a newer list (it keeps that one).
    pub async fn put_device_list_with_token(&self, user_hex: &str, signed: &[u8], registration_token: Option<&str>) -> Result<bool> {
        let mut req = self.anon.put(format!("{}/users/{user_hex}/device-list", self.base));
        if let Some(t) = registration_token {
            req = req.header(headers::REGISTRATION_TOKEN, t);
        }
        let resp = req
            .body(signed.to_vec())
            .send_retry()
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            return Ok(true);
        }
        Self::check(resp, "device list upload").await?;
        Ok(false)
    }

    /// The relay operator's policy text (`GET /policy`), cleaned for showing
    /// in a terminal: control characters (which could carry escape sequences)
    /// are removed and it's cut off at 64 KiB.
    pub async fn policy(&self) -> Result<String> {
        let resp = self.anon.get(format!("{}/policy", self.base)).send_retry().await?;
        let text = String::from_utf8_lossy(&read_capped(Self::check(resp, "policy fetch").await?, 64 << 10, "policy").await?).into_owned();
        Ok(clean_policy(&text))
    }

    /// What the relay speaks (`GET /info`).
    pub async fn info(&self) -> Result<api::RelayInfo> {
        let resp = self.anon.get(format!("{}/info", self.base)).send_retry().await?;
        read_json(Self::check(resp, "info").await?, 1 << 20).await
    }

    pub async fn get_device_list(&self, user_hex: &str) -> Result<Option<Vec<u8>>> {
        let resp = self.anon.get(format!("{}/users/{user_hex}/device-list", self.base)).send_retry().await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(read_capped(Self::check(resp, "device list fetch").await?, 1 << 20, "device list").await?))
    }

    /// Upload prekeys. `registration_token` is needed once per user on
    /// invite-only relays.
    pub async fn upload_keys(&self, auth: &DeviceAuth<'_>, up: &api::KeyUpload, registration_token: Option<&str>) -> Result<()> {
        let path = format!("/devices/{}/{}/keys", auth.user_hex, auth.device_id);
        let mut req = self.signed(Method::POST, &path, serde_json::to_vec(up)?, auth).await?;
        if let Some(t) = registration_token {
            req = req.header(headers::REGISTRATION_TOKEN, t);
        }
        Self::check(req.header("content-type", "application/json").send_retry().await?, "key upload").await?;
        Ok(())
    }

    pub async fn key_count(&self, auth: &DeviceAuth<'_>) -> Result<api::KeyCount> {
        let path = format!("/devices/{}/{}/keys/count", auth.user_hex, auth.device_id);
        let resp = Self::check(self.signed(Method::GET, &path, vec![], auth).await?.send_retry().await?, "key count").await?;
        read_json(resp, 1 << 20).await
    }

    /// Fetch a device's prekey bundle (paid with an access token).
    pub async fn bundle(&self, access: &[Token], user_hex: &str, device: u32) -> Result<api::Bundle> {
        let resp = self
            .anon
            .get(format!("{}/devices/{user_hex}/{device}/bundle", self.base))
            .header(headers::ACCESS, access_header(access))
            .send_retry()
            .await?;
        read_json(Self::check(resp, "prekey bundle fetch").await?, 1 << 20).await
    }

    // -- repos ---------------------------------------------------------------



    /// Returns `None` if the token is not accepted.
    pub async fn log_since(&self, rid_hex: &str, token: &[u8], since: u64) -> Result<Option<Vec<Vec<u8>>>> {
        let resp = self.tokened(Method::GET, &format!("/repos/{rid_hex}/log?since={since}"), token).send_retry().await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Ok(None);
        }
        Ok(Some(read_json::<api::LogEntries>(Self::check(resp, "log fetch").await?, 256 << 20).await?.entries))
    }

    /// Append to a repo's log. The first append creates the log; it is paid
    /// for with anonymous access tokens (no identity) and sets the repo token.
    /// `replace_token`: make this append a rotation to that token.
    pub async fn append(&self, rid_hex: &str, token: &[u8], access: &[Token], entry: &[u8], replace_token: Option<&[u8]>) -> Result<Append> {
        let mut req = self.tokened(Method::POST, &format!("/repos/{rid_hex}/log"), token);
        if let Some(t) = replace_token {
            req = req.header(headers::REPLACE_TOKEN, token_hash(t));
        }
        let resp = req
            .header(headers::ACCESS, access_header(access))
            .body(entry.to_vec())
            .send_retry()
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            return Ok(Append::Conflict);
        }
        // A refused repo token on an append means someone rotated it since
        // our last sync (or we were removed): either way the next fetch tells.
        if resp.status() == StatusCode::UNAUTHORIZED {
            let text = relay_text(resp).await;
            if text.trim() == api::BAD_REPO_TOKEN {
                return Ok(Append::Conflict);
            }
            return Err(RelayError(format!("relay log append failed: 401 Unauthorized {text}")).into());
        }
        Self::check(resp, "log append").await?;
        Ok(Append::Ok)
    }

    /// Store a blob in the relay's global blob store. Only the hash of
    /// `delete_token` is sent; presenting the token later deletes the blob.
    pub async fn put_blob(&self, access: &[Token], id: &str, data: Vec<u8>, delete_token: &[u8]) -> Result<()> {
        let resp = self
            .anon
            .put(format!("{}/blobs/{id}", self.base))
            .header(headers::ACCESS, access_header(access))
            .header(headers::BLOB_DELETE_HASH, token_hash(delete_token))
            .body(data)
            .send_retry()
            .await?;
        Self::check(resp, "blob upload").await?;
        Ok(())
    }

    /// A blob of at most `cap` bytes (anything longer is refused while
    /// downloading, not after).
    pub async fn get_blob(&self, access: &[Token], id: &str, cap: usize) -> Result<Vec<u8>> {
        let resp = self
            .anon
            .get(format!("{}/blobs/{id}", self.base))
            .header(headers::ACCESS, access_header(access))
            .send_retry()
            .await?;
        let resp = Self::check(resp, "blob download").await.with_context(|| format!("blob {id}"))?;
        read_capped(resp, cap, "blob").await
    }

    pub async fn delete_blob(&self, id: &str, delete_token: &[u8]) -> Result<()> {
        let resp = self
            .anon
            .delete(format!("{}/blobs/{id}", self.base))
            .header(headers::BLOB_DELETE_TOKEN, hex::encode(delete_token))
            .send_retry()
            .await?;
        Self::check(resp, "blob delete").await?;
        Ok(())
    }

    /// Obtain anonymous access tokens (evaluations of blinded nonces).
    pub async fn issue_tokens(&self, auth: &DeviceAuth<'_>, req: &api::TokenRequest) -> Result<api::TokenResponse> {
        let path = format!("/tokens/{}/{}", auth.user_hex, auth.device_id);
        let resp = self.signed(Method::POST, &path, serde_json::to_vec(req)?, auth).await?;
        read_json(Self::check(resp.header("content-type", "application/json").send_retry().await?, "token issuance").await?, 4 << 20).await
    }

    /// The token key of an epoch, fetched anonymously.
    /// An access-token public key, of the current generation or of `generation`.
    /// Fetched unauthenticated over a connection of its own (no pooling, no
    /// TLS session reuse), so it isn't trivially tied to our signed requests.
    /// The same IP still makes it, which is why members also compare keys.
    pub async fn token_key(&self, epoch: u64, generation: Option<u32>) -> Result<api::TokenKey> {
        let q = generation.map(|g| format!("?gen={g}")).unwrap_or_default();
        let resp = self.anon.get(format!("{}/token-key/{epoch}{q}", self.base)).send_retry().await?;
        read_json(Self::check(resp, "token key fetch").await?, 1 << 20).await
    }

    /// Register the hash of our user's delivery token.
    pub async fn put_delivery_token(&self, auth: &DeviceAuth<'_>, token: &[u8]) -> Result<()> {
        let path = format!("/users/{}/{}/delivery-token", auth.user_hex, auth.device_id);
        let body = serde_json::to_vec(&api::DeliveryTokenHash { token_hash: token_hash(token) })?;
        let resp = self.signed(Method::PUT, &path, body, auth).await?;
        Self::check(resp.header("content-type", "application/json").send_retry().await?, "delivery token upload").await?;
        Ok(())
    }

    /// Deliver to a device's mailbox, paying with access tokens. With the
    /// recipient's delivery token the mail goes to the normal lane.
    pub async fn send_mail(
        &self,
        access: &[Token],
        delivery: Option<&[u8]>,
        user_hex: &str,
        device: u32,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut req = self.anon.post(format!("{}/mailbox/{user_hex}/{device}", self.base)).header(headers::ACCESS, access_header(access));
        if let Some(d) = delivery {
            req = req.header(headers::DELIVERY, hex::encode(d));
        }
        Self::check(req.body(data).send_retry().await?, "mail delivery").await?;
        Ok(())
    }

    /// The device's mail, page by page, up to `MAIL_FETCH_BYTES` per call
    /// (the rest waits for the next sync).
    pub async fn mailbox(&self, auth: &DeviceAuth<'_>) -> Result<Vec<api::MailboxMessage>> {
        let mut out = Vec::new();
        let mut after = 0;
        loop {
            let page = self.mailbox_page(auth, after).await?;
            out.extend(page.messages);
            match page.next {
                Some(n) if n > after && out.iter().map(|m| m.data.len()).sum::<usize>() < MAIL_FETCH_BYTES => after = n,
                _ => return Ok(out),
            }
        }
    }

    /// One page of the device's mail, after mailbox seq `after`.
    pub async fn mailbox_page(&self, auth: &DeviceAuth<'_>, after: u64) -> Result<api::Mailbox> {
        let path = format!("/mailbox/{}/{}?after={after}", auth.user_hex, auth.device_id);
        let resp = Self::check(self.signed(Method::GET, &path, vec![], auth).await?.send_retry().await?, "mailbox fetch").await?;
        read_json(resp, 2 * api::MAIL_PAGE_BYTES).await
    }

    pub async fn delete_mail(&self, auth: &DeviceAuth<'_>, id: &str) -> Result<()> {
        let path = format!("/mailbox/{}/{}/{id}", auth.user_hex, auth.device_id);
        Self::check(self.signed(Method::DELETE, &path, vec![], auth).await?.send_retry().await?, "mail delete").await?;
        Ok(())
    }

    // -- pseudonymous mailboxes (anonymous; authorized by a per-mailbox key) --

    pub async fn create_pmail(&self, access: &[Token], id: &str, key: &[u8]) -> Result<()> {
        let req = self.anon.put(format!("{}/pmail/{id}", self.base)).header(headers::ACCESS, access_header(access));
        Self::check(req.header(headers::MAILBOX_KEY, hex::encode(key)).send_retry().await?, "mailbox creation").await?;
        Ok(())
    }

    pub async fn send_pmail(&self, access: &[Token], id: &str, data: Vec<u8>) -> Result<()> {
        let req = self.anon.post(format!("{}/pmail/{id}", self.base)).header(headers::ACCESS, access_header(access));
        Self::check(req.body(data).send_retry().await?, "mail delivery").await?;
        Ok(())
    }

    /// Like `mailbox`, for a pseudonymous mailbox.
    pub async fn pmail(&self, id: &str, key: &[u8]) -> Result<Vec<api::MailboxMessage>> {
        let mut out = Vec::new();
        let mut after = 0;
        loop {
            let req = self.anon.get(format!("{}/pmail/{id}?after={after}", self.base)).header(headers::MAILBOX_KEY, hex::encode(key));
            let resp = Self::check(req.send_retry().await?, "mailbox fetch").await?;
            let page: api::Mailbox = read_json(resp, 2 * api::MAIL_PAGE_BYTES).await?;
            out.extend(page.messages);
            match page.next {
                Some(n) if n > after && out.iter().map(|m| m.data.len()).sum::<usize>() < MAIL_FETCH_BYTES => after = n,
                _ => return Ok(out),
            }
        }
    }

    pub async fn delete_pmail(&self, id: &str, key: &[u8], msg: &str) -> Result<()> {
        let req = self.anon.delete(format!("{}/pmail/{id}/{msg}", self.base)).header(headers::MAILBOX_KEY, hex::encode(key));
        Self::check(req.send_retry().await?, "mail delete").await?;
        Ok(())
    }

    pub async fn retire_pmail(&self, id: &str, key: &[u8]) -> Result<()> {
        let req = self.anon.delete(format!("{}/pmail/{id}", self.base)).header(headers::MAILBOX_KEY, hex::encode(key));
        Self::check(req.send_retry().await?, "mailbox retirement").await?;
        Ok(())
    }
}

/// Make relay-supplied text safe to print: keep newlines and tabs, drop every
/// other control character, and cap the length.
pub fn clean_policy(text: &str) -> String {
    let mut out: String = text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect();
    if out.len() > 64 << 10 {
        let mut cut = 64 << 10;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n[policy cut off]\n");
    }
    out
}


fn access_header(tokens: &[Token]) -> String {
    tokens.iter().map(Token::encode).collect::<Vec<_>>().join(",")
}

fn token_hash(token: &[u8]) -> String {
    hex::encode(e2ee_proto::sha256(token))
}

#[cfg(test)]
mod tests {
    #[test]
    fn policy_text_is_cleaned_for_the_terminal() {
        let t = super::clean_policy("Rules\n\x1b[2J\x1b]0;evil\x07\tok\r\n");
        assert_eq!(t, "Rules\n[2J]0;evil\tok\n");
        assert!(super::clean_policy(&"x".repeat(70_000)).ends_with("[policy cut off]\n"));
    }
}
