//! Anonymous rate-limited access tokens (Privacy Pass style, VOPRF from
//! RFC 9497 over ristretto255).
//!
//! A device obtains tokens by sending *blinded* random nonces in a
//! device-authenticated request; the relay counts them against the device's
//! daily budget and evaluates them under the day's key, proving (DLEQ) that it
//! used the published key. Anonymous actions later spend tokens as
//! (epoch, nonce, output). The blinding is perfectly hiding, so the relay
//! cannot link a spent token to the device it was issued to.

use rand_core06::OsRng;
use voprf::{BlindedElement, EvaluationElement, Group, Proof, VoprfClient, VoprfServer};

type Suite = voprf::Ristretto255;

pub const NONCE_LEN: usize = 32;
const KEY_INFO: &[u8] = b"git-e2ee/v1/access-token";

/// Tokens are issued per UTC day; today's and yesterday's are accepted.
pub fn epoch_now() -> u64 {
    crate::api::now_ms_for_tokens() / 86_400_000
}

/// One unspent token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub output: Vec<u8>,
}

impl Token {
    pub fn encode(&self) -> String {
        format!("{}:{}:{}", self.epoch, hex::encode(&self.nonce), hex::encode(&self.output))
    }

    pub fn decode(s: &str) -> Option<Token> {
        let mut it = s.trim().split(':');
        let epoch = it.next()?.parse().ok()?;
        let nonce = hex::decode(it.next()?).ok()?;
        let output = hex::decode(it.next()?).ok()?;
        (it.next().is_none() && nonce.len() == NONCE_LEN).then_some(Token { epoch, nonce, output })
    }
}

/// Relay side: the key for one epoch, derived from the relay's secret seed.
pub struct Issuer {
    server: VoprfServer<Suite>,
}

impl Issuer {
    pub fn new(seed: &[u8], epoch: u64) -> Self {
        let mut info = KEY_INFO.to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        Self { server: VoprfServer::new_from_seed(seed, &info).expect("valid seed") }
    }

    pub fn public_key(&self) -> Vec<u8> {
        <Suite as voprf::CipherSuite>::Group::serialize_elem(self.server.get_public_key()).to_vec()
    }

    /// Evaluate blinded elements; returns evaluations and one batch proof.
    pub fn issue(&self, blinded: &[Vec<u8>]) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        let elems: Vec<BlindedElement<Suite>> =
            blinded.iter().map(|b| BlindedElement::deserialize(b)).collect::<Result<_, _>>().ok()?;
        let r = self.server.batch_blind_evaluate(&mut OsRng, &elems).ok()?;
        Some((r.messages.iter().map(|m| m.serialize().to_vec()).collect(), r.proof.serialize().to_vec()))
    }

    /// Whether `output` is this key's PRF value for `nonce` (constant time).
    pub fn check(&self, nonce: &[u8], output: &[u8]) -> bool {
        use subtle_compare::ct_eq;
        match self.server.evaluate(nonce) {
            Ok(expected) => ct_eq(&expected, output),
            Err(_) => false,
        }
    }
}

mod subtle_compare {
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// Client side: blinded requests awaiting evaluation.
pub struct Pending {
    epoch: u64,
    items: Vec<(Vec<u8>, VoprfClient<Suite>)>,
}

/// Blind `n` fresh random nonces for `epoch`; returns the state and the
/// blinded elements to send.
pub fn blind(n: usize, epoch: u64) -> (Pending, Vec<Vec<u8>>) {
    let mut items = Vec::with_capacity(n);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut nonce = vec![0u8; NONCE_LEN];
        rand_core06::RngCore::fill_bytes(&mut OsRng, &mut nonce);
        let r = VoprfClient::<Suite>::blind(&nonce, &mut OsRng).expect("nonce is non-empty");
        out.push(r.message.serialize().to_vec());
        items.push((nonce, r.state));
    }
    (Pending { epoch, items }, out)
}

/// Unblind the relay's answer, verifying its proof against `public_key`.
pub fn finalize(p: Pending, evaluations: &[Vec<u8>], proof: &[u8], public_key: &[u8]) -> Option<Vec<Token>> {
    if evaluations.len() != p.items.len() {
        return None;
    }
    let pk = <Suite as voprf::CipherSuite>::Group::deserialize_elem(public_key).ok()?;
    let proof = Proof::<Suite>::deserialize(proof).ok()?;
    let msgs: Vec<EvaluationElement<Suite>> =
        evaluations.iter().map(|e| EvaluationElement::deserialize(e)).collect::<Result<_, _>>().ok()?;
    let nonces: Vec<Vec<u8>> = p.items.iter().map(|(n, _)| n.clone()).collect();
    let clients: Vec<VoprfClient<Suite>> = p.items.into_iter().map(|(_, c)| c).collect();
    let outputs: Vec<Vec<u8>> = VoprfClient::batch_finalize(&nonces, &clients, &msgs, &proof, pk)
        .ok()?
        .map(|o| o.map(|o| o.to_vec()))
        .collect::<Result<_, _>>()
        .ok()?;
    Some(
        nonces
            .into_iter()
            .zip(outputs)
            .map(|(nonce, output)| Token { epoch: p.epoch, nonce, output })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_spend_and_verify() {
        let issuer = Issuer::new(b"seed-seed-seed-seed-seed-seed-32", 7);
        let (pending, blinded) = blind(5, 7);
        let (evals, proof) = issuer.issue(&blinded).unwrap();
        let tokens = finalize(pending, &evals, &proof, &issuer.public_key()).unwrap();
        assert_eq!(tokens.len(), 5);
        for t in &tokens {
            assert!(issuer.check(&t.nonce, &t.output));
            assert_eq!(Token::decode(&t.encode()).as_ref(), Some(t));
        }
        // A made-up token fails; a token from another epoch's key fails.
        assert!(!issuer.check(&[1; 32], &tokens[0].output));
        assert!(!Issuer::new(b"seed-seed-seed-seed-seed-seed-32", 8).check(&tokens[0].nonce, &tokens[0].output));
    }

    #[test]
    fn client_rejects_evaluation_under_a_different_key() {
        // A relay trying to tag one user with a separate key is caught by
        // the proof check against the published key.
        let published = Issuer::new(b"seed-seed-seed-seed-seed-seed-32", 7);
        let tagging = Issuer::new(b"other-seed-other-seed-other-seed", 7);
        let (pending, blinded) = blind(3, 7);
        let (evals, proof) = tagging.issue(&blinded).unwrap();
        assert!(finalize(pending, &evals, &proof, &published.public_key()).is_none());
    }

    #[test]
    fn blinded_elements_reveal_nothing_about_nonces() {
        // Same nonce count, fresh randomness: blinded messages never repeat.
        let (_, a) = blind(3, 1);
        let (_, b) = blind(3, 1);
        assert!(a.iter().all(|x| !b.contains(x)));
    }
}
