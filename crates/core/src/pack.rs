//! Bulk encryption of packfiles: XChaCha20-Poly1305 with a fresh random key
//! per blob, Padmé padding to blur sizes.

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use e2ee_proto::domain;
use rand::RngCore;

/// Plaintext bytes per encrypted chunk (`E2EE_CHUNK_BYTES`, default 15.5 MiB).
/// Senders and receivers hold about one chunk in memory at a time, whatever
/// the pack size.
/// Kept between 1 KiB and `MAX_CHUNK_BYTES`. The default, 15.5 MiB, seals
/// to just under 16 MiB, so it fills a relay's 16 MiB storage slot.
pub fn chunk_bytes() -> usize {
    std::env::var("E2EE_CHUNK_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_CHUNK_BYTES).clamp(1024, MAX_CHUNK_BYTES)
}

pub const DEFAULT_CHUNK_BYTES: usize = 31 << 19;

/// The largest chunk anyone sends: sealed (31.5 MiB), it stays under what
/// receivers accept per chunk (64 MiB) and a default relay's 32 MiB blobs.
pub const MAX_CHUNK_BYTES: usize = 31 << 20;
const MIN_PADDED: usize = 4096;

/// Largest pack accepted or produced (`E2EE_MAX_PACK_BYTES`, default 4 GiB).
pub fn max_pack_bytes() -> u64 {
    std::env::var("E2EE_MAX_PACK_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(4 << 30)
}

/// Padmé: pad to a length whose low bits are zero, leaking O(log log n) bits.
pub fn padme(len: usize) -> usize {
    let len = len.max(MIN_PADDED);
    let e = usize::BITS - 1 - len.leading_zeros();
    let s = u32::BITS - e.leading_zeros();
    let last_bits = e - s;
    let mask = (1usize << last_bits) - 1;
    (len + mask) & !mask
}

/// Size of a sealed chunk holding `len` bytes: length prefix and Padmé
/// padding, nonce and tag.
pub fn sealed_len(len: usize) -> usize {
    padme(len + 8) + 24 + 16
}

pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rng().fill_bytes(&mut k);
    k
}

/// Associated data binding a chunk to its position, so chunks can't be
/// reordered, dropped or the pack truncated.
fn chunk_aad(index: u32, last: bool) -> Vec<u8> {
    let mut aad = domain::PACK.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(last as u8);
    aad
}

/// Encrypt chunk `index` of a pack (`last` marks the final one).
pub fn seal_chunk(key: &[u8; 32], index: u32, last: bool, data: &[u8]) -> Result<Vec<u8>> {
    seal_with(key, data, &chunk_aad(index, last))
}

pub fn open_chunk(key: &[u8], index: u32, last: bool, blob: &[u8]) -> Result<Vec<u8>> {
    open_with(key, blob, &chunk_aad(index, last))
}

/// Encrypt `data` under `key`. Output: nonce(24) || ciphertext.
pub fn seal(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    seal_with(key, data, domain::PACK)
}

pub fn open(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    open_with(key, blob, domain::PACK)
}

fn seal_with(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let padded_len = padme(data.len() + 8);
    let mut pt = Vec::with_capacity(padded_len);
    pt.extend_from_slice(&(data.len() as u64).to_be_bytes());
    pt.extend_from_slice(data);
    pt.resize(padded_len, 0);
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: &pt, aad })
        .map_err(|_| anyhow!("pack encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_with(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 || blob.len() < 24 + 16 + 8 {
        bail!("malformed encrypted pack");
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad pack key"))?;
    let nonce: [u8; 24] = blob[..24].try_into()?;
    let pt = cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: &blob[24..], aad })
        .map_err(|_| anyhow!("pack decryption failed (wrong key or tampered blob)"))?;
    let len = u64::from_be_bytes(pt[..8].try_into()?) as usize;
    if len > pt.len() - 8 {
        bail!("pack length prefix out of range");
    }
    Ok(pt[8..8 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_padding() {
        let k = random_key();
        for n in [0usize, 1, 4000, 5000, 100_000] {
            let data = vec![7u8; n];
            let blob = seal(&k, &data).unwrap();
            assert_eq!(open(&k, &blob).unwrap(), data);
            assert!(blob.len() >= MIN_PADDED);
        }
        assert_eq!(seal(&k, &[1; 4000]).unwrap().len(), seal(&k, &[1; 10]).unwrap().len());
    }

    #[test]
    fn chunk_sizes_fit_relay_slots_and_limits() {
        assert!(sealed_len(DEFAULT_CHUNK_BYTES) + 16 <= 16 << 20);
        assert!(sealed_len(MAX_CHUNK_BYTES) <= 32 << 20);
    }

    #[test]
    fn padme_is_monotone_and_bounded() {
        let mut prev = 0;
        for n in 1..200_000 {
            let p = padme(n);
            assert!(p >= n && p >= prev);
            assert!(p as f64 <= (n.max(MIN_PADDED) as f64) * 1.13);
            prev = p;
        }
    }

    #[test]
    fn chunks_are_bound_to_position_and_end() {
        let k = random_key();
        let c0 = seal_chunk(&k, 0, false, b"first").unwrap();
        let c1 = seal_chunk(&k, 1, true, b"last").unwrap();
        assert_eq!(open_chunk(&k, 0, false, &c0).unwrap(), b"first");
        assert_eq!(open_chunk(&k, 1, true, &c1).unwrap(), b"last");
        // Swapped order, or presenting a non-final chunk as the last one
        // (truncation), fails.
        assert!(open_chunk(&k, 0, false, &c1).is_err());
        assert!(open_chunk(&k, 0, true, &c0).is_err());
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let k = random_key();
        let mut blob = seal(&k, b"hello").unwrap();
        assert!(open(&random_key(), &blob).is_err());
        blob[30] ^= 1;
        assert!(open(&k, &blob).is_err());
    }
}
