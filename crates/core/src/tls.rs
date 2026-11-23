//! Transport policy for talking to relays.
//!
//! End-to-end encryption already protects content; TLS keeps the relay's
//! metadata and availability powers (repo tokens, replayable requests, ids)
//! with the relay alone instead of everyone on the network path. The key
//! exchange must be post-quantum hybrid so recorded traffic stays private.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

#[derive(Debug, Clone, Default)]
pub struct TlsPolicy {
    /// Allow plain `http://` to non-loopback hosts (`E2EE_ALLOW_INSECURE_RELAY=1`).
    pub allow_insecure: bool,
    /// Allow classical-only TLS key exchange (`E2EE_ALLOW_CLASSICAL_TLS=1`).
    pub allow_classical: bool,
    /// Extra PEM root certificates for self-hosted relays (`E2EE_RELAY_CA_FILE`).
    pub extra_ca: Option<PathBuf>,
}

impl TlsPolicy {
    pub fn from_env() -> Self {
        let flag = |n: &str| std::env::var(n).is_ok_and(|v| v == "1" || v == "true");
        Self {
            allow_insecure: flag("E2EE_ALLOW_INSECURE_RELAY"),
            allow_classical: flag("E2EE_ALLOW_CLASSICAL_TLS"),
            extra_ca: std::env::var_os("E2EE_RELAY_CA_FILE").map(PathBuf::from),
        }
    }

    /// Reject plaintext URLs except to loopback, unless explicitly allowed.
    pub fn check_url(&self, url: &reqwest::Url) -> Result<()> {
        match url.scheme() {
            "https" => Ok(()),
            "http" if self.allow_insecure || is_loopback(url) => Ok(()),
            "http" => bail!(
                "refusing plaintext relay {url}: use https:// (anyone on the network path could \
                 steal the repo token and replay requests). Set E2EE_ALLOW_INSECURE_RELAY=1 to override."
            ),
            s => bail!("unsupported relay url scheme {s:?}"),
        }
    }

    /// TLS 1.3 client config: web roots (+ extra CA), hybrid PQ key exchange.
    pub fn client_config(&self) -> Result<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &self.extra_ca {
            for cert in CertificateDer::pem_file_iter(path).with_context(|| format!("reading {}", path.display()))? {
                roots.add(cert?)?;
            }
        }
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(provider(self.allow_classical)))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth())
    }
}

/// aws-lc-rs provider; unless classical is allowed, X25519MLKEM768 is the
/// only key exchange offered, so a downgrade to classical cannot happen.
pub fn provider(allow_classical: bool) -> rustls::crypto::CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    if !allow_classical {
        p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }
    p
}

fn is_loopback(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> reqwest::Url {
        s.parse().unwrap()
    }

    #[test]
    fn plaintext_only_to_loopback() {
        let p = TlsPolicy::default();
        assert!(p.check_url(&u("https://relay.example")).is_ok());
        assert!(p.check_url(&u("http://127.0.0.1:8470")).is_ok());
        assert!(p.check_url(&u("http://[::1]:8470")).is_ok());
        assert!(p.check_url(&u("http://localhost:8470")).is_ok());
        assert!(p.check_url(&u("http://relay.example")).is_err());
        assert!(p.check_url(&u("http://10.0.0.1")).is_err());
        assert!(p.check_url(&u("ftp://relay.example")).is_err());
        let lax = TlsPolicy { allow_insecure: true, ..Default::default() };
        assert!(lax.check_url(&u("http://relay.example")).is_ok());
    }

    #[test]
    fn pq_only_by_default() {
        assert_eq!(provider(false).kx_groups.len(), 1);
        assert_eq!(provider(false).kx_groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
        assert!(provider(true).kx_groups.len() > 1);
    }
}
