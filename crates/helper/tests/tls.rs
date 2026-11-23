//! Transport security: TLS 1.3 with mandatory hybrid post-quantum key exchange.

use std::sync::Arc;

use e2ee_core::client::RelayClient;
use e2ee_core::tls::TlsPolicy;
use e2ee_relay::{Relay, TlsConfig};
use tokio::io::AsyncWriteExt;

struct Certs {
    cert_pem: String,
    key_pem: String,
    ca_file: tempfile::NamedTempFile,
}

fn certs() -> Certs {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = ck.cert.pem();
    let ca_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ca_file.path(), &cert_pem).unwrap();
    Certs { cert_pem, key_pem: ck.signing_key.serialize_pem(), ca_file }
}

async fn relay_tls(c: &Certs, allow_classical: bool) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let tls = TlsConfig { cert_pem: c.cert_pem.clone().into(), key_pem: c.key_pem.clone().into(), allow_classical };
    tokio::spawn(e2ee_relay::serve_tls(l, Relay::open_in_memory().unwrap(), 0, tls));
    format!("https://localhost:{port}")
}

fn policy(c: &Certs) -> TlsPolicy {
    TlsPolicy { extra_ca: Some(c.ca_file.path().to_path_buf()), ..Default::default() }
}

/// A TLS server offering only classical X25519, answering 404 to anything.
async fn classical_only_server(c: &Certs) -> String {
    use rustls::pki_types::pem::PemObject;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from_pem_slice(c.cert_pem.as_bytes()).unwrap()],
            rustls::pki_types::PrivateKeyDer::from_pem_slice(c.key_pem.as_bytes()).unwrap(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(s).await {
                let _ = tls.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").await;
                let _ = tls.shutdown().await;
            }
        }
    });
    format!("https://localhost:{port}")
}

#[tokio::test(flavor = "current_thread")]
async fn relay_over_pq_tls_works() {
    let c = certs();
    let url = relay_tls(&c, false).await;
    let client = RelayClient::with_policy(&url, &policy(&c)).unwrap();
    assert!(client.get_device_list(&"0".repeat(64)).await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn untrusted_certificate_is_refused() {
    let c = certs();
    let url = relay_tls(&c, false).await;
    let client = RelayClient::with_policy(&url, &TlsPolicy::default()).unwrap();
    assert!(client.get_device_list(&"0".repeat(64)).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn client_refuses_classical_only_servers_unless_allowed() {
    let c = certs();
    let url = classical_only_server(&c).await;
    let strict = RelayClient::with_policy(&url, &policy(&c)).unwrap();
    assert!(strict.get_device_list(&"0".repeat(64)).await.is_err(), "downgraded to classical TLS");
    let lax = RelayClient::with_policy(&url, &TlsPolicy { allow_classical: true, ..policy(&c) }).unwrap();
    assert!(lax.get_device_list(&"0".repeat(64)).await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn relay_refuses_classical_only_clients() {
    use rustls::pki_types::pem::PemObject;
    let c = certs();
    let url = relay_tls(&c, false).await;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(c.cert_pem.as_bytes()).unwrap()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let http = reqwest::Client::builder().tls_backend_preconfigured(config).build().unwrap();
    assert!(http.get(format!("{url}/users/{}/device-list", "0".repeat(64))).send().await.is_err());
}

#[test]
fn plaintext_to_remote_hosts_is_refused() {
    let p = TlsPolicy::default();
    assert!(RelayClient::with_policy("http://relay.example", &p).is_err());
    assert!(RelayClient::with_policy("http://127.0.0.1:8470", &p).is_ok());
    assert!(RelayClient::with_policy("https://relay.example", &p).is_ok());
}
