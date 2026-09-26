//! The client sends SNI only for DNS names, and verifies the server's certificate against
//! the server name either way: its DNS SANs for a name, its IP SANs for an IP literal.

use btls::pkey::PKey;
use btls::x509::X509;
use quinn_btls::{helpers, HandshakeData, QuicSslContext};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

/// A server presenting a self-signed certificate for `sans`, and a client trusting it.
fn pair(sans: &[&str]) -> (quinn::Endpoint, quinn::ClientConfig) {
    let cert = rcgen::generate_simple_self_signed(
        sans.iter().map(|san| san.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();
    let x509 = X509::from_pem(cert.cert.pem().as_bytes()).unwrap();
    let key = PKey::private_key_from_pem(cert.signing_key.serialize_pem().as_bytes()).unwrap();

    let mut server_crypto = quinn_btls::ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_certificate(x509.clone())
        .unwrap();
    server_crypto.ctx_mut().set_private_key(key).unwrap();
    let server = quinn::Endpoint::new(
        helpers::default_endpoint_config(),
        Some(helpers::server_config(Arc::new(server_crypto)).unwrap()),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();

    let mut client_crypto = quinn_btls::ClientConfig::new().unwrap();
    client_crypto
        .ctx_mut()
        .cert_store_mut()
        .add_cert(x509)
        .unwrap();
    let client = quinn::ClientConfig::new(Arc::new(client_crypto));
    (server, client)
}

/// Connects to `server` as `server_name`; returns the SNI the server saw, or the client's
/// connection error.
async fn connect(
    server: &quinn::Endpoint,
    client: quinn::ClientConfig,
    server_name: &str,
) -> Result<Option<String>, quinn::ConnectionError> {
    let addr = server.local_addr().unwrap();
    let endpoint = helpers::client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let accept = async {
        let conn = server.accept().await.unwrap().await?;
        let data = conn.handshake_data().unwrap();
        Ok(data.downcast::<HandshakeData>().unwrap().server_name)
    };
    let dial = async {
        endpoint
            .connect_with(client, addr, server_name)
            .unwrap()
            .await
    };
    let (sni, conn) = tokio::join!(accept, dial);
    conn?;
    sni
}

#[tokio::test]
async fn ip_server_name_sends_no_sni_and_verifies_ip_san() {
    let (server, client) = pair(&["127.0.0.1"]);
    assert_eq!(connect(&server, client, "127.0.0.1").await.unwrap(), None);
}

#[tokio::test]
async fn ip_server_name_rejects_certificate_without_that_ip() {
    let (server, client) = pair(&["127.0.0.1"]);
    let endpoint = helpers::client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.accept().await.unwrap().await;
    });
    let result = endpoint
        .connect_with(client, addr, "127.0.0.2")
        .unwrap()
        .await;
    assert!(result.is_err(), "the certificate has no IP SAN 127.0.0.2");
    server_task.abort();
}

#[tokio::test]
async fn dns_server_name_sends_sni() {
    let (server, client) = pair(&["localhost"]);
    assert_eq!(
        connect(&server, client, "localhost").await.unwrap(),
        Some("localhost".to_owned())
    );
}
