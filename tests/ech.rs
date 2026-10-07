//! The client offers ECH with the ECHConfigList it is given: a server with the keys
//! decrypts its ClientHello and sees the inner server name; one without them rejects
//! ECH, and the handshake fails with the server's retry configs.

use btls::pkey::PKey;
use btls::x509::X509;
use btls_sys as bffi;
use foreign_types_shared::ForeignType;
use quinn_btls::{helpers, HandshakeData, QuicSslContext};
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

/// An ECHConfig for `public_name`, as an ECHConfigList, and the server keys that
/// decrypt what a client encrypts with it.
struct Ech {
    list: Vec<u8>,
    keys: *mut bffi::SSL_ECH_KEYS,
}

impl Ech {
    fn new(config_id: u8, public_name: &str, private_key: &[u8; 32]) -> Self {
        let name = CString::new(public_name).unwrap();
        unsafe {
            let key = bffi::EVP_HPKE_KEY_new();
            assert_eq!(
                bffi::EVP_HPKE_KEY_init(
                    key,
                    bffi::EVP_hpke_x25519_hkdf_sha256(),
                    private_key.as_ptr(),
                    private_key.len(),
                ),
                1
            );
            let (mut out, mut out_len) = (std::ptr::null_mut(), 0);
            assert_eq!(
                bffi::SSL_marshal_ech_config(
                    &mut out,
                    &mut out_len,
                    config_id,
                    key,
                    name.as_ptr(),
                    0
                ),
                1
            );
            let config = std::slice::from_raw_parts(out, out_len).to_vec();
            bffi::OPENSSL_free(out.cast());
            let keys = bffi::SSL_ECH_KEYS_new();
            assert_eq!(
                bffi::SSL_ECH_KEYS_add(keys, 1, config.as_ptr(), config.len(), key),
                1
            );
            bffi::EVP_HPKE_KEY_free(key);
            let mut list = (config.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&config);
            Self { list, keys }
        }
    }
}

impl Drop for Ech {
    fn drop(&mut self) {
        unsafe { bffi::SSL_ECH_KEYS_free(self.keys) }
    }
}

/// A server for `sans` that decrypts with `ech`'s keys, and a client trusting it.
fn pair(sans: &[&str], ech: &Ech) -> (quinn::Endpoint, quinn_btls::ClientConfig) {
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
    unsafe {
        assert_eq!(
            bffi::SSL_CTX_set1_ech_keys(server_crypto.ctx().as_ptr(), ech.keys),
            1
        );
    }
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
    (server, client_crypto)
}

/// Connects to `server` as `server_name`; what the server and the client saw of the
/// handshake, or the client's connection error.
async fn connect(
    server: &quinn::Endpoint,
    client: quinn_btls::ClientConfig,
    server_name: &str,
) -> Result<(HandshakeData, HandshakeData), quinn::ConnectionError> {
    let addr = server.local_addr().unwrap();
    let endpoint = helpers::client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let accept = async {
        let conn = server.accept().await.unwrap().await?;
        Ok::<_, quinn::ConnectionError>(*conn
            .handshake_data()
            .unwrap()
            .downcast::<HandshakeData>()
            .unwrap())
    };
    let dial = async {
        endpoint
            .connect_with(
                quinn::ClientConfig::new(Arc::new(client)),
                addr,
                server_name,
            )
            .unwrap()
            .await
    };
    let (served, conn) = tokio::join!(accept, dial);
    let conn = conn?;
    let dialed = *conn
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap();
    Ok((served?, dialed))
}

#[tokio::test]
async fn ech_hides_the_server_name_in_the_inner_client_hello() {
    let ech = Ech::new(1, "public.example", &[7; 32]);
    let (server, mut client) = pair(&["secret.example", "public.example"], &ech);
    client.set_ech_config_list(Some(&ech.list)).unwrap();
    let (served, dialed) = connect(&server, client, "secret.example").await.unwrap();
    assert_eq!(served.server_name.as_deref(), Some("secret.example"));
    assert!(served.ech_accepted);
    assert!(dialed.ech_accepted);
}

#[tokio::test]
async fn without_an_ech_config_list_there_is_no_ech() {
    let ech = Ech::new(1, "public.example", &[7; 32]);
    let (server, client) = pair(&["secret.example"], &ech);
    let (served, dialed) = connect(&server, client, "secret.example").await.unwrap();
    assert_eq!(served.server_name.as_deref(), Some("secret.example"));
    assert!(!served.ech_accepted);
    assert!(!dialed.ech_accepted);
}

#[tokio::test]
async fn a_clone_offers_its_own_ech_config_list() {
    let ech = Ech::new(1, "public.example", &[7; 32]);
    let (server, client) = pair(&["secret.example", "public.example"], &ech);
    let mut with = client.clone();
    with.set_ech_config_list(Some(&ech.list)).unwrap();
    let (_, dialed) = connect(&server, with, "secret.example").await.unwrap();
    assert!(dialed.ech_accepted);
    let (_, dialed) = connect(&server, client, "secret.example").await.unwrap();
    assert!(!dialed.ech_accepted);
}

#[tokio::test]
async fn a_rejected_ech_fails_with_the_retry_configs() {
    let ech = Ech::new(1, "public.example", &[7; 32]);
    let stale = Ech::new(1, "public.example", &[8; 32]);
    let (server, mut client) = pair(&["secret.example", "public.example"], &ech);
    client.set_ech_config_list(Some(&stale.list)).unwrap();
    let err = connect(&server, client, "secret.example")
        .await
        .err()
        .expect("ECH is rejected");
    let reason = err.to_string();
    assert!(
        reason.contains(&format!("[ECH_RETRY:{}]", hex::encode(&ech.list))),
        "{}",
        reason
    );
}

#[test]
fn an_ech_config_list_boringssl_cannot_take_is_an_error() {
    let mut client = quinn_btls::ClientConfig::new().unwrap();
    assert!(client.set_ech_config_list(Some(&[0, 3, 1, 2, 3])).is_err());
    assert!(client.set_ech_config_list(None).is_ok());
}
