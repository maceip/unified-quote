//! Live-loop attested-TLS test.
//!
//! Spins up a real TLS server on localhost with an attested-TLS cert, has
//! a client connect, pulls the peer cert, and runs the full
//! verification path except for the platform-quote signature chain
//! (no TEE, so the quote bytes are fabricated to have a matching
//! report_data layout).
//!
//! What this exercises that the static tests don't:
//!
//! - The rustls client actually sees the self-signed cert through the
//!   handshake, not just a DER we fed it manually.
//! - `peer_certificates()` returns the same cert bytes the server has
//!   in its config — confirming no funny business in how rustls
//!   serializes certs.
//! - The "accept anything" client verifier does not break extraction
//!   — cert extensions survive the handshake intact.
//! - `spki_hash_of_cert(peer_cert)` equals the producer-side
//!   `spki_hash_of(keypair)`, end-to-end across a real network socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use unified_quote::eat::{BuildComponents, EatToken};
use unified_quote::net::attested_tls::{
    extract_eat_from_cert, generate_keypair, make_attested_cert, spki_hash_of, spki_hash_of_cert,
};
use unified_quote::quote::Platform;

fn fake_snp_quote_with_binding(binding: &[u8; 32]) -> Vec<u8> {
    let mut q = vec![0u8; 1152];
    q[0x50..0x50 + 32].copy_from_slice(binding);
    q
}

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Arc<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
        .unwrap()
        .unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

fn client_config() -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}

#[test]
fn client_recovers_eat_from_live_tls_handshake() {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // --- producer side: generate cert like cmd_enclave does ---
    let kp = generate_keypair().unwrap();
    let tls_spki_hash = spki_hash_of(&kp);

    let mut eat = EatToken::from_build(BuildComponents {
        platform: Platform::SevSnp,
        value_x: [0xabu8; 48],
        source_hash: [0xcdu8; 48],
        artifact_hash: [0xefu8; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });
    eat.tls_spki_hash = tls_spki_hash;

    let binding = eat.binding_bytes();
    eat.platform_quote = fake_snp_quote_with_binding(&binding);

    let eat_cbor = eat.to_cbor().unwrap();
    let cert_material = make_attested_cert(&kp, "attested-tls.test.local", &eat_cbor).unwrap();

    // --- spin up a TLS server on localhost ---
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sconfig = server_config(
        cert_material.cert_pem.as_bytes(),
        cert_material.key_pem.as_bytes(),
    );
    let server_handle = thread::spawn(move || {
        let (mut sock, _peer) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(sconfig).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock.try_clone().unwrap());
        // Drain whatever the client sent, write a canned response
        let mut buf = [0u8; 4096];
        let _ = tls.read(&mut buf);
        let _ =
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
        let _ = tls.conn.send_close_notify();
        let _ = tls.flush();
        drop(tls);
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });

    // --- client side: connect, extract cert, run verification ---
    let cconfig = client_config();
    let server_name =
        rustls::pki_types::ServerName::try_from("attested-tls.test.local".to_string()).unwrap();
    let mut conn = rustls::ClientConnection::new(cconfig, server_name).unwrap();
    let mut sock = TcpStream::connect(addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let _ = tls.write_all(
        b"GET /eat HTTP/1.1\r\nHost: attested-tls.test.local\r\nConnection: close\r\n\r\n",
    );
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);

    let certs = conn
        .peer_certificates()
        .expect("peer presented certificates");
    let leaf = &certs[0];

    // 1. Extract the EAT from the cert extension
    let recovered_cbor = extract_eat_from_cert(leaf.as_ref())
        .unwrap()
        .expect("ext present");
    assert_eq!(
        recovered_cbor, eat_cbor,
        "EAT survived TLS handshake intact"
    );

    // 2. Decode
    let recovered = EatToken::from_cbor(&recovered_cbor).unwrap();
    assert_eq!(recovered.value_x, [0xabu8; 48]);

    // 3. Channel binding: cert SPKI hash matches eat claim
    let cert_spki = spki_hash_of_cert(leaf.as_ref()).unwrap();
    assert_eq!(cert_spki, recovered.tls_spki_hash);

    // 4. Quote binding: binding_bytes matches report_data[0..32]
    let recomputed = recovered.binding_bytes();
    assert_eq!(
        &recovered.platform_quote[0x50..0x50 + 32],
        &recomputed,
        "report_data in embedded quote must match EAT binding"
    );

    server_handle.join().unwrap();
}
