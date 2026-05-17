//! ACME TLS-ALPN-01 certificate provisioning.
//!
//! At boot, stage 1 requests a TLS cert from Let's Encrypt for its
//! Value X domain: <value_x_prefix>.aeon.site
//!
//! TLS-ALPN-01: Let's Encrypt connects to port 443, the TEE responds.
//! The cert appears in Certificate Transparency logs automatically.

use anyhow::Result;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};

/// Derive the domain name from Value X.
/// Uses the first 12 hex chars of Value X as the subdomain.
pub fn domain_from_value_x(value_x: &[u8; 48]) -> String {
    let prefix = hex::encode(&value_x[..6]);
    format!("{prefix}.aeon.site")
}

/// Provision a Let's Encrypt cert and install it into a running enclave.
///
/// Runs on the parent instance (which has internet access).
/// The enclave serves TLS on port 443 via the vsock proxy.
///
/// Flow:
///   1. Create ACME account + order
///   2. Generate TLS-ALPN-01 challenge cert (self-signed with acmeIdentifier extension)
///   3. POST challenge cert to enclave's /tls-cert endpoint
///   4. Tell Let's Encrypt to validate (LE connects through proxy → enclave)
///   5. Finalize order → get real cert
///   6. POST real cert to enclave's /tls-cert endpoint
pub async fn provision_cert_for_enclave(
    domain: &str,
    enclave_url: &str,
    use_staging: bool,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    eprintln!("[bountynet/acme] Requesting cert for: {domain}");

    let url = if use_staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    // Step 1: Create ACME account
    let (account, _credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_owned(),
            None,
        )
        .await?;
    eprintln!("[bountynet/acme] Account created");

    // Step 2: Create order
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    eprintln!("[bountynet/acme] Order created");

    // Step 3: Process authorizations
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => anyhow::bail!("Unexpected authorization status: {status:?}"),
        }

        // Get TLS-ALPN-01 challenge
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow::anyhow!("No TLS-ALPN-01 challenge offered"))?;

        let key_auth = challenge.key_authorization();
        eprintln!("[bountynet/acme] Challenge for {}", challenge.identifier());

        // Generate challenge cert with acmeIdentifier extension
        let challenge_pem = generate_alpn_challenge_cert(domain, key_auth.as_str())?;

        // Install challenge cert into enclave (with acme-tls/1 ALPN)
        let install_url = format!("{enclave_url}/acme-challenge");
        eprintln!("[bountynet/acme] Installing challenge cert into enclave...");
        let resp = http.post(&install_url).body(challenge_pem).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to install challenge cert: {}", resp.text().await?);
        }
        eprintln!("[bountynet/acme] Challenge cert installed");

        // Tell Let's Encrypt we're ready
        challenge.set_ready().await?;
        eprintln!("[bountynet/acme] Challenge submitted, waiting for validation...");
    }

    // Step 4: Wait for order to be ready
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        anyhow::bail!("Order not ready: {status:?}");
    }
    eprintln!("[bountynet/acme] Challenge PASSED");

    // Step 5: Finalize — get the real cert
    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    eprintln!("[bountynet/acme] Certificate issued for {domain}");

    // Step 6: Install real cert into enclave
    let real_pem = format!("{cert_chain_pem}\n{private_key_pem}");
    let install_url = format!("{enclave_url}/tls-cert");
    let resp = http.post(&install_url).body(real_pem).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to install real cert: {}", resp.text().await?);
    }

    eprintln!("[bountynet/acme] Real cert installed. TLS is now valid for {domain}");
    eprintln!("[bountynet/acme] Cert will appear in Certificate Transparency logs.");

    Ok(())
}

/// Generate a self-signed TLS-ALPN-01 challenge cert.
///
/// Per RFC 8737: the cert has a critical acmeIdentifier extension
/// (OID 1.3.6.1.5.5.7.1.31) containing the SHA-256 of the key authorization,
/// DER-encoded as an ASN.1 OCTET STRING.
///
/// Returns PEM (cert + key concatenated).
fn generate_alpn_challenge_cert(domain: &str, key_authorization: &str) -> Result<String> {
    use sha2::{Digest, Sha256};

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;

    // acmeIdentifier extension: OID 1.3.6.1.5.5.7.1.31
    // Value: DER-encoded ASN.1 OCTET STRING containing sha256(key_authorization)
    let digest = Sha256::digest(key_authorization.as_bytes());
    let mut der_value = vec![0x04, 0x20]; // ASN.1 OCTET STRING, 32 bytes
    der_value.extend_from_slice(&digest);

    let oid = vec![1, 3, 6, 1, 5, 5, 7, 1, 31];
    let mut ext = rcgen::CustomExtension::from_oid_content(&oid, der_value);
    ext.set_criticality(true); // RFC 8737: MUST be critical
    params.custom_extensions.push(ext);

    let cert = params.self_signed(&key_pair)?;
    let pem = format!("{}\n{}", cert.pem(), key_pair.serialize_pem());

    Ok(pem)
}
