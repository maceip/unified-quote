//! TPM2 client attestation for Linux and Windows desktops (no CVM).
//!
//! Two assurance levels share this verifier:
//!
//! - **channel-bound only** (legacy): the AK quote commits the eat-pass channel
//!   binding in `qualifyingData`, proving a genuine TPM on this machine signed
//!   *this* request — but the agent-binary identity (`build_digest`) is
//!   self-reported. `ima_verified = false`.
//! - **IMA-verified**: the bundle additionally carries the quoted PCRs and the
//!   Linux IMA measurement log. The verifier confirms the quote attests those
//!   PCRs, replays the IMA log into PCR 10, requires `build_digest` to appear as
//!   a kernel-measured file hash, and derives a boot-aggregate over PCR 0-9. Now
//!   the running binary is hardware-measured, not asserted. `ima_verified = true`.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use der::{Decode, Encode};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _};
use p256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as P256Sig, VerifyingKey as P256Vk,
};
use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;

use super::{desktop_build_id_hash, DesktopVerdict, LINUX_TPM_PLATFORM, WINDOWS_TPM_PLATFORM};

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_RSAPSS: u16 = 0x0016;
const ACTIVATION_TOKEN_DOMAIN: &[u8] = b"uq/desktop-tpm/activation-token/v1\0";

/// A single TPM PCR value reported alongside the quote.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PcrValue {
    pub index: u32,
    /// Hex-encoded PCR contents (32 bytes for the sha256 bank).
    pub value: String,
}

/// Verifier-side policy inputs for desktop TPM evidence.
///
/// These are intentionally not carried by the evidence bundle. EK roots and
/// activation-token signers are operator trust anchors.
#[derive(Debug, Clone, Default)]
pub struct TpmVerifierOptions {
    /// SHA-256 fingerprints of DER-encoded TPM manufacturer / privacy-CA roots.
    pub ek_root_sha256: Vec<String>,
    /// Ed25519 public keys allowed to sign credential-activation tokens.
    pub activation_pubkeys: Vec<[u8; 32]>,
    /// Unix time for token expiry checks. `None` uses the local clock.
    pub now: Option<u64>,
}

/// Signed verifier token proving an online makecredential/activatecredential
/// round completed for this EK and AK name.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TpmActivationToken {
    pub version: u32,
    /// Unix seconds after which the activation proof is no longer accepted.
    pub exp: u64,
    /// Verifier freshness nonce, hex.
    pub nonce: String,
    /// The eat-pass channel binding this activation was issued for, hex.
    pub binding: String,
    /// SHA-256 of the DER EK certificate, hex.
    pub ek_cert_sha256: String,
    /// SHA-256 of the DER AK certificate, hex.
    pub ak_cert_sha256: String,
    /// TPM2B_NAME of the AK used in makecredential, hex.
    pub ak_name: String,
    /// SHA-256 of the secret recovered by `tpm2_activatecredential`, hex.
    pub secret_sha256: String,
    /// Ed25519 public key that signed this token, hex.
    pub issuer_pubkey: String,
    /// Ed25519 signature over `signed_bytes()`, hex.
    pub sig: String,
}

impl TpmActivationToken {
    fn signed_bytes(&self) -> Vec<u8> {
        fn put_str(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(ACTIVATION_TOKEN_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        put_str(&mut out, &self.nonce);
        put_str(&mut out, &self.binding);
        put_str(&mut out, &self.ek_cert_sha256);
        put_str(&mut out, &self.ak_cert_sha256);
        put_str(&mut out, &self.ak_name);
        put_str(&mut out, &self.secret_sha256);
        put_str(&mut out, &self.issuer_pubkey);
        out
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TpmCredentialActivation {
    pub token: TpmActivationToken,
    /// Secret bytes returned by `tpm2_activatecredential`, hex.
    pub secret: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TpmClientBundle {
    pub version: u32,
    /// `linux-tpm-client` or `windows-tpm-client`.
    pub platform: String,
    /// Must equal eat-pass `binding_of(blinded)`.
    pub binding: String,
    /// SHA-256 of the agent binary or signed bundle (hex, 32 bytes).
    pub build_digest: String,
    /// Attestation Key certificate (hex DER).
    pub ak_cert: String,
    /// Endorsement Key certificate (hex DER). Required for hardware-rooted TPM
    /// verification.
    #[serde(default)]
    pub ek_cert: String,
    /// Issuer chain for `ek_cert`, hex DER, ordered EK issuer -> root.
    #[serde(default)]
    pub ek_ca_chain: Vec<String>,
    /// TPM2B_NAME of the AK that was credential-activated, hex.
    #[serde(default)]
    pub ak_name: String,
    /// Proof that an online verifier ran makecredential/activatecredential for
    /// this EK certificate and AK name. Required for hardware-rooted TPM
    /// verification.
    #[serde(default)]
    pub credential_activation: Option<TpmCredentialActivation>,
    /// TPM2B_ATTEST (hex), including the leading size field.
    pub quote_msg: String,
    /// TPMT_SIGNATURE (hex).
    pub quote_sig: String,
    /// Qualifying data from the quote (hex); must equal `binding`.
    pub qualifying_data: String,

    // --- IMA-verified mode (optional; both must be present together) ---
    /// PCR bank algorithm for `pcrs` / the quote. Only `sha256` is supported.
    #[serde(default)]
    pub pcr_bank: String,
    /// The PCR values the quote attests (PCR 0-10 for the IMA path).
    #[serde(default)]
    pub pcrs: Vec<PcrValue>,
    /// Linux IMA `ascii_runtime_measurements` log (template hashes must be
    /// sha256: collect with `ima_template=ima-ng ima_hash=sha256`).
    #[serde(default)]
    pub ima_log: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TpmVerifyError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub fn verify_bundle(
    bundle: &TpmClientBundle,
    expected_binding: &[u8; 32],
) -> Result<DesktopVerdict, TpmVerifyError> {
    verify_bundle_with_options(bundle, expected_binding, &TpmVerifierOptions::default())
}

pub fn verify_bundle_with_options(
    bundle: &TpmClientBundle,
    expected_binding: &[u8; 32],
    options: &TpmVerifierOptions,
) -> Result<DesktopVerdict, TpmVerifyError> {
    if bundle.version != 1 {
        return Err(TpmVerifyError::Verify(format!(
            "unsupported version {}",
            bundle.version
        )));
    }
    if bundle.platform != LINUX_TPM_PLATFORM && bundle.platform != WINDOWS_TPM_PLATFORM {
        return Err(TpmVerifyError::Verify(format!(
            "expected platform {LINUX_TPM_PLATFORM} or {WINDOWS_TPM_PLATFORM}, got {}",
            bundle.platform
        )));
    }
    let binding = parse_hex32(&bundle.binding, "binding")?;
    if &binding != expected_binding {
        return Err(TpmVerifyError::Verify(
            "binding does not match expected channel binding".into(),
        ));
    }
    let qualifying = parse_hex(&bundle.qualifying_data, "qualifying_data")?;
    if qualifying.as_slice() != expected_binding {
        return Err(TpmVerifyError::Verify(
            "qualifying_data does not match expected channel binding".into(),
        ));
    }
    let build_digest = parse_hex32(&bundle.build_digest, "build_digest")?;
    let ak_der = parse_hex(&bundle.ak_cert, "ak_cert")?;
    let quote_msg = parse_hex(&bundle.quote_msg, "quote_msg")?;
    let quote_sig = parse_hex(&bundle.quote_sig, "quote_sig")?;

    // Parse the full TPMS_ATTEST: extraData (channel binding) + the quoted PCR
    // selection and digest (for the IMA path).
    let quote = parse_quote(&quote_msg)?;
    if quote.extra_data.as_slice() != expected_binding {
        return Err(TpmVerifyError::Verify(
            "quote extraData does not match expected channel binding".into(),
        ));
    }

    // The AK signature authenticates the whole TPMS_ATTEST (including the PCR
    // digest), so everything derived from it below is hardware-signed.
    let ak = Certificate::from_der(&ak_der)
        .map_err(|e| TpmVerifyError::Parse(format!("ak_cert: {e}")))?;
    verify_quote_signature(&ak, &quote_msg, &quote_sig)?;
    verify_hardware_root(bundle, &ak_der, expected_binding, options)?;

    // IMA mode is engaged when the client supplies a measurement log and PCRs.
    // Sending one without the other is rejected so a client cannot present a
    // partial IMA story to look stronger than it is.
    let ima_mode = !bundle.ima_log.trim().is_empty() || !bundle.pcrs.is_empty();
    let (ima_verified, boot_aggregate) = if ima_mode {
        if bundle.ima_log.trim().is_empty() || bundle.pcrs.is_empty() {
            return Err(TpmVerifyError::Verify(
                "IMA mode requires both pcrs and ima_log".into(),
            ));
        }
        if !bundle.pcr_bank.is_empty() && bundle.pcr_bank.to_ascii_lowercase() != "sha256" {
            return Err(TpmVerifyError::Verify(format!(
                "only the sha256 PCR bank is supported, got {}",
                bundle.pcr_bank
            )));
        }
        let pcrs = parse_pcrs(&bundle.pcrs)?;

        // 1. The quote's pcrDigest must match the reported PCRs, tying the
        //    hardware-signed quote to the PCR values we reason about.
        verify_pcr_digest(&quote, &pcrs)?;

        // 2. Replaying the IMA log must reproduce the quoted PCR 10.
        let pcr10 = *pcrs
            .get(&10)
            .ok_or_else(|| TpmVerifyError::Verify("PCR 10 not in reported pcrs".into()))?;
        let replayed = replay_ima_pcr10(&bundle.ima_log)?;
        if replayed != pcr10 {
            return Err(TpmVerifyError::Verify(
                "IMA log does not reproduce the quoted PCR 10".into(),
            ));
        }

        // 3. The agent binary must actually have been measured by the kernel:
        //    its sha256 must appear as a file-data hash in the IMA log.
        if !ima_contains_filehash(&bundle.ima_log, &build_digest) {
            return Err(TpmVerifyError::Verify(
                "build_digest was not measured by IMA (binary not in the log)".into(),
            ));
        }

        // 4. Derive a known-good-boot fingerprint over PCR 0-9 for the policy
        //    to allowlist.
        let boot = boot_aggregate_over_0_9(&pcrs)?;
        (true, Some(hex::encode(boot)))
    } else {
        (false, None)
    };

    let identity = desktop_build_id_hash(&build_digest);
    Ok(DesktopVerdict {
        verdict: "verified".into(),
        platform: bundle.platform.clone(),
        identity_hash: hex::encode(identity),
        ima_verified,
        boot_aggregate,
    })
}

fn verify_hardware_root(
    bundle: &TpmClientBundle,
    ak_der: &[u8],
    expected_binding: &[u8; 32],
    options: &TpmVerifierOptions,
) -> Result<(), TpmVerifyError> {
    if options.ek_root_sha256.is_empty() {
        return Err(TpmVerifyError::Verify(
            "desktop TPM EK root fingerprints are not configured".into(),
        ));
    }
    if options.activation_pubkeys.is_empty() {
        return Err(TpmVerifyError::Verify(
            "desktop TPM credential-activation signer keys are not configured".into(),
        ));
    }

    let ek_der = parse_required_hex(&bundle.ek_cert, "ek_cert")?;
    let ek_chain = decode_hex_chain(&bundle.ek_ca_chain, "ek_ca_chain")?;
    verify_ek_chain(&ek_der, &ek_chain, &options.ek_root_sha256)?;
    verify_activation_proof(bundle, &ek_der, ak_der, expected_binding, options)?;
    Ok(())
}

fn verify_ek_chain(
    ek_der: &[u8],
    ca_chain: &[Vec<u8>],
    pinned_roots: &[String],
) -> Result<(), TpmVerifyError> {
    if ca_chain.is_empty() {
        return Err(TpmVerifyError::Verify(
            "ek_ca_chain is required and must end at a pinned root".into(),
        ));
    }
    Certificate::from_der(ek_der).map_err(|e| TpmVerifyError::Parse(format!("ek_cert: {e}")))?;

    let mut subject = ek_der;
    for (i, issuer) in ca_chain.iter().enumerate() {
        if !verify_cert_sig(issuer, subject)? {
            return Err(TpmVerifyError::Verify(format!(
                "ek_ca_chain link {i} failed signature check"
            )));
        }
        subject = issuer;
    }

    let root = ca_chain.last().expect("checked non-empty");
    if !verify_cert_sig(root, root)? {
        return Err(TpmVerifyError::Verify(
            "ek_ca_chain root is not self-signed".into(),
        ));
    }
    let root_fp = hex::encode(Sha256::digest(root));
    if !pinned_roots
        .iter()
        .any(|fp| fp.trim().eq_ignore_ascii_case(&root_fp))
    {
        return Err(TpmVerifyError::Verify(
            "ek_ca_chain root fingerprint is not pinned".into(),
        ));
    }
    Ok(())
}

fn verify_activation_proof(
    bundle: &TpmClientBundle,
    ek_der: &[u8],
    ak_der: &[u8],
    expected_binding: &[u8; 32],
    options: &TpmVerifierOptions,
) -> Result<(), TpmVerifyError> {
    let activation = bundle
        .credential_activation
        .as_ref()
        .ok_or_else(|| TpmVerifyError::Verify("credential_activation proof is required".into()))?;
    let token = &activation.token;
    if token.version != 1 {
        return Err(TpmVerifyError::Verify(format!(
            "unsupported credential_activation token version {}",
            token.version
        )));
    }
    let now = options.now.unwrap_or_else(unix_now);
    if now > token.exp {
        return Err(TpmVerifyError::Verify(
            "credential_activation token expired".into(),
        ));
    }
    if !token
        .binding
        .trim()
        .eq_ignore_ascii_case(&hex::encode(expected_binding))
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation token binding mismatch".into(),
        ));
    }
    if !token
        .ek_cert_sha256
        .trim()
        .eq_ignore_ascii_case(&hex::encode(Sha256::digest(ek_der)))
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation token EK certificate mismatch".into(),
        ));
    }
    if !token
        .ak_cert_sha256
        .trim()
        .eq_ignore_ascii_case(&hex::encode(Sha256::digest(ak_der)))
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation token AK certificate mismatch".into(),
        ));
    }
    if bundle.ak_name.trim().is_empty()
        || !token
            .ak_name
            .trim()
            .eq_ignore_ascii_case(bundle.ak_name.trim())
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation token AK name mismatch".into(),
        ));
    }

    let secret = parse_required_hex(&activation.secret, "credential_activation.secret")?;
    if !token
        .secret_sha256
        .trim()
        .eq_ignore_ascii_case(&hex::encode(Sha256::digest(&secret)))
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation secret does not match token".into(),
        ));
    }

    let issuer_pubkey = parse_hex32(&token.issuer_pubkey, "credential_activation.issuer_pubkey")?;
    if !options
        .activation_pubkeys
        .iter()
        .any(|pk| pk == &issuer_pubkey)
    {
        return Err(TpmVerifyError::Verify(
            "credential_activation issuer is not trusted".into(),
        ));
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&issuer_pubkey)
        .map_err(|e| TpmVerifyError::Parse(format!("activation issuer pubkey: {e}")))?;
    let sig_bytes = parse_required_hex(&token.sig, "credential_activation.sig")?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TpmVerifyError::Parse("credential_activation.sig must be 64 bytes".into()))?;
    let sig = Ed25519Signature::from_bytes(&sig_array);
    vk.verify(&token.signed_bytes(), &sig).map_err(|e| {
        TpmVerifyError::Verify(format!("credential_activation token signature: {e}"))
    })?;

    Ok(())
}

/// Parsed, hardware-signed contents of a TPM quote we care about.
struct ParsedQuote {
    extra_data: Vec<u8>,
    /// Selected PCR indices per bank: (hashAlg, sorted indices).
    selections: Vec<(u16, Vec<u32>)>,
    pcr_digest: Vec<u8>,
}

/// Parse a TPM2B_ATTEST blob (TPMS_ATTEST of type `TPM_ST_ATTEST_QUOTE`).
fn parse_quote(quote_msg: &[u8]) -> Result<ParsedQuote, TpmVerifyError> {
    let attest = read_tpm2b(quote_msg, 0)?.0;
    let mut off = 0usize;

    let magic = read_u32(&attest, &mut off)?;
    if magic != TPM_GENERATED_VALUE {
        return Err(TpmVerifyError::Verify(format!(
            "bad TPM_GENERATED magic 0x{magic:08x}"
        )));
    }
    let typ = read_u16(&attest, &mut off)?;
    if typ != TPM_ST_ATTEST_QUOTE {
        return Err(TpmVerifyError::Verify(format!(
            "not a quote attestation (type 0x{typ:04x})"
        )));
    }

    // qualifiedSigner (TPM2B_NAME) — skip.
    let (_, next) = read_tpm2b(&attest, off)?;
    off = next;
    // extraData (TPM2B_DATA) — the channel binding.
    let (extra_data, next) = read_tpm2b(&attest, off)?;
    off = next;

    // clockInfo (TPMS_CLOCK_INFO = 8+4+4+1) + firmwareVersion (8).
    skip(&attest, &mut off, 17 + 8)?;

    // TPMS_QUOTE_INFO: pcrSelect (TPML_PCR_SELECTION) + pcrDigest (TPM2B_DIGEST).
    let count = read_u32(&attest, &mut off)? as usize;
    let mut selections = Vec::with_capacity(count);
    for _ in 0..count {
        let hash_alg = read_u16(&attest, &mut off)?;
        let size_of_select = read_u8(&attest, &mut off)? as usize;
        let bitmap = read_bytes(&attest, &mut off, size_of_select)?;
        selections.push((hash_alg, pcr_indices_from_bitmap(bitmap)));
    }
    let (pcr_digest, _) = read_tpm2b(&attest, off)?;

    Ok(ParsedQuote {
        extra_data,
        selections,
        pcr_digest,
    })
}

/// Verify the quote's pcrDigest is the sha256 over the reported sha256-bank PCRs
/// in ascending index order. Binds the hardware-signed quote to `pcrs`.
fn verify_pcr_digest(
    quote: &ParsedQuote,
    pcrs: &BTreeMap<u32, [u8; 32]>,
) -> Result<(), TpmVerifyError> {
    let indices = quote
        .selections
        .iter()
        .find(|(alg, _)| *alg == TPM_ALG_SHA256)
        .map(|(_, idx)| idx.clone())
        .ok_or_else(|| TpmVerifyError::Verify("quote has no sha256 PCR selection".into()))?;

    let mut h = Sha256::new();
    for idx in &indices {
        let v = pcrs
            .get(idx)
            .ok_or_else(|| TpmVerifyError::Verify(format!("selected PCR {idx} not reported")))?;
        h.update(v);
    }
    let computed: [u8; 32] = h.finalize().into();
    if computed.as_slice() != quote.pcr_digest.as_slice() {
        return Err(TpmVerifyError::Verify(
            "reported PCRs do not match the quote's pcrDigest".into(),
        ));
    }
    Ok(())
}

/// Replay the IMA `ascii_runtime_measurements` log into PCR 10:
/// `PCR = sha256(PCR || template_hash)` for each entry, starting from zero.
fn replay_ima_pcr10(ima_log: &str) -> Result<[u8; 32], TpmVerifyError> {
    let mut pcr = [0u8; 32];
    for line in ima_log.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let tmpl_hex = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| TpmVerifyError::Parse("IMA line missing template hash".into()))?;
        let tmpl = hex::decode(tmpl_hex)
            .map_err(|e| TpmVerifyError::Parse(format!("IMA template hash hex: {e}")))?;
        if tmpl.len() != 32 {
            return Err(TpmVerifyError::Verify(
                "IMA template hash is not sha256 (use ima_template=ima-ng ima_hash=sha256)".into(),
            ));
        }
        let mut h = Sha256::new();
        h.update(pcr);
        h.update(&tmpl);
        pcr = h.finalize().into();
    }
    Ok(pcr)
}

/// True if `build_digest` appears as a measured file-data hash (the
/// `sha256:<hex>` column) in the IMA log.
fn ima_contains_filehash(ima_log: &str, build_digest: &[u8; 32]) -> bool {
    let want = hex::encode(build_digest);
    for line in ima_log.lines() {
        for field in line.split_whitespace() {
            if let Some(h) = field.strip_prefix("sha256:") {
                if h.eq_ignore_ascii_case(&want) {
                    return true;
                }
            }
        }
    }
    false
}

/// sha256 over PCR 0-9 (in order): a known-good-boot fingerprint.
fn boot_aggregate_over_0_9(pcrs: &BTreeMap<u32, [u8; 32]>) -> Result<[u8; 32], TpmVerifyError> {
    let mut h = Sha256::new();
    for idx in 0u32..=9 {
        let v = pcrs.get(&idx).ok_or_else(|| {
            TpmVerifyError::Verify(format!(
                "PCR {idx} required for boot aggregate but not reported"
            ))
        })?;
        h.update(v);
    }
    Ok(h.finalize().into())
}

fn parse_pcrs(pcrs: &[PcrValue]) -> Result<BTreeMap<u32, [u8; 32]>, TpmVerifyError> {
    let mut map = BTreeMap::new();
    for p in pcrs {
        let v = parse_hex32(&p.value, "pcr value")?;
        map.insert(p.index, v);
    }
    Ok(map)
}

fn pcr_indices_from_bitmap(bitmap: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    for (byte_idx, b) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if b & (1 << bit) != 0 {
                out.push((byte_idx * 8 + bit) as u32);
            }
        }
    }
    out.sort_unstable();
    out
}

fn verify_quote_signature(
    ak: &Certificate,
    quote_msg: &[u8],
    quote_sig: &[u8],
) -> Result<(), TpmVerifyError> {
    if quote_sig.len() < 2 {
        return Err(TpmVerifyError::Parse("quote_sig too short".into()));
    }
    let alg = u16::from_be_bytes([quote_sig[0], quote_sig[1]]);
    let body = &quote_sig[2..];
    let spki = ak
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    match alg {
        TPM_ALG_ECDSA => verify_ecdsa_quote(spki, quote_msg, body)?,
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS => verify_rsa_quote(spki, quote_msg, alg, body)?,
        other => {
            return Err(TpmVerifyError::Verify(format!(
                "unsupported TPM quote signature alg 0x{other:04x}"
            )))
        }
    }
    Ok(())
}

fn verify_ecdsa_quote(
    spki: &[u8],
    quote_msg: &[u8],
    sig_body: &[u8],
) -> Result<(), TpmVerifyError> {
    let sig = parse_tpm_ecc_signature(sig_body)?;
    let digest = digest_for_hash_alg(sig.hash_alg, quote_msg)?;

    if let Ok(vk) = P256Vk::from_sec1_bytes(spki) {
        let raw = raw_ecdsa_signature(&sig.r, &sig.s, 32, "p256")?;
        let sig = P256Sig::from_slice(&raw)
            .map_err(|e| TpmVerifyError::Parse(format!("p256 sig: {e}")))?;
        vk.verify_prehash(&digest, &sig)
            .map_err(|e| TpmVerifyError::Verify(format!("p256 quote sig: {e}")))?;
        return Ok(());
    }
    if let Ok(vk) = P384Vk::from_sec1_bytes(spki) {
        let raw = raw_ecdsa_signature(&sig.r, &sig.s, 48, "p384")?;
        let sig = P384Sig::from_slice(&raw)
            .map_err(|e| TpmVerifyError::Parse(format!("p384 sig: {e}")))?;
        vk.verify_prehash(&digest, &sig)
            .map_err(|e| TpmVerifyError::Verify(format!("p384 quote sig: {e}")))?;
        return Ok(());
    }
    Err(TpmVerifyError::Verify(
        "AK public key is not P-256 or P-384 ECDSA".into(),
    ))
}

fn verify_rsa_quote(
    spki: &[u8],
    quote_msg: &[u8],
    sig_alg: u16,
    sig_body: &[u8],
) -> Result<(), TpmVerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::SignatureScheme;

    let sig = parse_tpm_rsa_signature(sig_body)?;
    let digest = digest_for_hash_alg(sig.hash_alg, quote_msg)?;
    let pk = rsa::RsaPublicKey::from_pkcs1_der(spki)
        .map_err(|e| TpmVerifyError::Parse(format!("rsa ak: {e}")))?;

    match sig_alg {
        TPM_ALG_RSASSA => {
            pkcs1v15_scheme(sig.hash_alg)?
                .verify(&pk, &digest, &sig.sig)
                .map_err(|e| TpmVerifyError::Verify(format!("rsa rsassa quote sig: {e}")))?;
        }
        TPM_ALG_RSAPSS => verify_rsapss_quote(pk, sig.hash_alg, &digest, &sig.sig)?,
        _ => unreachable!("unsupported RSA signature algorithm was filtered by caller"),
    }
    Ok(())
}

fn verify_rsapss_quote(
    pk: rsa::RsaPublicKey,
    hash_alg: u16,
    digest: &[u8],
    sig_bytes: &[u8],
) -> Result<(), TpmVerifyError> {
    use rsa::pss::{Signature, VerifyingKey};

    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| TpmVerifyError::Parse(format!("rsa pss sig: {e}")))?;
    match hash_alg {
        TPM_ALG_SHA256 => {
            let vk = VerifyingKey::<Sha256>::new(pk);
            vk.verify_prehash(digest, &sig)
                .map_err(|e| TpmVerifyError::Verify(format!("rsa pss sha256 quote sig: {e}")))?;
        }
        TPM_ALG_SHA384 => {
            let vk = VerifyingKey::<Sha384>::new(pk);
            vk.verify_prehash(digest, &sig)
                .map_err(|e| TpmVerifyError::Verify(format!("rsa pss sha384 quote sig: {e}")))?;
        }
        other => {
            return Err(TpmVerifyError::Verify(format!(
                "unsupported TPM quote hash alg 0x{other:04x}"
            )))
        }
    }
    Ok(())
}

struct TpmEccSignature {
    hash_alg: u16,
    r: Vec<u8>,
    s: Vec<u8>,
}

struct TpmRsaSignature {
    hash_alg: u16,
    sig: Vec<u8>,
}

fn parse_tpm_ecc_signature(body: &[u8]) -> Result<TpmEccSignature, TpmVerifyError> {
    let mut off = 0usize;
    let hash_alg = read_u16(body, &mut off)?;
    let (r, next) = read_tpm2b(body, off)?;
    off = next;
    let (s, _) = read_tpm2b(body, off)?;
    Ok(TpmEccSignature { hash_alg, r, s })
}

fn parse_tpm_rsa_signature(body: &[u8]) -> Result<TpmRsaSignature, TpmVerifyError> {
    let mut off = 0usize;
    let hash_alg = read_u16(body, &mut off)?;
    let (sig, _) = read_tpm2b(body, off)?;
    Ok(TpmRsaSignature { hash_alg, sig })
}

fn digest_for_hash_alg(hash_alg: u16, msg: &[u8]) -> Result<Vec<u8>, TpmVerifyError> {
    match hash_alg {
        TPM_ALG_SHA256 => Ok(Sha256::digest(msg).to_vec()),
        TPM_ALG_SHA384 => Ok(Sha384::digest(msg).to_vec()),
        other => Err(TpmVerifyError::Verify(format!(
            "unsupported TPM quote hash alg 0x{other:04x}"
        ))),
    }
}

fn raw_ecdsa_signature(
    r: &[u8],
    s: &[u8],
    width: usize,
    curve: &str,
) -> Result<Vec<u8>, TpmVerifyError> {
    let r = fixed_width_component(r, width, &format!("{curve} r"))?;
    let s = fixed_width_component(s, width, &format!("{curve} s"))?;
    let mut raw = Vec::with_capacity(width * 2);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    Ok(raw)
}

fn fixed_width_component(v: &[u8], width: usize, field: &str) -> Result<Vec<u8>, TpmVerifyError> {
    let mut significant = v;
    if significant.len() > width {
        let first_nonzero = significant
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(significant.len());
        significant = &significant[first_nonzero..];
    }
    if significant.len() > width {
        return Err(TpmVerifyError::Parse(format!(
            "{field} is wider than {width} bytes"
        )));
    }
    let mut out = vec![0u8; width];
    out[width - significant.len()..].copy_from_slice(significant);
    Ok(out)
}

fn pkcs1v15_scheme(hash_alg: u16) -> Result<rsa::Pkcs1v15Sign, TpmVerifyError> {
    const SHA256_DIGESTINFO: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_DIGESTINFO: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];

    match hash_alg {
        TPM_ALG_SHA256 => Ok(rsa::Pkcs1v15Sign {
            hash_len: Some(32),
            prefix: SHA256_DIGESTINFO.into(),
        }),
        TPM_ALG_SHA384 => Ok(rsa::Pkcs1v15Sign {
            hash_len: Some(48),
            prefix: SHA384_DIGESTINFO.into(),
        }),
        other => Err(TpmVerifyError::Verify(format!(
            "unsupported TPM quote hash alg 0x{other:04x}"
        ))),
    }
}

fn verify_cert_sig(issuer_der: &[u8], subject_der: &[u8]) -> Result<bool, TpmVerifyError> {
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| TpmVerifyError::Parse(format!("issuer cert: {e}")))?;
    let subject = Certificate::from_der(subject_der)
        .map_err(|e| TpmVerifyError::Parse(format!("subject cert: {e}")))?;
    let issuer_pk = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| TpmVerifyError::Parse(format!("subject tbs: {e}")))?;
    let sig_bytes = subject.signature.raw_bytes();
    let sig_alg = subject.signature_algorithm.oid.to_string();

    match sig_alg.as_str() {
        // ecdsa-with-SHA256
        "1.2.840.10045.4.3.2" => verify_cert_ecdsa_p256(issuer_pk, &tbs_der, sig_bytes),
        // ecdsa-with-SHA384
        "1.2.840.10045.4.3.3" => verify_cert_ecdsa_p384(issuer_pk, &tbs_der, sig_bytes),
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => {
            verify_cert_rsa_pkcs1(issuer_pk, TPM_ALG_SHA256, &tbs_der, sig_bytes)
        }
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => {
            verify_cert_rsa_pkcs1(issuer_pk, TPM_ALG_SHA384, &tbs_der, sig_bytes)
        }
        // rsassaPss. TPM vendor certs commonly use SHA-256 or SHA-384; this
        // parser does not inspect the ASN.1 PSS params yet, so try both hash
        // profiles and accept only a real signature match.
        "1.2.840.113549.1.1.10" => {
            verify_cert_rsa_pss(issuer_pk, &tbs_der, sig_bytes, TPM_ALG_SHA256)
                .or_else(|_| verify_cert_rsa_pss(issuer_pk, &tbs_der, sig_bytes, TPM_ALG_SHA384))
        }
        other => Err(TpmVerifyError::Verify(format!(
            "unsupported cert signature algorithm OID {other}"
        ))),
    }
}

fn verify_cert_ecdsa_p256(
    issuer_pk: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, TpmVerifyError> {
    let vk = P256Vk::from_sec1_bytes(issuer_pk)
        .map_err(|e| TpmVerifyError::Parse(format!("issuer P-256 key: {e}")))?;
    let sig = p256::ecdsa::DerSignature::from_bytes(sig_bytes)
        .map_err(|e| TpmVerifyError::Parse(format!("cert sig: {e}")))?;
    let digest = Sha256::digest(tbs_der);
    Ok(vk.verify_prehash(&digest, &sig).is_ok())
}

fn verify_cert_ecdsa_p384(
    issuer_pk: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, TpmVerifyError> {
    let vk = P384Vk::from_sec1_bytes(issuer_pk)
        .map_err(|e| TpmVerifyError::Parse(format!("issuer P-384 key: {e}")))?;
    let sig = p384::ecdsa::DerSignature::from_bytes(sig_bytes)
        .map_err(|e| TpmVerifyError::Parse(format!("cert sig: {e}")))?;
    let digest = Sha384::digest(tbs_der);
    Ok(vk.verify_prehash(&digest, &sig).is_ok())
}

fn verify_cert_rsa_pkcs1(
    issuer_pk: &[u8],
    hash_alg: u16,
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, TpmVerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::SignatureScheme;

    let pk = rsa::RsaPublicKey::from_pkcs1_der(issuer_pk)
        .map_err(|e| TpmVerifyError::Parse(format!("issuer RSA key: {e}")))?;
    let digest = digest_for_hash_alg(hash_alg, tbs_der)?;
    Ok(pkcs1v15_scheme(hash_alg)?
        .verify(&pk, &digest, sig_bytes)
        .is_ok())
}

fn verify_cert_rsa_pss(
    issuer_pk: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
    hash_alg: u16,
) -> Result<bool, TpmVerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};

    let pk = rsa::RsaPublicKey::from_pkcs1_der(issuer_pk)
        .map_err(|e| TpmVerifyError::Parse(format!("issuer RSA key: {e}")))?;
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| TpmVerifyError::Parse(format!("rsa pss cert sig: {e}")))?;
    match hash_alg {
        TPM_ALG_SHA256 => {
            let vk = VerifyingKey::<Sha256>::new(pk);
            Ok(vk.verify_prehash(&Sha256::digest(tbs_der), &sig).is_ok())
        }
        TPM_ALG_SHA384 => {
            let vk = VerifyingKey::<Sha384>::new(pk);
            Ok(vk.verify_prehash(&Sha384::digest(tbs_der), &sig).is_ok())
        }
        _ => unreachable!("unsupported hash alg passed by caller"),
    }
}

fn read_tpm2b(buf: &[u8], mut off: usize) -> Result<(Vec<u8>, usize), TpmVerifyError> {
    if off + 2 > buf.len() {
        return Err(TpmVerifyError::Parse("truncated TPM2B".into()));
    }
    let sz = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2;
    if off + sz > buf.len() {
        return Err(TpmVerifyError::Parse("truncated TPM2B payload".into()));
    }
    Ok((buf[off..off + sz].to_vec(), off + sz))
}

fn read_u8(buf: &[u8], off: &mut usize) -> Result<u8, TpmVerifyError> {
    let b = *buf
        .get(*off)
        .ok_or_else(|| TpmVerifyError::Parse("truncated u8".into()))?;
    *off += 1;
    Ok(b)
}

fn read_u16(buf: &[u8], off: &mut usize) -> Result<u16, TpmVerifyError> {
    let b = read_bytes(buf, off, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], off: &mut usize) -> Result<u32, TpmVerifyError> {
    let b = read_bytes(buf, off, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], TpmVerifyError> {
    if *off + n > buf.len() {
        return Err(TpmVerifyError::Parse("truncated field".into()));
    }
    let s = &buf[*off..*off + n];
    *off += n;
    Ok(s)
}

fn skip(buf: &[u8], off: &mut usize, n: usize) -> Result<(), TpmVerifyError> {
    read_bytes(buf, off, n).map(|_| ())
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], TpmVerifyError> {
    let v = parse_hex(s, field)?;
    v.as_slice()
        .try_into()
        .map_err(|_| TpmVerifyError::Parse(format!("{field} must be 32 bytes")))
}

fn parse_hex(s: &str, field: &str) -> Result<Vec<u8>, TpmVerifyError> {
    hex::decode(s.trim()).map_err(|e| TpmVerifyError::Parse(format!("{field}: {e}")))
}

fn parse_required_hex(s: &str, field: &str) -> Result<Vec<u8>, TpmVerifyError> {
    if s.trim().is_empty() {
        return Err(TpmVerifyError::Verify(format!("{field} is required")));
    }
    parse_hex(s, field)
}

fn decode_hex_chain(hex_certs: &[String], field: &str) -> Result<Vec<Vec<u8>>, TpmVerifyError> {
    hex_certs
        .iter()
        .enumerate()
        .map(|(i, h)| parse_required_hex(h, &format!("{field}[{i}]")))
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpm2b(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn rejects_binding_mismatch() {
        let bundle = TpmClientBundle {
            version: 1,
            platform: LINUX_TPM_PLATFORM.into(),
            binding: hex::encode([1u8; 32]),
            build_digest: hex::encode([0u8; 32]),
            ak_cert: String::new(),
            ek_cert: String::new(),
            ek_ca_chain: Vec::new(),
            ak_name: String::new(),
            credential_activation: None,
            quote_msg: String::new(),
            quote_sig: String::new(),
            qualifying_data: hex::encode([1u8; 32]),
            pcr_bank: String::new(),
            pcrs: Vec::new(),
            ima_log: String::new(),
        };
        let err = verify_bundle(&bundle, &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("binding"));
    }

    #[test]
    fn ima_replay_extends_pcr10() {
        // Two synthetic sha256 template hashes; PCR10 = H(H(0||t0)||t1).
        let t0 = [0xAAu8; 32];
        let t1 = [0xBBu8; 32];
        let log = format!(
            "10 {} ima-ng sha256:{} boot_aggregate\n10 {} ima-ng sha256:{} /usr/bin/agent\n",
            hex::encode(t0),
            hex::encode([0u8; 32]),
            hex::encode(t1),
            hex::encode([0u8; 32])
        );
        let mut pcr = [0u8; 32];
        for t in [t0, t1] {
            let mut h = Sha256::new();
            h.update(pcr);
            h.update(t);
            pcr = h.finalize().into();
        }
        assert_eq!(replay_ima_pcr10(&log).unwrap(), pcr);
    }

    #[test]
    fn ima_finds_measured_binary() {
        let digest = [0x11u8; 32];
        let log = format!(
            "10 {} ima-ng sha256:{} /usr/bin/agent\n",
            hex::encode([0u8; 32]),
            hex::encode(digest)
        );
        assert!(ima_contains_filehash(&log, &digest));
        assert!(!ima_contains_filehash(&log, &[0x22u8; 32]));
    }

    #[test]
    fn pcr_bitmap_decodes_indices() {
        // byte0 bits 0,8? bitmap is per-byte; byte0=0b0000_0101 -> PCR0, PCR2.
        assert_eq!(pcr_indices_from_bitmap(&[0b0000_0101]), vec![0, 2]);
        // byte1 bit 2 -> PCR 10.
        assert_eq!(pcr_indices_from_bitmap(&[0x00, 0b0000_0100]), vec![10]);
    }

    #[test]
    fn parse_tpm_ecc_signature_consumes_hash_alg() {
        let mut body = TPM_ALG_SHA256.to_be_bytes().to_vec();
        body.extend_from_slice(&tpm2b(&[0x11; 32]));
        body.extend_from_slice(&tpm2b(&[0x22; 32]));

        let sig = parse_tpm_ecc_signature(&body).unwrap();

        assert_eq!(sig.hash_alg, TPM_ALG_SHA256);
        assert_eq!(sig.r, vec![0x11; 32]);
        assert_eq!(sig.s, vec![0x22; 32]);
    }

    #[test]
    fn parse_tpm_rsa_signature_consumes_hash_alg() {
        let mut body = TPM_ALG_SHA384.to_be_bytes().to_vec();
        body.extend_from_slice(&tpm2b(&[0xA5; 256]));

        let sig = parse_tpm_rsa_signature(&body).unwrap();

        assert_eq!(sig.hash_alg, TPM_ALG_SHA384);
        assert_eq!(sig.sig, vec![0xA5; 256]);
    }

    #[test]
    fn verify_ecdsa_quote_accepts_tpm_signature_with_hash_alg() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let quote_msg = b"synthetic TPMS_ATTEST bytes";
        let digest = Sha256::digest(quote_msg);
        let signature: P256Sig = sk.sign_prehash(&digest).unwrap();
        let raw = signature.to_bytes();

        let mut body = TPM_ALG_SHA256.to_be_bytes().to_vec();
        body.extend_from_slice(&tpm2b(&raw[..32]));
        body.extend_from_slice(&tpm2b(&raw[32..]));

        let public_key = sk.verifying_key().to_encoded_point(false);
        verify_ecdsa_quote(public_key.as_bytes(), quote_msg, &body).unwrap();
    }

    #[test]
    fn verifies_signed_activation_token() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let issuer_pubkey = sk.verifying_key().to_bytes();
        let binding = [9u8; 32];
        let ek_der = b"synthetic ek cert der";
        let ak_der = b"synthetic ak cert der";
        let secret = b"activated secret";
        let ak_name = "000b".to_string() + &hex::encode([0xA5u8; 32]);

        let mut token = TpmActivationToken {
            version: 1,
            exp: 2_000,
            nonce: hex::encode([0x11u8; 32]),
            binding: hex::encode(binding),
            ek_cert_sha256: hex::encode(Sha256::digest(ek_der)),
            ak_cert_sha256: hex::encode(Sha256::digest(ak_der)),
            ak_name: ak_name.clone(),
            secret_sha256: hex::encode(Sha256::digest(secret)),
            issuer_pubkey: hex::encode(issuer_pubkey),
            sig: String::new(),
        };
        token.sig = hex::encode(sk.sign(&token.signed_bytes()).to_bytes());

        let bundle = TpmClientBundle {
            version: 1,
            platform: LINUX_TPM_PLATFORM.into(),
            binding: hex::encode(binding),
            build_digest: hex::encode([0u8; 32]),
            ak_cert: hex::encode(ak_der),
            ek_cert: hex::encode(ek_der),
            ek_ca_chain: Vec::new(),
            ak_name,
            credential_activation: Some(TpmCredentialActivation {
                token,
                secret: hex::encode(secret),
            }),
            quote_msg: String::new(),
            quote_sig: String::new(),
            qualifying_data: hex::encode(binding),
            pcr_bank: String::new(),
            pcrs: Vec::new(),
            ima_log: String::new(),
        };
        let options = TpmVerifierOptions {
            ek_root_sha256: Vec::new(),
            activation_pubkeys: vec![issuer_pubkey],
            now: Some(1_000),
        };

        verify_activation_proof(&bundle, ek_der, ak_der, &binding, &options).unwrap();
    }

    #[test]
    fn rejects_partial_ima_mode() {
        // pcrs present but ima_log empty -> rejected before crypto.
        let bundle = TpmClientBundle {
            version: 1,
            platform: LINUX_TPM_PLATFORM.into(),
            binding: hex::encode([7u8; 32]),
            build_digest: hex::encode([0u8; 32]),
            ak_cert: String::new(),
            ek_cert: String::new(),
            ek_ca_chain: Vec::new(),
            ak_name: String::new(),
            credential_activation: None,
            quote_msg: String::new(),
            quote_sig: String::new(),
            qualifying_data: hex::encode([7u8; 32]),
            pcr_bank: "sha256".into(),
            pcrs: vec![PcrValue {
                index: 10,
                value: hex::encode([0u8; 32]),
            }],
            ima_log: String::new(),
        };
        // Fails earlier at quote parse (empty quote_msg) — the point is it does
        // not silently accept a partial IMA bundle; any error is acceptable.
        assert!(verify_bundle(&bundle, &[7u8; 32]).is_err());
    }
}
