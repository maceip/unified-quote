//! Registry of approved Value X entries.
//!
//! A registry entry says: "this Value X has been reviewed and is approved
//! for some status (recommended / deprecated / revoked)." Entries live as
//! JSON files in a `registry/` directory — same-repo today.
//!
//! ## Trust roots
//!
//! Entries are signed. There is no single global signer — this is not
//! a CI-only system. A `TrustRoot` is a configuration that says "these
//! signer identities are trusted." Our own project ships with a default
//! `TrustRoot` pointing at our GitHub workflow, but a downstream user
//! (e.g., a JS developer running their webserver in a TEE) configures
//! their own `TrustRoot` that trusts their signer. The registry format
//! does not change; only the set of accepted identities does.
//!
//! ## Signature sidecars
//!
//! Each `<entry>.json` may carry a detached signature sidecar
//! `<entry>.json.sig`. Two on-disk forms are accepted:
//!
//! - A JSON object `{ "alg": "ed25519"|"ecdsa-p256"|"sigstore",
//!   "sig": "<base64 detached signature over the exact json bytes>",
//!   "cert": "<PEM leaf>" }` (`cert` required for `sigstore`).
//! - A bare base64 detached signature (tried against every
//!   [`TrustedIdentity::RawPublicKey`] in the trust root).
//!
//! Verification is real: a `RawPublicKey` identity verifies the detached
//! signature over the file bytes with the pinned SPKI; a `SigstoreKeyless`
//! identity verifies the signature with the leaf certificate's key and then
//! binds the certificate's SAN URI + Fulcio OIDC-issuer extension to the
//! pinned `(issuer, subject_pattern)`. The on-disk format is stable: swapping
//! or extending the verifier (e.g. adding Rekor inclusion) does not require a
//! migration.
//!
//! See `v2/registry/README.md` for the schema and trust model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Recommended,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformMeasurements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_pcr0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_mrtd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp_measurement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub value_x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub platform_measurements: PlatformMeasurements,
    pub status: Status,
    pub approved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Result of looking up a Value X in the registry.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// Entry found. `signature` reports whether a sidecar verified against
    /// the trust root.
    Found {
        entry: Entry,
        signature: SignatureState,
    },
    /// Value X is not in the registry at all.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    /// Sidecar present and signature valid against a pinned trusted identity.
    Verified,
    /// Sidecar present but no trusted identity verified it (bad signature,
    /// unknown signer, or an empty trust root). NOT trustworthy.
    Untrusted,
    /// Sidecar missing.
    Missing,
}

/// A signed, timestamped snapshot of the whole registry (R.2).
///
/// Per-entry signatures answer "is this entry authentic?" but say nothing about
/// freshness: a relying party that only ever sees a stale mirror would never
/// observe a later `Revoked` flip. The snapshot is the CRL/OCSP-equivalent — a
/// single object covering every entry, signed and time-bounded, so acceptance
/// can bind to a *fresh* view and revocation propagates with a bounded lag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot schema version.
    pub version: u32,
    /// Unix seconds when this snapshot was generated.
    pub generated_at: u64,
    /// Unix seconds after which this snapshot MUST NOT be trusted. A relying
    /// party past this point must refetch — the equivalent of a CRL nextUpdate.
    pub expires_at: u64,
    /// Every known value_x and its authoritative status at snapshot time.
    pub entries: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub value_x: String,
    pub status: Status,
}

impl Snapshot {
    fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Authoritative status for `value_x` per this snapshot, if listed.
    pub fn status_of(&self, value_x: &str) -> Option<Status> {
        self.entries
            .iter()
            .find(|e| e.value_x == value_x)
            .map(|e| e.status)
    }
}

/// Trust + freshness verdict for the registry snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    /// Signed by a trusted identity and within its validity window.
    Fresh,
    /// Signed by a trusted identity but past `expires_at` — refetch required.
    Expired,
    /// Present but no trusted identity verified its signature.
    Untrusted,
    /// No snapshot shipped alongside the registry.
    Missing,
}

/// Identity of a trusted signer. Describes *who* is allowed to sign
/// registry entries for a given consumer of the registry. Having this
/// as data (not a hardcoded constant) is the hinge that keeps the
/// system from collapsing into "GitHub CI only."
#[derive(Debug, Clone)]
pub enum TrustedIdentity {
    /// Sigstore keyless signer, pinned by Fulcio cert subject.
    /// Matches any workflow identity matching (issuer, subject_pattern).
    /// `subject_pattern` is a glob — e.g.,
    ///   `https://github.com/maceip/uq-runner/.github/workflows/registry-sign.yml@refs/heads/main`
    /// or a looser match for downstream users.
    SigstoreKeyless {
        issuer: String,
        subject_pattern: String,
    },
    /// Raw public key (ed25519 or ecdsa). For offline / YubiKey signers
    /// who don't want GitHub or Sigstore in their trust chain.
    RawPublicKey {
        algorithm: String, // "ed25519" | "ecdsa-p256"
        spki_der: Vec<u8>,
        label: String, // human-readable, shown on verify
    },
}

/// A set of trusted identities. An entry is accepted if *any* identity
/// in the trust root successfully verifies its signature. The set can
/// be empty — in which case the registry is informational only and
/// every entry comes back as `SignatureState::Missing`.
#[derive(Debug, Clone, Default)]
pub struct TrustRoot {
    pub identities: Vec<TrustedIdentity>,
}

impl TrustRoot {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with(mut self, id: TrustedIdentity) -> Self {
        self.identities.push(id);
        self
    }

    /// The project's own default trust root: our GitHub workflow signing
    /// via Sigstore keyless. Downstream users should NOT use this — they
    /// should build their own `TrustRoot` pointing at their own signers.
    /// This exists so `uq check` of our own runner works out of
    /// the box without a config file.
    pub fn uq_default() -> Self {
        Self::empty().with(TrustedIdentity::SigstoreKeyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject_pattern:
                "https://github.com/maceip/uq-runner/.github/workflows/registry-sign.yml@refs/heads/main"
                    .to_string(),
        })
    }
}

pub struct Registry {
    entries: HashMap<String, (Entry, SignatureState)>,
    trust_root: TrustRoot,
    snapshot: Option<Snapshot>,
    snapshot_state: SnapshotState,
}

impl Registry {
    /// Load every `*.json` in the given directory as a registry entry.
    /// Files named `README.md` or `*.sig` are skipped. Signatures are
    /// checked against the provided `trust_root`.
    pub fn load(dir: &Path, trust_root: TrustRoot) -> anyhow::Result<Self> {
        let mut entries = HashMap::new();
        if !dir.exists() {
            return Ok(Self {
                entries,
                trust_root,
                snapshot: None,
                snapshot_state: SnapshotState::Missing,
            });
        }
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            // One malformed file must not sink the whole registry: skip files
            // that aren't valid UTF-8 JSON (e.g. a stray binary), reporting each,
            // rather than failing the entire load.
            let body = match std::fs::read(&path)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            {
                Some(s) => s,
                None => {
                    eprintln!(
                        "[uq] Registry: skipping {} (not valid UTF-8)",
                        path.display()
                    );
                    continue;
                }
            };
            let entry: Entry = match serde_json::from_str(&body) {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("[uq] Registry: skipping {} ({err})", path.display());
                    continue;
                }
            };
            let sig_state = Self::check_sidecar(&path, &body, &trust_root)?;
            entries.insert(entry.value_x.clone(), (entry, sig_state));
        }
        let (snapshot, snapshot_state) = Self::load_snapshot(dir, &trust_root);
        Ok(Self {
            entries,
            trust_root,
            snapshot,
            snapshot_state,
        })
    }

    /// Load and verify `<dir>/snapshot.json` against `<dir>/snapshot.json.sig`.
    /// A snapshot is `Fresh` only when a trusted identity signs it AND it is
    /// within its validity window.
    fn load_snapshot(dir: &Path, trust_root: &TrustRoot) -> (Option<Snapshot>, SnapshotState) {
        let json_path = dir.join("snapshot.json");
        let body = match std::fs::read(&json_path) {
            Ok(b) => b,
            Err(_) => return (None, SnapshotState::Missing),
        };
        let snapshot: Snapshot = match serde_json::from_slice(&body) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[uq] Registry: snapshot.json unparseable ({e})");
                return (None, SnapshotState::Untrusted);
            }
        };
        let sig_path = dir.join("snapshot.json.sig");
        let verified = std::fs::read(&sig_path)
            .ok()
            .and_then(|raw| sigverify::Sidecar::parse(&raw))
            .map(|sc| {
                trust_root
                    .identities
                    .iter()
                    .any(|id| sigverify::verify_against(id, &body, &sc))
            })
            .unwrap_or(false);
        if !verified {
            return (Some(snapshot), SnapshotState::Untrusted);
        }
        let now = now_unix();
        let state = if snapshot.is_expired(now) {
            SnapshotState::Expired
        } else {
            SnapshotState::Fresh
        };
        (Some(snapshot), state)
    }

    /// Default load: look for the project's registry directory and use
    /// the project's default `TrustRoot`. This is the path
    /// `uq check` takes when no config is provided.
    pub fn load_default() -> anyhow::Result<Self> {
        let trust_root = TrustRoot::uq_default();
        let mut merged = Self {
            entries: HashMap::new(),
            trust_root: trust_root.clone(),
            snapshot: None,
            snapshot_state: SnapshotState::Missing,
        };

        for c in [PathBuf::from("v2/registry"), PathBuf::from("registry")] {
            if c.exists() && c.is_dir() {
                let loaded = Self::load(&c, trust_root.clone())?;
                merged.entries.extend(loaded.entries);
                // Adopt the first snapshot we find (Fresh preferred over a
                // weaker state we may already hold).
                if !matches!(loaded.snapshot_state, SnapshotState::Missing)
                    && matches!(merged.snapshot_state, SnapshotState::Missing)
                {
                    merged.snapshot = loaded.snapshot;
                    merged.snapshot_state = loaded.snapshot_state;
                }
            }
        }

        // v1 kept a root `registry.json` containing `{ entries: [...] }`.
        // Keep reading it during the v2 migration so the CLI reports the
        // same trust state the repository visibly publishes.
        for c in [PathBuf::from("registry.json")] {
            if c.exists() && c.is_file() {
                if let Err(e) = merged.load_legacy_registry_json(&c) {
                    eprintln!("[uq] Registry: skipping legacy {} ({e})", c.display());
                }
            }
        }

        Ok(merged)
    }

    pub fn lookup(&self, value_x_hex: &str) -> Lookup {
        match self.entries.get(value_x_hex) {
            Some((entry, sig)) => Lookup::Found {
                entry: entry.clone(),
                signature: *sig,
            },
            None => Lookup::Unknown,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    /// Trust + freshness verdict for the registry snapshot (R.2).
    pub fn snapshot_state(&self) -> SnapshotState {
        self.snapshot_state
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Authoritative status for `value_x`, preferring a *fresh, signed*
    /// snapshot over the per-entry files. Returns `None` when no fresh snapshot
    /// covers it (the caller then falls back to [`Self::lookup`]).
    ///
    /// This is what makes a later `Revoked` flip propagate: a relying party
    /// that requires `snapshot_state() == Fresh` cannot be pinned to a stale
    /// pre-revocation mirror.
    pub fn fresh_status(&self, value_x: &str) -> Option<Status> {
        if self.snapshot_state != SnapshotState::Fresh {
            return None;
        }
        self.snapshot.as_ref().and_then(|s| s.status_of(value_x))
    }

    fn check_sidecar(
        json_path: &Path,
        body: &str,
        trust_root: &TrustRoot,
    ) -> anyhow::Result<SignatureState> {
        let sig_path = {
            let mut p = json_path.as_os_str().to_owned();
            p.push(".sig");
            PathBuf::from(p)
        };
        if !sig_path.exists() {
            return Ok(SignatureState::Missing);
        }
        let raw = std::fs::read(&sig_path)?;
        let sidecar = match sigverify::Sidecar::parse(&raw) {
            Some(s) => s,
            None => {
                eprintln!(
                    "[uq] Registry: {} present but unparseable",
                    sig_path.display()
                );
                return Ok(SignatureState::Untrusted);
            }
        };
        // An entry is accepted if ANY identity in the trust root verifies it.
        for id in &trust_root.identities {
            if sigverify::verify_against(id, body.as_bytes(), &sidecar) {
                return Ok(SignatureState::Verified);
            }
        }
        Ok(SignatureState::Untrusted)
    }

    fn load_legacy_registry_json(&mut self, path: &Path) -> anyhow::Result<()> {
        let body = std::fs::read_to_string(path)?;
        let root: serde_json::Value = serde_json::from_str(&body)
            .map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))?;
        let entries = root
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("{}: missing entries array", path.display()))?;

        for raw in entries {
            let value_x = raw
                .get("value_x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("{}: entry missing value_x", path.display()))?
                .to_string();
            let deprecated = raw
                .get("deprecated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let recommended = raw
                .get("recommended")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let status = if deprecated {
                Status::Deprecated
            } else if recommended {
                Status::Recommended
            } else {
                Status::Revoked
            };
            let pm = raw
                .get("platform_measurements")
                .cloned()
                .unwrap_or_default();
            let entry = Entry {
                value_x: value_x.clone(),
                source_commit: raw
                    .get("source_commit")
                    .or_else(|| raw.get("git_commit"))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string),
                platform_measurements: PlatformMeasurements {
                    nitro_pcr0: pm
                        .get("nitro_pcr0")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                    tdx_mrtd: pm
                        .get("tdx_mrtd")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                    snp_measurement: pm
                        .get("snp_measurement")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                },
                status,
                approved_at: raw
                    .get("approved_at")
                    .or_else(|| raw.get("registered_at"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                deprecated_at: None,
                revoked_at: None,
                notes: raw
                    .get("notes")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };

            self.entries
                .entry(value_x)
                .or_insert((entry, SignatureState::Missing));
        }

        Ok(())
    }
}

/// Detached-signature sidecar verification.
///
/// Verification is fully offline. For `SigstoreKeyless` identities we bind the
/// leaf certificate's identity (SAN URI + Fulcio OIDC-issuer extension) to the
/// pinned `(issuer, subject_pattern)` and verify the detached signature with
/// the leaf key. Rekor transparency-log inclusion is an additional check that
/// can be layered on without changing the on-disk format (tracked as R.2).
mod sigverify {
    use super::TrustedIdentity;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use der::{Decode, Encode};
    use sha2::{Digest, Sha256};

    /// Parsed sidecar: a detached signature plus optional algorithm hint and a
    /// leaf certificate (PEM) for keyless identities.
    pub struct Sidecar {
        pub sig: Vec<u8>,
        pub alg: Option<String>,
        pub cert_pem: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct SidecarJson {
        #[serde(default)]
        alg: Option<String>,
        sig: String,
        #[serde(default)]
        cert: Option<String>,
    }

    impl Sidecar {
        /// Parse either the JSON object form or a bare base64 detached signature.
        pub fn parse(raw: &[u8]) -> Option<Self> {
            let text = std::str::from_utf8(raw).ok()?.trim();
            if text.starts_with('{') {
                let j: SidecarJson = serde_json::from_str(text).ok()?;
                let sig = B64.decode(j.sig.trim()).ok()?;
                return Some(Sidecar {
                    sig,
                    alg: j.alg,
                    cert_pem: j.cert,
                });
            }
            // Bare base64 detached signature.
            let sig = B64.decode(text).ok()?;
            Some(Sidecar {
                sig,
                alg: None,
                cert_pem: None,
            })
        }
    }

    /// Does `id` verify `sidecar` over `msg` (the exact entry json bytes)?
    pub fn verify_against(id: &TrustedIdentity, msg: &[u8], sidecar: &Sidecar) -> bool {
        match id {
            TrustedIdentity::RawPublicKey { spki_der, .. } => {
                verify_sig_with_spki(spki_der, msg, &sidecar.sig)
            }
            TrustedIdentity::SigstoreKeyless {
                issuer,
                subject_pattern,
            } => {
                let pem = match &sidecar.cert_pem {
                    Some(p) => p,
                    None => return false, // keyless requires a leaf cert
                };
                let der = match pem_to_der(pem) {
                    Some(d) => d,
                    None => return false,
                };
                let cert = match x509_cert::Certificate::from_der(&der) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                // 1. the leaf key must have produced the detached signature.
                let spki = match cert.tbs_certificate.subject_public_key_info.to_der() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                if !verify_sig_with_spki(&spki, msg, &sidecar.sig) {
                    return false;
                }
                // 2. the leaf identity must match the pinned signer.
                cert_identity_matches(&cert, issuer, subject_pattern)
            }
        }
    }

    /// Auto-detect the key type from the SPKI algorithm OID and verify a
    /// detached signature over `msg`. Supports ed25519 and ECDSA P-256
    /// (the two Fulcio/cosign + offline-signer cases we accept).
    fn verify_sig_with_spki(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let spki = match spki::SubjectPublicKeyInfoRef::from_der(spki_der) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let oid = spki.algorithm.oid.to_string();
        let key = match spki.subject_public_key.as_bytes() {
            Some(k) => k,
            None => return false,
        };
        match oid.as_str() {
            // id-Ed25519
            "1.3.101.112" => verify_ed25519(key, msg, sig),
            // id-ecPublicKey (assume P-256 — the curve cosign/Fulcio use)
            "1.2.840.10045.2.1" => verify_ecdsa_p256(key, msg, sig),
            _ => false,
        }
    }

    fn verify_ed25519(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key: [u8; 32] = match key.try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let vk = match VerifyingKey::from_bytes(&key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig: [u8; 64] = match sig.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
    }

    fn verify_ecdsa_p256(sec1_point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let vk = match VerifyingKey::from_sec1_bytes(sec1_point) {
            Ok(v) => v,
            Err(_) => return false,
        };
        // cosign emits ASN.1 DER signatures; accept fixed-length too.
        let parsed = Signature::from_der(sig).or_else(|_| Signature::from_slice(sig));
        match parsed {
            Ok(s) => vk.verify(msg, &s).is_ok(),
            Err(_) => false,
        }
    }

    /// PEM (`-----BEGIN CERTIFICATE-----`) to DER.
    fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
        let mut b64 = String::new();
        let mut in_block = false;
        for line in pem.lines() {
            let t = line.trim();
            if t.starts_with("-----BEGIN") {
                in_block = true;
                continue;
            }
            if t.starts_with("-----END") {
                break;
            }
            if in_block {
                b64.push_str(t);
            }
        }
        if b64.is_empty() {
            return None;
        }
        B64.decode(b64).ok()
    }

    /// Match a Fulcio leaf certificate against the pinned `(issuer,
    /// subject_pattern)`: the SAN URI must glob-match `subject_pattern`, and
    /// the OIDC issuer extension must equal `issuer`.
    fn cert_identity_matches(
        cert: &x509_cert::Certificate,
        issuer: &str,
        subject_pattern: &str,
    ) -> bool {
        let exts = match &cert.tbs_certificate.extensions {
            Some(e) => e,
            None => return false,
        };
        let mut san_ok = false;
        let mut issuer_ok = false;
        for ext in exts.iter() {
            match ext.extn_id.to_string().as_str() {
                // subjectAltName
                "2.5.29.17" => {
                    if let Ok(san) =
                        x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                    {
                        for gn in san.0.iter() {
                            if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                                uri,
                            ) = gn
                            {
                                if glob_match(subject_pattern, uri.as_str()) {
                                    san_ok = true;
                                }
                            }
                        }
                    }
                }
                // Fulcio OIDC issuer (v1: raw UTF-8 string)
                "1.3.6.1.4.1.57264.1.1" => {
                    if std::str::from_utf8(ext.extn_value.as_bytes())
                        .map(|s| s == issuer)
                        .unwrap_or(false)
                    {
                        issuer_ok = true;
                    }
                }
                // Fulcio OIDC issuer (v2: DER-encoded UTF8String)
                "1.3.6.1.4.1.57264.1.8" => {
                    if let Ok(s) = der::asn1::Utf8StringRef::from_der(ext.extn_value.as_bytes()) {
                        if s.as_str() == issuer {
                            issuer_ok = true;
                        }
                    }
                }
                _ => {}
            }
        }
        san_ok && issuer_ok
    }

    /// Minimal glob: `*` matches any run of characters (greedy with
    /// backtracking). No `?`/character-class support — registry signer
    /// patterns only ever use `*`.
    pub fn glob_match(pattern: &str, value: &str) -> bool {
        fn rec(p: &[u8], v: &[u8]) -> bool {
            if p.is_empty() {
                return v.is_empty();
            }
            if p[0] == b'*' {
                // collapse consecutive stars
                let mut i = 1;
                while i < p.len() && p[i] == b'*' {
                    i += 1;
                }
                let rest = &p[i..];
                if rest.is_empty() {
                    return true;
                }
                for k in 0..=v.len() {
                    if rec(rest, &v[k..]) {
                        return true;
                    }
                }
                false
            } else if !v.is_empty() && p[0] == v[0] {
                rec(&p[1..], &v[1..])
            } else {
                false
            }
        }
        rec(pattern.as_bytes(), value.as_bytes())
    }

    /// SPKI DER for an ed25519 raw public key (RFC 8410 prefix + key).
    #[cfg(test)]
    pub fn ed25519_spki(pubkey: &[u8; 32]) -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(pubkey);
        der
    }

    /// SHA-256 over a sidecar's referenced bytes, exposed so the registry can
    /// expose a stable digest if needed.
    #[allow(dead_code)]
    pub fn body_digest(msg: &[u8]) -> [u8; 32] {
        Sha256::digest(msg).into()
    }
}

#[cfg(test)]
mod sig_tests {
    use super::sigverify::{ed25519_spki, glob_match, verify_against, Sidecar};
    use super::TrustedIdentity;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn raw_id(spki: Vec<u8>) -> TrustedIdentity {
        TrustedIdentity::RawPublicKey {
            algorithm: "ed25519".into(),
            spki_der: spki,
            label: "test".into(),
        }
    }

    #[test]
    fn raw_ed25519_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let spki = ed25519_spki(&sk.verifying_key().to_bytes());
        let body = br#"{"value_x":"abc"}"#;
        let sig = sk.sign(body).to_bytes().to_vec();
        let sidecar = Sidecar::parse(B64.encode(&sig).as_bytes()).unwrap();
        assert!(verify_against(&raw_id(spki), body, &sidecar));
    }

    #[test]
    fn raw_ed25519_json_form() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let spki = ed25519_spki(&sk.verifying_key().to_bytes());
        let body = br#"{"value_x":"def"}"#;
        let sig = sk.sign(body).to_bytes().to_vec();
        let json = format!(r#"{{"alg":"ed25519","sig":"{}"}}"#, B64.encode(&sig));
        let sidecar = Sidecar::parse(json.as_bytes()).unwrap();
        assert!(verify_against(&raw_id(spki), body, &sidecar));
    }

    #[test]
    fn tampered_body_fails() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let spki = ed25519_spki(&sk.verifying_key().to_bytes());
        let sig = sk.sign(b"original").to_bytes().to_vec();
        let sidecar = Sidecar::parse(B64.encode(&sig).as_bytes()).unwrap();
        assert!(!verify_against(&raw_id(spki), b"tampered", &sidecar));
    }

    #[test]
    fn untrusted_key_fails() {
        let signer = SigningKey::from_bytes(&[2u8; 32]);
        let other = SigningKey::from_bytes(&[3u8; 32]);
        let spki = ed25519_spki(&other.verifying_key().to_bytes());
        let body = b"body";
        let sig = signer.sign(body).to_bytes().to_vec();
        let sidecar = Sidecar::parse(B64.encode(&sig).as_bytes()).unwrap();
        assert!(!verify_against(&raw_id(spki), body, &sidecar));
    }

    #[test]
    fn glob_matches_workflow_identity() {
        let pat = "https://github.com/maceip/*/.github/workflows/registry-sign.yml@refs/heads/main";
        assert!(glob_match(
            pat,
            "https://github.com/maceip/uq-runner/.github/workflows/registry-sign.yml@refs/heads/main"
        ));
        assert!(!glob_match(pat, "https://evil.example/maceip/x"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*c", "abc"));
        assert!(!glob_match("a*c", "abd"));
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One-line description of the registry snapshot's trust + freshness (R.2).
pub fn describe_snapshot(state: SnapshotState) -> &'static str {
    match state {
        SnapshotState::Fresh => "fresh (signed, unexpired)",
        SnapshotState::Expired => "EXPIRED — refetch required",
        SnapshotState::Untrusted => "present but UNTRUSTED signature",
        SnapshotState::Missing => "none",
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::sigverify::ed25519_spki;
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn write_signed_snapshot(dir: &Path, snap: &Snapshot, sk: &SigningKey) {
        let body = serde_json::to_vec_pretty(snap).unwrap();
        std::fs::write(dir.join("snapshot.json"), &body).unwrap();
        let sig = sk.sign(&body).to_bytes().to_vec();
        std::fs::write(dir.join("snapshot.json.sig"), B64.encode(&sig)).unwrap();
    }

    fn trust_root_for(sk: &SigningKey) -> TrustRoot {
        TrustRoot::empty().with(TrustedIdentity::RawPublicKey {
            algorithm: "ed25519".into(),
            spki_der: ed25519_spki(&sk.verifying_key().to_bytes()),
            label: "snapshot-signer".into(),
        })
    }

    fn snap(expires_at: u64, status: Status) -> Snapshot {
        Snapshot {
            version: 1,
            generated_at: 1,
            expires_at,
            entries: vec![SnapshotEntry {
                value_x: "deadbeef".into(),
                status,
            }],
        }
    }

    #[test]
    fn fresh_signed_snapshot_is_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        write_signed_snapshot(dir.path(), &snap(u64::MAX, Status::Revoked), &sk);
        let reg = Registry::load(dir.path(), trust_root_for(&sk)).unwrap();
        assert_eq!(reg.snapshot_state(), SnapshotState::Fresh);
        assert_eq!(reg.fresh_status("deadbeef"), Some(Status::Revoked));
    }

    #[test]
    fn expired_snapshot_does_not_back_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let sk = SigningKey::from_bytes(&[12u8; 32]);
        write_signed_snapshot(dir.path(), &snap(1, Status::Revoked), &sk); // expires_at=1, long past
        let reg = Registry::load(dir.path(), trust_root_for(&sk)).unwrap();
        assert_eq!(reg.snapshot_state(), SnapshotState::Expired);
        // not fresh → not authoritative
        assert_eq!(reg.fresh_status("deadbeef"), None);
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let signer = SigningKey::from_bytes(&[13u8; 32]);
        let other = SigningKey::from_bytes(&[14u8; 32]);
        write_signed_snapshot(dir.path(), &snap(u64::MAX, Status::Revoked), &signer);
        let reg = Registry::load(dir.path(), trust_root_for(&other)).unwrap();
        assert_eq!(reg.snapshot_state(), SnapshotState::Untrusted);
        assert_eq!(reg.fresh_status("deadbeef"), None);
    }

    #[test]
    fn missing_snapshot_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let sk = SigningKey::from_bytes(&[15u8; 32]);
        let reg = Registry::load(dir.path(), trust_root_for(&sk)).unwrap();
        assert_eq!(reg.snapshot_state(), SnapshotState::Missing);
    }
}

/// Human-readable summary of a lookup result. Used by `uq check`.
pub fn describe(lookup: &Lookup) -> String {
    match lookup {
        Lookup::Found { entry, signature } => {
            let sig = match signature {
                SignatureState::Verified => "signed",
                SignatureState::Untrusted => "signature present but UNTRUSTED",
                SignatureState::Missing => "UNSIGNED",
            };
            let status = match entry.status {
                Status::Recommended => "RECOMMENDED",
                Status::Deprecated => "DEPRECATED",
                Status::Revoked => "REVOKED",
            };
            format!("{status} ({sig}) — approved {}", entry.approved_at)
        }
        Lookup::Unknown => "UNKNOWN (not in registry)".to_string(),
    }
}
