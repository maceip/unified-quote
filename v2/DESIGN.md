# Design Notes

Architectural decisions and lineage. Not a spec — specs live next to code.
This document exists to capture intent so future work doesn't relitigate
settled questions or lose context on why a design went the way it did.

## Spiritual ancestors

Two papers + one real-world system.

### LATTE (Xu et al., SJTU, EuroS&P 2025)

Separate what the hardware measures (platform) from what the developer
cares about (application). Check both independently. The platform
measurement proves the code that computed the application identity is
genuine. The application identity proves the output matches expectations.

We take from LATTE: the two-layer check. Platform measurement (MRTD /
SNP MEASUREMENT / PCR0) is layer 1. Value X (sha384 of source files) is
layer 2. Both must pass.

### Attestable Containers (Hugenroth et al., Cambridge/JKU, CCS 2025)

Build inside a TEE. The hardware attests that source S compiled into
artifact A inside environment E. No reproducible builds required; the
TEE is the witness. The ratcheting mechanism locks the source hash
before any build commands run, so the build cannot modify what it
claims to have built.

We take from Attestable Containers: the ratchet, and the "TEE as
witness" framing that lets us skip reproducibility engineering.

### Flashbots Andromeda / SUAVE / SIRRAH

The repos that cory helped build in a past life:
- `gramine-andromeda-revm` — Gramine-SGX TEE running a stateless REVM
- `suave-andromeda-revm` — same, with SUAVE precompiles for kettles
- `andromeda-sirrah-contracts` — Solidity contracts that verify SGX
  attestations on-chain in pure Solidity, no precompile required

These taught us things the papers don't emphasize:

#### 1. Bootstrap-once, then cheap verification

Raw TEE attestation verification is expensive: cert chain walking,
ECDSA over several signatures, collateral fetches, CRL checks. Tens
to hundreds of milliseconds off-chain; millions of gas on-chain. It
is not something to do on the hot path.

The pattern SIRRAH's Key Manager uses, generalized:

> Some trusted verifier runs the expensive attestation check **once**,
> produces a cheap transferable credential, and every downstream
> consumer checks the credential instead of redoing the full verify.

The substrate doesn't matter. The verifier can be:

- **A smart contract** — SIRRAH's Key Manager on SUAVE. Public,
  censorship-resistant, but expensive and slow. One instance of the
  pattern, not the definition.
- **A CA + CT log** — what we're already doing with Let's Encrypt. The
  CA is the "expensive verifier" (they run domain control validation),
  the cert is the credential, the CT log is the public append-only
  witness that the verification happened.
- **A peer node** — the trust inheritance case. Node A verifies B's raw
  quote, issues a signed statement over a mutually-attested channel.
  B presents the statement to C without C touching raw quotes.
- **A Sigstore bundle** — Fulcio + Rekor as the "expensive verifier,"
  the cosign bundle as the cheap credential.
- **A local cache inside the client** — we are our own trusted verifier
  for subsequent polls.

All five are the same structural thing: an expensive, infrequent,
publicly-observable verification step produces a cheap credential that
many parties can check. Pick the verifier that matches the trust
requirement; the split is what matters.

**How this shapes our work:**

- `bountynet check` should not re-verify the full quote chain on every
  poll. First successful verification caches
  `(domain, pubkey_hash, value_x, not_after)`. Subsequent checks do a
  TLS handshake + cached-pubkey comparison and short-circuit. Full
  re-verify happens on expiry, on anomaly, or on explicit `--force`.
- Policy gates (KMS, Vault, the future `bountynet-gate`) follow the
  same pattern. Expensive check admits a key to a cache; cheap
  signature check grants access afterwards.
- This is how a BountyNet-style agent network makes thousands of
  requests per second without grinding to a halt on attestation
  verification: agents get verified once by whatever trusted verifier
  their use case requires, they're cheap to talk to from then on.

#### 2. Trust inheritance between nodes

A new enclave joining a running trust domain does NOT re-bootstrap from
scratch. It receives keys from an already-trusted instance. The
ceremony runs once, the cluster inherits.

**How this shapes our work:** the multi-node case (once it exists) is
modeled as a trust graph, not a set of independent islands. Node A
bootstraps, verifies its own Value X, gets keys. Node B joins by
presenting a fresh quote to Node A, proving (a) it runs in a TEE and
(b) its Value X matches the trust domain. Node A hands over the key
material over a mutually-attested channel (attested TLS on both sides).

We don't build this now. We just avoid assumptions that prevent it:
- KMS / policy primitives must accept a *set* of acceptable Value X
  values, not a single one (the upgrade cohort case)
- Attestation format must carry enough to identify the node, not just
  the code (so cluster membership is decidable)
- Key material must be thinkable as transferable, even if today it's
  per-node only

#### 3. Small API surface (precompiles, not frameworks)

Andromeda exposes four precompiles: `localRandom`, `volatileSet/Get`,
`attestSgx`, `sealingKey`. That's it. Contracts don't see Gramine,
don't see `/dev/attestation/quote`, don't parse SGX quote bytes. They
see four function calls.

**How this shapes our work:** `bountynet-gate` (the policy evaluator)
gets a business-card-sized public API. No frameworks. No configuration
DSLs. A consumer calls `gate.check(eat_token, policy) -> Result<Claims>`
and that's the whole interface.

#### 4. Stateless by construction

Andromeda-REVM is stateless. It doesn't persist EVM state. It pulls
blockchain state on demand via Helios (a light client that
cryptographically verifies the data it returns). The TEE is an
execution substrate, not a storage substrate.

**How this shapes our work:** we already have this property on the
build side (no state, no keys, every boot fresh). We preserve it on
the runtime side too. Any state that absolutely has to persist goes
through an attestation-gated storage service (KMS today, Vault-shaped
primitive eventually). The TEE never holds durable secrets between
reboots.

Note: "eventually" here is specifically the seal/unseal problem. Users
will want to push secrets in. We don't build it yet. We just don't
bake in assumptions that prevent it from fitting cleanly later.

#### 5. Build the right thing even if the ecosystem isn't ready

SIRRAH put `verifySgx` in pure Solidity. Ethereum has no SGX
verification precompile; they ate the gas cost and moved on. Same
with attested TLS in general: no modern TLS stack supports it natively
(rustls, OpenSSL, BoringSSL all require custom parsing to extract the
attestation extension, and several reject non-critical extensions
with unknown OIDs depending on config); we implement it anyway and
let the ecosystem catch up.

**How this shapes our work:** we use the TCG DICE OID
(`2.23.133.5.4.9`) for attestation-in-X.509 because it's where Gramine
and the TCG DICE v1.1 standard are converging, not because mainstream
TLS libraries parse it today. Same with EAT (CBOR/COSE) as the wire
format. If we're alone for a while, fine — we're alone in the direction
things are going, not against it.

## Decisions downstream of the above

### Vocabulary: "attested TLS", "RA-TLS", "RATS", "CMW", "EAT"

Several overlapping terms are in use. They are not synonyms. To keep
future discussion precise:

- **EAT** — IETF RATS token format (RFC 9711). CBOR-based attestation
  claim envelope. The payload in our X.509 extension is an EAT
  following the `bountynet-v2` profile. Defined in `src/eat.rs`.
- **CMW** (Conceptual Messages Wrapper) — IETF RATS draft
  (`draft-ietf-rats-msg-wrap`) for a transport-agnostic wrapper around
  attestation evidence. Still a draft; we use its concept, not a
  frozen wire format.
- **TCG DICE CMW OID** — `2.23.133.5.4.9`
  (`tcg-dice-conceptual-message-wrapper`). Defined in TCG DICE
  Attestation Architecture v1.1 (not IETF). Specifies an X.509
  extension for carrying a CMW-wrapped attestation evidence blob.
  Gramine uses this OID. **This is our cert-embedding point**, and
  it gives us interop with Gramine.
- **RATS** (Remote ATtestation procedureS) — IETF WG. Defines the
  architecture (Attester / Verifier / Relying Party roles) in
  RFC 9334. Does NOT define a TLS binding — there is no IETF standard
  for "attestation in X.509 for TLS" as of April 2026. The closest
  draft (`draft-ounsworth-rats-x509-evidence`) is early and has no
  implementers.
- **RA-TLS** — industry shorthand for "do a TLS handshake whose cert
  embeds an attestation." Coined by Intel in 2019. Not a specification.
  Not an IETF WG output. Just a name for a pattern. We implement the
  pattern but we **don't track an RA-TLS spec** (there isn't one) —
  we track EAT for the token and TCG DICE CMW for the cert binding.

In code, we use **"attested TLS"** as the generic name for our flow
(`src/net/attested_tls.rs`) to avoid implying we're tracking a spec
named "RA-TLS." We cite TCG DICE for the OID, IETF RATS / EAT for
the payload, and document that the flow itself is industry convention.

### Attested TLS + Let's Encrypt coexist

- Self-signed attested-TLS cert with TCG DICE CMW extension for
  machine-to-machine clients. Trust rooted in the CPU vendor, not a CA.
- Let's Encrypt cert for the same domain for browser / curl DX.
- LE is not decorative. Every boot triggers a fresh ACME flow, so every
  deployment lands a CT log entry keyed by `<value_x_prefix>.aeon.site`.
  CT = public, append-only witness that a given Value X ran at a given
  time. A malicious enclave modifier either gets logged or is
  unreachable (no cert, no clients).
- `bountynet check` verifies both the attested-TLS attestation (primary)
  and the SCTs on the LE cert (secondary, catches deployment anomalies
  that impersonate legit Value X values via a different domain).

### Registry trust is configurable, not hardcoded

- A `TrustRoot` is data, not a constant. Our own project ships a default
  TrustRoot pointing at our GitHub signing workflow via Sigstore keyless.
- Downstream users (the JS developer running their webserver in a TEE)
  configure their own TrustRoot. Their identity can be Sigstore keyless
  pointed at their workflow, an offline YubiKey pubkey, a cosign key
  file, whatever.
- There is no single global registry. Registries are per-project.
- The on-disk entry format is stable across trust roots.

### Build-once-then-cache is the performance primitive

- First `bountynet check` for a domain: full quote chain verification,
  ~10-100ms depending on platform.
- Subsequent checks: TLS handshake + cached-pubkey comparison, sub-ms.
- Cache keyed by `(domain, pubkey_hash, value_x, not_after)`.
- Cache invalidation: expiry, on-demand flag, or signature mismatch.
- Same pattern applies to `bountynet-gate` (KMS / Vault / future
  services): expensive verify once, cheap check many times.

### Stage 0 vs Stage 1 (the pivot we're in the middle of)

- Stage 0: the attested builder. Done-for-now. Outputs an attestation
  binding (CT, A, X) and a platform quote. Lives in `stage0/` as a shell
  script + in `v2/src/main.rs::cmd_build` as the Rust path.
- Stage 1: the attested runtime. The artifact from stage 0 running
  inside a TEE, self-verifying at boot, serving its own attestation
  over attested TLS + LE.
- The stage-0-to-stage-1 transition is where we commit to attested TLS
  as the stage 1 wire format. EAT token (IETF RATS) as the payload.
  CMW as the wrapper concept. TCG DICE OID `2.23.133.5.4.9` as the
  X.509 address.

## What we are deliberately NOT building yet

- Multi-node trust inheritance (the cluster join ceremony from SIRRAH
  point #2). Design space preserved, implementation deferred.
- Seal/unseal for durable secrets (the SGX-style state problem). We
  will need this eventually for users who want to push secrets into our
  infra without using a cloud KMS. Until we build it, KMS is the only
  gate and we document that clearly.
- On-chain contracts (UpdateChallenge, AttestRegistry). The EAT token
  is the primitive; on-chain is a consumer of it, not a prerequisite.
- Update challenge game (multi-winner commit-reveal). Research reads
  exist (the impossibility paper, Hollow Victory, RogueOne,
  Anomalicious). Implementation waits until the registry + gate
  primitives are stable.

## Order of current work (April 2026)

1. `TrustRoot` layer in `registry.rs` — **done**.
2. EAT token schema + encoder (CBOR / minimal subset of RFC 9711) — **done**.
3. Attested-TLS cert generation: enclave-held TLS key,
   `sha256(tls_spki)` in report_data, EAT in X.509 ext `2.23.133.5.4.9`
   (non-critical per rustls trade-off) — **done**.
4. Attested-TLS verifier in `bountynet check`: cert → extension → EAT
   → quote → SPKI binding → registry lookup — **done**.
5. Source identity hardening: symlinks rejected, path separators
   canonicalized, and binding-invariant checks fail closed — **done**.
6. SCT / CT verification on the LE path.
7. Boot-time ACME re-provision (verify we're not caching across
   reboots, which would break the CT property).
8. Sigstore bundle verifier (hand-rolled, for registry entry sidecars).
9. Registry update workflow that consumes the ouroboros attestation
   artifact — **done, unsigned entries remain informational only**.
10. Dual-cert wiring: LE cert and self-signed attested-TLS cert both
   served from the enclave, selected by SNI / ALPN.
11. `bountynet-gate` extraction: pull the policy evaluator out of
    `cmd_enclave` into a standalone module with a business-card API.
12. Stage 0 output migration: stage 0 produces CBOR EAT alongside
    JSON, so the verifier has one canonical proof format — **done**.
13. DCAP collateral layer: QE Identity + TCB Info + CRL + `nextUpdate`
    freshness. Matches Intel attestation service quality. AMD KDS VCEK
    fetch is already done; the missing pieces are collateral policy
    checks inside `verify_platform_quote`.
14. Runtime TOCTOU fields in EAT: wire `heartbeat_seq` (monotonic
    counter, gaps are suspicious) and `integrity_ok` (runtime integrity
    monitor status) into the claim set in `src/eat.rs`.
15. Shadow attestation service (`SHADOW.md`): public `/shadow-build`
    endpoint (v1 accessed via a GitHub Action shim,
    `maceip/bountynet-shadow@v1`) where a build bundle is submitted,
    an isolated ephemeral TDX VM rebuilds it, and a
    `bountynet-shadow-v1` EAT is returned. Isolation = separate VM per
    request in dedicated GCP project `bountynet-shadow-20260415`,
    isolated VPC, zero network on build VMs. Rails = daily spend cap
    ($100), wall-clock ceiling (15 min default / 60 min hard cap), no
    egress, PoW admission, submission dedup. GitHub OIDC + SBOM
    attestation verification gates the Action-mediated path; raw PoW
    gates the eventual public API. See `SHADOW.md` for the full threat
    model + rail design. Do NOT co-locate with the current live
    runner. Code lives in `maceip/bountynet-shadow` (separate repo).
