# bountynet-genesis

**A trust receipt for code, packages, and agents.** BountyNet proves the
thing you are about to run, deploy, or hand secrets to is the code you
think it is — in hardware, across three TEE vendors, verifiable by
anyone with the source. The chain is closed on itself: the runner that
built this binary is itself an attested build of this repo.

---

## The one question

> **Is this live thing really the source it claims to be?**

Not "probably." Not "we checked last Tuesday." Not "the cloud provider
promises." A proof rooted in hardware that anyone can verify and nobody
can argue with.

That is the useful mass-market surface. Code signing says who published
an artifact. BountyNet says what code is live before an AI agent gets a
token, a package reaches production, or a secret leaves KMS.

---

## Hardware Results

| Platform | Hardware | Root of trust | Chain | Status |
|---|---|---|---|---|
| **Intel TDX** | GCP c3-standard-4 | Intel SGX Root CA | stage 0 → stage 1 | ✅ Proven |
| **AMD SEV-SNP** | AWS c6a.xlarge | AMD Root Key (ARK) | stage 0 → stage 1 | ✅ Proven |
| **AWS Nitro** | AWS m5.xlarge enclave | AWS Nitro Root CA | stage 0 (single-process) | ✅ Proven |
| **Azure SEV-SNP** | Azure Standard_DC4as_v5 CVM | AMD PSP + Azure vTOM/paravisor | blocked before stage 0 | Tested, not verified |

Real attestation bytes captured from each proven platform live in
[`v2/testdata/chain/`](v2/testdata/chain). Every commit runs them through
the signature verifier as a regression gate.
[`v2/tests/hardware_regression.rs`](v2/tests/hardware_regression.rs).

Azure was tested on 2026-05-01. The VM provisioned successfully in
`northeurope`, booted with `Memory Encryption Features active: AMD SEV`,
and produced a Linux release build. It did **not** expose the raw SNP
interfaces bountynet needs today: `/dev/sev-guest` was absent and
configfs-tsm report creation failed with `No such device or address`.
That means Azure is recorded as tested but not yet verified; support
needs an Azure MAA/vTOM evidence collector or a SKU/image that exposes
fresh raw SNP/TDX quote collection.

## The ouroboros

Every push to `main` that touches `v2/` triggers
[`.github/workflows/attested-self-build.yml`](.github/workflows/attested-self-build.yml),
which dispatches to a self-hosted GCP TDX runner. The runner checks out
the commit, runs `bountynet build v2/` inside the TEE, and uploads a
real Intel-TDX-signed EAT attestation as a workflow artifact.

The first ouroboros run is preserved byte-identically at
[`v2/testdata/chain/tdx_ouroboros.cbor`](v2/testdata/chain/tdx_ouroboros.cbor)
with its own regression test. **From that commit forward, every release
of bountynet is provably built by a previous attested build of bountynet**,
and the chain can be walked back to the first hardware run.

---

## How it works

### Stage 0 — Attested build

`bountynet build <source-dir>` runs inside a TEE. It:

1. Refuses to run outside a TEE.
2. Hashes the source tree (`CT` = sha384 of all files, sorted).
3. Freezes the source into a read-only copy (**ratchet** — Attestable
   Containers contribution #1).
4. Runs the build command.
5. Verifies the source is byte-identical after the build (ratchet check).
6. Hashes the artifact (`A`).
7. Computes `Value X` = sha384 of the frozen source tree (the canonical
   identity of the code — LATTE layer 2).
8. Builds a partial EAT with the above claims plus `tls_spki_hash` (if
   the caller bound a TLS key).
9. Calls `binding_bytes()` on the partial EAT — this is the sha256 that
   goes into the hardware quote's `report_data[0..32]`.
10. Collects a hardware quote with that binding in `report_data`.
11. Fills the quote and platform measurement into the EAT.
12. Serializes to CBOR (`attestation.cbor`).

The EAT format is the
[IETF RATS](https://datatracker.ietf.org/wg/rats/about/) Entity Attestation
Token (RFC 9711) with our profile URI `https://bountynet.dev/eat/v2`.
Delivery is via a TCG DICE Conceptual Message Wrapper extension at OID
`2.23.133.5.4.9` embedded in a self-signed X.509 cert — the same
convention Gramine uses.

### Stage 1 — Attested runtime

`bountynet run <work-dir> --attestation stage0.cbor` runs inside a TEE
and:

1. Loads the stage 0 EAT.
2. **Verifies stage 0's quote** against the pinned vendor root CA
   (Intel / AMD / AWS). This is the "verify myself at boot" step from
   LATTE — the runtime doesn't trust the producer.
3. Re-computes Value X from disk, confirms it matches stage 0's claim.
4. Generates a stage 1 TLS keypair.
5. Builds a stage 1 EAT that **chains to stage 0** by setting
   `previous_attestation = stage0_cbor`. `binding_bytes()` commits to
   `sha256(previous_attestation)` via `previous_hash()`.
6. Collects a fresh stage 1 quote with the new binding in report_data.
7. Generates an attested-TLS cert carrying the stage 1 EAT.
8. Serves over rustls with the attested cert.

### Client-side verification

`bountynet check https://<domain>/` runs anywhere (including your laptop)
and:

1. TLS handshake with a cert-accepting verifier — auth is by attestation,
   not CA chain.
2. Pulls the leaf certificate out of the rustls session.
3. Extracts the EAT from the TCG DICE CMW extension.
4. Recomputes `sha256(cert_spki)` and checks it against
   `eat.tls_spki_hash` — **channel binding** (makes this attested-TLS,
   not just attestation-over-TLS).
5. Calls `verify_platform_quote(platform, quote, binding_bytes())`,
   which checks both the report_data binding AND the full signature
   chain against the pinned hardware root CA.
6. Walks `previous_attestation` recursively: decodes each previous
   stage, asserts Value X stability, verifies each ancestor's quote.
7. (Optional) Registry lookup for project governance policy.

This is Attestable Containers contribution #6 (build-to-runtime chain),
which the paper explicitly left to the consumer.

---

## Why users should care

The first useful product is not "better code signing." It is a verifier
for trust decisions people already make:

- **Before an AI agent gets credentials:** prove the running agent image
  matches reviewed source and a pinned Value X.
- **Before a package is promoted:** compare the normal CI artifact to a
  hardware-rooted rebuild witness.
- **Before a service receives secrets:** release them only to a runtime
  whose attested TLS certificate chains back to the reviewed build.

[`v2/SHADOW.md`](v2/SHADOW.md) is the planned no-TEE-required entry
point: a GitHub Action submits a build bundle, an isolated TDX VM
rebuilds it, and the workflow gets back `shadow-attestation.cbor`.

---

## Standards and papers

| What we build | Derived from |
|---|---|
| Two-layer check (platform + portable identity) | [LATTE (Xu et al., SJTU, EuroS&P 2025)](https://ieeexplore.ieee.org/document/11041949) |
| Ratchet + build-inside-TEE + (PCR, CT, A) binding | [Attestable Containers (Hugenroth et al., Cambridge/JKU, CCS 2025)](https://dl.acm.org/doi/10.1145/3719027.3744812) |
| Build-to-runtime chain (AC contribution #6) | Left to consumer; we implement it |
| EAT token format | [IETF RATS RFC 9711](https://datatracker.ietf.org/doc/rfc9711/) |
| X.509 extension delivery | [TCG DICE Attestation Architecture v1.1](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) — OID `2.23.133.5.4.9` |
| Bootstrap-once then cheap signatures | [Flashbots Andromeda / SIRRAH](https://github.com/flashbots/andromeda-sirrah-contracts) |

---

## Quick start

```bash
# Clone + build
git clone https://github.com/maceip/bountynet-genesis
cd bountynet-genesis/v2
cargo build --release

# Run the full test suite (65 tests including 6 that run real hardware
# attestation bytes through verify_platform_quote)
cargo test

# Attested build (must run inside a TEE — refuses otherwise)
sudo ./target/release/bountynet build /path/to/your/source \
  --cmd "your build command" \
  --output ./attest-out

# Attested runtime (serves TLS on :443 with the EAT in the cert extension)
sudo ./target/release/bountynet run /path/to/your/source \
  --attestation ./attest-out/attestation.cbor

# Verify from any machine — no TEE required on the verifier
./target/release/bountynet check https://<domain>/
```

---

## Repository layout

```
v2/
├── src/
│   ├── main.rs                  cmd_build, cmd_run, cmd_check, cmd_enclave
│   ├── eat.rs                   IETF RATS EAT profile `bountynet-v2`
│   ├── quote/
│   │   ├── mod.rs               Platform discriminant
│   │   └── verify.rs            signature chain verification per platform
│   ├── tee/
│   │   ├── detect.rs            auto-detect TDX/SNP/Nitro
│   │   ├── nitro.rs             /dev/nsm via aws-nitro-enclaves-nsm-api
│   │   ├── snp.rs               /dev/sev-guest ioctl
│   │   ├── tdx.rs               configfs-tsm
│   │   └── tpm.rs               NitroTPM linking (SNP kernel measurement)
│   ├── net/
│   │   ├── attested_tls.rs      TCG DICE CMW X.509 extension + cert gen
│   │   ├── tls.rs               rustls server config
│   │   ├── vsock.rs             Nitro vsock bridge
│   │   ├── acme.rs              Let's Encrypt TLS-ALPN-01
│   │   └── ct.rs                SCT verification (module present, dead
│   │                            code until dual-cert path lands)
│   └── registry.rs              TrustRoot + entry lookup (governance,
│                                LATTE says no DB needed for the proof)
├── tests/
│   ├── eat_kms_e2e.rs           EAT + KMS flow
│   ├── attested_tls_e2e.rs      cert generation + extraction cycle
│   ├── attested_tls_live.rs     real rustls server + client over TCP
│   ├── chain_e2e.rs             2-stage + 3-stage chain walk
│   └── hardware_regression.rs   real TDX/SNP/Nitro bytes, verify_platform_quote
├── testdata/chain/              real EAT CBOR from live hardware runs
│   ├── tdx_stage0.cbor          8436 B   GCP c3-standard-4 TDX
│   ├── tdx_stage1.cbor         16896 B   chained to tdx_stage0
│   ├── tdx_ouroboros.cbor       8436 B   produced by CI on commit 2593db6
│   ├── snp_stage0.cbor          1620 B   AWS c6a.xlarge SNP
│   ├── snp_stage1.cbor          3264 B   chained to snp_stage0
│   └── nitro_stage0.cbor        5208 B   AWS m5.xlarge Nitro (debug-mode)
├── CONSTITUTION.md              what we're building and why
├── INVARIANT.md                 the three checks that define "done"
├── DESIGN.md                    architectural memory — LATTE, AC, Andromeda
├── HARDWARE_VALIDATION.md       the runbook that predicted both bugs caught
│                                during the first TDX run
├── STAGES.md                    platform status matrix
├── BOOTSTRAP.md                 per-platform trust chain walk
└── BUILD.md                     reproducible Nitro .eif build
```

---

## Status

- **v2 is the current codebase.** The top-level `src/` + `contracts/` +
  older workflows in this repo are v1 (the original `bountynet-shim`
  crate, pre-chain). v1 still builds and runs; v2 is where the chain
  work lives.
- Three TEE paths are proven on live hardware: GCP TDX, AWS SEV-SNP,
  and AWS Nitro. Azure SEV-SNP has been provisioned and tested, but is
  not verified until bountynet can bind EAT `report_data` through
  Azure's vTPM/MAA path or a raw quote interface.
- GitHub Actions self-hosted TDX runner registered and idle, ready for
  the next push.
- 65 tests passing on release.

## License

MIT
