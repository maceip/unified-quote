# Unified-Quote Capability Delta, GPU/NVLink Specification & OS Interface Architecture

This document defines the architectural gap analysis, NVIDIA GPU/NVLink attestation design, boot-chain measurement requirements, and OS integration interfaces for `unified-quote`. It establishes the roadmap for transitioning `unified-quote` into an enterprise-grade, pure-Rust confidential computing attestation engine positioned under the `ZUNFTMAX` organization alongside the `zmax-ntrust` confidential VM stack.

---

## 1. Capability Delta: Current State vs. State-of-the-Art Reference Toolchains

The following matrix contrasts the current implementation of `unified-quote` (`v2`) against leading industry-reference attestation stacks across four critical dimensions:

| Dimension | `unified-quote` (Current State) | Industry-Reference Architecture | Delta & Required Upgrades |
| :--- | :--- | :--- | :--- |
| **1. Confidential GPU & NVLink Attestation** | **Absent.** CPU-only (AMD SEV-SNP, Intel TDX, AWS Nitro). Completely ignores GPU SPDM reports, driver/VBIOS RIMs, and NVLink interconnect topology. | **Full-Stack GPU/NVLink Verification.** Direct NVML/NSCQ collection; parses binary SPDM measurement blocks; verifies GPU cert chain against pinned hardware root CA; verifies XML-DSig on driver/VBIOS Reference Integrity Manifests (RIMs); validates Single-Partition (SPT), Multi-Partition (MPT), and PCIe/NVLink HGX topologies (PPCIE); offline OCSP/CRL caching. | **High Priority Gap.** `unified-quote` must implement native GPU/NVLink attestation in pure Rust, removing this burden from guest operating system images. |
| **2. Boot Chain & Measured Storage** | **Raw PCR / RTMR Reading.** Reads raw `MRTD`/`RTMR` (TDX) or `MEASUREMENT` + sysfs PCRs (SEV-SNP). Opaque hashes only; does not interpret boot events. | **TCG Event Log & CCEL Replay.** Reads and replays binary TCG Event Log (`/sys/kernel/security/tpm0/binary_bios_measurements`) and ACPI CCEL tables against PCR 0..9 and RTMR 0..3 to prove exact firmware, bootloader, kernel binary, and command-line parameters. Verifies `dm-verity` root filesystem hash embedded in cmdline. | **Medium Priority Gap.** `unified-quote` must parse TCG 2.0 / CCEL event logs in Rust to prove the complete boot chain and verify immutable `dm-verity` rootfs digests. |
| **3. Multi-Cloud Silicon Roots** | **Industry-Leading.** Native support across major clouds: direct SEV-SNP/TDX ConfigFS-TSM, Azure paravisor vTPM HCL (`NV 0x01400001`), and AWS Nitro + NitroTPM cryptographically linked roots. | **Cloud-Siloed.** Reference implementations are typically hardcoded to a single cloud provider's internal metadata or centralized SaaS token services. | **Strength to Preserve.** Maintain multi-cloud silicon rooting (AMD ARK, Intel SGX/TDX Root, AWS Nitro Root) without introducing external cloud verifier dependencies. |
| **4. Channel Binding & EAT Tokens** | **Strong.** Embeds TLS leaf certificate `SubjectPublicKeyInfo` (SPKI) hash directly into hardware `REPORT_DATA` (`EatToken` v2, `https://uq.secure.build/eat/v2`). | **Disconnected or Custom TLS.** Often relies on non-standard self-signed mTLS extensions that break standard WebPKI clients and OpenAI SDKs. | **Strength to Preserve.** Maintain RFC 9711 EAT CBOR/JSON tokens and TLS SPKI channel binding so standard HTTPS clients work out of the box. |

---

## 2. NVIDIA GPU & NVLink Attestation Architecture

### 2.1 The Principle of Separation of Concerns
In previous image builds, guest operating system images attempted to handle GPU attestation directly using shell scripts, local CLI utilities, and ad-hoc JSON validation. **This is an architectural anti-pattern:**
- Guest OS images (`zmax-ntrust`) should focus exclusively on minimal kernel compilation, systemd service sandboxing, read-only root filesystems, and serving inference workloads.
- **`unified-quote` must own all confidential attestation logic:** hardware evidence collection, cryptographic certificate validation, manifest signature checking, topology verification, and composite CPU+GPU token synthesis.

### 2.2 Supported Topologies
`unified-quote` must support three GPU hardware topology profiles:

1. **Single Partition Topology (SPT):**
   - Single Hopper (H100/H200) or Blackwell (B100/B200) GPU attached via PCIe.
   - Evaluates SPDM measurements, driver version, VBIOS version, and CC-On production readiness.
2. **Multi-Partition Topology (MPT):**
   - Multiple independent GPUs attached via PCIe without hardware NVSwitch interconnects.
   - Collects and validates quotes from all attached GPUs under a single freshness challenge.
3. **PCIe Peer-to-Peer & NVLink HGX Topology (PPCIE):**
   - 8-GPU HGX clusters interconnected via high-bandwidth NVSwitches.
   - Collects evidence from both GPU devices (`libnvidia-ml.so`) and NVSwitch devices (`libnvidia-nscq.so`).
   - Validates that the physical routing topology matches expected NVLink fabric policies and that all switches are running authorized firmware in secure mode.

### 2.3 Verification Pipeline (Pure-Rust Implementation)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       unified-quote::gpu Subsystem                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌───────────────────────┐                           ┌─────────────────────┐
│ NVML Evidence Source  │                           │ NSCQ Switch Source  │
│  (libnvidia-ml.so)    │                           │ (libnvidia-nscq.so) │
└───────────────────────┘                           └─────────────────────┘
           │                                                   │
           └─────────────────────────┬─────────────────────────┘
                                     ▼
                ┌────────────────────────────────────────┐
                │ Raw SPDM Report & Certificate Extraction│
                └────────────────────────────────────────┘
                                     │
     ┌───────────────────────────────┼───────────────────────────────┐
     ▼                               ▼                               ▼
┌────────────────────────┐ ┌────────────────────────┐ ┌────────────────────────┐
│ Certificate Chain Verif│ │  XML RIM & Signature   │ │  OCSP / Revocation     │
│ • Device Identity Root │ │ • Parse XML-DSig       │ │ • Check cached OCSP    │
│ • Intermediate CAs     │ │ • Verify RIM Root CA   │ │ • Validate CRL status  │
│ • GPU Device Alias Cert│ │ • Extract Golden Values│ │ • Offline cache rules  │
└────────────────────────┘ └────────────────────────┘ └────────────────────────┘
     │                               │                               │
     └───────────────────────────────┼───────────────────────────────┘
                                     ▼
                ┌────────────────────────────────────────┐
                │      Golden Measurement Comparison     │
                │ • VBIOS measurement matches RIM       │
                │ • Driver measurement matches RIM      │
                │ • Runtime security registers verified  │
                └────────────────────────────────────────┘
                                     │
                                     ▼
                ┌────────────────────────────────────────┐
                │      Topology & Fabric Validation      │
                │ • Expected GPU count verified          │
                │ • Expected NVSwitch count verified     │
                │ • NVLink routing authorized            │
                └────────────────────────────────────────┘
```

1. **Hardware Evidence Extraction:**
   - Dynamically binds to `libnvidia-ml.so` via pure-Rust FFI (`nvmlDeviceGetFieldValues` / `nvmlDeviceGetConfidentialComputingGpuCertificate`) to pull raw SPDM quotes without shelling out to external binaries.
   - For HGX platforms, binds to `libnvidia-nscq.so` to extract NVSwitch attestation reports.
2. **Device Certificate Chain Verification:**
   - Validates the X.509 certificate chain from the GPU device-unique alias key up to the pinned **NVIDIA Device Identity Root CA** (`p384` / `ecdsa-p384`).
3. **Reference Integrity Manifest (RIM) Verification:**
   - Ingests VBIOS and Driver RIMs formatted as standard TCG CoRIM / XML documents.
   - Validates the XML-DSig signature enclosing the RIM against the pinned **NVIDIA RIM Root CA**.
   - Extracts expected "golden" cryptographic hashes for firmware components, driver binaries, and security register states.
4. **Runtime Measurement Comparison:**
   - Compares the hardware SPDM measurements returned by the GPU against the golden values extracted from the verified RIM.
   - Fails immediately if any driver module, VBIOS partition, or debug mode flag deviates from the manifest.
5. **Revocation & Offline Caching:**
   - Supports both online OCSP checking and **100% offline air-gapped verification** using cached `.textproto` or JSON certificate revocation lists, validating that evidence was valid at the recorded timestamp.

---

## 3. Boot Chain & Measured Storage Specification

To guarantee that any third party can fork the repository, build an image, boot it on a confidential VM, and observe the exact same cryptographic measurement:

### 3.1 TCG Event Log & CCEL Replay in Rust
Currently, reading raw PCR or RTMR registers provides an opaque 32-byte or 48-byte hash. If an unexpected hash is observed, the operator cannot identify whether firmware, the bootloader, the kernel, or command-line parameters changed.

`unified-quote` will incorporate a pure-Rust event log parser:
- **ACPI CCEL (Confidential Computing Event Log):** On Intel TDX platforms, reads `/sys/firmware/acpi/tables/data/CCEL` and replays the binary events into simulated `RTMR[0..3]`.
- **TCG 2.0 Binary Event Log:** On TPM platforms (including Azure HCL and AWS NitroTPM), reads `/sys/kernel/security/tpm0/binary_bios_measurements` and replays events against PCR banks.
- **Verification Output:** Replay produces a human-readable and machine-verifiable manifest proving:
  - Exact UEFI firmware volume hash (`RTMR0` / `PCR 0`)
  - Exact bootloader binary hash (`RTMR1` / `PCR 4`)
  - Exact kernel binary and command-line parameters (`RTMR1` / `PCR 8,9`)

### 3.2 Root Filesystem Measurement via `dm-verity`
Because cloud environments mutate local state on first boot (e.g., dynamic network provisioning, ephemeral machine IDs), hashing raw disk blocks after boot produces non-deterministic measurements.

The solution implemented across `unified-quote` and `zmax-ntrust`:
1. **Read-Only System Closure (`Value X`):**
   - The root filesystem contains an immutable system tree comprising kernel binaries, systemd units, admission scripts, and pinned application lockfiles.
   - `unified-quote::value_x` computes a deterministic 48-byte SHA-384 Merkle tree hash over this sorted closure.
2. **Hardware Kernel Command-Line Extension (`dm-verity`):**
   - When configured with `dm-verity`, the root filesystem's Merkle tree root hash (`roothash=<hex>`) is embedded directly into the kernel command line or a Unified Kernel Image (UKI).
   - The bootloader measures the UKI into hardware registers (`RTMR1` / `PCR 8,9`) before the kernel boots.
   - `unified-quote` recomputes `Value X` and verifies that the `roothash` active in the hardware boot log matches the static manifest, binding the entire disk image into the hardware quote before workload execution begins.

---

## 4. Operating System / Workload Communication Interface

To cleanly decouple the operating system image from the attestation engine, `unified-quote` provides three interface surfaces:

### 4.1 CLI Interface (Host & Script Integration)
For use in build pipelines, cloud-init scripts, and administrative debugging:

```bash
# Collect composite CPU + GPU evidence with a fresh client nonce
uq collect --nonce <64-hex> --gpu --out /run/ntrust/attestation.cbor

# Verify an endpoint or captured receipt against pinned silicon roots
uq verify /run/ntrust/attestation.cbor \
  --expected-value-x <96-hex> \
  --expected-mrtd <96-hex> \
  --json

# Probe and display live TEE platform & GPU readiness status
uq status --json
```

### 4.2 Local IPC / Daemon Interface (Loopback Service)
For integration with web servers (e.g., NGINX reverse proxies) and containerized workloads:
- `unified-quote` can run as a sandboxed systemd service listening on `127.0.0.1:8082` or a dedicated Unix domain socket (`/run/ntrust/attest.sock`).
- Exposes a minimal REST endpoint:
  ```http
  GET /v1/attest?nonce=<64-hex> HTTP/1.1
  Host: 127.0.0.1:8082
  Accept: application/eat+json, application/cbor
  ```
- **Zero Configuration Overhead:** The guest OS simply forwards `GET /v1/attest` traffic from port 443 to `127.0.0.1:8082`. `unified-quote` automatically handles NVML evidence gathering, ConfigFS-TSM quote requests, and TLS SPKI binding.

### 4.3 Native Rust Library Crate (`unified-quote`)
For high-performance in-process integration directly within Rust services:

```rust
use unified_quote::{
    AttestationCollector,
    AttestationVerifier,
    EatToken,
    GpuTopologyMode,
    Platform,
};

// --- In-Guest Collection ---
let collector = AttestationCollector::builder()
    .with_nonce(&client_nonce)
    .with_tls_spki_der(&leaf_cert_spki_der)
    .with_gpu_topology(GpuTopologyMode::AutoDetect) // SPT, MPT, or PPCIE
    .build()?;

let eat_token: EatToken = collector.collect()?;
let cbor_bytes = eat_token.to_cbor()?;

// --- Client / Relying Party Verification ---
let verifier = AttestationVerifier::builder()
    .require_platform(Platform::Tdx)
    .require_gpu_verified(true)
    .with_expected_value_x(&expected_value_x)
    .with_pinned_vendor_roots() // AMD, Intel, AWS Nitro, NVIDIA Device Root
    .build()?;

let verdict = verifier.verify(&eat_token)?;
assert!(verdict.is_valid());
println!("Verified TEE: {:?}, GPU Model: {:?}", verdict.platform, verdict.gpu_model);
```

---

## 5. Organizational Transition to `ZUNFTMAX`

To unify confidential compute infrastructure under a single open-source identity:

1. **Repository Relocation:**
   - Move `maceip/unified-quote` into `https://github.com/ZUNFTMAX/unified-quote`.
   - Update repository documentation, cargo package identifiers, and CI workflows to reflect the unified organization.
2. **Cohesive Product Stack:**
   - **`ZUNFTMAX/unified-quote`:** The foundational pure-Rust attestation and verification engine (CPU + GPU + Storage).
   - **`ZUNFTMAX/zmax-ntrust-vllm`:** Reference confidential GPU VM image running vLLM.
   - **`ZUNFTMAX/zmax-ntrust-sglang`:** Reference confidential GPU VM image running SGLang.
   - **`ZUNFTMAX/zmax-ntrust-relay`:** Lightweight confidential TEE proxy for remote inference origins.
   - **`ZUNFTMAX/zmax-ntrust-dev`:** CPU-first development and testing image.
3. **Release Alignment:**
   - VM build workflows in `zmax-ntrust-*` will directly consume pre-compiled, SLSA-provenance-attested `uq` binaries or crates published by `ZUNFTMAX/unified-quote`.
   - This delivers a seamless, audit-ready confidential AI infrastructure stack with end-to-end silicon verification from hardware to inference tokens.
