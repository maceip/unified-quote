# Stages

## Stage 0: The Attested Builder

Stage 0 is a build environment running inside a TEE. It takes source
code, builds it, and produces an artifact with a hardware-rooted proof
of what was built. The proof is a TEE quote binding the source hash,
dependency hash, and artifact hash into a single signed statement from
the CPU.

Stage 0 is the root of trust for the entire system. Everything
downstream depends on the integrity of the build. If stage 0 is
compromised, nothing else matters.

### Why it exists

Two academic papers motivate this design:

**Attestable Containers** (Hugenroth et al., Cambridge/JKU, CCS 2025)
says: build inside a TEE, and the hardware attests that source S was
compiled into artifact A by environment E. No reproducible builds
required — the TEE is the witness. The ratcheting mechanism locks
the source hash before any untrusted code runs.

**LATTE** (Xu et al., SJTU, EuroS&P 2025) says: separate platform
measurements (what the hardware measures) from application identity
(what the developer cares about). Check both independently. The
platform measurement proves the build environment is genuine. The
application identity (Value X) proves the output matches expectations.

Stage 0 combines them: the platform measurement proves the builder
is genuine TEE hardware. The ratchet locks the source. The build
runs inside the TEE. The quote binds everything together. Anyone
can verify the proof without trusting the operator.

### Requirements for a stage 0 implementation

1. The TEE measurement of the build environment must be verifiable
   from source, or from a trusted endorsement.
2. The build must run inside the TEE's trust boundary.
3. The source hash (CT) must be locked before the build starts.
4. The output (artifact hash, Value X) must be bound into the
   TEE quote alongside CT.

## Stage 0 Implementations

| Platform | Provider | TEE | Firmware verification | Kernel in measurement | Status |
|----------|----------|-----|----------------------|----------------------|--------|
| AWS Nitro | Amazon | Nitro Enclave | .eif reproducible from source (verified: two builds → same PCR0) | Yes — PCR0 covers everything | **Proven** — production KMS ceremony, ACME TLS, remote verify |
| GCP TDX | Google | Intel TDX | Google signed endorsement (MRTD). RTMR[1-3] cover our code, verifiable from source. | RTMR[1-2] cover kernel | **Proven** — attestation collected, TLS serving |
| Azure SNP | Microsoft | AMD SEV-SNP via vTOM/paravisor | Azure Confidential VM launch stack; raw guest report device not exposed on tested DCasv5 VM | Not available to current raw SNP collector (`/dev/sev-guest` absent; configfs-tsm report create fails) | **Tested / not verified** — Azure VM created 2026-05-01, needs MAA/vTOM collector or raw SNP/TDX SKU |
| Azure TDX | Microsoft | Intel TDX | Custom firmware, reproducible from source | Full control | **Next** |
| AWS SNP | Amazon | AMD SEV-SNP | Published source does not match production firmware ([aws/uefi#19](https://github.com/aws/uefi/issues/19)). Kernel measurement via NitroTPM (see below). | Kernel via NitroTPM, not SNP MEASUREMENT | **Proven** — attestation collected, TLS serving |
| Equinix Metal | Equinix | AMD SEV-SNP (bare metal) | Full BIOS control via IPMI. Run your own hypervisor + OVMF. | Full control | Not tested |
| Hetzner | Hetzner | None | BIOS locked, no SNP/TDX exposed | N/A | Not available |
| OVH | OVHcloud | None | BIOS locked, no SNP/TDX | N/A | Not available |
| Vultr | Vultr | None | No confidential VM offering | N/A | Not available |
| Oracle Cloud | Oracle | AMD SEV (not full SNP) | No remote attestation path documented | N/A | Not viable |
| Scaleway | Scaleway | None | No confidential computing | N/A | Not available |
| DigitalOcean | DigitalOcean | None | No TEE support | N/A | Not available |
| IBM Cloud | IBM | SGX (x86), Secure Execution (s390x) | SGX bare metal only, no TDX/SNP | N/A | Not viable for our use |
| STACKIT | Schwarz Group | None GA | CCC member, no public product | N/A | Not available |

## AWS SNP + NitroTPM: Kernel Measurement Path

On EC2, the SNP MEASUREMENT only covers the OVMF firmware. The kernel,
initrd, and cmdline are measured by the NitroTPM (a virtual TPM in the
Nitro hypervisor), not by the AMD PSP. There is no `SNP_KERNEL_HASHES`
support — EC2 does not use direct kernel boot.

We link the two by having stage 0 (running inside the SNP VM) read
the NitroTPM's Endorsement Key and TPM PCR values, then bind them
into the SNP report:

1. Stage 0 boots inside SNP VM with NitroTPM enabled
2. Stage 0 reads TPM PCRs (kernel measurements) from `/dev/tpm0`
3. Stage 0 reads the NitroTPM Endorsement Key (EK) via EC2 API
4. Stage 0 requests a TPM quote over PCRs with a fresh nonce
5. Stage 0 puts `sha256(PCR values)` into SNP REPORT_DATA
6. Stage 0 collects the SNP report (AMD PSP signs it)
7. Attestation output includes: SNP report + EK + TPM quote + PCRs

Verification:
- SNP report is genuine → AMD root CA (hardware trust)
- REPORT_DATA contains PCR hash → stage 0 code bound them
- Stage 0 code is verified via SNP MEASUREMENT → it's open source
- TPM quote verifies against EK → PCRs are what the TPM measured
- PCR hash in SNP report matches PCRs in TPM quote → linked

**Trust assumptions:**

| What | Trusted by |
|------|-----------|
| SNP report is genuine | AMD hardware (PSP) |
| Stage 0 code is unmodified | SNP MEASUREMENT (verifiable from source) |
| NitroTPM PCR values are accurate | AWS (NitroTPM is a virtual TPM controlled by the Nitro hypervisor) |
| EK is genuine | Stage 0 read it from inside the attested TEE — the code is verified, so the data it reports is what it saw |

This is the same trust model as GCP TDX, where we trust Google for
the firmware endorsement but verify our own code independently. On
AWS SNP, we trust AMD for the hardware and AWS for the virtual TPM.

**Verified on real hardware:** c6a.xlarge, us-east-2, Ubuntu 24.04,
`AmdSevSnp=enabled` + NitroTPM v2.0. Both `/dev/sev-guest` and
`/dev/tpm0` present. SNP report and TPM quote obtained simultaneously.
PCR hash successfully bound into SNP REPORT_DATA.

## Trust Assumptions Per Platform

| Platform | Hardware trust | Cloud provider trust | What provider is trusted for |
|----------|---------------|---------------------|----------------------------|
| AWS Nitro | Amazon (NSM chip) | None | — |
| AWS SNP | AMD (PSP) | AWS | NitroTPM kernel measurement |
| GCP TDX | Intel (TDX Module) | Google | Firmware endorsement (MRTD) |
| Azure SNP (tested DCasv5 path) | AMD (PSP) | Microsoft | vTOM/paravisor + MAA/vTPM evidence path; raw SNP report device not exposed |
| Azure SNP/TDX (custom IGVM target) | AMD/Intel | None | Future target if custom firmware + raw quote path are available |

AWS Nitro requires no cloud provider trust beyond the Nitro root itself.
AWS SNP, GCP TDX, and the tested Azure CVM path require trusting the
provider for one component. This is documented, not hidden.

## Stage 1: The Attested Runtime

Stage 1 is the artifact from stage 0, running inside a TEE. At boot,
it loads the stage 0 attestation, re-computes Value X from its own
files, and verifies the match. If anything was modified between build
and deploy, stage 1 refuses to start.

Stage 1 produces its own TEE quote chaining to the stage 0 attestation.
A verifier can walk the full chain: source → attested build → attested
runtime.

Stage 1 can run on any TEE platform. The trust model for the runtime
platform is independent of stage 0. Stage 0 provides the build trust.
The runtime platform provides the execution trust.

| Stage 1 platform | Firmware verification | Our code verification |
|------------------|----------------------|----------------------|
| GCP TDX | Google endorsement (MRTD) | RTMR[1-3] from source |
| Azure SNP (tested DCasv5 path) | Azure vTOM/paravisor + vTPM/MAA path; not supported by current raw collector | Not yet verified by unified-quote |
| Azure SNP (custom IGVM target) | Our OVMF via IGVM (MEASUREMENT from source) | Included in MEASUREMENT |
| Azure TDX | Our OVMF (MRTD from source) | RTMR[1-3] from source |
| AWS SNP | SNP MEASUREMENT (firmware) + NitroTPM (kernel) | PCRs via NitroTPM, linked to SNP report |
| AWS Nitro | .eif reproducible | PCR0 covers everything |
| Equinix Metal | Full control | Full control |

## What's Proven (April 2026)

End-to-end on real hardware, not simulated:

- **Three platforms** produce attestations with matching Value X from the same source
- **Nitro full stack**: build inside enclave, TLS inside enclave via vsock, Let's Encrypt cert via TLS-ALPN-01, KMS integration with real PCR0 enforcement, remote verification from a laptop
- **Reproducible builds**: two `nitro-cli build-enclave` from the same source produce identical PCR0
- **KMS upgrade ceremony**: NodeA (PCR0 A) gets secret, NodeA' (PCR0 B) denied — hardware identity enforced
- **GitHub Action**: `maceip/unified-quote/v2/action` tested on real workflow, correctly refuses on non-TEE runners
- **One-command verify**: `uq verify --remote https://<value_x>.aeon.site` from any machine
- **Azure result (2026-05-01)**: `Standard_DC4as_v5` CVM provisions and boots with AMD SEV memory encryption, but `/dev/sev-guest` is absent and configfs-tsm report creation fails. Azure is tested, not verified, until an Azure MAA/vTOM provider or raw quote SKU exists.
