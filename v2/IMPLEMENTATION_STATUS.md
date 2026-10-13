# Production implementation and hardware acceptance

Work authorized 2026-10-13. No deployment or admission for users before the
joint hardware acceptance pass. This ledger distinguishes implementation from
hardware evidence; an unchecked item is not a completion claim.

## Implementation work

- [x] Pinned NVIDIA certificate trust, validity, constraints and algorithms.
- [x] Authenticated OCSP/direct CRL checking, raw-byte cache, expiry and strict
  missing-status rejection. Alias coverage remains unresolved below.
- [x] XMLDSig driver/VBIOS/LS10 reference manifests and measurement extraction.
- [x] Signed CoRIM/CoMID authentication and typed reference claims. CoRIM device
  appraisal is a separate unfinished profile, not an XML substitute.
- [x] Signed GPU security-state and measurement policy for supported profiles,
  including explicit rejection of absent/masked required fields.
- [x] NVSwitch certificates/reports and enrolled reciprocal fabric policy.
- [x] CPU/GPU EAT commitments, exact inventory, nonce and TLS SPKI binding.
- [x] Collector/verifier builders, captured-token CLI and structured verdicts.
- [x] TCG 2.0/CCEL parsing and authenticated replay; measured command-line
  dm-verity root comparison and explicit immutable-file closure identity.
- [x] Bounded PE32/PE32+ UKI section parsing and systemd-stub v258 measurement
  pairs; authenticated embedded metadata and independent section/verity policy.
- [x] TPM exact quoted-PCR coverage and authenticated IMA template reconstruction.
- [x] Local fresh-evidence service, systemd source, and downstream Rust adapters.
- [x] Exact-source/binary provenance consumption and manual release hold.
- [x] Bounded configfs collection, corrected SNP Linux ioctl ABI and rejection
  of MAC-only TDREPORTs as remote quotes.
- [x] Strict CPU PKIX and Nitro signature checking; current Intel TDX collateral,
  QE/module/TCB/CRL appraisal; AMD SNP endorsement/SPL/HWID/CSP/CRL appraisal.
- [x] Independent CPU TCB floors and launch measurements in composite admission;
  no guessed AMD product, unapproved debug state or absent vendor collateral.
- [x] Pinned Google `go-eventlog` replay through a bounded local helper;
  explicit all-four-RTMR coverage, disabled inferred events, request correlation,
  process deadlines, dependency-owner enforcement and license notices.
- [x] CoCo AAEL RTMR3 parsing, exact measured preimages and independently
  approved ordered runtime-event policy.
- [x] Explicit UKI multi-profile/device selection and effective command-line
  policy for systemd-stub v258, including supported measured add-ons.
- [x] Native Linux mounted dm-verity observation and strict table policy,
  exposed only as an unverified diagnostic rather than invented mount proof.
- [x] Exact prior-stage receipt pins, complete chain appraisal, independent
  per-stage image/TCB/boot/GPU policy, bounded ancestry and full EAT binding.
- [x] Explicit Azure SNP/vTPM and AWS SNP/NitroTPM collection and verification
  profiles, independent TPM policy, full EAT commitment and authenticated PCR
  inputs to measured-boot verification. Azure requires trusted enrollment of
  restricted TPM public areas and verifies their signed qualified names.
- [x] Per-request SDK attestation and actual request-connection TLS key checks
  across all four downstream clients. Reconnects recheck before HTTP bytes;
  failed refresh, changed keys and expired consumption windows reject.
- [x] Removed structural SDK admission, signature-only relay admission,
  legacy Azure network admission, automatic TLS downgrade and unauthenticated
  remote key/certificate administration. Registry keyless identities cannot
  authorize entries without a complete Fulcio/transparency verifier.

Completed source mechanisms are not claims that a supported device has passed
the complete policy. [GPU.md](GPU.md), [BOOT_MEASUREMENTS.md](BOOT_MEASUREMENTS.md)
and [ATTESTATION_SERVICE.md](ATTESTATION_SERVICE.md) describe their exact inputs.

## Outstanding source or vendor-profile requirements

- Obtain an authoritative, authenticated NVIDIA alias-revocation coverage
  contract. The reference SDK skips aliases, while this policy requires fresh
  status for every non-root. Unsupported status is never assumed good.
- Establish a GPU/LS10 evidence profile containing all required signed security
  fields. Historical Hopper/LS10 captures omit some; the published Blackwell
  capture reports not-configured. None is promoted to production-ready.
- Establish authoritative typed fabric/chip-info discriminators for newer
  NVDAOD profiles. Unsupported consumed types reject; older published layouts
  and compatible NVDAOD minor/patch versions have explicit parsing rules.
- Implement CEC appraisal and CoRIM device-reference matching once supported
  published device profiles establish the necessary semantics. Nonempty CEC
  currently rejects; authenticated CoRIM remains a separate manifest API.
- Connect Google's TDX v4/v5 verifier/collector and reviewed GPU/NVSwitch
  packages after approval for their required non-Google dependencies. The
  event-log helper is already integrated. Standard-library CPU policy guards
  are staged but are not a substitute for the pending vendor verification calls.
- Implement the separately selected legacy QGS transport if required by the
  target. Current native TDX collection requires complete DCAP v4 quotes through
  configfs; MAC-only TDREPORTs cannot become remote quotes.
- Complete Authenticode trust/signature/revocation appraisal using Google's
  parser/digest library after approval of its required RustCrypto CMS dependency.
  Existing UKI section measurements and enrollment remain independently checked.
- Extend additional Azure HCL versions, TPM algorithm profiles or signed
  NitroTPM debug semantics only from authoritative formats and independently
  approved enrollment. The current supported profiles are documented in
  [AZURE_COMPOSITE.md](AZURE_COMPOSITE.md) and [NITROTPM.md](NITROTPM.md).
- A mounted-filesystem observation requires an approved measuring component
  and authenticated observation policy before it can become admission proof.
  Current boot/UKI policy proves measured roots, while the native mount inspector
  reports observations explicitly as unverified.
- Registry keyless signatures need full pinned Fulcio, certificate-time, SCT
  and Rekor proof verification. Independently pinned raw-key signatures remain
  supported; certificate identity labels alone always reject.
- Rebuild the four native Linux images on their configured build host with
  actual approved release pins. No binary/source digest has been invented.

## Acceptance requiring hardware

- [ ] Fresh NVML GPU collection on the actual driver/hardware combinations.
- [ ] Fresh NSCQ collection and physical NVLink/fabric correspondence.
- [ ] Current vendor collateral retrieval for the deployed firmware and driver.
- [ ] CPU quotes carrying composite commitments and observed TLS key binding.
- [ ] Boot-log replay versus the platform's signed PCR/RTMR values.
- [ ] GPU reset, missing-device, debug/CC-mode and fabric-change failure cases.
- [ ] End-to-end service behavior and explicit operator approval for admission.

The new library decision and exact approval-dependent package list are recorded
in [UPSTREAM_REUSE.md](UPSTREAM_REUSE.md); no pending dependency has been adopted.

The release workflow requires `UQ_HARDWARE_ACCEPTED_SHA` to equal the dispatched
commit. The downstream installer leaves the attestation service disabled.
This work has not enabled either gate or performed a guest-image build,
deployment or hardware acceptance.

## Source validation

The final macOS source matrix passed with **197 default-feature Rust tests**
and **281 all-feature Rust tests**, zero failures. Two preexisting archival SNP
regressions remain ignored because their original cloud-provisioned VLEK
endorsement leaves were not captured; public KDS cannot supply them. These
counts include cryptographic vectors, parser/transport checks and captured
regressions, and do not claim current device admission. Individual no-default,
GPU, Nitro, TDX and SNP feature checks passed. Formatting and whitespace checks
passed; the compiler still reports warnings in existing and feature-specific
code, so this is not a warning-free result.

The Google helper passed `go test ./...`, `go vet ./...`, a real subprocess
captured-CCEL replay and rejection of a changed unlogged register. The helper
built natively for macOS and cross-compiled for Linux amd64, with actual linked
licenses and production dependency-owner checks. Full native Linux Rust/image
builds have not run: the available SSH attempt to `axp.computer` was rejected
by public-key authentication, and local Linux Rust linking lacks the cross C
compiler. Linux collector code has separate compile/contract checks, which do
not substitute for a native image build.

The four downstream Python suites passed **273 tests** total: dev 69,
vLLM 68, SGLang 68 and relay 68. Their TLS continuity tests perform actual local
TLS handshakes and assert zero HTTP bytes on rejected connections; attestation
subprocess results in those transport tests are explicitly mocked, not hardware
verdicts. Bash syntax, Python source compilation and diff checks passed. Release
helper copies retain their existing pins and activation gates. No source check
has enabled deployment or admission.
