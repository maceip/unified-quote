# Azure HCL SNP and vTPM composite profile

The `sev-snp` feature exposes `tee::azure_composite`. Its validator requires
both an AMD-authenticated HCL report and a fresh quote from the HCL-endorsed,
independently enrolled vTPM attestation key. Collection produces evidence; it
does not produce an admission verdict.

## Supported protocol

The parser implements the published Microsoft HCL version 2 layout, runtime
version 1, AMD SNP report type 2 and SHA-256 hash type 1. All declared lengths
must agree. The report can end at its declared size or occupy the documented
2,600-byte NV buffer with an entirely zero remainder. Other versions, report
types, hash profiles, unknown runtime JSON fields, duplicate keys and malformed
reserved fields are rejected. Runtime JSON is extracted only from the declared
offset and length; its exact bytes must hash to SNP `REPORT_DATA[0..32]`, and
the remaining 32 bytes must be zero.

The fresh TPM quote contains raw `TPMS_ATTEST` with no `TPM2B_ATTEST` size
prefix. It must be `TPM_ST_ATTEST_QUOTE`, identify one SHA-256 PCR bank with
a three-byte bitmap, cover exactly the supplied static PCRs 0–15, and contain
the SHA-256 digest of those PCR values in increasing order. Its complete body
is verified against the endorsed AK using exact `TPMT_SIGNATURE`
RSASSA/SHA-256 framing. TPM `clockInfo.safe` must be true. The qualified signer
must match the name derived from the independently enrolled full AK public
area and endorsement hierarchy. A JWK or syntactically valid name cannot
establish the key's restricted signing role.

The quote's 32-byte `extraData` must equal:

```text
SHA256("uq/azure-hcl-vtpm/eat-report-data/v1\0" || EAT_report_data_64)
```

Both 32-byte halves of the parent EAT commitment are mandatory. The parent must
derive these bytes from its independently expected nonce, TLS public key,
Value X and complete evidence commitment. Runtime `user-data`, HCL historical
timestamps, or evidence-supplied expected values cannot supply this challenge.

## Independent policy and current AMD appraisal

`AzureCompositePolicy` requires version 1, one or more non-placeholder AK DER
SPKI SHA-256 pins, a corresponding `enrolled_ak_public_areas` entry per pin,
one or more approved 48-byte SNP paravisor measurements, an enrolled VM UUID,
and an exact nonempty SHA-256 PCR profile. Policy indices
must be strictly increasing; a profile with all PCR values zero is rejected.
Console access requires explicit `allow_console: true`. Authenticated runtime
claims must assert secure boot, TPM enablement and TPM persistence. The JWK
profile requires exactly `HCLAkPub` with `key_ops: ["sign"]` and `HCLEkPub` with
`key_ops: ["encrypt"]`, exponent 65537 and canonical unpadded base64url. The
enrolled AK is restricted to the published Microsoft RSA-2048 primary template;
EK parsing supports RSA 2048/3072/4096. Older/unknown profiles require explicit
implementation, not a relaxed fallback.

Every enrolled public area is exactly the 280-byte raw `TPMT_PUBLIC`, without
the `TPM2B_PUBLIC` length prefix. Enrollment must obtain the **actual full public
area through a trusted provisioning channel**, verify its key against HCL and
the VM enrollment, and preserve those bytes in verifier-owned policy. Never
construct that enrollment by attaching desired attributes to an evidence JWK,
or copy it from the received request. The validator requires RSA/SHA-256,
RSASSA/SHA-256, the default exponent encoding, empty authPolicy, and exactly
`fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | restricted |
signEncrypt` (`0x00050472`). It derives the object Name from that exact public
area, then the qualified Name under `TPM_RH_ENDORSEMENT`, and compares the
signed quote field. The public-area key and SPKI pin sets must be identical.

This enrollment requirement is substantive: Microsoft OpenVMM's published
`ak_pub_template()` creates that restricted key, but `create_ak_pub()` can
retain an existing key with different attributes while denying AK certificate
renewal. The runtime JWK does not include those attributes. An unrestricted
signing key could sign fabricated quote-shaped bytes, so an n/e/key_ops check
or a mathematically valid RSA signature alone is insufficient evidence of a
TPM PCR snapshot. The independently approved public area supplies the missing
role constraint; paravisor approval and current AMD appraisal remain required.

The caller separately supplies current `SnpCollateral` and an independent
`SnpTcbPolicy`; HCL additionally requires VMPL0. The production AMD admission
path checks pinned roots, certificate signatures and validity, endorsement
SPL/report matching, authenticated current revocation evidence, security flags
and TCB floors using the verifier's current clock. Azure verification performs
no implicit network fetching and exposes no historical-clock accepting API.

`verify(evidence, report_data_64, azure_policy, collateral, tcb_policy)` is the
only constructor of `VerifiedAzureComposite`. Its `measurements()` accessor
preserves authenticated SNP values, including the HCL `REPORT_DATA`, and adds
`TPM_PCR{index}`, `AZURE_AK_SPKI_SHA256`, `AZURE_AK_QUALIFIED_NAME`, and
`AZURE_EAT_REPORT_DATA`. The last
value is authenticated through the quote's domain-separated hash; it is not
the static SNP report-data field. `authenticated_registers()` supplies the
quoted PCRs to the boot-log verifier. Additional boot/UKI policy belongs to
the parent attestation verifier.

## Evidence and collection API

Evidence contains `version`, `hcl_report`, `quote_message`, `quote_signature`,
and `pcrs: [{index, value}]`. Bytes serialize as JSON byte arrays, consistent
with the existing Rust collateral format. `from_json` bounds the complete
document to 48 KiB, rejects unknown fields and duplicate known fields, then
checks component sizes and index uniqueness. Evidence contains no policy,
expected nonce, expected TLS key, expected PCR profile or collateral URLs.
The separate policy parser permits at most 128 KiB and 64 AK enrollments.

```rust,ignore
let evidence = azure_composite::collect(&report_data, &[0, 2, 4, 7, 11])?;
let wire = evidence.to_json()?;
// On the relying party, these policy/collateral arguments come from its own
// trusted configuration, independently of the received evidence:
let evidence = AzureCompositeEvidence::from_json(&wire)?;
let verified = azure_composite::verify(
    &evidence, &expected_report_data, &policy, &amd_collateral, &amd_tcb_policy,
)?;
```

The default Linux collector explicitly uses `/usr/bin/tpm2_nvread`,
`/usr/bin/tpm2_quote`, `/dev/tpmrm0`, NV index `0x01400001` and AK handle
`0x81000003`. `AzureCompositeCollector::new(nvread, quote, device)` accepts
absolute operator-selected tool paths and an explicit `/dev/tpmrm0` or
`/dev/tpm0` device. It never searches PATH or switches transport on failure.
No tool is installed automatically and no TPM NV data is written. The existing
tpm2-tools installation must support `tpm2_quote -F values` and explicit
RSASSA/SHA-256 output.

Each command has a 15-second deadline, runs without a shell in a fresh private
0700 directory, and uses bounded output files. PCR bytes are obtained by the
same quote command, then checked against its signature, selection and digest;
the collector does not return mismatched PCR-read snapshots. Collection still
does not establish vendor trust or approve any guest state. Missing hardware,
tools, required claims, policy or fresh collateral are errors.

## Assurance and qualification boundary

HCL endorses the paravisor/UEFI and AK. The fresh AK quote authenticates the
request and selected guest PCRs. Neither step alone proves a running workload,
mounted root filesystem, physical GPU attachment, or a source-build claim.
Those require the corresponding independently approved boot, runtime,
workload and GPU policies. The HCL `root-cert-thumbprint` is authenticated
metadata only and is never a newly accepted trust anchor.

Source checks and signed test-key negative tests are possible without a CVM.
Successful current Azure admission is not claimed from those tests. Live
qualification still needs a supported HCL v2 capture, its AK quote, current
AMD collateral, independently enrolled full AK public-area/VM/paravisor/PCR
policy and exercised
collector behavior on the actual guest. The retained Microsoft v1 fixture is
an explicit unsupported-profile regression, not successful admission proof.

## Sources

- [Microsoft HCL layout and trust design](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design).
- [Microsoft Azure guidance, pinned source](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/47a35799748934ad494f396e202f053408dd342f/cvm-guest-attestation.md), which identifies the HCL report as boot-generated and describes its coverage.
- [Microsoft HCL structures](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/47a35799748934ad494f396e202f053408dd342f/client-library/src/external/SnpVmReport/SnpVmReport.h), a historical version 1 reference; the current profile uses version 2 from the published layout.
- [tpm2-tools 5.7 quote options](https://github.com/tpm2-software/tpm2-tools/blob/5.7/man/tpm2_quote.1.md) and [PCR values output](https://github.com/tpm2-software/tpm2-tools/blob/5.7/lib/pcr.c).
- [Microsoft's pinned AK template and provisioning behavior](https://github.com/microsoft/openvmm/blob/1e5ed0ad0c7a705a8fd7e2c34256d2d40ae61f60/vm/devices/tpm/tpm_lib/src/lib.rs) and [expected AK attributes](https://github.com/microsoft/openvmm/blob/1e5ed0ad0c7a705a8fd7e2c34256d2d40ae61f60/vm/devices/tpm/tpm_protocol/src/lib.rs).
- [Microsoft TPM reference Name and qualified Name derivation](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/subsystem/Object.c).

These sources were inspected as protocol references. No additional Rust or Go
library was adopted for this implementation.
