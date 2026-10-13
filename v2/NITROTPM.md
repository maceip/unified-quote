# AWS NitroTPM signed documents

`tee::tpm::collect_nitrotpm_document(&nonce, Some(&user_data))` collects the
binary AWS NitroTPM COSE document through the installed AWS `nitro-tpm-attest`
tool. The request supports a 32-byte challenge and up to 1024 bytes of user data.
The composite attestation path uses the full 64-byte EAT report-data commitment
as user data, and independently requires the SNP report to sign that commitment.
The shared commitment prevents evidence substitution; it does not independently
prove that the two signing devices have a physical attachment.

The collector checks the returned structure and exact request bytes. These are
unverified transport bytes until `verify_nitrotpm_document` succeeds. Tool
errors, malformed output, and challenge mismatches are errors. No sysfs or
alternate-provider fallback is part of attestation. The separately named
`read_unverified_sysfs_pcrs` returns diagnostic data only.

Collection uses fixed executable paths, a cleared environment, a fresh private
directory under `/tmp`, exclusively created request files, a 20-second deadline,
and bounded stdout/stderr. Each invocation has its own process group; timeout or
output failure kills that group. There is no shared nonce file. This reuses the
tool dependency present in the previous collector and adds no library.

## Verification and policy

The verifier accepts tagged or untagged COSE_Sign1, requires protected ES384 and
an empty unprotected header, and verifies the exact encoded signed payload. It
checks the AWS commercial Nitro root fingerprint, every certificate signature,
validity, CA/path constraints, key usage, and approved algorithms through the
existing CPU PKIX implementation. The AWS published NitroTPM profile explicitly
disables CRL checking; this implementation does not invent a revocation source.

The parser preserves map entries while checking duplicate claims and PCR
indices. It accepts `nitrotpm_pcrs`, rejecting the enclave-only `pcrs` claim. The
document is bounded to 32 KiB, the signing path to ten bundled CAs, and each
certificate to the published 1024-byte limit. It requires the published PCR set
0 through 16 and 23. The profile's `digest` string is `SHA384`; the schema also
permits PCR values of 32, 48, or 64 bytes. The caller must independently choose
the actual SHA-256, SHA-384, or SHA-512 PCR bank through `pcr_algorithm`; every
received PCR must have that bank's width.

`NitroTpmPolicy` is independently configured and has these required fields:

- `pcr_algorithm`: TPM SHA-2 algorithm identifier, 11, 12, or 13.
- `expected_pcrs`: map from PCR index to the exact approved digest in hex.
- `max_age_secs`: from 1 through 3600 seconds.
- `max_future_skew_secs`: from 0 through 30 seconds.

At least one expected PCR must be a nonzero static measurement at index 2
through 15. Policies containing only AWS constants or resettable registers are
rejected. Every configured PCR must match. The nonce and optional user data must
match exactly, including the distinction between absent and present data.
`now_secs` in the low-level verifier must come from a trusted verifier clock,
never the received document; the integrated verifier obtains its own clock.

Only successful verification constructs `VerifiedNitroTpm`. Its
`authenticated_registers()` method exposes PCR2 through PCR15 to authenticated
boot replay. AWS intentionally replaces PCR0 and PCR1 with constants, so neither
can authenticate early firmware event replay. PCR16 and PCR23 are not promoted
as static boot measurements. AWS labels PCR16 as Debug but does not publish a
security-state mapping in the document specification; this code makes no
enabled/disabled debug claim from that label. The independent SNP policy checks
the SNP report's signed debug state.

Tests use explicitly constructed malformed COSE and cryptographic vectors,
untrusted signing roots, a previously captured TCG2 log to test PCR coverage, and
bounded shell subprocesses to test transport cancellation. They are source and
cryptographic checks, not captured NitroTPM hardware validation.

## Primary references

- [AWS NitroTPM document validation and CDDL](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html)
- [AWS NitroTPM PCR contents and constant PCR0/PCR1 behavior](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html)
- [AWS NitroTPM-Tools collector CLI](https://github.com/aws/NitroTPM-Tools/blob/441fe310cce206efc79d88287fa2ee00355f5ce3/nitro-tpm-attest/src/main.rs)
- [AWS NitroTPM-Tools vendor-request implementation](https://github.com/aws/NitroTPM-Tools/blob/441fe310cce206efc79d88287fa2ee00355f5ce3/nitro-tpm-attest/src/lib.rs)
