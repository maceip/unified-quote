# AMD SNP admission and collateral

`quote::verify::verify_platform_quote_for_admission` checks the current trusted
verifier clock, quote signature, pinned AMD certificate path, independently
supplied vendor collateral, and independently configured `CpuTcbPolicy::AmdSnp`.
The composite verifier uses this admission entry point. Missing, malformed,
expired, mismatched or unacceptable evidence is an error. It performs no network
retrieval and does not use an attester-supplied minimum version or clock.

The older `verify_platform_quote` entry point authenticates signatures, PKIX and
binding only; it does not establish acceptable CPU firmware state.
`verify_platform_quote_at` is an explicitly historical cryptographic primitive
whose caller supplies a trusted clock. Neither is an admission substitute.

## Supported profiles

SNP report versions 2 and 5, signature algorithm 1 (ECDSA P-384), VCEK and VLEK
endorsements, and pinned Milan/Genoa/Turin AMD roots are supported. Version 2 has
no signed CPUID field: its product comes from the independently selected root
policy and authenticated endorsement. Turin requires the newer profile. Unknown
report versions, product profiles, reserved values and malformed certificate
transport tables fail. The fixed SNP report is 1184 bytes; any appended table is
bounded and checked for duplicate GUIDs, overlap and truncation.

Endorsement certificates use the AMD KDS profile: RSA-PSS SHA-384 with MGF1
SHA-384 and 48-byte salt, P-384 leaf key, exact VCEK/VLEK subject and issuer
roles, AMD extension structure version, product and security patch levels.
AMD's published endorsement profile can omit leaf KeyUsage; a supplied KeyUsage
must authorize digitalSignature and forbid certificate signing. CA constraints,
path length, key usage, signature algorithms and validity are enforced for all
issuers. Unknown critical extensions and unsupported name/policy constraints
fail closed.

VCEK HWID must match signed CHIP_ID, with 64-byte Milan/Genoa or 8-byte Turin
identifiers and zero reserved tail. VLEK has an authenticated CSP ID instead of
a chip identity; that exact CSP ID must be independently enrolled. VLEK is not
represented as proof of a particular physical CPU. VCEK product stepping is
compared with signed CPUID stepping where version 5 provides it. No workaround
ignores a mismatching product name or stepping.

## Revocation and security policy

`SnpCollateral` contains a leaf-first three-certificate DER path and one complete
current DER product CRL. The ARK authenticates the CRL and it covers the ASK or
ASVK intermediate. This is AMD's KDS revocation hierarchy; version-derived
endorsement leaf acceptability additionally depends on their authenticated SPLs
and independent minimum versions. The implementation does not label a missing
leaf OCSP response as a checked response. CRLs require thisUpdate/nextUpdate and
signature verification, correct issuer and serial matching, and reject revoked,
future, expired, indirect/scoped/delta or unsupported-extension lists.

`SnpTcbPolicy` is trusted verifier configuration, separate from signed collateral:

| Field | Requirement |
| --- | --- |
| `product` | `Milan`, `Genoa` or `Turin`, selecting one pinned root |
| `minimum_tcb` | Explicit bootloader, TEE, SNP, microcode and Turin FMC minima; no all-zero profile |
| `minimum_guest_svn` | Minimum signed guest SVN |
| `expected_vmpl` | Exact signed VMPL, 0 through 3 |
| `require_smt_disabled` | When true, both policy and platform must disable SMT |
| `require_alias_check_complete` | When true, signed alias-check mitigation must be present and set |
| `minimum_launch_mitigation_vector` | Required launch mitigation bits |
| `minimum_current_mitigation_vector` | Required current mitigation bits |
| `allowed_vlek_csp_ids` | Exact enrolled IDs; empty rejects VLEK |

Certificate SPLs must equal signed REPORTED_TCB. Each component of reported,
current, committed and launch TCB must meet its minimum; current and committed
must cover the reported TCB. Provisional firmware, debug-enabled guests,
migration-agent permission, masked signing keys, and host-generated VMPL values
are rejected. Required fields absent from a legacy report fail, rather than
being assigned a safe value. An operator must maintain current minima according
to relevant vendor advisories; the library does not invent a secure version.

## Evidence and remaining validation

Tests authenticate an unchanged public AMD VCEK/report and current-at-fixture-time
AMD product CRL. That genuine report has debug enabled and correctly fails
admission. Separate claim-parser tests deliberately use unsigned mutated data
only to exercise policy branches; the signature regression verifies those
mutations cannot pass the quote verifier. Fresh CPU/GPU hardware admission and
operational provisioning remain unexercised. No successful complete combined
CPU/GPU hardware admission is claimed.

The current implementation does not support SNP report versions 3, 4 or the
extended TCB / TPM fields of later report profiles, indirect/delta CRLs, migration
agent attestation, or provisional firmware. Those inputs fail explicitly.

Sources:
- [AMD SNP ABI 56860 revision 1.58](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf), sections 2.2, 3.6, 4.3 and 7.3.
- [AMD VCEK/KDS 57230](https://docs.amd.com/v/u/en-US/57230), extension tables 9–11 and product CRL interface.
- [AMD Turin Zen 5 CPUID revision guide 58251](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/revision-guides/58251.pdf) and [Zen 5c guide 58730](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/revision-guides/58730.pdf), family 1Ah models 00h–1Fh. These processor-specific guides resolve the inconsistent model range printed in the earlier SNP ABI TCB description.
- [Google go-sev-guest AMD revocation implementation](https://github.com/google/go-sev-guest/blob/9c5dffcd8230247336e07c70804a31f6b39ab3c9/verify/verify.go), authentic fixture provenance and AMD KDS revocation hierarchy.
- [AMD GHCB 56421 revision 2.04](https://docs.amd.com/api/khub/documents/oJly8EPzLO1Bt7ncrkCytw/content), section 4.1.8.1, certificate-table UUIDs in canonical RFC 4122 byte order.
