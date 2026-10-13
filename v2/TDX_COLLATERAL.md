# Intel TDX collateral appraisal

Composite TDX admission requires both an authentic quote and explicit Intel
collateral with independent verifier policy. `quote::tdx_collateral::TdxCollateral`
is evidence: it contains original PCS TCB Info and TD QE Identity response bytes,
their DER signing chains in leaf-to-root order, a DER Intel root CA CRL and a DER
PCK issuer CRL. The `CpuTcbPolicy::IntelTdx` minimum evaluation-data number comes
from verifier configuration. A received quote or collateral file cannot select
that floor. Zero is rejected.

The production admission API calls the collateral appraiser after authenticating
the quote, PCK-signed QE report and the QE binding to the attestation public key.
Its result is not available as an independently deserializable trusted-quote type.
The module performs these checks:

- Exact quote-v4 framing and certification types 6 (QE report) and 5 (PCK chain).
- Intel root pin, certificate signatures, validity, CA constraints and key usage
  through shared CPU PKIX. PCK leaf and issuer roles and collateral signer roles
  are constrained. The root CRL covers the PCK issuer and both JSON signers; the
  PCK CRL covers the PCK leaf. Missing, expired, malformed, scoped or unauthentic
  required CRLs reject admission.
- ECDSA-P256/SHA256 over the exact original `tcbInfo` and `enclaveIdentity` object
  bytes retained with `RawValue`. Reformatting a signed object is unsupported;
  supply the original response rather than parsing and regenerating it. Duplicate
  and unknown JSON fields reject. Each response is limited to 1 MiB.
- TDX TCB Info version 3, TCB type 0, TD_QE Identity version 2, valid issuance and
  expiration times, and both evaluation-data numbers at or above enrolled policy.
- QE MRSIGNER, product ID, MISCSELECT and ATTRIBUTES masks, debug-disabled state,
  and the first matching SVN level. A selected status must be `UpToDate`.
- PCK SGX extension FMSPC/PCEID equality, all 16 SGX component SVNs, PCESVN, and the
  relevant TEE_TCB_SVN components. Matching follows the signed TCB-level ordering;
  an unacceptable matching level cannot be skipped in favor of a weaker entry.
- TDX module version selection (`TDX_XX`), module SVN, MRSIGNERSEAM and SEAM attribute
  mask. Module version zero uses the base module profile. Higher versions require
  a matching signed module identity. The supported profile requires zero SEAM
  attributes. Selected module status must also be `UpToDate`.

The PCK extension parser enforces DER, unique known OIDs, required fields and their
fixed widths. The component SVNs drive matching; the opaque CPUSVN bytes are not
mistaken for independently ordered component security versions. No URL from a
received document is fetched by this module. Certificates and vendor statements
cannot replace the independently enrolled CPU launch measurement.

`MRENCLAVE` and `MRSEAM` are not supplied as golden measurements by these Intel
identity structures. The appraiser makes no invented allowlist claim about them;
Intel's signer/product/security-version rules are enforced. TDX quote v5,
DICE/CWT, unknown TCB types, future nonzero SEAM attributes and unrecognized
collateral schemas reject as unsupported. Legacy TDX QGS transport remains a
separate source limitation. No hardware collection or service activation was
performed for this implementation.

The [captured fixture record](testdata/tdx-collateral/README.md) pins Intel responses
retrieved on 2026-10-13. Checks authenticate their signatures and current CRLs at
an explicit fixture time. The repository's older GCP quote is deliberately
rejected as `OutOfDate` against those responses; it is not relabeled as a positive
hardware acceptance result. Negative cases cover changed signed bytes, policy
rollback, missing/broken CRLs, identity masks and SVNs, module mismatch, dates,
ambiguous JSON and truncated quote framing.

Primary format references:

- [Intel PCS API and comparison rules](https://api.portal.trustedservices.intel.com/content/documentation.html)
- [Intel quote/module appraisal](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/main/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp)
- [Intel QE report matching](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/main/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp)
- [Intel PCK SGX-extension parser](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/main/Src/AttestationParsers/src/X509/PckCertificate.cpp)
- [Intel module identity selection](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/main/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp)
