# Captured Intel PCS collateral

Fetched on 2026-10-13 from Intel production endpoints. These are original signed
JSON bytes, X.509 DER certificates and DER CRLs. They are test evidence with
finite validity, never bundled production policy or a live acceptance result.

- QE identity: https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity
- TCB Info: https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00806f050000
- PCK CRL: https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der
- Root CRL: https://certificates.trustedservices.intel.com/IntelSGXRootCA.der

The signing certificates were decoded from the URL-encoded issuer-chain response
headers. Root certificate SHA-256 must match the existing pinned Intel root.
Unit checks use fixed trusted verification time 2026-10-13T12:00:00Z and an
explicit evaluation-data floor of 20. The existing repository TDX quote is
older than the highest platform TCB level and must be rejected as OutOfDate.

## SHA-256

- `pck.crl.der`: `f0f016e8d7c006e46c429391834578c2c157dce96a3a402d50b40287cff2b5e8`
- `qe-identity.json`: `9d25d55dec58a9fdf77c0bc42c16d017c9f8caf801718c2af96a49c05e215a8a`
- `qe-signer-0.der`: `c0575e76d0303b61d09cde8cbdb70db34a74f38318300d7c0e6ba8cf4bf45aea`
- `qe-signer-1.der`: `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`
- `root.crl.der`: `c114be5d5ca7aab2d37817eca55aa8a2353853809904ff3695b31c26bcb7465b`
- `tcb-info.json`: `f58543a0a03c98d4a0ec0fa6bbae3fa35b9c5e232a5c2afe363c743cfa326e0f`
- `tcb-signer-0.der`: `c0575e76d0303b61d09cde8cbdb70db34a74f38318300d7c0e6ba8cf4bf45aea`
- `tcb-signer-1.der`: `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`
