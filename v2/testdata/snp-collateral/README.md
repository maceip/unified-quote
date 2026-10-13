# AMD SNP certificate and report fixtures

`google-milan-debug-report.bin` and `google-milan-vcek.der` are unchanged public
hardware-report / AMD KDS certificate fixtures from Google go-sev-guest
revision `9c5dffcd8230247336e07c70804a31f6b39ab3c9`, respectively
`verify/testdata/attestation.bin` and `verify/testdata/vcek.testcer`:
https://github.com/google/go-sev-guest/tree/9c5dffcd8230247336e07c70804a31f6b39ab3c9/verify/testdata
Copyright 2022 Google LLC, Apache-2.0; see LICENSE-GOOGLE. The report is debug
enabled and MUST NOT pass admission, even though its signature is authentic.

`amd-milan-chain.pem` and `amd-milan-2026-09.crl` are unchanged public AMD KDS
responses retrieved on 2026-10-13 from:
- https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
- https://kdsintf.amd.com/vcek/v1/Milan/crl

The CRL is valid from 2026-09-22 07:35:42 through 2026-11-09 01:00:00 UTC.
Archival tests use the independently fixed 2026-10-13 clock. It is not current
collateral for deployment; tests explicitly reject use past nextUpdate.

SHA-256:
- report: `377e6241d3b373ab1df80c0f96978594e7e21f4797dd6ea95e2957e1c1e26060`
- VCEK: `0d057f9b6e29a69eda9c0154b259567d291c1c08d73a11e9d31ace07c435b6d8`
- chain: `22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6`
- CRL: `dd68e9e3feb97dd0e95135feeae47d9cc193c73239a6281ec9884c00d5e6a525`

Sources for parsing/appraisal: AMD SNP ABI 56860 rev 1.58 sections 2.2/7.3 and
AMD VCEK/KDS 57230 tables 9–11 and section 4.3. AMD KDS revocation is an
ARK-signed product CRL covering ASK/ASVK. Endorsement leaves are version-derived
and their approved versions require independent policy; no absent leaf OCSP
response is synthesized. Google go-sev-guest `verify/verify.go` documents and
implements the same vendor revocation hierarchy.
