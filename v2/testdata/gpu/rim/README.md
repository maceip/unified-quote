# NVIDIA signed RIM interoperability fixtures

These XML files are unmodified signed reference documents. Their signatures and
paths are tested at a fixed historical verification time (2026-10-13 UTC).
They are not hardware collection evidence and contain no revocation proof.
Production verification continues to require current authenticated revocation.

The driver and switch XML originate in NVIDIA/attestation-sdk commit
`11b2bfeb42a1158aa08744603ecb239ccb3d2265` under
`nv-attestation-sdk-cpp/unit-tests/testdata/`, distributed under Apache-2.0:
https://github.com/NVIDIA/attestation-sdk/tree/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata

The VBIOS XML was downloaded from NVIDIA's public RIM service on 2026-10-13:
https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_1010_0200_882_96005E0001
The service's base64 payload was decoded without modifying the XML. The
service response SHA-256 matched the downloaded bytes; this transport hash
is not substituted for certificate/signature verification.

The XML profile follows W3C XML Signature 1.1, including SignedInfo
canonicalization in its original ancestor namespace context:
https://www.w3.org/TR/xmldsig-core/

SHA-256 of exact fixture bytes:

- `NV_GPU_DRIVER_GH100_550.144.03.xml`: `585ccd55e3d9420d693f82f4a1aa0b7506f126ba2ab9344ec67e244fde0c6305`
- `NV_GPU_VBIOS_1010_0200_882_96005E0001.xml`: `622b302b120d3733c3ece11d2d4cb3487cafc6f99e19a9d726b14ab9e7222bba`
- `switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml`: `c0f2e7f20da21da7287390c08c2641388595cd6929baaf0b5f728c4751a1f1d6`

The `.diag` CoRIM examples are unmodified **unsigned** NVIDIA examples from
`nv-attestation-sdk-cpp/unit-tests/testdata/sample_rims/corim/` at the same
commit. Parser tests extract their embedded CoMID bytes. Separate signing tests
use explicitly test-only P-384 certificates, real ECDSA signatures and signed
CRLs; they never represent NVIDIA-issued CoRIM credentials. No genuine signed
NVIDIA CoRIM artifact is included in the upstream fixture set.

The CoRIM implementation's supported typed claim subset is documented in
`v2/src/gpu/corim.rs`. It implements COSE RFC 9052/9360 authentication and the
CoRIM draft-11 inline envelope with protected content type and signer metadata;
unsupported extensions, dependent external RIMs, linked tags and unknown triple
kinds fail explicitly rather than being silently ignored. This authentication
API does not substitute CoMID environment claims for the XML GPU appraisal.

- https://www.rfc-editor.org/rfc/rfc9052.html
- https://www.rfc-editor.org/rfc/rfc9360.html
- https://datatracker.ietf.org/doc/draft-ietf-rats-corim/11/

Additional SHA-256 values:

- `blackwell_fsp_real.diag`: `0ef18649113cb7d157497c857694b82570a0c2c67fa1c0a663cc3f43cecb4e0b`
- `rubin_driver_example.diag`: `d7dcb361e4082e55d413150810f129c1df534aa02407483aa3f11d6f6dbaddb9`
- `rubin_vbios_example.diag`: `0f773344130e574f95d89f438e20993eb55a0d1a3e2f0b71f92f0c540e946f16`

The upstream Apache-2.0 license is retained in `../nvidia/LICENSE`.
