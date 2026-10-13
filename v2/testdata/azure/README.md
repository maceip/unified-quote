# Azure source fixture

`hcl-legacy-v1.bin` is the exact base64url-decoded `hcl_report_base64` test
vector in Microsoft's `ClientLibTests.cpp`, at revision
`47a35799748934ad494f396e202f053408dd342f` of
[Azure/confidential-computing-cvm-guest-attestation](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/47a35799748934ad494f396e202f053408dd342f/client-library/src/Attestation/AttestationClient/tests/lib/ClientLibTests.cpp#L684).

SHA-256: `54b5e72f382f77655f0550a3cd755dd7cf34242b7c00f8684500889b38426255`.
The vector is unchanged (2,048 bytes), including its original zero NV padding.
Microsoft's MIT license is retained in `MICROSOFT-LICENSE.txt`.

This is a historical HCL **version 1** source test vector, used to verify
explicit rejection by the current version 2 profile. It is not accompanied by
current AMD collateral or a challenge-bound TPM quote and is never treated as
successful hardware admission. Generated RSA keys and signed TPM framing
vectors in `azure_composite/tests.rs` are explicitly test-only and cannot pass
AMD endorsement verification.

`microsoft-ak-public.bin` is the 280-byte raw `TPMT_PUBLIC` (no size prefix)
from `AK_PUB_REPLY_SUCCEED` in
[Microsoft OpenVMM's TPM protocol tests](https://github.com/microsoft/openvmm/blob/1e5ed0ad0c7a705a8fd7e2c34256d2d40ae61f60/vm/devices/tpm/tpm_protocol/src/tpm20proto.rs#L3801).
The source CreatePrimary reply is 488 bytes; the public area occupies
`reply[20..300]`, and its computed object Name matches `reply[449..483]`.
SHA-256: `9257643821f968e9fc47fabf9c56497a63c2c08a12804973c38b000699e9fc22`.
The separate expected qualified-name vector was computed with Python hashlib
as `0x000b || SHA256(0x4000000b || 0x000b || SHA256(public_area))`.
Its original MIT license is in `OPENVMM-LICENSE.txt`. This public-area vector
tests the protocol parser/name derivation and is not an enrollment for a live VM.
