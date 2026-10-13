# NVIDIA trust anchors

These PEM certificates are pinned from NVIDIA attestation-sdk revision
`11b2bfeb42a1158aa08744603ecb239ccb3d2265`,
`nv-attestation-sdk-cpp/src/internal/certs.h`:

- `device-identity.pem`: `DEVICE_ROOT_CERT`
- `rim-signing.pem`: `RIM_ROOT_CERT`
- `rim-ca001.pem`: `RIM_ROOT_CERT_CA001`

Source: https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/src/internal/certs.h

NVIDIA source is Apache-2.0 licensed; the source license is preserved at
`v2/testdata/gpu/nvidia/LICENSE`. Certificate validity is enforced at the
verifier's trusted current time, including for these roots. Evidence-provided
self-signed certificates never become trust anchors. Updating a trust anchor
requires an explicit software/configuration update, never an evidence field.
