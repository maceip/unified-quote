# NVIDIA SPDM reference vectors

These files are unmodified NVIDIA Attestation SDK test fixtures from
revision `11b2bfeb42a1158aa08744603ecb239ccb3d2265`:

- [hopperAttestationReport.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/hopperAttestationReport.txt)
- [hopperCertChain.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/hopperCertChain.txt)
- [blackwellAttestationReport.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/blackwellAttestationReport.txt)
- [blackwellCertChain.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/blackwellCertChain.txt)
- [nvdaodAttestationReport.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_nvdaod_transcript.txt) (upstream filename `sample_nvdaod_transcript.txt`)
- [switchAttestationReport.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/switch/switchAttestationReport.txt)
- [switchCertChain.txt](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/switch/switchCertChain.txt)

Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
Distributed under Apache-2.0; the upstream license is included as `LICENSE`.

Reports are hex-encoded; certificate chains are PEM, leaf first. The Hopper
Blackwell and LS10 vectors support report-signature, certificate-path, and DICE
parsing tests. They do not include current revocation evidence or a complete
admission policy. Their historical nonces must never become live challenges.

The NVDAOD vector has **no matching certificate chain** in the published
fixture. It is used only to check wire-format parsing, including the typed
feature flag and header version. No signature or authenticity verdict is
asserted for that vector. Passing these tests is interoperability evidence,
not a live GPU test or a successful production admission.
