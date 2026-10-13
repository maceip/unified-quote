# GPU verifier library review — 2026-10-13

Research only. No project dependency, verifier, collector, deployment, or admission setting was changed during this review.

## Candidate and exact pins

| Repository owner / component | Reviewed revision and version | License | Fit |
| --- | --- | --- | --- |
| Google / `google/go-nvattest-tools` | `1a098bebccd3790f71e7e6403c4f15a85f0a3494`; Go proxy confirms `v0.0.0-20261009053956-1a098bebccd3`; no Git release tags found | Apache-2.0 | Reusable local legacy SPDM, XML RIM, GPU/NVSwitch verification and PPCIE topology APIs. README says this is not an officially supported Google product. |
| Google Cloud / `GoogleCloudPlatform/confidential-space` | `78a680fd8b60b08822115d0d138ea4d7b70fb787` | Apache-2.0 | CPU-bound COS event-log extraction includes GPU state and serialized GPU evidence; it is not the local GPU certificate/SPDM/RIM verifier. |
| NVIDIA / `NVIDIA/attestation-sdk` | tag `2026.10.02`, commit `11b2bfeb42a1158aa08744603ecb239ccb3d2265`; Rust bindings workspace version `2.0.0` | Apache-2.0, plus dependency licenses | Current vendor C++ SDK with C API and Rust FFI; legacy XML, typed opaque/minimum-SVN and an experimental CoRIM/CMW/EAR verifier. Additional non-Google dependency approval would be needed. |
| Confident Security / `confidentsecurity/go-nvtrust` | HEAD `33efe3bbb4ffa918cdfadb30193b12fba624d979`; latest tag `v0.2.2` = `8961b5e9887be0c2f4123fd09023be1aeebbaa25` | Apache-2.0 | GPU/NVSwitch collection and remote NVIDIA NRAS JWT verification; not a local XML/CoRIM verifier. This is neither Google-owned nor NVIDIA-owned. |

Primary sources: [Google GPU repository](https://github.com/google/go-nvattest-tools/tree/1a098bebccd3790f71e7e6403c4f15a85f0a3494), [official Google Cloud GPU instructions](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation#gpu-based_attestation), [Confidential Space GPU evidence schema](https://github.com/GoogleCloudPlatform/confidential-space/blob/78a680fd8b60b08822115d0d138ea4d7b70fb787/server/proto/gpu_attestation.proto), [NVIDIA SDK README](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/README.md), [go-nvtrust README](https://github.com/confidentsecurity/go-nvtrust/blob/33efe3bbb4ffa918cdfadb30193b12fba624d979/README.md).

NVIDIA's [nvtrust README](https://github.com/NVIDIA/nvtrust/blob/main/README.md) deprecates the Python SDK and Local GPU Verifier in favor of this C++ SDK. That README does not establish an exact deprecation date, so no date is inferred here.

## Minimal production dependency closure

The runtime list below is from non-test imports of `spt`, `mpt`, `ppcie/server`, their `server`, `abi`, and generated proto dependencies, plus the two patched XML forks. Collection packages and command-line packages are excluded.

| Non-Google runtime component | Required version / replacement | License | Reason |
| --- | --- | --- | --- |
| `github.com/beevik/etree` | `v1.6.0` | BSD-2-Clause | XML tree operations |
| `github.com/russellhaering/goxmldsig` | `v1.6.0`, **replaced** by `github.com/atulpatildbz/goxmldsig v0.0.0-20260325075722-e806be5e3c3a`; full fork SHA `e806be5e3c3ac90a79b0c6e9921aae48ab21e53c` | Apache-2.0 | XML signature/canonicalization implementation required by upstream |
| `github.com/lestrrat-go/libxml2` | `v0.0.0-20260304224138-bb3877930cf7`, **replaced** by `github.com/atulpatildbz/libxml2 v0.0.0-20260624132807-d06374c0f56f`; full fork SHA `d06374c0f56fe2f3e7ff6dacc46d0d376a6c88bd` | MIT | cgo XML/XSD bindings; Google uses this for RIM schema validation |
| `github.com/pkg/errors` | `v0.9.1` | BSD-2-Clause | libxml2 binding runtime dependency |
| `github.com/jonboulle/clockwork` | `v0.5.0` | Apache-2.0 | XML verifier clock abstraction |
| `go.uber.org/multierr` | `v1.11.0` | MIT | `mpt` error aggregation; unnecessary if avoiding that orchestrator, but CPU integration already requires it |
| Native GNOME `libxml2` | Recommended candidate `2.15.4`, source SHA256 `98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821` | MIT | Required by cgo via `pkg-config libxml-2.0` |

Both Go `replace` rules must be copied to the consuming main module: replacements in a dependency's `go.mod` are not inherited. [Exact upstream go.mod](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/go.mod).

Google/Go runtime dependencies also include `github.com/google/go-cmp v0.7.0` (used in production topology code), `golang.org/x/crypto v0.50.0` (OCSP), and `google.golang.org/protobuf v1.36.11`. Verifier-only imports do not need NVIDIA `go-nvml`, Google `subcommands`, or test-only `testify`, `go-spew`, `go-difflib`, `yaml`, and `xmlpath`.

No minimum native libxml2 version is declared in the reviewed Go binding. The exact 2.15.4 source hash is [published by GNOME](https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.sha256sum), and NVIDIA's current [CMake configuration](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/CMakeLists.txt#L378) pins the same tarball. This makes it a concrete pin candidate, not proof of Google binding compatibility. Configure and record native optional features explicitly; a distro build may link additional zlib, ICU, libiconv or other libraries. No Linux build or dependency installation was performed.

## Coverage and concrete gaps at the Google pin

| Requirement | Google source coverage | Required integration behavior |
| --- | --- | --- |
| Device/alias chain and raw SPDM signature | `verify.GpuInfo`, `verify.SwitchInfo`, Go `crypto/x509`, ECDSA | Preserve stricter chain order, purpose, allowed algorithm and identity constraints. Require authenticated FWID/PDI and production-security policy separately. |
| Revocation | Real DER OCSP parsing/signature/status through `server/ocsp` | Add strict freshness and all-nonroot coverage, including alias leaf. Do not treat CRL data as OCSP. |
| Driver/VBIOS/switch XML RIM | XSD + patched XMLDSig + pinned root + golden hashes | Restrict XML profile, metadata and algorithms; pass immutable identical RIM bytes to both verification and measurement validation. |
| Signed modes/debug/security | Some mode/feature parsing; DICE structure definitions | Enforce missing-field, six-flag production policy, model/profile and field-width/type policy separately. |
| NVSwitch/PPCIE | Per-device verification and exported topology validator | Call topology separately and preserve exact enrolled GPU/switch identities and certificate-to-PDI linkage. |
| Typed `NVDAOD`, minimum SVN | No parser/appraisal path found | Explicitly unsupported by this Google pin; no silent conversion or alternate verifier after failure. |
| CoRIM/CoEV/CMW/EAR | No path found | Explicitly unsupported by this Google pin. |
| CEC reports | No path found | Explicitly unsupported. NVIDIA SDK only exposes CEC collection structure members at this pin; no CEC verifier found. |
| CPU/GPU EAT, TLS key, nonce and required inventory | Out of this library's scope | Remain mandatory application policy in Rust. |

Decisive source findings:

1. `defaultVerifyCertificateChainWithOCSP` starts device/switch checking at chain index 1, skipping the alias leaf. It validates responder chains, response signature and status, but does not enforce `ThisUpdate`, `NextUpdate`, or `ProducedAt`. [verify.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/verify/verify.go#L414).
2. `server/ocsp/nvidiaocsp` contains `constructFakeOCSPResponse`: it constructs an unsigned OCSP object from a device certificate's signature/TBS bytes and an unsigned cached L4 revocation map. Do not import or use this cache. Real DER OCSP should be parsed with `ParseResponseForCert`, tied to exact target/issuer and checked at the trusted verifier time. [caching_client.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/ocsp/nvidiaocsp/caching_client.go#L124).
3. `defaultVerifyRIM` records a false `VersionMatched` but does not return an error for it. The application must require that result, not only a nil top-level error. [verify.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/verify/verify.go#L471).
4. `spt.VerifyGpuQuote` first verifies fetched RIMs, then `validate.AttestationReport` fetches/parses RIMs again for matching. Inject exactly the same immutable RIM map into both option structures to prevent a source changing between the signature and reference steps. [spt.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/spt/spt.go#L23), [validate.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/validate/validate.go#L214).
5. `ValidateModes` skips zero/one GPU, and skips missing, invalid or pre-v1 opaque versions. SPT orchestration does not call it. Therefore strict signed CC mode policy must not rely on this function alone. [utility.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/utility/utility.go#L22).
6. `ValidateSystemTopology` is a separate call; it checks counts, consistent peer sets and GPU-reported switch IDs against switch self-IDs. It does not compare switch-reported GPU IDs to authenticated GPU self-identities. [ppcie.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/ppcie/server/ppcie.go#L39), [topology_validator.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/ppcie/server/topology_validator.go#L140).
7. The SPDM parser accepts duplicate measurement indices; validation builds a map that overwrites duplicate entries. Header bytes and DMTF value types need strict policy preflight. The opaque parser uses four-byte legacy TLV headers, without NVDAOD or value-type discriminators. `formatGpuVbiosVersion` can panic on malformed short fields, and switch port-tail parsing can panic on odd trailing lengths. Keep the subprocess bounded and reject malformed inputs before appraisal. [abi.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/abi/abi.go), [utility.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/utility/utility.go#L91).
8. Hopper and switch FWID extraction takes the final 48 bytes of the DICE extension; Blackwell extraction takes the first FWID digest without checking its algorithm. Preserve strict ASN.1, unique extension, hash algorithm and DICE flags policy. [verify.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/verify/verify.go#L598).
9. Default RIM and OCSP HTTP clients use `http.DefaultClient` and unbounded `io.ReadAll`. Avoid default network clients in the helper. Supply bounded pre-fetched evidence with controlled IDs, no attacker-controlled URLs and no network fallback. [rim.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/rim/rim.go), [ocsp.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/ocsp/ocsp.go).
10. Google's XMLDSig fork accepts multiple reference forms and multiple algorithms, and searches for a signature. Before calling it, preserve the constrained NVIDIA XML profile: one root signature, one whole-document reference, allowed digest/signature/C14N transforms, no DTD/entities/ambiguous IDs. Metadata was parsed before signature validation, so requiring a whole-document signature matters. [rim.go](https://github.com/google/go-nvattest-tools/blob/1a098bebccd3790f71e7e6403c4f15a85f0a3494/server/rim/rim.go#L201), [pinned XMLDSig validator](https://github.com/atulpatildbz/goxmldsig/blob/e806be5e3c3ac90a79b0c6e9921aae48ab21e53c/validate.go).

## Concrete adapter mapping

Use `v2/google-attestation/internal/gpu` behind the parent's version-1 bounded helper envelope. The operation payload should carry:

- Trusted verifier time, exactly 32 nonce bytes, an explicitly supported profile and independent policy.
- Per-device exact raw SPDM and certificate-chain bytes, architecture selected from supported policy, and metadata that will be compared to authenticated fields. UUIDs remain routing labels.
- An immutable map from expected NVIDIA RIM identifiers to exact XML bytes, plus raw authenticated collateral; helper code must not fetch missing data.
- Exact required inventory/fabric constraints in application policy. Caller-declared verification booleans are not accepted.

For GPUs, create `proto.GpuInfo` and call `spt.VerifyGpuQuote` with `Verification: verify.Options` and `Validation: validate.Options`. Set nonce, expected architecture, expected certificate-chain count and all five `verify.TimeSet` fields from the trusted time. Supply the same immutable `rim.Client` in both options. Keep `DisableOCSPCheck`, `DisableRIMCheck`, `DisableRefCheck`, and `AllowOCSPCertHold` false in a full Google verification path.

For switches, call `verify.SwitchInfo`, then `validate.AttestationReport` with `AttestationType: abi.SWITCH` and the returned BIOS version. Alternatively use PPCIE orchestration, but always call `ValidateSystemTopology` separately after all devices have been authenticated and require exact result counts. A single orchestration error rejects the whole operation; partial result arrays are not success.

Require positive structured fields for every device: signature verified, measurements matched, nonnil driver/VBIOS RIM states with schema/signature/version matched, and nonnil GOOD OCSP states. Return evidence/request digests and precise backend/profile information, not a policy-free global trust boolean. Rust remains responsible for CPU/EAT/TLS binding, exact policy and final verdict.

Revocation adapter choices must remain explicit. A `server/ocsp.Client` can enforce real OCSP certificate binding and time freshness before returning the parsed object, and all nonroot certificates can be checked separately. It cannot represent an authenticated CRL without manufacturing an OCSP object. CRL-only evidence therefore needs the existing mandatory strict revocation layer or an explicit lower-level integration; it must never be converted into synthetic OCSP success.

The Google pin cannot replace the full currently implemented typed-opaque/CoRIM surface. A Google-only profile must reject those formats clearly; preserving existing support requires an explicit design decision, not fallback after Google failure. NVIDIA's C++ SDK is a separately approvable reuse candidate for those formats; its CoRIM verifier is marked experimental, takes optional OCSP collaborators, and includes optional backup/synthetic environment behavior that needs its own review before adoption.

## Additional candidate cost

NVIDIA's SDK brings a substantially larger non-Google native dependency graph: Regorus `regorus-v0.4.0`, jwt-cpp `v0.7.1`, nlohmann/json `v3.12.0`, zcbor commit `bd28ef9fc2abe154cb420c232910a1a9f8258114`, fmt `10.2.1`, spdlog `v1.14.1`, OpenSSL `3.6.4`, curl `8.22.0`, libxml2 `2.15.4`, xmlsec `1.2.39`, and zlib, plus their dependencies; Corrosion `v0.6.1` and Rust bindgen `0.72.1` are build dependencies. This is a direct CMake audit, not an exhaustive transitive SBOM. None is proposed for unapproved adoption.

Confident Security's remote alternative adds `MicahParks/keyfunc/v3 v3.3.11`, `MicahParks/jwkset v0.8.0`, `golang-jwt/jwt/v5 v5.2.2`, NVIDIA `go-nvml v0.13.0-1`, and native NVML/NSCQ, plus Google UUID and Go time packages. It does not address the local appraisal requirement and is not recommended for this integration.
