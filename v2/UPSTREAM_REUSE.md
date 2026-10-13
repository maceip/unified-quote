# Upstream library integration

The user authorized reuse of Google libraries on 2026-10-13 and subsequently
approved all eight non-Google dependencies listed below. Any additional library
from another owner still requires explicit approval, including a transitive
runtime dependency. Existing project dependencies are unchanged by that decision.

## Selected Google components

| Component | Source pin | Integration |
| --- | --- | --- |
| Intel quote verification and collection | [`google/go-tdx-guest`](https://github.com/google/go-tdx-guest/tree/b0a2dd8100a04a52310c6f7869dbc14297e39e8b) | Planned TDX v4/v5 verification through one bounded Go helper. Standard-library policy guards are staged; vendor calls await dependency approval. Collateral and revocation checks must be explicit, with independent measurement and TCB policy. |
| GPU and NVSwitch verification | [`google/go-nvattest-tools`](https://github.com/google/go-nvattest-tools/tree/1a098bebccd3790f71e7e6403c4f15a85f0a3494) | Evaluate verifier packages for SPDM, XML RIM, certificates and topology. Its upstream XML replacement modules must be pinned explicitly in the consuming module. |
| Authenticode parsing and PE hashing | [`google/authenticode-rs` 0.6.0](https://github.com/google/authenticode-rs/tree/5d8df58ecc53309ca628b7353db4402264f862a1) | Planned native Rust parser/digest reuse; awaits CMS approval. Signature, certificate, revocation and relying-party policy remain required. |
| TCG/CCEL replay | [`google/go-eventlog` 0.0.2](https://github.com/google/go-eventlog/tree/f984981ba6b88f0b91c6a17aa3ec0a5267f1c762) | Implemented TDX replay against all four CPU-authenticated RTMRs through the bounded helper. Application-specific event policy remains in Rust. |

Google's AMD library was also inspected. Its current TCB/HWID model does not
cover our Turin FMC policy, so it cannot replace that path faithfully. No
verification failure will trigger a switch to a different implementation.

The [GPU source review](GOOGLE_GPU_REVIEW.md) also compares NVIDIA's current
native SDK and Confident Security's Go wrapper. Neither has been adopted.
It records upstream checks that need explicit policy, as well as the OCSP
cache implementation that must not be used for this project.

## Additional dependencies approved on 2026-10-13

These are components of the selected Google libraries, not Google-owned code:

| Dependency | Version / revision | Purpose |
| --- | --- | --- |
| RustCrypto `cms` | 0.2.3 | Mandatory CMS/PKCS7 structure support for Google's Authenticode crate. |
| Uber `go.uber.org/multierr` | 1.11.0 | Error aggregation used by Google's CPU and multi-GPU verification. |
| `beevik/etree` | 1.6.0 | XML tree handling for GPU reference manifests. |
| `atulpatildbz/goxmldsig` | `e806be5e3c3a` | Google's pinned replacement for `russellhaering/goxmldsig`; XML signature verification. |
| `atulpatildbz/libxml2` | `d06374c0f56f` | Google's pinned replacement for `lestrrat-go/libxml2`; native XML schema validation bindings. |
| native `libxml2` | Candidate 2.15.4, SHA256 `98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821` | XML schema validation runtime. Build without optional compression/ICU dependencies; verify compatibility with the pinned Google binding. |
| `pkg/errors` | 0.9.1 | Error handling used by the XML binding. |
| `jonboulle/clockwork` | 0.5.0 | Clock abstraction used by XML signature validation. |

The user selected “Approve the listed dependencies” for this exact list.
The production import closure must be checked before adoption; any additional
non-Google component requires a separate approval. Collection can retain the
existing native NVML/NSCQ path, avoiding an additional Go NVML dependency.

## Adapter contract

The Rust public API remains the relying-party entry point. A single explicitly
configured local executable accepts versioned JSON on stdin and returns one
bounded response on stdout. Evidence cannot choose the executable. Requests
carry independent policy and exact evidence bytes; responses identify the
request digest. Timeout, malformed response, missing evidence, or verifier
failure rejects the operation. There is no automatic alternate-verifier path.

The Go helper is an additional build/runtime artifact. Source pins, licenses,
checksums and release provenance must cover it as well as the Rust executable.
This document records integration decisions; it does not claim those adapters
or pending dependencies have already been built or accepted.
