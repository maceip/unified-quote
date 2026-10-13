# Native GPU and composite attestation

The canonical implementation is the `unified-quote` crate in this directory.
Enable `gpu` for NVIDIA collection and verification. No CUDA SDK, Python
verifier, `nvidia-smi`, or external XML signature process is required. Collection
loads installed NVML/NSCQ driver libraries on Linux; cryptographic appraisal
and format handling run in Rust.

**Implementation is under development and unavailable for user admission.**
Source checks and published reference evidence do not establish hardware
acceptance. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) records both
source limitations and hardware work still required. Full requirements remain
in [the capability delta](../CAPABILITY_DELTA_AND_GPU_SPEC.md).

## Implemented mechanisms

| Component | Behavior |
| --- | --- |
| Native collection | Bounded NVML GPU and NSCQ LS10 switch collection, one verifier nonce, complete enumerated inventory, stable identities and driver-state checks, and propagation of device errors. No ready-state mutation. |
| Certificate trust | Compiled NVIDIA device/RIM roots; strict PEM/DER, signatures, allowed algorithms, validity, issuer relationships, CA/path-length/key-usage constraints and critical extensions. Alias identity is tied to its certified device issuer key. |
| Revocation | Authenticated OCSP and direct complete CRLs; authorized responders, exact certificate IDs, freshness and expiration. Every non-root certificate needs current status. Signed cache entries are revalidated; metadata never grants trust. |
| XML manifests | Bounded whole-document enveloped XMLDSig, C14N 1.1, SHA-384 and ES384. One signed DOM supplies driver/VBIOS/switch measurements and minimum-SVN constraints. DTDs, external references and unsupported transforms reject. |
| CoRIM | COSE ES384, pinned signing path/revocation, typed CoMID reference/dependency triples, versions, digests, flags, masks and ranges. A separate authenticated-manifest API, without an invented mapping to legacy SPDM indices. |
| GPU appraisal | SPDM 1.1 signature and request nonce; exact signed version/model manifest selection; active measurements, signed inactive indices and documented NVDEC exception; firmware identity binding where the supported report supplies it. |
| Security policy | Signed CC mode and DICE flags. Required not-configured, not-secure, recovery, debug, not-replay-protected and not-integrity-protected flags must explicitly be false. Missing/masked flags reject. Unsigned NVML readiness never substitutes. |
| Fabric policy | Exact enrolled identities, switch PDIs, reciprocal peer sets and explicit signed protected-PCIe/routing/port-lock constraints, with format-specific byte ordering. No claim of physical CPU/GPU attachment. |
| Composite EAT | Suite 2 commits exact GPU and boot bytes and lengths into CPU report data together with nonce, TLS SPKI, Value X and existing fields. Collection precedes CPU quoting. Substitution, removal and legacy-suite downgrade reject. |
| Interfaces | Collector/verifier builders, structured verdicts, mandatory independent CPU launch measurement and GPU inventory policy, captured-token verification, and a fresh-evidence local HTTP/Unix-socket service. |
| Boot metadata | Authenticated CCEL/TPM replay, approved event digests, GRUB/systemd command-line profiles and singleton systemd-stub v258 UKI section-pair appraisal. Measured verity roots and embedded metadata remain distinct from effective mounted state. |

The device verdict's `nvidia_signed_reference_measurements_matched` security profile
states reference matching and the six explicit adverse-state checks above. It
does not claim runtime measurement, immutability or TCB membership. Those three
DICE flags remain visible in the verdict for a separately established policy.

## Production interfaces

Build the implementation:

```sh
cargo build --locked -p unified-quote --bin uq --features gpu
```

After hardware acceptance, collection uses the deployment's actual TLS leaf
SubjectPublicKeyInfo DER and a fresh relying-party challenge:

```text
uq collect --nonce <64-hex> --tls-spki <actual-spki.der> --value-x <96-hex>
    --gpu --topology auto --out <new-receipt.cbor>

uq verify <receipt.cbor> --nonce <same-64-hex> --tls-spki <observed-spki.der>
    --expected-value-x <approved-96-hex> --expected-mrtd <approved-96-hex>
    --cpu-collateral <signed-cpu-collateral.json> --cpu-tcb-policy <approved-tcb-policy.json>
    --require-gpu-verified --gpu-policy <enrolled-policy.json> --json
```

Verifier SPKI comes from its own TLS connection. Value X, CPU measurement,
device-key pins, model, mode and fabric inventory come from independent
enrollment. A bundle cannot nominate its own policy. No placeholder enrollment
values are distributed. `--expected-mrtd` also requires TDX; the general CPU
option is `--expected-platform-measurement`.

Without `--collateral`, collection obtains collateral through fixed NVIDIA
HTTPS endpoints using authenticated report selectors. Explicit collateral and
the library cache retain original signed bytes and receive the same strict
appraisal. See [ATTESTATION_SERVICE.md](ATTESTATION_SERVICE.md) for CLI/service
integration and [deploy/README.md](deploy/README.md) for release holds.

The primitive `uq gpu collect --nonce <64-hex> --out <new-file.cbor>` preserves
raw GPU evidence. Its output is not an EAT or verdict. UUIDs, device names and
NVML state remain unauthenticated diagnostics. CEC bytes are preserved; strict
appraisal rejects nonempty CEC evidence until a CEC profile is implemented.

## Explicit remaining boundaries

- **Alias revocation:** NVIDIA's reference verifier skips alias revocation.
  Our policy does not. Published fixtures and responder contracts do not
  establish fresh direct status for every alias. Missing status rejects,
  including automatic collateral acquisition. Resolve the authenticated vendor
  coverage contract before admission; this is a source/profile issue as well
  as a hardware capture requirement.
- **Security fields:** historical Hopper and LS10 evidence lacks some required
  signed fields. The published Blackwell fixture sets `notConfigured`. Such
  evidence cannot pass current production policy. Establish firmware/profile
  compatibility without treating absence as safe or trusting NVML metadata.
- **Typed opaque fields:** supported NVDAOD fields require their published or
  captured value types; compatible minor/patch versions are accepted. Typed
  fabric and chip-info fields without authoritative discriminator definitions
  remain unappraised and reject when consumed by the supported profile or
  required by policy. Present GB100 chip-info fields are always consumed and
  therefore reject if their type is unsupported. Legacy wire profiles
  use their own explicit parsing rules, including LS10 model and PDI ordering.
- **CoRIM device appraisal:** manifest authentication and typed references are
  implemented. Complete device matching needs the actual supported evidence
  profile and authoritative mapping; XML SPDM does not accept CoRIM as
  interchangeable input.
- **Physical association:** CPU commitment prevents evidence substitution;
  signed topology describes enrolled relationships. Neither alone establishes
  that CPU and GPUs occupy the same machine.
- **Build ancestry:** composite runtime verification rejects prior attestations
  pending an explicit prior-stage policy. It does not claim build ancestry from
  the current-stage CPU signature.
- **Boot and CPU profiles:** see [BOOT_MEASUREMENTS.md](BOOT_MEASUREMENTS.md).
  Unsupported quote layouts, unauthenticated PCR snapshots and local MAC-only
  TDREPORTs cannot become remotely verified evidence.

Strict CPU admission uses current signed collateral and independently selected
TCB floors: [Intel TDX](TDX_COLLATERAL.md) and [AMD SNP](SNP_COLLATERAL.md).
The legacy JSON receipt and certificate `check` commands only inspect signatures
and bindings; their results cannot grant admission. Legacy SNP acquisition does
not guess a product for v2 reports or use an FMC-blind Turin KDS request.

## Development validation and provenance

```sh
cargo test --locked -p unified-quote
cargo test --locked -p unified-quote --all-features
cargo check --locked -p unified-quote --no-default-features --features gpu
cargo fmt --all -- --check
```

Checks include NVIDIA-published Hopper/Blackwell signatures and XML manifests,
bounded parsing, evidence mutation, adversarial certificates/status and
commitment substitution. Locally generated keys/status and wire mutations are
test inputs, never production evidence. The NVDAOD structural fixture has no
matching published certificate and does not establish signature trust. Sources
and licenses are under [testdata/gpu/nvidia](testdata/gpu/nvidia/README.md).

Primary references include NVIDIA's pinned
[SPDM implementation](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/src/gpu/evidence.cpp),
[NVML collector](https://github.com/NVIDIA/attestation-sdk/blob/11b2bfeb42a1158aa08744603ecb239ccb3d2265/nv-attestation-sdk-cpp/src/gpu/nvml_client.cpp),
and [NVML definitions](https://github.com/NVIDIA/go-nvml/blob/main/pkg/nvml/nvml.h).
The exports are `nvmlDeviceGetConfComputeGpuCertificate` and
`nvmlDeviceGetConfComputeGpuAttestationReport`.
