# Composite CLI and local evidence service

The local endpoint generates evidence using the same `AttestationCollector` as
the composite CLI. It is source-only at this stage: it has not been installed,
started, or exercised on target hardware. Do not expose it to users until the
hardware acceptance review is complete.

Prepare the deployment's real TLS public-key SPKI in DER, approved 48-byte
Value X, NVIDIA signed manifests and authenticated revocation material. Verifier
GPU and boot policies must be enrolled independently from received evidence.
No example identity or allow-all policy is bundled.

The new command handlers support:

```text
uq collect --nonce <64-hex> --tls-spki <DER-file> --value-x <96-hex>
    --gpu --collateral <JSON-file> --topology auto|independent|ppcie
    --boot-log <TDX-CCEL-file> --out <new-file> --format cbor|json
    [--runtime-log <CoCo-AAEL-file>]
    [--source-hash <96-hex> --artifact-hash <96-hex> --previous-attestation <CBOR-file>]

uq verify-composite --in <receipt> --format cbor|json
    --nonce <64-hex> --tls-spki <DER-file> --value-x <96-hex>
    --platform tdx|sev-snp|nitro --expected-platform-measurement <96-hex>
    --cpu-collateral <signed-vendor-material.json> --cpu-tcb-policy <approved-policy.json>
    --require-gpu --gpu-policy <JSON-file> --boot-policy <JSON-file>
    --uki <UKI-image-file> --max-age <seconds> --json
    [--google-boot-verifier <absolute-helper-path>] [--prior-stage-policy <JSON-file>]

uq serve-attestation --unix /run/zmax-attestation/attest.sock
    --tls-spki <DER-file> --value-x <96-hex>
    --gpu --collateral <JSON-file> --boot-log <TDX-CCEL-file>
    [--runtime-log <CoCo-AAEL-file>]
```

`--gpu` requires a build with `--features gpu`. If `--collateral` is omitted,
the collector obtains collateral through its fixed NVIDIA provider endpoints.
The GPU-related options and `--boot-log` are optional for CPU-only collection.
Enabling a GPU policy in verification also requires GPU evidence. `--platform`
constrains hardware; `--expected-platform-measurement` is mandatory and must come
from an approved image manifest. CPU collateral carries signed vendor material;
CPU TCB policy separately supplies independent rollback floors. The verifier
rejects missing collateral/policy required by the CPU platform; quote signatures
alone do not establish TCB acceptance. For TDX, `--expected-mrtd` is an alias that also
requires TDX. Supplying nonce, SPKI and Value X remains mandatory. Verification prints structured verdicts and
exits unsuccessfully on rejection. Collection does not declare evidence trusted.
Output files are created exclusively with owner-only permission and are never
silently overwritten.

`--runtime-log` requires `--boot-log`. The collector appends bounded CoCo AAEL
TCG2 runtime events before committing the resulting bytes to the CPU quote.
Verification requires an independently enrolled `boot_policy.runtime` with
the exact ordered events, compares all four RTMRs, and hashes every runtime
preimage. It rejects missing runtime history, unknown profiles and changed
events.

`--google-boot-verifier` explicitly requires the local
[Google adapter](google-attestation/README.md) in addition to the Rust
application policy. The helper receives only CPU-authenticated registers and
validated log bytes. A missing helper, timeout or failed replay rejects the
receipt. The helper is a separate trusted executable, included in release
provenance; selecting it does not enable a network verifier.

Build claims require both nonzero `--source-hash` and `--artifact-hash`.
`--previous-attestation` carries the exact prior CBOR receipt and requires those
hashes. Collection commits these claims without appraising them. Verification
requires an explicit `--prior-stage-policy` with independently pinned receipts,
stage identities, challenges, measurements, freshness limits and CPU security
policy. A receipt cannot supply its own approved build policy.

`--uki` is optional and verifier-local. It requires a boot policy containing an
explicit `uki` section, including the supported loader profile and independently
approved section digests; that policy also requires the image file. The image
is limited to 512 MiB. Embedded metadata is exposed only after section name/data
measurements match the authenticated boot log and policy. The policy's other
boot events must approve the loader/image identity. This does not claim whole-
image Authenticode verification or resolve the effective mounted filesystem.

The service accepts `GET /v1/attest?nonce=<64-hex>` using HTTP/1.1. The default
response is CBOR; use `Accept: application/json` or `&format=json` for JSON.
Every request invokes fresh device collection and CPU quoting. Boot-log and
collateral files are read again per request so growing logs and operator-refreshed
revocation evidence are included. The TLS SPKI file is also read per request;
rotate it atomically with the TLS terminator's key. The expected Value X is fixed
service configuration and requires restart when rotated. The configured SPKI
must match the deployment's TLS terminator; the local HTTP service does not
itself provide that TLS connection or prove possession of its private key.

The Unix socket is mode `0600`; its parent directory is required to be owned by
the service user and inaccessible to other users. The alternative `--listen 127.0.0.1:<port>` is restricted to numeric
loopback addresses. The service serializes native device operations and bounds
headers to 8 KiB, input/output evidence to 64 MiB, request reads to a five-second
absolute deadline and response writes to a ten-second absolute deadline. It rejects request
bodies, duplicate headers or query parameters, unsupported transfer encoding,
unknown query keys, malformed challenges and non-GET methods. Every response
closes the connection and uses `Cache-Control: no-store`. Collection failures
return HTTP 503 without cached or synthetic evidence. Native driver calls retain
their native blocking behavior; systemd process supervision is responsible for
termination if a driver hangs.

The [systemd example](deploy/zmax-attestation.service.example) is for a TDX GPU
guest. It grants the runtime directory and configfs TSM report area required by
the collector while restricting filesystem mutation, privilege acquisition,
namespaces and kernel configuration. Device permissions and driver behavior must
be verified on the actual image before installation. An existing Unix socket is
never deleted by this command; the example's private RuntimeDirectory is cleaned
by systemd when the service stops.

Boot tooling is available independently through `uq boot inspect`, `uq boot
collect`, and `uq boot closure`. Inspect output is explicitly an unverified
diagnostic. See [boot-measurement boundaries](BOOT_MEASUREMENTS.md) for replay,
loader profiles, dm-verity commitments and closure identity semantics.

CPU collection uses an exclusively created, unpredictable configfs report
instance for each probe and request. Both providers require an exact kernel
`provider` value before and after reading evidence; an unavailable or malformed
provider, conflicting devices, failed read, or oversized blob rejects collection.
Only a missing optional `auxblob` is treated as absent collateral. TDX accepts
full DCAP v4 ECDSA-P256 quote framing and verifies the complete requested 64-byte
REPORTDATA echo before returning evidence. The local MAC-protected TDREPORT ioctl
is deliberately not a remote-evidence transport. Legacy-device-only TDX hosts
require a QGS transport that is **not implemented**; this is a source limitation
as well as a deployment requirement. Quote v5 and DICE/CWT TDX formats are also
unsupported by this collection path.

Composite collection supports direct SNP/TDX or Nitro NSM and the explicit
Azure SNP/vTPM and AWS SNP/NitroTPM profiles described below. Those profiles
require their own independently enrolled TPM policy in addition to current
AMD appraisal. A static HCL SNP report cannot substitute for a fresh quote;
legacy HCL inspection remains separate from composite admission.

SNP uses configfs when available at provider construction, otherwise the genuine
Linux x86-64 `SNP_GET_EXT_REPORT` ioctl. A failed selected transport does not switch
paths. The ioctl matches the Linux UAPI (32-byte ioctl argument, 112-byte extended
request, 4000-byte response, command `0xc0205302`); buffers are bounded by the
kernel's 16-KiB certificate maximum. Response status, exact 1184-byte report,
versions 2/5 supported by the verifier, signature algorithm, full REPORT_DATA,
and returned VMPL0 for the ioctl request are checked. Certificate tables require
a terminator, unique GUIDs, in-bounds nonoverlapping certificate ranges, and no
entry pointing into the table header. Structural checks do not authenticate a
report or endorsement; the independent verifier still performs cryptographic
appraisal. Configfs and ioctl paths have not been exercised on the target CPU.

These interfaces follow the Linux [configfs-TSM ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/configfs-tsm-report),
[SNP guest UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h),
[SNP driver](https://github.com/torvalds/linux/blob/master/drivers/virt/coco/sev-guest/sev-guest.c),
and [TDX driver](https://github.com/torvalds/linux/blob/master/drivers/virt/coco/tdx-guest/tdx-guest.c).

TDX composite verification also requires explicit CPU collateral and an enrolled
CPU TCB policy through `--cpu-collateral` and `--cpu-tcb-policy`. These inputs are
separate from the attester's receipt. See [Intel TDX collateral appraisal](TDX_COLLATERAL.md)
for formats, exact signed bytes, revocation and the independent evaluation-data
floor. A quote signature alone is insufficient for composite admission.

## Explicit CPU/TPM profiles

`uq collect` and `uq serve-attestation` accept `--cpu-profile`:

- `direct` (default): the detected direct Nitro NSM, SNP or TDX provider.
- `azure-snp-vtpm --tpm-pcrs 0,2,4,7,11,12`: Azure HCL v2 plus one fresh
  SHA-256-bank TPM quote. The indices are an explicit collection selection;
  the relying party must supply its own approved values.
- `aws-snp-nitrotpm`: direct SNP plus the signed NitroTPM document. Both sign
  the same full EAT commitment, and NitroTPM also signs the client nonce.

Verification requires the matching `--platform azure-snp-vtpm` and
`--azure-policy FILE`, or `--platform aws-snp-nitrotpm` and
`--nitrotpm-policy FILE`. Both require `--cpu-collateral` and
`--cpu-tcb-policy` for AMD, an independently approved 48-byte SNP measurement,
nonce, TLS SPKI and Value X. Policies are verifier configuration, not fields
trusted from the received receipt. Missing or mismatched policy rejects.
`--boot-policy` replays the supplied TCG2 log against the authenticated TPM
selection; only those signed registers can authorize individual boot events.
AWS constant PCR0/1 are excluded from firmware replay. CoCo AAEL and the Google
TDX replay profile remain specific to TDX.

The two compound profiles have distinct EAT platform codes (4 and 5), require
binding suite 2 and carry versioned JSON evidence in `platform_quote`.
A common nonce and commitment prove transaction binding, not physical
co-location. Azure HCL alone is a static endorsement, never proof of freshness.
See [AZURE_COMPOSITE.md](AZURE_COMPOSITE.md) for its exact policy and formats.

## Admission corrections

The relay constructor requires an actual composite verifier verdict. Legacy
Azure commands offer collection/signature inspection only; their historical
admission/network paths reject. Runtime chaining requires exact CBOR receipts
and independent prior-stage policy. TLS initialization or service errors no
longer cause an automatic plaintext downgrade. Unauthenticated remote key
unwrap, certificate replacement and ACME challenge administration are disabled.
The SDK requires the strict Rust verifier and independent policy before making
an attestation request; parsing JSON cannot produce a successful verdict.

The four downstream SDKs now request fresh attestation for every GET, POST or
stream in attestation-enabled mode. After successful Rust appraisal, the shared
adapter supplies the hash of the observed receipt-connection SPKI. Each actual
request connection validates PKIX/hostname and that exact key before sending
HTTP bytes; reconnects repeat the check. A bounded monotonic consumption window
and failed-refresh rejection prevent a stored display verdict from authorizing
later requests. This is key continuity across connections; it does not assert
that two distinct connections are the same socket.
