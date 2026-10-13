# Google attestation adapter

The Rust API invokes this executable by an explicit absolute path. It is a
trusted local component, not a service, and never selects policy from received
evidence. There is no alternate-verifier retry on error. The currently active
operation is exact TDX event-log replay through Google's `go-eventlog` v0.0.2.
The production dependency closure currently contains only this project and
Google/Go project modules; `build.sh` checks that boundary.

Build with Go 1.25 or newer and Python 3 (only for collecting license notices):

```sh
./v2/google-attestation/build.sh /absolute/output/uq-google-attestation
```

The build also writes `uq-google-attestation.NOTICES.txt` containing licenses
from the exact linked modules. Distribute that file with the executable.

Run source checks from this directory with `go test ./...` and `go vet ./...`.
Use `uq verify-composite ... --boot-policy policy.json
--google-boot-verifier /absolute/output/uq-google-attestation` to require the
Google replay check. The Rust verifier obtains all four RTMR values from a
fully authenticated CPU quote, validates the log bounds/padding, invokes Google
replay, and applies independently supplied event, UKI and runtime policies.
Failure of any required check rejects the receipt.

The adapter disables Google's inferred-event workarounds and checks unextended
registers explicitly. It accepts no trailing log padding; Rust passes only the
validated event bytes. Event descriptions do not become authenticated merely
because their digest replay succeeds.

`collect` and `serve-attestation` accept `--runtime-log` alongside `--boot-log`
to append the published CoCo AAEL TCG2 events. The verifier's boot policy must
explicitly enroll the runtime profile and exact ordered events. Collection
does not produce an admission verdict.

The helper protocol is `--stdio-v1`, one JSON object on stdin, one on stdout.
Input, output and execution time are bounded by Rust. A response includes the
SHA256 of the exact request bytes. This correlation is not an independent
attestation signature; the executable itself is part of the trusted verifier.

The CPU adapter's standard-library policy code is staged under `internal/cpu`.
Its Google verification/collection calls are not connected pending approval
for the required non-Google dependency. GPU and Authenticode reuse have the
same explicit approval boundary, recorded in [UPSTREAM_REUSE.md](../UPSTREAM_REUSE.md).
