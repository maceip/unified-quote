# Integration sources and release hold

These files are implementation inputs. Nothing here has been installed or
started on a GPU machine. User admission and publication remain on hold until
the joint hardware acceptance pass recorded in `../IMPLEMENTATION_STATUS.md`.

`zmax-attestation.service.example` supplies the local Rust responder. The HTTPS
terminator must export its actual leaf **SubjectPublicKeyInfo DER** to the
configured path and update it on key rotation. Forward only `/v1/attest` to the
local responder; the relying party must compare the token binding against the
SPKI it observed on its own TLS connection. A caller-supplied HTTP header must
never select the attested TLS key.

`fetch-verified-uq.sh` is for the Linux image build host. It downloads an exact
release binary only after checking an independently approved SHA-256 and its
GitHub artifact attestation, pinned to this repository, release workflow, source
commit, SLSA provenance predicate and hosted runner. It never executes the
downloaded binary. The flags follow the [GitHub CLI attestation verifier](https://cli.github.com/manual/gh_attestation_verify).
Provide the release tag, source commit, binary digest, target and a new absolute
destination path; no `latest` or mutable source lookup is accepted.

The release workflow is manual and requires the repository variable
`UQ_HARDWARE_ACCEPTED_SHA` to equal the dispatched source commit. That variable
must only be set following actual hardware acceptance. Provenance authenticates
the build origin; it is not evidence of GPU or CPU hardware validation.

The four `zmax-ntrust-*` source trees now stage an exactly pinned, provenance-
verified Rust binary and invoke its collector/verifier through thin adapters.
Their clients supply a fresh nonce and the SPKI from the same TLS connection,
plus independent CPU and GPU policy. Image installation leaves the attestation
service disabled pending acceptance. No guest image has been rebuilt, deployed,
or switched over in this work. Native Linux image builds belong on the configured
build host, not macOS emulation.
