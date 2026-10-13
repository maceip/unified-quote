# Google CPU backend source review

The adapter uses explicit backend selection. A backend failure must remain a
failure; it must never trigger a different verifier, transport, signature-only
path, or weaker policy. Collection returns unverified evidence.

## Reviewed revisions and dependency approval

- [`google/go-tdx-guest` `b0a2dd8100a04a52310c6f7869dbc14297e39e8b`](https://github.com/google/go-tdx-guest/tree/b0a2dd8100a04a52310c6f7869dbc14297e39e8b)
- [`google/go-sev-guest` `9c5dffcd8230247336e07c70804a31f6b39ab3c9`](https://github.com/google/go-sev-guest/tree/9c5dffcd8230247336e07c70804a31f6b39ab3c9)

Both verification/validation packages import `go.uber.org/multierr v1.11.0`
at runtime. That is a non-Google dependency and requires the user's explicit
approval before adopting either verifier. The Google/Go dependency graph also
includes configfs-tsm, protobuf, logger, uuid, x/crypto and x/sys; TDX's module
references Google's SEV library and event-log/TPM libraries. Exact resolved
versions belong in the parent module's dependency ledger and lockfile.

The files currently staged in this directory use only Go's standard library.
They define the wire contract and strict policy guards. They do not yet import
or invoke either Google verifier and therefore are not a completed CPU backend.

## TDX mapping

The reviewed TDX revision parses and verifies quote v4 and quote v5 bodies for
TDX 1.0 and 1.5. Some upstream comments still say v4 only; the actual dispatch in
`abi.QuoteToProto`, `abi.CheckQuote`, and `verify.TdxQuoteContext` includes v5.

The planned adapter calls are:

1. Validate bounded request, full expected 64-byte report data, independent
   nonzero 48-byte MRTD, and nonzero minimum TCB evaluation-data number.
2. Reject bytes beyond the exact quote framing before `abi.QuoteToProto`.
   Upstream preserves extra bytes instead of rejecting them.
3. Use `verify.ExtractChainFromQuote` and `pcs.PckCertificateExtensions` to
   identify collateral. Require the compiled Intel root pin and strict PKIX.
4. Pass `verify.Options` with `GetCollateral=true`, `CheckRevocations=true`,
   `DisableTcbStatusCheck=false`, an explicit trusted-root pool, one trusted
   clock for every `TimeSet` member, and a captured-only getter. This getter
   implements the upstream interface without a network client.
5. Authenticate the quote and signed Intel documents with
   `verify.TdxQuoteContext`. Reuse `validate.TdxQuote` for exact REPORTDATA/MRTD
   and explicit DEBUG/MIGRATABLE rejection.
6. Require both results from `verify.SupportedTcbLevelsFromCollateral` to be
   `UpToDate`; do not interpret another Intel status as sufficient admission.
7. Return measurements only after all checks succeed. TDX1.5 service-TD fields
   need explicit policy; zero service-TD measurement is the initial strict
   profile, rather than assuming an arbitrary attached service TD is trusted.

The local guards preserve restrictions not guaranteed by upstream defaults:

- `DefaultOptions` does not enable collateral retrieval or revocation checks.
- Signed JSON has mandatory issue/expiry windows, duplicate-name rejection,
  and a relying-party rollback floor for both TCB Info and QE identity.
- Certificates remain subject to root validity, allowed algorithms, key usage,
  purpose, unsupported constraints and duplicate/critical-extension rejection.
- CRLs must be complete, direct, correctly scoped, authenticated, and current;
  missing, future, stale, delta or unsupported evidence is an error.
- Vendor URLs are matched against four exact captured responses. Certificate
  URLs cannot cause network access, retry, redirect or substitute collateral.

Collection can reuse `LinuxConfigFsQuoteProvider` directly, or an explicitly
selected legacy ioctl device. Do not use `client.GetRawQuote` with a provider,
because it automatically falls back to the legacy device. Google has no direct
userspace vsock/QGS protocol client at this revision: configfs relies on the
kernel and host's quote-generation configuration. Hardware qualification is
still required for both real transports.

The upstream logger initializes stdout. The helper must direct vendor logging
to stderr before handling IPC so stdout remains one framed JSON result.

## SEV-SNP mapping and current limitation

For Milan/Genoa, Google separates signature/certificate verification
(`verify.SnpAttestationContext`) from report policy
(`validate.SnpAttestation`). Both are mandatory. Explicit roots, product,
report-data, measurement, VMPL, component minima, launch minimum, mitigation
masks, debug/migration denial, SMT/alias-check policy, and provisional-firmware
denial must be supplied. `DisableCertFetching=true` plus a captured-only getter
prevents certificate fallback or network access. VLEK CSP enrollment and strict
nonzero VCEK HWID binding require additional local policy checks.

Although the current SEV ABI parses reports v2 through v5 and recognizes the
Turin product name, its KDS implementation constructs only `TCBVersionV0`,
expects a 64-byte HWID and decomposes report TCB fields as V0. It therefore does
not replace the existing Rust Turin FMC/8-byte-HWID appraisal faithfully.
Do not silently route an unsupported Google Turin request to native Rust.

Other differences requiring guards include permissive zero CHIP_ID handling,
optional mitigation minima, and CRL retrieval paths that do not themselves
enforce the full current-window policy. Google's SEV ioctl provider can fall
back to a report without certificates when certificate querying fails; an
explicit transport adapter must not hide that failure.

## Wire contract

All bytes are JSON base64 strings. The parent owns strict envelope decoding,
overall IPC bounds, process timeouts and stdout framing. See `types.go` for
field names, which preserve the Rust collateral and TCB-policy names.

- `tdx_verify` passes `VerifyRequest` and returns `VerifyResult` only after
  complete vendor verification and independent policy appraisal.
- `tdx_collect` passes `CollectRequest` and returns `CollectResult`, explicitly
  unverified. `platform` is `tdx`; transport is selected as `configfs` or `ioctl`.
- The verifier clock is internal trusted state, never a field in the request.

The package's current standard-library tests exercise real captured Intel
signing certificates and CRLs at their documented fixed capture time. They also
check freshness/rollback and adversarial framing. Unsigned framing vectors are
test data only and never stand in for successful quote verification.
