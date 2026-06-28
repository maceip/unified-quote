# Registry

A list of Value X entries that have been reviewed and approved by
maintainers. Each entry is a JSON file; each file has a detached
signature sidecar.

## What's in a registry entry

```json
{
  "value_x": "b1b09aae...",        // sha384 of runner source (48 bytes hex)
  "source_commit": "abc123...",    // git commit this was built from
  "platform_measurements": {        // optional: known-good platform hashes
    "nitro_pcr0": "...",
    "tdx_mrtd":   "...",
    "snp_measurement": "..."
  },
  "status": "recommended",          // recommended | deprecated | revoked
  "approved_at": "2026-04-13T00:00:00Z",
  "deprecated_at": null,            // when status changed to deprecated
  "revoked_at":    null,            // when status changed to revoked
  "notes": "free-form text"
}
```

Filename: `<value_x[0..16]>.json` — short prefix of Value X, for easy lookup.

## Signatures

Each entry has a detached signature sidecar: `<value_x[0..16]>.json.sig`.

**Today:** unsigned entries are informational only, and sidecars are reported
as unchecked until Sigstore verification lands in `src/registry.rs`. The
signer will be Sigstore keyless (cosign + Fulcio + GitHub OIDC), so a
maintainer never holds a key — the CI workflow identity is what signs.

**Migration path:** swap the verifier impl in `src/registry.rs`. The
on-disk format does not change.

## Trust model

- **Who can add entries:** whoever controls the Sigstore signing identity
  (the GitHub workflow in `.github/workflows/registry-sign.yml`).
- **Who verifies:** anyone — verification is `cosign verify-blob` against
  the pinned identity.
- **What's in the trust chain:** Sigstore root → Fulcio CA → GitHub OIDC
  issuer → workflow path. All pinned in `src/registry.rs`.

## How it's used

1. `uq build` in a TEE emits an attestation with a Value X.
2. Maintainer reviews, runs the `registry-sign` workflow, entry is committed.
3. `uq check https://<domain>` fetches the attestation, verifies
   the TEE quote, looks up Value X in the registry, reports status:
   - `recommended` — green
   - `deprecated`  — yellow (grace period, client policy decides)
   - `revoked`     — red
   - `unknown`     — gray (not in registry at all)

Clients set their own acceptance policy. The registry is the source of
truth; what to do with it is local.

## eat-pass / mobile binding

When minting eat-pass tokens from a CVM or mobile app:

- **Channel binding** — `value_x` / quote `report_data` must equal
  `binding_of(blinded)` from the mint (Hanff CCS 2025).
- **EAT freshness** — verifiers may set `UQ_EAT_NONCE` (64 hex) before quote
  collection so `eat_nonce` is server-chosen (Fahl ASIACCS 2023 pattern).
  See `v2/src/eat.rs` (`EAT_NONCE_ENV`).

Mobile attestation bundles live in `v2/src/tee/mobile/`; policy uses
`app_id_hash` on the attester (Leierzopf SPICES 2025).
