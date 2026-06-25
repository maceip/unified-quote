# unified-quote

one attestation receipt across cloud tees.

`unified-quote` is a single eat-based quote format and verifier that behaves
identically on **aws nitro**, **amd sev-snp**, and **intel tdx**. a workload
proves what code is running with a hardware quote; that proof verifies the same
on any cloud or bare metal, because trust is rooted in the cpu vendor — not in a
provider.

## what works

- attested build inside a tee (stage 0).
- attested runtime that verifies the build before serving (stage 1).
- attested-tls: the certificate spki is bound into the hardware quote.
- recursive chain walk from runtime back to build.
- real quote verification for intel tdx, amd sev-snp, and aws nitro — each with
  its own evidence device, quote format, and pinned vendor root.

## live attestation (verified)

a real quote, minted on genuine hardware and verified end-to-end against the
amd vendor root — not a fixture.

- **node:** aws `c6a.xlarge`, us-east-2 — amd epyc 7r13 (milan), sev-snp at vmpl0
  (instance `i-0280d827121bac1e5`, left running).
- **signing key:** vlek (aws/azure cvms sign with a cloud-provisioned vlek, not a
  per-chip vcek; chip_id is masked).
- **chain:** report → vlek → asvk → **ark-milan** (pinned amd root).
- **launch measurement:**
  `b756dde72c548e42560ba6b43955b68c1239682104c78fa07989ed3d15478107cb0e0a2a9637604586b9615eb8da7617`

re-verify the captured receipt yourself (fetches the vlek cert chain from amd kds):

```bash
cargo build --release --bin uq
./target/release/uq verify deploy/live-snp/snp-verified.json
# → binding PASS · quote binding PASS · measurement PASS · signature chain PASS
```

## verify a live endpoint

```bash
# verifier only — no tee required (v2/)
cargo build --release --bin uq
./target/release/uq check https://<host>/
```

## platform support

| platform | evidence | signature → pinned root |
|---|---|---|
| intel tdx | configfs-tsm · /dev/tdx-guest | ecdsa-p256 → intel sgx root ca |
| amd sev-snp | /dev/sev-guest · configfs-tsm | ecdsa-p384 vcek/vlek → amd ark (milan/genoa) |
| aws nitro | /dev/nsm (nsm api) | ecdsa-p384 → aws nitro root ca |

## the stack

- agent platform — [cvm-agent](https://github.com/maceip/cvm-agent)
- attestation service — [attestation-service](https://github.com/maceip/attestation-service)
- quote format — **unified-quote** (here)
- in-tee runtime — [attested-workload](https://github.com/maceip/attested-workload)

this is the base layer. the others depend on it directly — it is the `uq`
verifier in the `v2/` workspace member crate `unified-quote`:

```toml
unified-quote = { git = "https://github.com/maceip/unified-quote", package = "unified-quote" }
```

attestation-service issues/verifies with it, attested-workload emits + cross-
verifies its receipts under it, and cvm-agent meshes the whole stack on top.

pages: https://maceip.github.io/unified-quote/

## license

mit

<!-- agentic-canon -->
## agentic canon

<table>
<tr>
<td width="200" valign="top"><img src="docs/assets/canon-scroll.png" width="180" alt="agentic canon" /></td>
<td valign="top">

**no proof, no privilege.**

1. **make behavior enforceable.** replace conventions with hardware quotes, attested gates, and runtime checks.
2. **turn failures into evolution.** each failed verification hardens the shared verifier, not just one deployment.
3. **compose through proofs.** every layer declares what it accepts, returns, and can prove.
4. **carry trust forward.** a proof from one stage becomes the ground the next stands on.

</td>
</tr>
</table>
