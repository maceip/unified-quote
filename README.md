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
- **live endpoint:** `https://3.138.156.141/` — the node serves attested-TLS
  (stage 1) with the receipt embedded in the cert. re-verify remotely below.

re-verify the captured receipt yourself (fetches the vlek cert chain from amd kds):

```bash
cargo build --release --bin uq
./target/release/uq verify deploy/live-snp/snp-verified.json
# → binding PASS · quote binding PASS · measurement PASS · signature chain PASS
```

## verify the live endpoint

no tee required — the verifier authenticates the cert by attestation, not by ca:

```bash
cargo build --release --bin uq
./target/release/uq check https://3.138.156.141/
# → spki binding PASS · quote signature PASS · chain PASS (stage1 → stage0)
# → "3.138.156.141 is a genuine SevSnp TEE running Value X 174dbc6ab29abf3d"
```

a second live node proves the same verifier on **aws nitro** (enclave on
`m5.xlarge`, us-east-2). the pcr0 reported by `uq check` matches the pcr0 from
`nitro-cli build-enclave` exactly — the enclave runs precisely the image we built:

```bash
./target/release/uq check https://3.17.186.5/
# → spki binding PASS · quote signature PASS (→ pinned aws nitro root)
# → pcr0 1289f1bd… · "3.17.186.5 is a genuine Nitro TEE"
```

a third live node runs on **azure** (confidential vm, `Standard_DC2as_v5`,
westeurope). azure runs sev-snp under the vTOM paravisor, so there is no
`/dev/sev-guest`; the paravisor publishes the snp report through the **vTPM**
(NV index `0x01400001`). `uq azure` extracts that report and verifies it against
the **amd root** — per-chip vcek → ask → ark-milan — so the verdict chains to amd
silicon, not to microsoft azure attestation (MAA):

the node is served over **attested-TLS** at `attest.secure.build` — the leaf
cert itself carries the snp→amd evidence (no ca in the chain), and the cert key
is bound into the hardware quote:

```bash
./target/release/uq azure check-tls https://attest.secure.build:8443/
# → channel binding PASS (cert SPKI bound into the AK quote)
# → verdict verified · sig + chain PASS (→ pinned amd ark-milan)
# → measurement 41f77fe5… · value_x dde6f4c1… (source identity, see below)

# or re-verify captured vTPM evidence offline (fetches vcek from amd kds):
./target/release/uq azure verify deploy/azure-hcl/azure-hcl.bin
```

the azure node also carries a **source-level `value_x`**. report_data only
endorses the vTPM ak (the paravisor owns it), so `value_x` rides an ak-signed
`tpm2` quote instead: amd root → snp report → endorses the vTPM ak → ak signs a
quote whose `qualifyingData` is `value_x`. `uq azure collect --value-x <sha256>`
produces a bundle carrying that quote; `check`/`verify` confirm the signature and
that `extraData == value_x`. here `value_x` is the digest of `attestation-service`,
built inside that same cvm by a self-hosted github runner with github build
provenance for the identical digest — two roots (sigstore + amd) meeting at one
value. same linked pattern as nitro+nitrotpm.

## platform support

| platform | evidence | signature → pinned root |
|---|---|---|
| intel tdx | configfs-tsm · /dev/tdx-guest | ecdsa-p256 → intel sgx root ca |
| amd sev-snp | /dev/sev-guest · configfs-tsm | ecdsa-p384 vcek/vlek → amd ark (milan/genoa) |
| aws nitro | /dev/nsm (nsm api) | ecdsa-p384 → aws nitro root ca |

## aws: nitro vs sev-snp, and how we link them

a fair question about the aws node: **a nitro attestation roots to aws, not to
silicon.** the nitro security module signs the enclave document with the same
pki as nitro enclaves, so it attests *the guest image* (pcr0…) but the trust
ultimately terminates at the **aws nitro root ca** — aws vouches for it.
tdx/sev-snp are different: the **cpu vendor** (intel/amd) signs the report, so
the verdict roots in silicon and you don't have to trust the cloud operator.

there is a symmetric gap on the snp side: on an snp instance the hardware
`MEASUREMENT` only covers the **ovmf firmware** launched by the cpu — it does
**not** cover the kernel, initrd, or cmdline. those guest layers are measured by
**nitrotpm** into pcr 0–7.

so each root sees half the picture: amd signs the platform/firmware launch but
not the kernel; nitro signs the kernel pcrs but roots in aws, not silicon. we
close both gaps by **linking the two roots through one field**:

1. collect the **nitrotpm** attestation document (`COSE_Sign1`, nitro-signed)
   covering the kernel pcrs;
2. bind `sha256(nitrotpm_doc)` into the snp **`REPORT_DATA[0..32]`** (the lower
   32 bytes; `value_x` rides the upper 32);
3. amd signs that `REPORT_DATA`. so the **amd root** now cryptographically
   vouches that *a genuine snp tee collected exactly this nitrotpm document* —
   and the nitro root vouches the kernel pcrs inside it.

the result is a single receipt with **two independent hardware roots of trust,
cryptographically chained** (`v2/src/tee/tpm.rs`): amd silicon for the platform,
aws nitro for the kernel image, joined at `REPORT_DATA`. neither root alone is
sufficient; together they cover firmware → kernel → workload with no trust in
the host operator. it is the same linking pattern the azure node uses for
`value_x` (snp-endorsed vTPM ak signs a quote over the source identity).

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

live dashboard: https://maceip.github.io/unified-quote/live.html — aws sev-snp, aws
nitro, and azure sev-snp all show verified; azure value_x is registry-recommended.

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

