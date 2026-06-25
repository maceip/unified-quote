# unified-quote

**One attestation receipt across cloud TEEs.** `unified-quote` defines a single
EAT-based quote format and verifier that behaves identically on **AWS Nitro**,
**AMD SEV-SNP**, and **Intel TDX**. A workload proves what code is running with a
hardware quote, and that proof verifies the same way regardless of which cloud
or chip it landed on.

The trust is rooted in the CPU vendor, not in any one provider: the same receipt
verifies on AWS, Azure, GCP, or bare metal and travels with the workload across
clouds — no shared control plane required.

## The stack

`unified-quote` is the **quote-format** layer of a confidential-compute platform
for running agents inside hardware TEEs across clouds. Each layer is its own
repo so it can be adopted independently:

| Layer | Repo | Role |
|---|---|---|
| Agent platform | [cvm-agent](https://github.com/maceip/cvm-agent) | End-to-end confidential-VM agent runtime — the product capstone |
| Attestation service | [attestation-service](https://github.com/maceip/attestation-service) | Shadow-builds and verifies EAT receipts for arbitrary source |
| **Quote format** | **unified-quote** — you are here | One EAT/quote format + verifier across Nitro, SEV-SNP, TDX |
| In-TEE runtime | [attested-workload](https://github.com/maceip/attested-workload) | Runs and serves a workload inside the TEE over attested TLS |

Read bottom-up: a workload runs inside a TEE ([attested-workload](https://github.com/maceip/attested-workload)),
emits a portable receipt in this format (`unified-quote`), gets that receipt
issued/verified as a service ([attestation-service](https://github.com/maceip/attestation-service)),
and an agent runtime gates privilege on it ([cvm-agent](https://github.com/maceip/cvm-agent)).

## What works today

The `v2/` implementation proves the cryptographic core:

- Stage 0 attested build inside a TEE.
- Stage 1 attested runtime that verifies Stage 0 before serving.
- Attested TLS certificate carrying an EAT receipt.
- Recursive chain walk from runtime back to build.
- Real hardware quote verification for Intel TDX, AMD SEV-SNP, and AWS Nitro,
  each with its own evidence device, quote format, and pinned vendor root
  (see [Platform Support](#platform-support)).
- Ouroboros CI path where this repo is built by its own attested runner.

## Product Surface

### Shareable Card

A Runcard should be something a developer can show, not just a file they store.
The card is the human-facing receipt:

- verdict: `verified`, `pending`, or `failed`
- subject: the service, package, tool server, or workflow
- source: repository and commit
- policy: the rule that allowed or denied privilege
- receipt URL: the full machine-verifiable evidence

Target surfaces:

```md
[![Runcard verified](https://runcard.dev/badge/agent.example.com.svg)](
  https://runcard.dev/card/agent.example.com
)
```

```http
GET /.well-known/runcard/card.json
GET /.well-known/runcard/receipt
```

### App/API

Apps should not parse attestation internals. They should ask for a verdict.

```ts
const verdict = await runcard.verify(target, {
  source: "github.com/acme/support-flow",
  policy: "reviewed-main-only"
});
```

### CI Receipt

Drop one step into CI and receive `proof-receipt.json` plus the raw
`attestation.cbor` evidence.

```yaml
- uses: maceip/cvm-agent/action@main
  with:
    source: .
    cmd: npm test && npm run build
```

Today this wrapper expects a TEE-capable runner. The mass-market path should not
ask an app team to own that runner; it should send the checked-out workspace or
artifact digest to a short-lived shadow build service and return the receipt to
the normal GitHub job. See [`v2/SHADOW.md`](v2/SHADOW.md).

### Policy Gate

```bash
runcard gate \
  --receipt ./proof-receipt.json \
  --policy .runcard.yml
```

Example policy:

```yaml
source: github.com/acme/support-flow
ref: refs/heads/main
require_reviewed_commit: true
allow:
  secrets:
    - PROD_SUPPORT_TOKEN
```

### Agentic Integrations

- **MCP server:** `verify_runtime`, `verify_artifact`, `explain_receipt`,
  `should_release_secret`.
- **Agent SDK guardrail:** block tool calls that would release secrets, deploy,
  mutate repos, or access customer data unless the target has a valid receipt.
- **Runtime API:** `GET /.well-known/runcard/receipt` for services that want to
  advertise their proof.
- **GitHub check summary:** a PR-level line that says whether this code can
  receive privilege.

## How The Proof Works

Stage 0 runs the build inside trusted hardware:

1. Refuses to run outside a TEE.
2. Hashes and freezes the source tree.
3. Runs the build.
4. Hashes the artifact.
5. Computes `Value X`, the portable source identity.
6. Places the binding hash into the TEE quote.
7. Emits an EAT receipt as CBOR.

Stage 1 runs the service:

1. Loads the Stage 0 receipt.
2. Verifies the Stage 0 hardware quote.
3. Recomputes `Value X` from disk.
4. Generates a TLS key inside the TEE.
5. Collects a fresh runtime quote bound to that TLS key.
6. Serves an attested TLS certificate containing the runtime receipt.

A verifier checks that the TLS key matches the receipt, the hardware quote is
signed by the pinned vendor root, the runtime chains back to the build,
`Value X` stays stable across the chain, and project policy allows that
identity to receive privilege.

## Platform Support

Runcard speaks three hardware attestation dialects behind one verifier. Each
platform has its own evidence device, quote format, and vendor signature
scheme; `verify_platform_quote` ([`v2/src/quote/verify.rs`](v2/src/quote/verify.rs))
normalizes all three to the same check: *report_data binds our value, and the
signature chains to a pinned vendor root.*

### Intel TDX

- **Evidence:** configfs-tsm (`/sys/kernel/config/tsm/report`, preferred) or the
  legacy `/dev/tdx-guest` ioctl plus a Quote Generation Service.
  ([`v2/src/tee/tdx.rs`](v2/src/tee/tdx.rs))
- **Quote:** DCAP TD Quote v4. Measurements are `MRTD` (boot-locked firmware
  measurement) and `RTMR0-3`; the binding lives in `REPORTDATA[0..32]`.
- **Root of trust:** ECDSA-P256 chain `Intel SGX Root CA → PCK → QE report →
  Attestation Key`, root pinned by SHA-256 fingerprint.
- **Status:** proven Stage 0 → Stage 1 on GCP `c3-standard-4`. Verified in the
  default test suite, including the ouroboros self-build fixture.

### AMD SEV-SNP

- **Evidence:** `/dev/sev-guest` ioctl (`SNP_GET_EXT_REPORT`, falling back to
  `SNP_GET_REPORT`) or configfs-tsm on Linux 6.7+.
  ([`v2/src/tee/snp.rs`](v2/src/tee/snp.rs))
- **Quote:** 1184-byte SNP attestation report. `MEASUREMENT` is the launch
  digest; the binding lives in `REPORT_DATA[0..32]`.
- **Root of trust:** ECDSA-P384 chain `ARK → ASK → VCEK`. The VCEK is read from
  the report's embedded cert table when present, otherwise fetched live from
  AMD KDS. Root pinned to the AMD ARK fingerprint (Milan for report v2, Genoa
  for v5).
- **Status:** verifier proven against captured fixtures. The committed fixtures
  do not carry the embedded cert table, so the full signature test calls AMD
  KDS and is `#[ignore]`d in the default `cargo test` to avoid a live network
  dependency.

### AWS Nitro

- **Evidence:** `/dev/nsm` via the Nitro Security Module API.
  ([`v2/src/tee/nitro.rs`](v2/src/tee/nitro.rs))
- **Quote:** a COSE_Sign1 attestation document carrying `PCR0-15` and an
  enclave-generated RSA-2048 public key (used so AWS KMS can encrypt a
  `CiphertextForRecipient` only this enclave can decrypt). The binding lives in
  `user_data[0..32]`.
- **Root of trust:** ECDSA-P384 / ES384 chain `AWS Nitro Root CA → cabundle →
  leaf certificate`, root pinned by SHA-256 fingerprint.
- **Status:** proven single-process Stage 0 on an `m5.xlarge` enclave. Verified
  in the default test suite. Stage 0 → Stage 1 chaining needs a second enclave
  running `cmd_run` (a follow-up, not a gap in verification).

### Summary

| Platform | Hardware | Evidence path | Signature → pinned root | Chain | Status |
|---|---|---|---|---|---|
| Intel TDX | GCP c3-standard-4 | configfs-tsm / `/dev/tdx-guest` | ECDSA-P256 → Intel SGX Root CA | Stage 0 to Stage 1 | Proven (default tests) |
| AMD SEV-SNP | AWS c6a.xlarge | `/dev/sev-guest` / configfs-tsm | ECDSA-P384 → AMD ARK | Stage 0 to Stage 1 | Proven; full sig test needs live AMD KDS |
| AWS Nitro | AWS m5.xlarge enclave | `/dev/nsm` (NSM) | ECDSA-P384 → AWS Nitro Root CA | Stage 0 single-process | Proven (default tests) |
| Azure SEV-SNP | Azure Standard_DC4as_v5 CVM | AMD PSP + Azure vTOM | (no raw SNP evidence path) | blocked before Stage 0 | Tested, not verified |

Real attestation bytes live in [`v2/testdata/chain/`](v2/testdata/chain) and the
pinned vendor roots are in [`v2/src/quote/roots.rs`](v2/src/quote/roots.rs). The
regression suite ([`v2/tests/hardware_regression.rs`](v2/tests/hardware_regression.rs))
runs TDX and Nitro verification by default; the SNP signature test is present
but ignored by default because the captured reports currently require live AMD
KDS access. Azure CVM provisions with AMD SEV memory encryption but does not
expose a raw `/dev/sev-guest` / configfs-tsm evidence path through its vTOM
paravisor, so it stays *tested, not verified* until an Azure MAA/vTOM collector
is added — see [`v2/HARDWARE_VALIDATION.md`](v2/HARDWARE_VALIDATION.md).

## Quick Start

You need Rust installed to build the current engine locally.

```bash
git clone https://github.com/maceip/unified-quote
cd unified-quote/v2
cargo build --release --bin runcard
cargo test
```

Run an attested build inside a TEE-capable host:

```bash
sudo ./target/release/runcard build /path/to/source \
  --cmd "your build command" \
  --output ./attest-out
```

Run an attested service:

```bash
sudo ./target/release/runcard run /path/to/source \
  --attestation ./attest-out/attestation.cbor
```

Verify it from any machine:

```bash
./target/release/runcard check https://<domain>/
```

## Agent Workflow

For an agent deployed across clouds, the useful boundary is not "this binary is
signed." It is:

1. Build the agent, tool server, package, or release artifact.
2. Get a Runcard receipt for the source and artifact.
3. Gate secrets, publish rights, deploy rights, or live tool access on that
   receipt — wherever the agent runs.
4. Show the card in the PR, release page, package page, or live status view.

The receipt travels with the agent, so the same verification works whether it
lands on AWS, Azure, GCP, or your own hardware. This flow should be usable from
an ordinary GitHub-hosted job; the current repository has the cryptographic
pieces, and the next product cut is the developer path: `proof-receipt.json`,
`runcard gate`, check summaries, and a hosted shadow receipt option for teams
that do not run their own TEE hardware.

## Live Status

A public dashboard at [maceip.github.io/unified-quote/live.html](https://maceip.github.io/unified-quote/live.html)
shows the current verdict for each registered node. A scheduled workflow runs
`runcard check` against every node, writes the results to
[`docs/status/nodes.json`](docs/status/nodes.json), and republishes the page —
so the dashboard reflects live, independently re-verified attestations rather
than a static claim.

## Repo Map

- [`v2/src/eat.rs`](v2/src/eat.rs): EAT receipt schema and binding bytes.
- [`v2/src/main.rs`](v2/src/main.rs): build, run, check, enclave commands.
- [`v2/src/quote/verify.rs`](v2/src/quote/verify.rs): platform quote
  verification.
- [`v2/src/registry.rs`](v2/src/registry.rs): local verification registry.
- [`v2/action/action.yml`](v2/action/action.yml): GitHub Action wrapper.
- [`v2/SHADOW.md`](v2/SHADOW.md): no-TEE-required shadow attestation plan.
- [`docs/index.html`](docs/index.html): public Runcard narrative and browser
  proof.
- [`docs/live.html`](docs/live.html): live cross-cloud node status dashboard.
- [`deploy/`](deploy): per-cloud provisioning scripts (AWS, Azure, GCP).

## Status

`v2/` is the current codebase. The proof engine works; the next job is to make
Runcard feel like ordinary developer infrastructure:

- `proof-receipt.json`
- `runcard gate`
- GitHub Action check summaries
- MCP and agent guardrails
- shadow attestation service

## License

MIT
