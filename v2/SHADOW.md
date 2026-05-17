# Shadow Attestation

A GitHub Action (`maceip/bountynet-shadow@v1`) that developers add to
their normal workflow. The Action packages the checked-out workspace,
binds it to GitHub's own OIDC/Sigstore SBOM or provenance attestation,
and sends that build bundle to our shadow spawner. The spawner creates
a fresh isolated TDX VM, rebuilds inside the TEE, and returns an EAT
token binding (GitHub workflow identity, source, build command,
artifact, Value X) to genuine hardware. The user never has to rent a
TEE or handle tarballs. They get a hardware-rooted rebuild witness
anyway.

This document is the design. Code lives elsewhere when it exists.

## Why this exists

Shadow attestation is the feature that makes bountynet useful to people
who do not care about TEEs or code signing. Without it, the story is
"we run our own stuff in a TEE, you'd have to do the same." With it, the
story is "add one workflow step, get a hardware-rooted rebuild witness
bound to GitHub's own attestation of your workflow." That is the path to
package promotion, AI-agent trust receipts, and secret release gates.

It is also where the project's hardest questions live: running untrusted
code in the most sensitive part of our own infrastructure. Everything
below is designed on the assumption that shadow attestation is
adversarial by default.

## Product shape

The public v1 surface is a GitHub Action, not a raw anonymous tarball
upload API:

```yaml
- uses: maceip/bountynet-shadow@v1
  with:
    build: cargo build --release
    artifact: target/release/my-app
```

The Action hides the transport details:

1. Checks the workspace already present in the user's workflow.
2. Packages the workspace deterministically into a build bundle.
3. Records GitHub context: repository, ref, SHA, workflow, run ID, job.
4. Requests a GitHub OIDC token for audience `bountynet-shadow`.
5. Produces or locates a GitHub-sourced SBOM/provenance attestation
   for the workflow artifact.
6. Sends bundle + build command + artifact digest + OIDC token +
   GitHub attestation to the shadow spawner.
7. Uploads `shadow-attestation.cbor` as a workflow artifact.

The internal spawner still exposes `/shadow-build`, but v1 treats it as
the Action backend. A raw public "paste a tarball" API is deferred until
the abuse, identity, and billing rails have survived real use.

The useful verifier claim is:

> GitHub says workflow `repo@sha` produced artifact digest `A`.
> BountyNet says an isolated TDX VM rebuilt the submitted source and
> produced artifact digest `A'`, CT, and Value X. If `A == A'`, the
> normal GitHub build and the TEE rebuild agree. If not, the shadow
> attestation is still valid, but the build is not reproducible or the
> submitted inputs differ.

## Constitutional check

- **Build the thing the ecosystem isn't ready for.** Nobody is running
  third-party-submitted builds inside a TEE with a hardware-rooted
  attestation contract today. This is exactly the kind of pattern the
  design note §5 ("Build the right thing even if the ecosystem isn't
  ready") defends.
- **Single primitive, many consumers.** EAT is the output. The shadow
  service is just another producer of the same token our own build path
  produces. No new wire format.
- **Stateless.** The shadow VM holds no durable state. Every request =
  a fresh VM. Death = all data gone.
- **Peripheral vision.** Seal/unseal, cluster join, multi-node trust
  graph — shadow attestation does not contradict any of them. It
  doesn't need them either.

## The core threat

Running arbitrary code inside a TEE that shares any trust relationship
with the rest of bountynet is an existential risk to the project. If a
shadow build escapes its sandbox into the host, the attacker gets:

- The GitHub self-hosted runner token for `maceip/bountynet-genesis`
- Root on the machine running `bountynet-live.service`
- The ability to issue fresh attestations from a compromised environment
  that still looks legitimate to any verifier that doesn't pin Value X
- The ouroboros lineage — the attacker can now build malicious code and
  have it attested as "built by the genuine TDX runner"

**Non-negotiable isolation rule:** the shadow service runs on its own
instance with zero network path to the primary runner. No shared cache,
no shared service account credentials, no DNS overlap, no filesystem
bridge. If the shadow host is compromised, the blast radius is the
shadow host and the current day's spend cap — and that's it.

**v1 isolation posture (dedicated project + isolated VPC):** the
shadow service lives in its own GCP project
(`bountynet-shadow-20260415`), distinct from the project that hosts
`bountynet-tdx-runner`. Same organization (`rex-org`, 176195637999),
same billing account, but a project-level trust boundary between the
two. Inside that project the shadow VMs run in their own dedicated
VPC. A build escape must compromise the sandbox, escape the VM,
traverse the VPC with no route to anywhere useful, *and* cross a
project boundary before it can reach the primary runner. Credentials
are partitioned at the project level, so even a compromised shadow
host has no IAM path into `lowkey-b7136` or wherever the primary
runner lives.

Concretely for v1:

- **Project:** `bountynet-shadow-20260415`. Created via Cloud
  Resource Manager API on 2026-04-15. Compute and Confidential
  Computing APIs enabled. No service accounts, no IAM bindings
  granted yet beyond the default.
- **VPC:** `shadow-vpc`, created inside the shadow project. No VPC
  peering to the primary runner's VPC. No shared VPC setup. No VPN
  tunnel. No Cloud Router route leak. Cross-project networking is
  off by default and stays off.
- **Subnet:** a single `/24` subnet in the same region as the primary
  runner (for PoP latency parity), reserved exclusively for shadow VMs.
- **Firewall — ingress:** deny all by default. Allow only `tcp:443`
  from `0.0.0.0/0` to the shadow frontend (the request handler). No
  SSH from the internet. Operator SSH goes through IAP tunnel only.
- **Firewall — egress:** deny all by default. Allow only to the
  caching proxy's internal IP on the ports the proxy serves. No
  metadata-service access from shadow VMs (disable on instance
  creation via `--no-service-account` + `--no-scopes`). No GCP API
  access. No DNS except a pinned resolver pointing at the proxy.
- **Service accounts:** shadow VMs boot with no service account
  attached. The request handler that spawns them runs as a dedicated
  service account with permission to create/delete VMs in
  `shadow-vpc` only — IAM policy explicitly scoped, no project-wide
  compute.admin.
- **Metadata service:** disabled at boot via the instance metadata
  flag `block-project-ssh-keys=true` and no scopes granted. A build
  escaping into the VM that tries `curl metadata.google.internal`
  gets nothing.

## Threat categories (seven)

Cataloged during the 2026-04-15 design discussion. Every rail below
maps to one or more of these.

### 1. Host compromise → repo takeover

Build escape via toolchain bug, kernel exploit, or supply chain
compromise of a build dependency. Attacker reaches the host, exfiltrates
credentials, issues fake attestations, modifies future builds.

**Mitigation:** dedicated host, ephemeral VM per request, no shared
credentials, no persistent storage, no network path to the primary
runner. This is the single most important control.

### 2. Claim laundering / reputation attack

Attacker submits malware and receives a real hardware-rooted attestation
that the malware was "built in a genuine TDX environment." Uses the
attestation to launder reputation — the signed token looks identical to
a legitimate build.

**Mitigation:** v1 requests must carry GitHub workflow identity and a
GitHub-sourced SBOM/provenance attestation. The shadow EAT explicitly
tags shadow-origin builds (`eat_profile: "bountynet-shadow-v1"`),
separate from `bountynet-v2`, and includes the requester identity:
repository, ref, SHA, workflow, run ID, and the GitHub attestation
subject digest. Verifiers can choose to reject shadow-profile tokens.
The registry never accepts a shadow-profile EAT as a trust root. Value
X from shadow builds is never merged into the project's TrustRoot.

### 3. Resource / economic abuse

Attacker floods the endpoint to drive up GCP bills, burn bandwidth,
saturate disk, or run cryptomining workloads inside the TEE.

**Mitigation:** all the rails in §Rails below. Spend cap is the
backstop; PoW + rate limits + no-egress + submission dedup handle the
common cases first.

### 4. Attestation semantics attacks

- **Replay:** reusing an old attestation for a new context.
- **SLSA pairing:** forging a Sigstore bundle that claims the shadow
  attestation as evidence.
- **Timestamp warp:** submitting with a forged `iat` to pass policy
  checks.
- **Downgrade:** requesting an older token profile to avoid a newer
  control.
- **Value X collision:** crafting inputs that produce a Value X
  matching a different legitimate project.

**Mitigation:** shadow EATs always carry a server-chosen nonce and
`iat`; clients can't control either. The `eat_profile` field is
pinned at the token issuer; no downgrade path. Sigstore bundle
verifiers don't accept shadow-profile EATs as evidence (enforced at the
registry layer, not at shadow). Value X collision is handled by the
length + domain separation already built into `compute_tree_hash`.

### 5. Data leakage / privacy

- **Source privacy:** the submitter's code is visible to us (and in the
  VM's memory) during the build.
- **Build output leakage:** cross-tenant cache leaks between requests.
- **Timing side channels:** measuring build time to leak information
  about a submitted secret.

**Mitigation:** every build is a fresh VM. No shared cache, no shared
disk, no shared memory. The VM boots, builds, emits the attestation,
and dies. We document explicitly that shadow attestation is **not a
confidentiality guarantee** — it is an integrity guarantee. Don't
submit secrets. This is in the endpoint's API docs in bold.

### 6. Protocol parser attacks

- Tarball path traversal, symlink escape, zip bomb, tar-in-tar nested
  decompression, huge member headers.
- CBOR panic via crafted claim set (fuzz surface).
- Unicode normalization attacks on build command strings.

**Mitigation:** tarball extraction happens inside the ephemeral VM, not
on the host. Worst case of a parser bug is the VM crashes — cost is
one wasted slot in the spend cap. Host-side, submissions are byte
arrays, never parsed, never interpreted. CBOR parsing uses `ciborium`'s
strict mode, and the server rejects any request > 10 MB outright.

### 7. Trust model undermining

If every project on earth uses our shadow service, bountynet becomes
the single vendor root for everyone's attestation chain. We are now
the target of every advanced threat actor, and any compromise of the
shadow host is a supply chain compromise for every downstream user.

**Mitigation:** shadow is explicitly not a replacement for running your
own TEE. The docs say so. We do not target ubiquity. We target the
demo. The registry layer is per-project-configurable (see DESIGN.md
§"Registry trust is configurable, not hardcoded") so users who care can
point their TrustRoot at their own signing identity and never trust
ours.

## Rails

Cheapest-first, so subsets can ship incrementally.

### 1. Daily spend cap — **$100/day**

Enforced at the admission layer, not billing. A process-local counter
(persisted to disk or a small KV) increments when a VM is spun up and
is compared against the day's budget in the request handler. When the
budget is exhausted, new requests return `503 Service Unavailable` with
`Retry-After: <seconds-until-UTC-midnight>`.

GCP billing alerts are after-the-fact and will not save us from a
runaway. This counter is the real backstop.

**Budget math** (n2d-standard-2, TDX-capable, ~$0.18/hr on-demand):

| Tier | Wall clock | Boot/teardown | Cost per build | Max builds/day at $100 |
|---|---|---|---|---|
| Default | 15 min | ~2 min | ~$0.051 | ~1,960 |
| Extended | 60 min | ~2 min | ~$0.186 | ~537 |

Comfortable ceiling for a viral moment. Abusive traffic hits the cap
long before genuine users get rate-limited.

### 2. Wall clock — **15 min default, 60 min extended opt-in, 60 min hard cap**

Data from 10 maceip repos sampled 2026-04-15:

| Tier | Representative repo | Observed build time |
|---|---|---|
| Trivial (~2–3 min) | socket.iwa, cs16.css | 2m30s |
| Medium (~7–8 min) | mobile-sandbox (Kotlin APK) | 7m48s |
| Heavy (~11–15 min) | v9 (CI failing at ~11m30s) | ≥11m30s |

Default tier of 15 min covers every repo in the sample with headroom.
Extended tier opt-in lets a caller request 60 min by paying 4× the PoW
cost. Hard cap of 60 min is absolute; full-WebKit-shaped builds are
explicitly out of scope and should run on dedicated infrastructure.

### 3. No egress except allowlist

The shadow VM boots with outbound network disabled except to a fixed
allowlist. Initial allowlist:

- `crates.io` + `index.crates.io` (via a caching proxy we control)
- A local npm / pypi / maven mirror (same proxy)
- Nothing else

The caching proxy sits on the shadow host (not the VM) and enforces
both the allowlist and a per-request bandwidth ceiling. This single
control kills cryptomining exfil, C2 callbacks, external DoS amplifiers,
and most data exfiltration vectors at once.

### 4. GitHub identity admission

Before a VM is spawned, the spawner verifies:

- The OIDC JWT signature against GitHub's JWKS.
- The token `aud` equals `bountynet-shadow`.
- The token carries the expected repository, ref, SHA, workflow, run ID,
  and job claims.
- The submitted GitHub SBOM/provenance attestation is GitHub-issued.
- The attestation subject digest matches the artifact digest claimed by
  the workflow.
- The build bundle's source identity matches the request context well
  enough for v1 policy. For GitHub Actions this means the checked-out
  SHA in the request must match the OIDC/SBOM SHA; local uncommitted
  files are not part of v1.

This is the v1 anti-impersonation rail. It does not prove the source is
good. It proves who asked for the rebuild and which GitHub workflow
artifact the shadow witness is being paired with.

### 5. Proof-of-work admission ticket

Before a VM is spawned, the client must present a hashcash-style
preimage against a server-chosen target. Default tier: ~2–10 seconds
of client CPU on a modern laptop. Extended tier: ~10–40 seconds.

Properties:
- No account system, no API keys, no captchas. Works from a static page.
- Cheap for a demo visitor building one or two projects.
- Linearly expensive for an attacker trying to exhaust the spend cap.
- Tunable: if abuse rises, the target difficulty goes up with no code
  change.

### 6. Submission dedup

Hash the `(bundle_sha256, build_command, artifact_path, github_sha,
tier)` tuple. If we built it in the last 24 hours, return the cached
attestation instead of spinning a new VM. Cost: one blob store read.

Properties:
- Legitimate visitors replaying a demo get an instant response.
- Spammers can't force new VM allocations by resubmitting identical
  payloads.
- The cache is keyed by content + command + tier, so changing the build
  command or tier invalidates it.
- Cache entries carry their original `iat`, so stale attestations stay
  stale (replay defense in §Threats #4 still applies).

### 7. Per-repo + per-IP + per-ASN rate limits

Classic token buckets:
- 1 build per repository per 5 minutes
- 1 build per IP per 5 minutes
- 20 builds per /24 per hour
- 100 builds per ASN per hour

These don't stop determined attackers using Tor or residential proxies.
They do make the dumb case free to defend and force the smart case
through PoW + spend cap.

## What NOT to do

- **Don't statically analyze submissions.** Malware detection in
  arbitrary source tarballs is undecidable and a cat-and-mouse drain
  on attention.
- **Don't trust container-level isolation.** Not gVisor, not rootless
  Docker, not nsjail. VM-level is the isolation boundary.
- **Don't reuse the primary runner.** See §Core threat. Dedicated host.
  Dedicated project. Dedicated billing.
- **Don't accept shadow-profile EATs into the TrustRoot.** Shadow EATs
  are always explicitly tagged and verifiers can filter them.
- **Don't promise confidentiality.** Shadow attestation is an integrity
  primitive. The API docs say so in bold.

## Stake-to-build (deferred)

For any request above the per-IP/ASN floor, the future design requires
a tiny Lightning payment or a hash-locked on-chain deposit before the
VM is spawned. This is the BountyNet-native answer: the shadow service
becomes the first place where "stake something you already have" shows
up as a product surface instead of a thesis.

Deferred. Not in v1. Leave the hook in the admission path so it can be
added without restructuring. Stake-to-build is the rail that makes
shadow attestation sustainable at scale; PoW + spend cap is what lets
us ship this week.

## Action and GitHub attestation identity

The shim is a GitHub Action (`maceip/bountynet-shadow`, future repo) that
users drop into their workflow. It packages the workspace mid-job and
POSTs it to the spawner. For the spawner to distinguish a real Action
call from a handcrafted forgery, the request must carry a verifiable
identity rooted in GitHub and Sigstore, not in a secret we manage.

**Chain of trust design:**

1. **Publish-time:** every release of `bountynet-shadow` uses
   `actions/attest@v4` (or `actions/attest-sbom@v4`) in its release
   workflow to generate a Sigstore-backed SBOM attestation bound to the
   published artifact. Stored in Rekor, retrievable via the GitHub
   Attestations API.
2. **Runtime (inside user's workflow):** the Action reads its own
   on-disk bytes (for JS Actions, `dist/index.js`; for container
   Actions, the image digest the runner already knows).
3. **OIDC token:** the Action requests a GitHub Actions OIDC token via
   `ACTIONS_ID_TOKEN_REQUEST_URL`. The token carries
   `job_workflow_ref` which identifies *which Action release* is running
   (e.g. `maceip/bountynet-shadow/.github/workflows/shadow.yml@refs/tags/v1.0.0`),
   plus the caller's `repository`, `workflow`, `sha`, and `run_id`.
4. **GitHub artifact attestation:** the workflow produces a GitHub
   SBOM/provenance attestation for the artifact being paired with the
   shadow rebuild. The Action sends this attestation, the artifact
   digest, and the workspace bundle digest to the spawner.
5. **POST to spawner:** the Action includes the OIDC JWT + its own
   bytes digest + GitHub artifact attestation in the request headers
   or body.
6. **Spawner verifies:**
   - JWT signature against GitHub's JWKS
   - `aud` claim matches our expected audience
   - `job_workflow_ref` points at an Action release we've published
   - Fetches the published SBOM attestation for that release via the
     GitHub Attestations API
   - Confirms the Action's reported digest matches the SBOM subject
   - Checks the release tag against an allowlist of accepted Action
     versions (so we can retire buggy versions)
   - Verifies the caller's GitHub artifact attestation
   - Confirms the artifact digest in that attestation matches the
     digest submitted with the shadow request

**What this buys us:**
- No shared secret. No API key on our side to lose.
- Action and artifact identity rooted in Sigstore keyless via GitHub's
  Fulcio trust.
- Independent of the spawner — anyone can re-run the verification
  chain from scratch given only the attestation and the JWT.
- Defends against claim laundering: a forged POST without a valid OIDC
  token and matching GitHub attestation cannot pass. PoW + spend cap
  handle flood attacks; GitHub identity handles impersonation.

**Policy choice flagged for the Action phase:**

Accept only pinned release tags (`@v1.0.0`) vs any ref whose bytes
match some attestation we've published. Start strict (tags only),
relax if the UX hurts.

**Dependencies for this to work:**
- `maceip/bountynet-shadow` repo exists with a release workflow that
  runs `actions/attest@v4`
- First release cut, first attestation in Rekor
- Spawner has a module that fetches GitHub Attestations API results
  and caches them (not every request should re-hit the API)

Raw unauthenticated POSTs are not v1. The Action can be thin, but the
first public path is still Action-mediated and GitHub-identity-bound.
Local testing can use a fake identity provider or a dev-only bypass
behind a compile-time flag, but production shadow builds require the
GitHub OIDC + GitHub attestation pair.

## Open questions

- **Billing account separation.** v1 uses the same billing account as
  the primary runner (`018429-89A58A-3C3919`). If sustained abuse
  occurs, or if the shadow service gets advertised beyond the GitHub
  Pages demo, split billing so the spend cap has an enforceable
  hardware backstop (budget alerts + automated project disable on
  overrun) that can't be undone from a compromised primary-runner
  service account.
- **Does the shadow host re-attest to itself on every request?** A
  full attested-TLS handshake per inbound `/shadow-build` proves the
  host hasn't drifted. Costs ~50ms per request. Probably worth it.
- **Can submitters pin a base image?** Allowing `FROM debian:bookworm`
  vs `FROM scratch + user-supplied layers` is a big UX delta. Start
  with a single curated base image (Debian slim) and add choice later.
- **How does the caller discover the shadow host's Value X?** Published
  on the GitHub Pages site alongside the primary runner's. Rotated on
  every deploy, so CT logs are still the audit trail.
- **What happens when the spend cap trips?** `Retry-After` header is
  the honest answer, but we should also surface "today's spend used"
  on a public status page so visitors know before they burn a PoW
  ticket on a 503.

## Prototype implementation blockers

These are from the recovered shadow-spawner prototype notes. The
prototype code itself is not present in the current worktree; it appears
only in local Claude file-history. Treat these as the first checklist
when reconstructing the spawner.

1. **Subnet not created yet.** `shadow-vpc` exists, but the subnet does
   not. Any GCE boot path that passes `--subnet <shadow-subnet>` will
   fail until `gcloud compute networks subnets create ...` has run in
   `bountynet-shadow-20260415`.
2. **Cloud-init user-data escaping.** The recovered `boot_build_vm`
   prototype used `--metadata user-data=<multiline cloud-config>`.
   Real GCE may require different quoting or `--metadata-from-file`
   once the cloud-config grows past trivial content. Verify on live
   infrastructure before relying on it.
3. **Container-Optimized OS execution model.** The prototype staged the
   agent binary on an attached data disk and ran it from there. COS may
   mount non-boot disks with restrictive execution flags or otherwise
   block that model. Real infra must prove the agent can execute from
   the staged disk, or switch to copying into an executable boot-disk
   path before launch.
4. **Agent wall-clock enforcement.** The spawner can enforce wall clock
   externally by deleting or stopping the VM, but the agent should also
   enforce its own timeout for defense in depth. The recovered prototype
   had an unused internal timeout parameter; implement an agent-side
   deadline before public traffic.
5. **TDX MRTD extraction offset.** The recovered agent prototype parsed
   the TDX quote v4 layout with a hardcoded MRTD offset (`0x130`). That
   matched existing testdata, but it must be cross-checked against the
   actual COS-TDX image and quote format used by shadow VMs. Prefer a
   structured TDX quote parser over hardcoded offsets before this
   becomes a verifier-facing claim.

## Minimum viable v1

Six rails, in order of implementation:

1. Daily spend cap ($100, process-local counter, file-persisted)
2. Wall clock (15 min default, 60 min hard cap — no extended tier v1)
3. No-egress VM with a fixed allowlist through a caching proxy
4. GitHub OIDC + GitHub SBOM/provenance attestation verification
5. Submission dedup (content-hash keyed, 24 hour TTL)
6. PoW admission ticket (hashcash, SHA-256, server-chosen target)

Ship those six and the demo is safe enough to show the world. Per-IP
buckets, extended tier, and stake-to-build are v2. PoW can be relaxed
for a narrow allowlist during private testing, but not for the public
GitHub Pages demo.

The thing to decide before any code is written: **which GCP project
hosts the shadow service, and how is its billing scope separated from
`bountynet-tdx-runner`?** That is the constitutional boundary.
Everything else is implementation.
