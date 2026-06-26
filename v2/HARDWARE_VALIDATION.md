# Hardware Validation Runbook

End-to-end validation of the Stage 0 → Stage 1 chain on real TEE
hardware. Everything in this document is code that's already passing
unit + integration tests — the goal here is to confirm the tests
match reality on silicon.

## What we're proving

> "Is the code running on **that machine** the same code that's in
> the repo?"

Concretely, the chain:

```
source files
  → [TEE: stage 0 build, ratchet CT, collect quote A with
          binding_bytes_0 in report_data[0..32]]
  → stage 0 EAT (includes quote A, source_hash, value_x,
                 tls_spki_hash=0, previous_attestation=empty)
  → [TEE: stage 1 boot, load stage 0 EAT, verify quote A,
          re-compute value_x from disk,
          generate TLS keypair,
          set_previous(stage0_cbor),
          binding_bytes_1 includes sha256(stage0_cbor),
          collect quote B with binding_bytes_1 in report_data[0..32]]
  → stage 1 EAT (includes quote B, value_x, tls_spki_hash,
                 previous_attestation=stage0_cbor)
  → attested-TLS cert carrying stage 1 EAT at OID 2.23.133.5.4.9
  → [remote client: uq check]
  → [client verifies leaf quote, walks chain to stage 0,
     confirms value_x stable, checks SPKI binding]
```

Every link is a hash in a hardware-signed `report_data`. No gaps.

## What the unit/integration tests already prove

- EAT schema round-trips through CBOR.
- `binding_bytes()` is stable, excludes post-quote fields, includes
  `previous_hash()`, detects tampering.
- Attested-TLS cert carries the EAT at `2.23.133.5.4.9`, extension
  survives TLS handshake, SPKI hash of cert matches SPKI hash of
  keypair.
- Chain walker detects Value X drift, detects `previous_attestation`
  tampering, handles 3+ stage chains.
- Live rustls client + rustls server round-trip over TCP with a
  synthetic quote — everything except the platform signature
  verification.

## What only hardware can prove

These are the things we explicitly cannot test without a live TEE:

1. **The quote's report_data actually contains what we asked for.**
   `collect_evidence(&report_data)` on each platform must put our
   bytes in the right field of the hardware-signed quote. In tests
   we fake this; on hardware the NSM / SEV / TDX module does it.
2. **`verify_platform_quote` accepts real vendor-signed quotes.**
   Our signature verifier is pinned against AMD / Intel / AWS Nitro
   root CAs. Tests use synthetic quotes that don't verify. On hardware
   the signature chain must actually chain.
3. **Platform-specific report_data extraction.** `verify_platform_quote`
   parses CBOR for Nitro, byte offsets for SNP/TDX. A single off-by-one
   would pass tests (because the test quotes are synthetic) but fail
   on real quotes. Most likely failure mode on hardware.
4. **rcgen's SPKI DER encoding matches x509-cert's SPKI DER encoding.**
   Producer hashes `rcgen::KeyPair::public_key_der()`. Verifier hashes
   the `SubjectPublicKeyInfo` re-encoded via `x509-cert::der::Encode`.
   If the two disagree on, e.g., ECDSA parameters encoding, channel
   binding fails in a way the tests would not catch.
5. **Stage 0 → Stage 1 `NSM` re-initialization (Nitro only).** Nitro
   historically had issues with calling `nsm_init` twice in one
   enclave process. `cmd_run` on a Nitro instance calls NSM once
   for the stage 1 quote; if this fails we need to fall back to a
   single-process flow.

Every other failure would have been caught by the test suite.

## Platforms to test

The code has to work on all core TEE paths; a single-platform pass is not
sufficient. Priority order by cost to spin up:

1. **GCP TDX (`c3-standard-4` with `confidential-instance-type=TDX`)** —
   cheapest hourly, simplest setup, fastest quote collection.
2. **AWS SEV-SNP (`c6a.xlarge` with `AmdSevSnp=enabled`)** —
   second cheapest; tests our SNP path which is the most common
   production TEE.
3. **AWS Nitro Enclaves (`m5.xlarge` + enclave enabled)** —
   most expensive to set up (needs `nitro-cli`, `.eif` build,
   vsock bridge). Validates the most platform-specific code
   (CBOR report_data extraction, NSM re-init) — by far the
   most likely to surface a real bug.
4. **Azure SEV-SNP (`Standard_DC4as_v5` Confidential VM)** —
   tested on 2026-05-01. The VM provisions and boots with AMD SEV memory
   encryption, but Azure's vTOM/paravisor path does not expose
   `/dev/sev-guest`; configfs-tsm report creation fails with
   `No such device or address`. This is not counted as proven until we
   add an Azure MAA/vTOM evidence collector or get access to a raw
   SNP/TDX attestation SKU.

## Prep — build the release binary

On your local machine (or any x86_64 Linux host):

```bash
cd /home/cory/uq-runner/v2
cargo build --release
file target/release/uq     # should say ELF 64-bit LSB pie executable
ls -la target/release/uq    # should be ~13MB
```

Copy the binary to each target machine. `scp`, `aws s3 cp`,
`gcloud compute scp` — whatever works for your environment.

## Runbook — TDX (start here)

```bash
# 1. Spin up a TDX instance
gcloud compute instances create tdx-test \
  --zone=us-central1-a \
  --machine-type=c3-standard-4 \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE

# 2. Copy binary + a small test source tree
gcloud compute scp target/release/uq tdx-test:~/uq --zone=us-central1-a
gcloud compute scp --recurse testdata/sample-source tdx-test:~/source --zone=us-central1-a

# 3. SSH in
gcloud compute ssh tdx-test --zone=us-central1-a

# 4. Inside the VM: confirm TDX is available
ls /dev/tdx_guest /sys/kernel/config/tsm/report 2>&1
# At least one must exist; otherwise this isn't a TDX VM

# 5. Stage 0: attested build
mkdir -p ~/out
sudo ~/uq build ~/source --cmd 'echo stage0 build' --output ~/out 2>&1 | tee stage0.log

# 6. Confirm stage 0 outputs
ls -la ~/out/
#   attestation.json   — legacy
#   attestation.cbor   — the one we care about
file ~/out/attestation.cbor    # should be "data" (CBOR is binary)
wc -c ~/out/attestation.cbor   # typical size: 8-20KB for TDX

# 7. Stage 1: attested runtime (serves on :443)
sudo ~/uq run ~/source --attestation ~/out/attestation.cbor 2>&1 | tee stage1.log &
sleep 3

# 8. In another SSH session, run cmd_check against the local instance
~/uq check https://127.0.0.1/ 2>&1 | tee check.log
```

**Expected output of `cmd_check`** (ordered lines):

```
[uq] === attested-TLS check ===
[uq] Target: 127.0.0.1:443
[uq] Leaf cert: <~300> bytes DER
[uq] EAT extension: <~8000+> bytes
[uq] EAT profile: https://bountynet.dev/eat/v2
[uq] Platform:    Some(Tdx)
[uq] Value X:     <96 hex chars>
[uq] SPKI binding:    PASS
[uq] Verifying platform quote (binding + signature)...
[uq] Quote binding:   PASS
[uq] Quote signature: PASS
[uq]   MRTD: <hex>
[uq]   RTMR0: <hex>
[uq]   RTMR1: <hex>
...
[uq] Chain step 1: verifying previous stage (<N> bytes EAT)
[uq]   ✓ step 1 quote verifies (Value X stable)
[uq] Chain:           PASS (1 stage(s) walked)
[uq] CT (SCTs):       none in cert (self-signed path — expected)
[uq] Registry:        empty (no entries loaded)
[uq] === Check Complete ===
[uq] 127.0.0.1 is a genuine Tdx TEE running Value X <first-16-hex>
```

**If this exact sequence appears, the chain is proven on TDX.** Save
`stage0.log`, `stage1.log`, `check.log`, `out/attestation.cbor`, and
`~/out/stage1-attestation.cbor` — those are the validation artifacts.

## Runbook — SEV-SNP

Same as TDX structure, different instance type:

```bash
aws ec2 run-instances \
  --instance-type c6a.xlarge \
  --image-id ami-<ubuntu-2404-x86> \
  --cpu-options AmdSevSnp=enabled \
  --key-name <your-key>
```

Inside the VM: `/dev/sev-guest` must exist, then the same
`uq build → uq run → uq check` sequence. Expected
output is the same except `Platform: Some(SevSnp)` and the measurements
section shows `MEASUREMENT:` instead of `MRTD`.

## Runbook — Azure SEV-SNP

Azure provisioning uses the Azure CLI. The local CLI must be authenticated
first (`az login`) and the subscription must have confidential VM quota in
the selected region.

```bash
# 1. Spin up an Azure Confidential VM
./deploy/azure-cvm.sh

# Equivalent core az command used by the script:
az vm create \
  --resource-group uq-tee-validation \
  --location northeurope \
  --name uq-azure-snp \
  --size Standard_DC4as_v5 \
  --admin-username azureuser \
  --image "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest" \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --enable-secure-boot true \
  --public-ip-sku Standard \
  --generate-ssh-keys
```

Inside the VM, confirm one of the SNP evidence paths exists:

```bash
ls /dev/sev-guest /sys/kernel/config/tsm/report 2>&1
```

On the 2026-05-01 `Standard_DC4as_v5` test this failed:

```text
ls: cannot access '/dev/sev-guest': No such file or directory
mkdir /sys/kernel/config/tsm/report/uq-probe: No such device or address
```

The kernel did report encrypted execution:

```text
Memory Encryption Features active: AMD SEV
```

That proves Azure CVM provisioning, but not unified-quote's stage chain.
Azure can be added to the proven platform set only after `cmd_build`
can collect an evidence object that binds `EatToken::binding_bytes()`,
`cmd_check` prints `Chain: PASS (1 stage(s) walked)`, and the captured
`azure_snp_stage0.cbor` / `azure_snp_stage1.cbor` are committed as
hardware regression fixtures.

## Runbook — Nitro

This one is the most involved and most likely to surface a real bug.

```bash
# 1. Launch m5.xlarge with enclave enabled
aws ec2 run-instances \
  --instance-type m5.xlarge \
  --image-id ami-<nitro-enabled> \
  --enclave-options 'Enabled=true'

# 2. On the parent: install nitro-cli, allocate enclave resources
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo systemctl enable --now nitro-enclaves-allocator

# 3. Build the .eif (reproducible build path — see BUILD.md)
#    This packages unified-quote + source into an EIF image
#    Outputs uq.eif with PCR0 visible in nitro-cli describe

# 4. Start the enclave
sudo nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 1024 \
  --eif-path uq.eif \
  --debug-mode

# 5. Note the enclave CID from the output
#    Run the parent-side proxy
~/uq proxy --cid <CID> &

# 6. From your laptop:
curl -k https://<value_x>.aeon.site/  # should return EAT summary
~/uq check https://<value_x>.aeon.site/ 2>&1 | tee check.log
```

For Nitro, `cmd_enclave` runs stage 0 and serves it — there's no
separate `cmd_run` step in the single-enclave flow. Chain walking on
Nitro therefore reports "leaf only (no previous stage)" which is
correct for stage 0. To exercise the chain on Nitro you'd need a
second enclave that runs `cmd_run` — **that's a follow-up, not
required for this pass**.

**Primary Nitro validation goal:** confirm that `verify_platform_quote`
correctly parses the real Nitro COSE_Sign1 attestation doc and extracts
`user_data` for the binding check. This is the path that was broken in
the old byte-offset pre-check and was fixed in this round of changes.

## Things to look for that indicate real bugs

These are the specific failure signatures that mean the tests lied
(or missed a case). If you see any of these, capture the full logs
before retrying anything.

### "SPKI binding: FAIL"

Producer computed `sha256(rcgen.public_key_der())`. Verifier computed
`sha256(x509_cert.tbs_certificate.subject_public_key_info.to_der())`.
The two disagreed.

**Likely cause:** DER encoding mismatch between rcgen and x509-cert.
ECDSA-P256 SPKI DER is sensitive to whether the parameters field has
NULL or is absent.

**Fix:** compare the two DER blobs byte-by-byte in a debugger. Adjust
whichever side is wrong. Add a test.

### "Quote verify: FAIL — <report_data mismatch>"

Producer put `eat.binding_bytes()` in report_data before collecting
the quote. Verifier recomputed `eat.binding_bytes()` from the same
EAT and got a different value.

**Likely cause:** a field we're hashing in `binding_bytes()` got
mutated between pre-quote and post-quote. Either we're not respecting
the "exclude post-quote fields" rule somewhere, or serde's CBOR
round-trip is non-deterministic for a particular field type.

**Fix:** dump the stage 1 EAT before serialization and after
deserialization. Compare every field. The one that changed is the bug.

### "Quote verify: FAIL — <signature invalid>"

Hardware quote is there but the signature chain doesn't verify.

**Likely cause:** pinned root CA stale, vendor rotated keys, or
collateral fetching failed.

**Fix:** this is outside the chain work — it's a `quote/verify.rs`
issue. The existing `cmd_build` → JSON path should also fail in the
same way. If it does, the pinned root is the problem. If `cmd_build`
works but `cmd_run`/`cmd_check` don't, something in the new code
corrupted the quote bytes.

### "Value X drift across chain"

Stage 1 re-computed Value X from the work_dir and it didn't match
stage 0's. Legitimate if someone modified files between build and
run. Bug if nothing changed.

**Likely cause:** `compute_tree_hash` is non-deterministic (reads
directory entries in filesystem order instead of sorted). OR: stage 0
was built in a sandbox that includes files that stage 1's work_dir
doesn't have (or vice versa).

**Fix:** confirm `compute_tree_hash` sorts entries before hashing.
Confirm stage 1's work_dir matches stage 0's source_dir exactly.

### "chain step 1: quote signature failed" (Nitro only)

Chain walker successfully decoded stage 0 EAT but couldn't verify
its quote. This is the thing the old byte-offset pre-check masked.

**Likely cause:** the Nitro CBOR parser in `quote/verify.rs::verify_nitro_quote`
doesn't accept the quote format we stored. Maybe we stored the wrong
bytes in stage 0's `platform_quote` field.

**Fix:** dump stage 0's `platform_quote` hex. Compare with what
`cmd_build` originally wrote to `attestation.cbor`. If they're
identical, the parser is broken. If not, the round-trip corrupted them.

## Success criteria

All three of these must hold on at least one platform (TDX is the
easiest to get there first; Nitro is the most thorough):

1. **`cmd_build`** exits 0 and writes `attestation.cbor`.
2. **`cmd_run`** exits 0, writes `stage1-attestation.cbor`, and
   prints `Stage 1 Verified`.
3. **`cmd_check`** connects to the running stage 1 server, prints
   `Chain: PASS (1 stage(s) walked)`, and exits 0.

Once TDX passes, move to SNP. Once SNP passes, move to Nitro.
Once all three pass, the core chain is **proven on hardware** and
we can move to the next plumbing decision with confidence.

## After the hardware pass

Capture the real attestation bytes from each platform into
`v2/testdata/` (overwriting the old stage-0-only samples):

- `testdata/tdx_stage0.cbor`
- `testdata/tdx_stage1.cbor`
- `testdata/snp_stage0.cbor`
- `testdata/snp_stage1.cbor`
- `testdata/nitro_stage0.cbor`

Then update the integration tests to load these and run
`verify_platform_quote` against them, so future CI catches any
regression in the signature-verifier code against real inputs.
This turns the hardware pass from a one-time event into a
permanent regression gate.
