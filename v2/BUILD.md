# Reproducible Enclave Build

How to verify that a running enclave matches source code.

## Prerequisites

- AWS Nitro-enabled instance (e.g., m5.xlarge with enclave support)
- Docker, `nitro-cli`, Rust toolchain

## Build Steps

```bash
# 1. Build the unified-quote binary
cd v2
cargo build --release

# 2. Prepare build context
cp target/release/uq /tmp/uq-bin
cp -r src /tmp/src

# 3. Build Docker image
cp /path/to/v2/Dockerfile.enclave /tmp/Dockerfile.enclave
cd /tmp
docker build -t nodea -f Dockerfile.enclave .

# 4. Build EIF (Enclave Image Format)
nitro-cli build-enclave --docker-uri nodea:latest --output-file nodea.eif
```

The output includes PCR0 (sha384 hash of the enclave image):
```
{
  "Measurements": {
    "PCR0": "6a7a3ec78ff901bc2edbd7f0a5b091b1e4c7ab4f459644b0c8271574c1ae918c58e33928579d0106003ec880e0ac0a56",
    "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
    "PCR2": "..."
  }
}
```

## Verification

A verifier builds the same EIF from source and compares PCR0:

```bash
# Verifier builds from the same git commit
git clone https://github.com/maceip/unified-quote.git
cd unified-quote/v2
cargo build --release
cp target/release/uq /tmp/uq-bin
cp -r src /tmp/src
cd /tmp
docker build -t verify -f unified-quote/v2/Dockerfile.enclave .
nitro-cli build-enclave --docker-uri verify:latest --output-file verify.eif

# Compare PCR0 — must match the running enclave
```

Then verify the running enclave:
```bash
uq verify --remote https://<domain>
```

The TEE signature chain proves the attestation came from real Nitro hardware.
PCR0 proves the enclave image matches the one you built from source.
Value X proves the source files inside the enclave match what you hashed.

## What Each PCR Measures

| PCR | Measures |
|-----|----------|
| PCR0 | Enclave image (hash of EIF — kernel + ramdisk + application) |
| PCR1 | Linux kernel and boot ramfs |
| PCR2 | Application (Docker layer — unified-quote binary + source) |

## Running

```bash
# Launch (production mode — real PCR0 in attestation docs)
nitro-cli run-enclave --eif-path nodea.eif --memory 3500 --cpu-count 2

# Start proxy with ACME cert provisioning
CID=$(nitro-cli describe-enclaves | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['EnclaveCID'])")
uq proxy --cid $CID --port 443 --acme

# Verify from anywhere
uq verify --remote https://<value_x_prefix>.aeon.site
```

## Reproducibility Guarantee

Two builds from the same source produce identical PCR0. Verified:
```
Build #1 PCR0: e40110d5e9ef810cf15ca2c90c90927ee6ca46a486716a614269aaa1217a1b14a17ef59edd122e1a5cd0021849cccd79
Build #2 PCR0: e40110d5e9ef810cf15ca2c90c90927ee6ca46a486716a614269aaa1217a1b14a17ef59edd122e1a5cd0021849cccd79
```

This closes the BOOTSTRAP.md verification loop for Nitro:
source code → deterministic build → known PCR0 → hardware-attested quote → verified.
