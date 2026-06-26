# unified-quote Attested Runner

```text
      *         .              .      *           .        *

   .=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=.
   |   B O U N T Y N E T   A T T E S T E D   R U N N E R         |
   |   confidential compute // remote proof // retro future      |
   '=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='

        .       *         trust the build, verify the machine
```


## Architecture

```text
╭────────────────────────────────────────────────────────────────╮
│        ╭──────────── ✦ UNIFIED-QUOTE ✦ ────────────╮             │
│        │ trust the build // verify the machine │             │
│        ╰──── confidential enclave // proof ────╯             │
├────────────────────────────────────────────────────────────────┤
│ [ TEE HARDWARE LAYER ]                                        │
│ AWS Nitro (/dev/nsm) • Intel TDX (/dev/tdx-guest) • AMD SNP  │
│                              │                                 │
│                              ▼                                 │
│ ╭────────────────────────────────────────────────────────────╮ │
│ │ uq-runner (Rust, boots first)                        │ │
│ │                                                            │ │
│ │ LAYER 1 // Application Identity                           │ │
│ │   Value X = sha384(runner binary manifest)                │ │
│ │   Same X on Nitro, TDX, and SNP for the same image        │ │
│ │   Anyone can rebuild from source and compute X            │ │
│ │                                                            │ │
│ │ LAYER 2 // Platform Proof                                 │ │
│ │   TEE quote binds (Value X + signing pubkey) to hardware  │ │
│ │   Proves this X was computed inside a genuine TEE         │ │
│ │   Raw quote off-chain, sha256 hash on-chain               │ │
│ │                                                            │ │
│ │ LAYER 3 // Attestable Builds                              │ │
│ │   source S -> artifact A inside environment E             │ │
│ │   TEE attests: (X, S, E) -> A even if build is non-repro  │ │
│ │   No need for deterministic user workloads                │ │
│ ╰──────────────────────────┬───────────────┬───────────────╯ │
│                            │               │                 │
│                  ╭─────────▼──────╮  ╭─────▼──────────╮     │
│                  │ GH Actions     │  │ /attest        │     │
│                  │ Runner         │  │ endpoint       │     │
│                  │ stock C#/.NET  │  │ GET  /attest   │     │
│                  │ + Node.js      │  │ GET  /attest/x │     │
│                  │ unmodified     │  │ POST /full     │     │
│                  ╰────────────────╯  ╰────────────────╯     │
╰──────────────────────────────┬──────────────────────┬────────╯
                               │                      │
                     job results + build     UnifiedQuote
                        attestation            "one ring"
                               │                      │
                               ▼                      ▼
```

```text
┌──────────────────────────┐     ┌────────────────────────────────────┐
│ GitHub Actions           │     │ UnifiedQuote                       │
│                          │     │                                    │
│ artifacts uploaded       │     │ version: 1                         │
│ SLSA provenance attached │     │ platform: Nitro | SNP | TDX        │
│                          │     │ value_x: [48 bytes]                │
└──────────────────────────┘     │ quote_hash: [32 bytes]             │
                                 │ timestamp, nonce                   │
                                 │ ed25519 signature                  │
                                 │ pubkey                             │
                                 └─────────────────┬──────────────────┘
                                                   │
                                                   ▼
                                 ┌────────────────────────────────────┐
                                 │ On-chain Oracle                    │
                                 │                                    │
                                 │ stores about 180 bytes:            │
                                 │ value_x, platform, quote_hash,     │
                                 │ timestamp, signature, pubkey       │
                                 │                                    │
                                 │ full platform quote lives          │
                                 │ off-chain and is hash-linked       │
                                 └────────────────────────────────────┘
```

```text
 .----------------------------------.   .------------------------------------.
 | GITHUB ACTIONS // UPLOAD BUS     |   | UNIFIEDQUOTE // STATUS PANEL       |
 |----------------------------------|   |------------------------------------|
 | artifacts: pushed                |   | version      : 1                   |
 | provenance: attached             |   | platform     : Nitro | SNP | TDX   |
 | logs + outputs: available        |   | value_x      : [48 bytes]          |
 '----------------------------------'   | quote_hash   : [32 bytes]          |
                                        | timestamp     : unix epoch         |
                                        | nonce         : anti-replay        |
                                        | signature     : ed25519            |
                                        | pubkey        : TEE-bound          |
                                        '-------------------.----------------'
                                                            |
                                                     .------'------.
                                                     |  CHAIN LINK  |
                                                     '------.------'
                                                            |
                                                            v
                                        .====================================.
                                        | ORACLE // CHAIN ANCHOR             |
                                        |====================================|
                                        | stores compact attestation fields  |
                                        | full quote blob remains off-chain  |
                                        | quote_hash links the two layers    |
                                        '===================================='
```

## Verification Paths

- User A runs the Action, checks job output, sees `Value X` in the attestation, and trusts the build.
- User B rebuilds the runner from source, computes `sha384(runner manifest)`, gets `X`, and matches it against on-chain `X`.
- User C queries a running runner with `GET /attest`, receives `UnifiedQuote`, verifies the signature, and extracts `X`.
- User D performs deep verification by fetching the full platform quote off-chain, validating the platform chain, matching the `pubkey`, and confirming `Value X` in report data matches `value_x`.
