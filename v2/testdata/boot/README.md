# Boot event-log fixtures

These are unmodified captured binary fixtures published by Intel's Trust Authority
Go SDK at commit `8f1ca9666f6e1c785bb32798b46ad2aec3401846`, retrieved 2026-10-13.
The upstream BSD-3-Clause license is included as `INTEL-LICENSE`.

| Local file | Upstream path | SHA-256 |
| --- | --- | --- |
| `intel-CCEL.bin` | `go-tdx/test/resources/CCEL.bin` | `922ff5a35693d28e14aa829cbd5579979c701743c38e8f1fc55bdecb64f19164` |
| `intel-CCEL.data.bin` | `go-tdx/test/resources/CCEL.data.bin` | `14204df175f0d6daadb9face0ba514a933611e83351da30c08550fa4cd7982bc` |
| `intel-tpm2-bios.bin` | `go-tpm/test_data/binary_bios_measurements20` | `059f4d55e9bc19f1a7e411087dc7649e44859487ac48b51ed7fb761e77c6b001` |

[Pinned upstream repository](https://github.com/intel/trustauthority-client-for-go/tree/8f1ca9666f6e1c785bb32798b46ad2aec3401846).
The CCEL contains 19 measurements followed by erased `0xff` padding in a 64 KiB
log area. The TPM2 log contains 135 events, SHA-1 and SHA-256 banks, locality 3
initialization and a GRUB kernel command-line event.

These fixtures do not include fresh authenticated CPU quotes. Their expected
replay values were independently computed with Python `hashlib`, not presented as
live hardware verification. Unit-only constructors supply register expectations
to exercise the verification boundary and negative cases. Production APIs cannot
deserialize or publicly construct an authenticated-register or verified-log type.
