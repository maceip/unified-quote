# Boot measurements and immutable system closure

`boot` implements bounded TCG2 and Intel TDX CCEL parsing, register replay,
authenticated measurement appraisal, measured command-line/root-hash checks,
and an explicit system-closure SHA-384 Merkle identity. Hardware collection and
end-to-end acceptance remain unexercised until the target machines arrive.

## Verification boundary

`EventLog::parse_tcg2` and `EventLog::parse_tdx_ccel` return unverified data.
`EventLog::replay` returns `UnverifiedReplay`; reproducing a hash does not prove
that a genuine hardware quote exists. `EventLog::verify` requires
`AuthenticatedRegisters`, whose constructors are private to the crate. Platform
integration must call them only after validating the CPU quote, its collateral,
freshness, and report-data binding. Comparing raw `/sys` register reads does not
meet that condition.

With the `desktop` feature, `tee::desktop::tpm::verify_boot_event_log` connects
replay to the existing TPM AK-signature, pinned EK and credential-activation
verifier. Its expected channel binding must contain the relying party's fresh
challenge. The API requires the quoted PCR/IMA profile, a single SHA-256 bank,
exact equality between reported and signed PCR selections, and PCR 0–10
coverage. Unquoted extra PCRs, duplicate values, unbounded selections and trailing
TPM quote bytes are rejected. The IMA path now reconstructs each `ima-ng`
template digest from its SHA-256 file digest and NUL-terminated name before
using either field, following
[Linux's IMA field encoding](https://github.com/torvalds/linux/blob/master/security/integrity/ima/ima_template_lib.c)
and [template hashing](https://github.com/torvalds/linux/blob/master/security/integrity/ima/ima_crypto.c).
Other IMA template/byte-order profiles are rejected, not guessed. This is a
separate TPM API; a raw SNP report or Nitro-enclave NSM PCR is not a TPM quote.

The explicit Azure SNP/vTPM and AWS SNP/NitroTPM composite profiles also
supply authenticated TPM registers after their CPU and TPM verification.
Azure requires independently enrolled restricted AK public areas and exact PCR
policy; AWS excludes its constant PCR0/1 and resettable registers from boot
replay. See [Azure profile](AZURE_COMPOSITE.md) and [NitroTPM profile](NITROTPM.md).

Successful comparison yields `VerifiedBootLog`. Only digests in the authenticated
register selection can be obtained through `authenticated_digest`. Description
bytes, event-type values, filenames, and global cross-register event ordering do
not become authenticated merely because register replay succeeded. Known
firmware, bootloader and kernel identities must be supplied by verifier policy
and checked using `verify_expected_digest`, or measured content checked with
`verify_measured_bytes` for a raw-hash measurement profile. PE/COFF images use
Authenticode rules; this module does not substitute a raw image hash for them.

## Formats and register semantics

The parser handles the legacy first `Spec ID Event03` record, advertised digest
sizes, crypto-agile event records, and bounded event data. It rejects truncated
fields, duplicate banks, inconsistent known digest sizes, unexpected registers,
zero digest counts and configured resource-limit violations. SHA-256, SHA-384
and SHA-512 are replayable. Other banks can be transported using their declared
lengths, but selecting them for verification returns an unsupported-algorithm
error. SHA-1 is deliberately unavailable as a verification bank.

Static TPM PCRs 0–15 replay from reset values, including the well-formed, early,
unique `StartupLocality` event for locality 0 or 3. PCRs 0–9 can therefore be
required together. Resettable/dynamic PCR replay is not implemented. This follows
the [TCG PC Client Platform Firmware Profile](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/).

The capability document's RTMR assignment was imprecise. The firmware CCEL profile
uses **MRIndex 1 → RTMR0, 2 → RTMR1, 3 → RTMR2**. MRIndex 0 denotes MRTD and is
not an extendable RTMR. PCR 8–15 map to MRIndex 3, so command-line measurements are
normally in RTMR2 under that profile. Firmware-only parsing rejects application
MRIndex4 records; its RTMR3 must therefore remain zero. The separately selected
CoCo AAEL TCG2 runtime profile below permits MRIndex4 and authenticates its
complete tagged preimages against quoted RTMR3. See
[UEFI 2.11 §38.4.1, Table 38.1](https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html#intel-trust-domain-extension).

`read_tpm_event_log` reads the securityfs TPM log. `read_tdx_ccel` validates the
56-byte ACPI CCEL header's signature, checksum, revision, Intel TDX type/subtype,
reserved fields, address overflow and log-area bound before reading the sysfs
data. It accepts only a fully erased `0xff` trailing area. Missing final events
or events racing quote collection cause register mismatch. It does not invent
events or ignore mismatched registers. ACPI layout is documented in
[Linux's CCEL table definition](https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/acpi/actbl2.h#L442).

## Measured command lines and dm-verity

The verifier selects the known loader profile and event index; untrusted event
labels cannot select policy. `authenticated_command_line` implements:

- GRUB PCR 8 (TDX MRIndex 3): remove the descriptive `kernel_cmdline: ` prefix
  and terminating NUL, then hash the actual UTF-8 command-line bytes, as
  [GRUB's TPM verifier does](https://github.com/rhboot/grub2/blob/master/grub-core/commands/tpm.c).
- systemd load options PCR 12 (TDX MRIndex 3): hash the full UTF-16LE buffer
  including its terminating NUL, reject malformed strings, then decode it, as
  [systemd's load-options measurement does](https://github.com/systemd/systemd/blob/main/src/boot/measure.c).

`verified_dm_verity` requires an authenticated command line and exact equality
between its `roothash` and the expected manifest digest. It rejects duplicates,
invalid hexadecimal data, recognized explicit disabling flags, roots passed
after `--`, and unsupported quoting/escaping. It returns a **measured root
commitment**. This cannot by itself prove that the kernel mounted dm-verity,
that an initrd honored the parameter, that a particular file is on that device,
or that the selected event was the final effective command line. Acceptance
policy must also approve the measured loader/kernel/initrd and their boot
semantics. UKI embedded-command-line extraction is described below. Effective
command-line resolution is not silently emulated.

## Authenticated UKI metadata

`boot::uki::UnverifiedUki::parse` is a native Rust PE32/PE32+ parser. It accepts
UEFI application images containing `.linux`, with a 512 MiB file/image limit,
96 sections, and 64 KiB per extracted text section. It checks header/table
bounds, alignment, section overlap and the certificate-directory
range. Parsing does not authenticate these headers or any image signature.
Section hashing uses `VirtualSize`: disk alignment padding is excluded and
missing initialized bytes are streamed as zeroes, following the
[PE section definitions](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers).

`VerifiedBootLog::verify_uki(image, policy)` supports the explicitly selected
`systemd_stub_v258` profile. It checks section pairs in that release's canonical
order: `.linux`, `.osrel`, `.cmdline`, `.initrd`, `.ucode`, `.splash`, `.dtb`,
`.uname`, `.sbat`, `.pcrpkey`, `.profile`, `.dtbauto`, `.hwids`, `.efifw`, skipping absent sections. Each pair
authenticates the ASCII section name including NUL, followed by its loaded
contents. Both must be consecutive extended events in PCR 11, or TDX MRIndex 3,
and covered by the already verified quote. Events in other registers may be
interleaved; their relative positions are not authenticated. Event-description
labels are ignored. These rules follow systemd v258's
[measurement loop](https://github.com/systemd/systemd/blob/v258/src/boot/stub.c#L738),
[section order](https://github.com/systemd/systemd/blob/v258/src/fundamental/uki.h),
and [section-size handling](https://github.com/systemd/systemd/blob/v258/src/boot/pe.c#L330).

The independent `UkiPolicy` contains `profile`, `first_section_event`,
`algorithm` (TCG SHA-256/384/512 identifier), and `expected_sections`, an exact
map from every measured section name to its approved hexadecimal digest.
Optional `expected_command_line` requires an exact embedded string;
`expected_verity_root` requires an exact canonical measured `roothash`.
`UkiPolicy::validate` checks this configuration without platform I/O.
Missing, additional, unsupported or mismatched expectations fail. There is no
path that learns approved digests from the candidate and grants admission.

Only after these checks does `VerifiedUki` expose the measured `.cmdline`,
`.osrel` and `.uname` strings and section digests. Text is bounded UTF-8, and
nonzero hidden bytes after a NUL are rejected. The `.osrel` result is its text;
no shell expansion or inference about the running host is performed. This is
embedded content, not the command line after loader overrides or addons.
The optional dm-verity result remains a measured root commitment, not evidence
of an effective mount or a file-tree hash.

`.pcrsig` is deliberately excluded from measured claims. Optional `selection`
chooses a numeric profile: base sections before the first `.profile` are overlaid
with sections in the selected `.profile` block, and the first matching section
within each block wins. Missing nondefault profiles fail. The selected `.profile`
bytes are themselves measured. This follows [v258's profile locator](https://github.com/systemd/systemd/blob/v258/src/boot/pe.c#L681).

Device selection uses independently configured `expected_compatible` and
`expected_firmware_id` values. Bounded FDT v17 parsing compares the **first** root
`compatible` string; subsequent SoC-compatible strings cannot select a device.
EFI firmware blobs require the `0xfeeddead` header and bounded, NUL-terminated
FWID field. Each profile uses its first matching `.dtbauto` and `.efifw` section,
and the resulting payload must also match its quoted pair and independent
digest. These rules follow [systemd's DT matcher](https://github.com/systemd/systemd/blob/v258/src/boot/devicetree.c#L182)
and [firmware matcher](https://github.com/systemd/systemd/blob/v258/src/boot/efi-firmware.c).
Selectors state verifier expectations; they do not authenticate host SMBIOS,
firmware device-tree contents, or physical model identity. Measuring selected
payload bytes proves which approved content is represented by the log.

A configured `profile_event` additionally checks the numeric nondefault profile
UTF-16LE-with-NUL measurement in authenticated TPM PCR12.
`authenticated_profile_index()` is absent unless that check succeeds. v258's
[tagged-event helper](https://github.com/systemd/systemd/blob/v258/src/boot/measure.c#L275)
only invokes EFI_TCG2, so it cannot establish a numeric profile or binary addon
measurement through a TDX CCEL. Its section-pair IPL helper does invoke EFI_CC;
selected content therefore remains verifiable on TDX.

The optional `execution` policy reconstructs command-line composition using the
selected embedded command line or an independently approved, measured load-option
string, followed by the measured aggregate addon string and then an optional
SMBIOS append. v258 trims ASCII control/space/DEL at the ends and replaces each
inner such character with a space, preserving repeated spaces. Addon fragments
are joined in configured directory order (global before image-specific), then
mangled and authenticated as the single UTF-16LE-with-NUL buffer actually measured
by the stub. SMBIOS appends are rejected for TDX, where v258 ignores them.
The reconstructed string must equal `expected_effective_command_line` exactly.
The result describes the approved stub's measured inputs and composition; it
requires independently approved loader/kernel/initrd behavior and does not prove
subsequent mount state.

Execution appraisal accounts for **every** extended configuration-register event:
PCR12 for TPM, MRIndex3 for TDX. UKI pairs in MRIndex3 are covered automatically;
other measurements need explicit independently approved `other_config_events`
digests. Missing, additional, reordered, or substituted command-line measurements
fail. TPM binary addons use exact approved payload digests in device-tree,
microcode, then initrd measurement order; microcode order is the reverse of its
configured loading order. The measured payload does not authenticate the event's
filename or imply that the addon PE signature was accepted. These rules follow
[v258's addon measurement and command-line sequence](https://github.com/systemd/systemd/blob/v258/src/boot/stub.c#L1190).

Other PE sections belong to the opaque stub image and are not promoted to
metadata. Authenticode validation, Secure Boot state, the executed loader/stub
identity, and actual mounted state remain separate requirements. Approve the
loader/image measurements independently; matching section content cannot prove
that an approved loader executed or honored it.

The composite verifier accepts candidate bytes through
`AttestationVerifierBuilder::with_uki_evidence`, together with `BootPolicy.uki`
and independent approved loader events. It applies UKI appraisal only after
CPU admission and boot-log replay. `uq verify ... --boot-policy policy.json
--uki candidate.efi` forwards the same inputs. The candidate file is content
evidence; its trust comes from the quoted measurements and verifier policy.

## Immutable system closure

`boot::closure::measure_closure` measures an explicit, sorted, unique list of
relative regular-file paths. There are no implicit build/VCS exclusions. SHA-384
leaves commit length-prefixed UTF-8 paths, POSIX permission bits, file lengths
and content digests. Branches and the root have separate domains, child counts,
and an overall file count. The serialized format is `uq-system-closure-v1`.
File content is streamed with count/byte limits; descriptor-relative traversal
rejects symlinks in every root and file-path component, and metadata changes
during hashing cause failure. Filesystem ownership and timestamps are not part
of the identity. A caller must provide the actual immutable mount and trusted
path manifest before use.

This explicit closure identity is separate from the existing source-tree
`value_x::compute_tree_hash`; its hash encoding is not changed. Neither file-tree
hash is a dm-verity block-device Merkle root. Pin and verify those identities
separately in admission policy.

## Validation evidence

`testdata/boot` includes licensed, pinned Intel SDK captured TPM2 and CCEL logs.
Their replay results are checked against independently computed SHA-256/SHA-384
values. Negative checks exercise interior truncation, corrupt counts and ACPI
headers, hidden padding tails, resource limits, digest tampering, reorderings,
untrusted description changes, uncovered registers, duplicate verity roots,
disabled verity, unaccounted RTMR3 state, and closure path/permission changes.
These are implementation checks; they are not a claim of hardware acceptance.

UKI checks use explicitly constructed PE/profile conformance vectors and
independent Python-hashlib PCR constants, not purported captured hardware
evidence. They cover PE32/PE32+, TPM/TDX mappings, NUL-inclusive name hashing,
canonical pairs, false event labels, policy mismatch, missing/uncovered events,
cross-register interleaving, truncation/overflow/overlap, zero-fill versus raw
padding, text ambiguity, profile overlay, device selection, complete command-line
measurement accounting and dm-verity root mismatch.

## CoCo runtime events in RTMR3

`EventLog::parse_tdx_ccel_with_aael` adds the explicitly selected CoCo AAEL TCG2
profile. It permits CC measurement register index 4, corresponding to TDX RTMR3,
and requires each such record to be `EV_EVENT_TAG` with one SHA-384 digest and
AAEL tag `0x4141454c`. The tag and its length are little-endian; the serialized tag
bytes are `4c 45 41 41`. The measured preimage is the complete tag, length, and
UTF-8 `domain operation content` record, with no appended NUL or newline. The
current producer is [CoCo's TCG2 event writer](https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/attestation-agent/src/eventlog/tcg2.rs).
[Google go-eventlog's RTMR type](https://github.com/google/go-eventlog/blob/v0.0.2/register/rtmr.go)
also defines `CC MRIndex = RTMR index + 1`.

`verify_tdx_runtime` requires all four registers from the authenticated CPU quote,
replays the combined firmware/application log, rehashes every AAEL preimage, and
requires exact ordered equality with `RuntimePolicy.expected_events`. Missing,
extra, reordered, or differently encoded events fail. JSON-looking content is
opaque UTF-8, never merged or interpreted as verifier configuration. A runtime
record attests to a statement by the measuring agent approved in the image/boot
policy; it does not by itself establish a continuous monitor, arbitrary process
state, or mounted filesystem integrity.

`runtime::append_coco_aael` joins a firmware CCEL and the agent's standalone
Event2 file (normally `/run/attestation-agent/eventlog`). It retains the firmware
SpecID, removes only validated erased firmware padding, requires complete
MRIndex4 application records, and applies the combined log limits. The result
remains unverified collector evidence. The firmware-only parser continues to
reject application records unless this profile was explicitly selected.

The captured regression input `testdata/boot/coco-ccel-aael.bin` comes from
[Trustee commit 71251310045d8be2e95041cf0028691623c73957](https://github.com/confidential-containers/trustee/blob/71251310045d8be2e95041cf0028691623c73957/deps/eventlog/test_data/CCEL_AAEL_alibabacloud),
under Apache-2.0 (`testdata/boot/LICENSE-coco`). Its SHA-256 is
`ebc70a8e808203895b3c7426d1eded355b8677fc47531705b6539e3c8aa5b841`.
Independent Python `hashlib` replay constants test the implementation; the
fixture contains no authenticated quote and is not represented as deployment
attestation evidence. Mutation tests cover metadata substitution despite an
unchanged replay, changed digests, malformed tags/lengths, truncated records,
policy omission/order changes, and omitted RTMR coverage.

## Native mounted dm-verity observations

`boot::verity::collect_mounted_verity` implements read-only Linux x86_64/aarch64
`DM_TABLE_STATUS` ioctls without shelling out to `dmsetup`. It identifies the
complete `/` mount through bounded `/proc/self/mountinfo`, addresses the mapped
device by its Linux major/minor encoding, and requests the active table and
runtime status. It requires one verity target covering the full mapped device,
checks table geometry and active/read-only/suspension flags, and compares a
second table read and the mount namespace snapshot to reject observable races.
It parses both legacy `V`/`C` status and the current optional FEC correction
counter. Kernel ABI references are [dm-ioctl.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/dm-ioctl.h),
[verity status serialization](https://github.com/torvalds/linux/blob/master/drivers/md/dm-verity-target.c),
and [device-number encoding](https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h).

The bounded verity-table parser checks versions 0/1, SHA-256/384/512 root lengths,
block geometry, salt, exact option counts, duplicate/conflicting options and FEC
arguments. `MountedVerityPolicy` compares independently approved roots, geometry,
filesystem and exact options. Strict policy rejects `ignore_corruption` and
`check_at_most_once`; their behavior is described in the
[Linux dm-verity documentation](https://docs.kernel.org/admin-guide/device-mapper/verity.html).

The return type is deliberately `UnverifiedMountedVerity`.
`check_observed_policy()` does not create an authenticated claim, and this
observation is not accepted as composite attestation proof. Runtime files,
namespace identity, device-mapper reads and a matching `roothash` remain
statements of the guest that produced them. Promoting them requires a separately
approved measuring component, authenticated challenge-bound snapshot, and a
policy establishing that component's authority to observe this kernel and mount
namespace. Merely placing arbitrary state JSON in an AAEL record is insufficient;
AAEL verifies bytes measured by its producer, not an arbitrary caller's authority
to assert mounted state. Even an authenticated snapshot would describe that
observation time and namespace, not promise that future remounts are impossible.
