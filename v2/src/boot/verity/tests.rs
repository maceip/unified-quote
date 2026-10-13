use super::*;
fn params() -> String {
    format!("1 8:1 8:1 4096 4096 8192 8192 sha256 {} -", "ab".repeat(32))
}
#[test]
fn strict_root_mount_parser_rejects_overlay_ambiguity_and_partial_ro() {
    let mount = b"31 1 253:0 / / ro,relatime - ext4 /dev/dm-0 ro\n";
    let root = parse_root_mountinfo(mount).unwrap();
    assert!(root.read_only);
    assert_eq!((root.major, root.minor), (253, 0));
    assert!(parse_root_mountinfo(&[mount.as_slice(), mount.as_slice()].concat()).is_err());
    assert!(parse_root_mountinfo(b"31 1 253:0 /subdir / ro - ext4 /dev/dm-0 ro\n").is_err());
    assert!(
        !parse_root_mountinfo(b"31 1 253:0 / / ro - ext4 /dev/dm-0 rw\n")
            .unwrap()
            .read_only
    );
    assert!(parse_root_mountinfo(b"31 1 253:0 / / ro,rw - ext4 /dev/dm-0 ro\n").is_err());
}
#[test]
fn table_parser_checks_geometry_options_roots_and_option_arguments() {
    let p = params();
    let table = parse_verity_parameters(&p).unwrap();
    assert_eq!(table.data_blocks, 8192);
    assert_eq!(table.root_digest_hex, "ab".repeat(32));
    for extra in [
        " 1 unknown_option",
        " 2 ignore_corruption",
        " 3 restart_on_corruption panic_on_corruption ignore_zero_blocks",
        " 2 fec_roots 2",
        " 2 fec_roots overflow",
        " 2 ignore_zero_blocks ignore_zero_blocks",
    ] {
        assert!(
            parse_verity_parameters(&format!("{p}{extra}")).is_err(),
            "{extra}"
        );
    }
    assert!(parse_verity_parameters(&format!(
        "{p} 8 use_fec_from_device 8:2 fec_roots 2 fec_blocks 9000 fec_start 0"
    ))
    .is_ok());
    assert!(parse_verity_parameters(&p.replace("4096 4096", "513 4096")).is_err());
    assert!(parse_verity_parameters(&p.replace("sha256", "sha1")).is_err());
    assert!(parse_verity_parameters(&p.replace("8192 8192", "18446744073709551615 8192")).is_err());
}
fn response(parameters: &str) -> Vec<u8> {
    let n = DM_HEADER + 40 + parameters.len() + 1;
    let mut b = vec![0; n];
    for (at, v) in [
        (0, 4),
        (12, n as u32),
        (16, DM_HEADER as u32),
        (20, 1),
        (28, 33),
        (32, 10),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }
    b[40..48].copy_from_slice(&0xfd00u64.to_ne_bytes());
    b[48..52].copy_from_slice(b"root");
    b[DM_HEADER + 8..DM_HEADER + 16].copy_from_slice(&65536u64.to_ne_bytes());
    b[DM_HEADER + 20..DM_HEADER + 24]
        .copy_from_slice(&(((40 + parameters.len() + 1 + 7) & !7) as u32).to_ne_bytes());
    b[DM_HEADER + 24..DM_HEADER + 30].copy_from_slice(b"verity");
    b[DM_HEADER + 40..n - 1].copy_from_slice(parameters.as_bytes());
    b
}
#[test]
fn ioctl_parser_rejects_inactive_suspended_extra_targets_and_out_of_bounds() {
    let b = response(&params());
    let r = parse_dm_response(&b, 0xfd00).unwrap();
    assert_eq!(r.name, "root");
    assert_eq!(r.sectors, 65536);
    for (at, n) in [
        (0, 3),
        (12, u32::MAX),
        (16, 313),
        (20, 2),
        (28, 33 | 2),
        (28, 33 | 256),
        (28, 33 | 4096),
        (DM_HEADER + 20, 0),
    ] {
        let mut bad = b.clone();
        bad[at..at + 4].copy_from_slice(&n.to_ne_bytes());
        assert!(parse_dm_response(&bad, 0xfd00).is_err());
    }
    assert!(parse_dm_response(&b, 0xfd01).is_err());
    assert!(parse_dm_response(&b[..DM_HEADER + 40], 0xfd00).is_err());
    let mut bad = b;
    *bad.last_mut().unwrap() = b'x';
    assert!(parse_dm_response(&bad, 0xfd00).is_err());
}
#[test]
fn status_profiles_preserve_corruption_and_fec_counts() {
    assert_eq!(parse_verity_status("V").unwrap(), (false, None));
    assert_eq!(parse_verity_status("C -").unwrap(), (true, None));
    assert_eq!(parse_verity_status("V 42").unwrap(), (false, Some(42)));
    for s in ["", "V false", "valid", "V 2 more", "C -1"] {
        assert!(parse_verity_status(s).is_err());
    }
}
