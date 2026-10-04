//! Public fixed-flow model and independent PSC checks; native tests prove forwarding.
use opc_gtpu_dataplane::n3::{
    LocalN3DownlinkTnl, N3FlowMarking, N3ForwardingIntent, N3ForwardingRole, N3Qfi,
    ReceivedN3UplinkTnl,
};
use opc_gtpu_dataplane::{
    GtpBearerMark, GtpuSessionEntry, GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy, Teid,
};
use opc_gtpu_ebpf_common::{n3_downlink_psc_matches, n3_uplink_extension};

fn intent(qfi: u8) -> N3ForwardingIntent {
    N3ForwardingIntent::new(
        N3ForwardingRole::N3iwf,
        ReceivedN3UplinkTnl::new(
            "192.0.2.10".parse().unwrap(),
            Teid::new(0x55667788).unwrap(),
        )
        .unwrap(),
        LocalN3DownlinkTnl::new("192.0.2.1".parse().unwrap(), Teid::new(0x11223344).unwrap())
            .unwrap(),
        N3FlowMarking::new(N3Qfi::new(qfi).unwrap(), GtpBearerMark::new(0x10203040)),
    )
}

#[test]
fn directional_intent_survives_fixed_flow_construction_and_debug_redacts_it() {
    for qfi in 0..64 {
        let input = intent(qfi);
        let entry = GtpuSessionEntry::from_n3(
            input,
            "10.45.0.2".parse().unwrap(),
            7,
            GtpuSourcePortPolicy::Exact(2152),
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
            None,
        )
        .unwrap();
        assert_eq!(entry.n3_intent(), Some(input));
        assert_eq!(entry.n3_qfi().unwrap().get(), qfi);
        assert_eq!(entry.context().peer_teid, input.received_uplink().teid());
        assert_eq!(entry.context().local_teid, input.local_downlink().teid());
        assert_eq!(
            entry.context().peer_address,
            input.received_uplink().destination()
        );
        assert_eq!(
            entry.local_outer_address(),
            input.local_downlink().local_address()
        );
        let legacy =
            GtpuSessionEntry::new(entry.context().clone(), entry.local_outer_address()).unwrap();
        assert_ne!(entry, legacy);
        assert_eq!(legacy.n3_intent(), None);
        assert_eq!(legacy.n3_qfi(), None);
        assert_eq!(format!("{entry:?}"), format!("{legacy:?}"));
    }
}

#[test]
fn all_qfi_uplink_bytes_match_independent_packet_oracle() {
    let reference = include_str!("n3_reference.tsv");
    let mut count = 0;
    for line in reference.lines().filter(|line| !line.starts_with('#')) {
        let row: Vec<_> = line.split('\t').collect();
        if row[1] != "ul" || row[2] != "accept" {
            continue;
        }
        let bytes: Vec<_> = row[7]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        // Only the independently generated canonical one-PSC shape is an
        // uplink construction oracle; receive-only variants remain separate.
        if bytes.len() < 16
            || bytes[0] != 0x34
            || bytes[11..14] != [0x85, 1, 0x10]
            || bytes[15] != 0
        {
            continue;
        }
        let qfi: u8 = row[3].parse().unwrap();
        let mut expected: [u8; 8] = bytes[8..16].try_into().unwrap();
        // S and PN are clear: receive ignores these fields; construction zeros them.
        expected[..3].fill(0);
        assert_eq!(n3_uplink_extension(qfi).unwrap(), expected);
        count += 1;
    }
    assert_eq!(count, 64);
    for qfi in 64..=255 {
        assert!(n3_uplink_extension(qfi).is_none());
    }
}

#[test]
fn psc_prefix_validation_agrees_with_independent_downlink_packet_oracle() {
    let reference = include_str!("n3_reference.tsv");
    let mut count = 0;
    for line in reference.lines().filter(|line| !line.starts_with('#')) {
        let row: Vec<_> = line.split('\t').collect();
        if row[1] != "dl" || row[2] != "accept" {
            continue;
        }
        let bytes: Vec<_> = row[7]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        let mut next = bytes[11];
        let mut cursor = 12;
        while next != 0 {
            let end = cursor + usize::from(bytes[cursor]) * 4;
            if next == 0x85 {
                let prefix = [bytes[cursor], bytes[cursor + 1], bytes[cursor + 2]];
                let qfi: u8 = row[3].parse().unwrap();
                assert!(n3_downlink_psc_matches(prefix, qfi));
                assert!(!n3_downlink_psc_matches(prefix, (qfi + 1) % 64));
                let mut mutation = prefix;
                mutation[1] |= 0x10;
                assert!(!n3_downlink_psc_matches(mutation, qfi));
                for flag in [2, 4, 8] {
                    let mut mutation = prefix;
                    mutation[1] |= flag;
                    assert!(!n3_downlink_psc_matches(mutation, qfi));
                }
                let mut mutation = prefix;
                mutation[0] = 3;
                assert!(!n3_downlink_psc_matches(mutation, qfi));
                count += 1;
            }
            next = bytes[end - 1];
            cursor = end;
        }
    }
    assert!(count >= 64);
}
